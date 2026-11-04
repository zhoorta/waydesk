//! Clipboard (CLIPRDR), text only. The RDP channel lives here, in the network daemon; the Wayland clipboard belongs to
//! the account and is reached through the session process (`sessionclip.rs`), which this side talks to over the link.
//! Client copy: the client announces formats, we ask for the text and send it to the session.
//! Session copy: the session sends its text when the clipboard changes, we announce it and answer the client's request.
//! Images (CF_DIB on the RDP side, PNG on the Wayland side) go the same way and are converted here (`clipimage.rs`), with limits.
//! Files from the client (docs/decisions/016-clipboard-files.md) are fetched in ranges here and handed to the session, which
//! writes them (`sessionfiles.rs`); they are on only when the daemon is started with `--clipboard-files in`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ironrdp_cliprdr::backend::{CliprdrBackend, CliprdrBackendFactory, ClipboardMessage};
use ironrdp_cliprdr::pdu::{
    ClipboardFileAttributes, ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsFlags,
    FileContentsRequest, FileContentsResponse, FileDescriptor, FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_server::tokio::sync::mpsc::UnboundedSender;
use ironrdp_server::{CliprdrServerFactory, ServerEvent, ServerEventSender};
use tracing::{debug, info};

use crate::link::FilesEvent;
use crate::proto::{Down, FILE_CHUNK, MAX_CLIPBOARD, MAX_CLIPBOARD_IMAGE, MAX_FILES, MAX_FILES_TOTAL, MAX_FILE_BYTES};
use crate::Slot;

struct Shared {
    sender: Mutex<Option<UnboundedSender<ServerEvent>>>,
    /// The connection's session (its link appears once the session is up).
    slot: Arc<Slot>,
    /// The text the session's clipboard holds, as the session last reported it.
    session_text: Mutex<Option<String>>,
    /// The image (PNG) the session's clipboard holds, as the session last reported it. Only one of text and image is set.
    session_image: Mutex<Option<Vec<u8>>>,
    /// Files from the client are accepted (`--clipboard-files in`).
    files_in: bool,
    /// The file transfer in progress, if any (one at a time).
    xfer: Mutex<Option<Xfer>>,
    next_id: AtomicU32,
}

/// A transfer of the client's files to the session: the daemon asks the client for one range at a time.
struct Xfer {
    id: u32,
    clip_data_id: Option<u32>,
    sizes: Vec<u64>,
    /// The file and the offset of the next range.
    index: usize,
    offset: u64,
    /// The session has accepted the transfer.
    ready: bool,
    /// The range asked for and not yet answered: stream id and length.
    in_flight: Option<(u32, u32)>,
    stream: u32,
    started: Instant,
    last: Instant,
}

/// Longest the client may take over one range, and over the whole transfer.
const FILE_IDLE: Duration = Duration::from_secs(30);
const FILE_TOTAL: Duration = Duration::from_secs(600);

impl Shared {
    /// Ends the transfer (if it is `id`) and tells the session to drop what it has.
    fn fail_transfer(&self, id: u32, why: &str) {
        let mut x = self.xfer.lock().unwrap();
        if x.as_ref().is_some_and(|t| t.id == id) {
            info!(id, why, "clipboard file transfer ended");
            *x = None;
            drop(x);
            if let Some(link) = self.slot.link() {
                link.send(Down::FilesCancel { id });
            }
        }
    }

    /// Asks the client for the next range, or ends the transfer when everything is in.
    fn request_next(&self) {
        let mut guard = self.xfer.lock().unwrap();
        let Some(t) = guard.as_mut() else { return };
        if !t.ready || t.in_flight.is_some() {
            return;
        }
        while t.sizes.get(t.index).is_some_and(|&s| t.offset >= s) {
            t.index += 1;
            t.offset = 0;
        }
        if t.index >= t.sizes.len() {
            info!(id = t.id, "clipboard file transfer complete");
            *guard = None;
            return;
        }
        let len = u32::try_from((t.sizes[t.index] - t.offset).min(u64::from(FILE_CHUNK))).unwrap_or(FILE_CHUNK);
        t.stream = t.stream.wrapping_add(1);
        t.in_flight = Some((t.stream, len));
        let request = FileContentsRequest {
            stream_id: t.stream,
            index: t.index as i32,
            flags: FileContentsFlags::RANGE,
            position: t.offset,
            requested_size: len,
            data_id: t.clip_data_id,
        };
        t.last = Instant::now();
        drop(guard);
        self.send(ClipboardMessage::SendFileContentsRequest(request));
    }

    fn send(&self, msg: ClipboardMessage) {
        if let Some(tx) = self.sender.lock().unwrap().as_ref() {
            if tx.send(ServerEvent::Clipboard(msg)).is_err() {
                debug!("clipboard message dropped: server event channel closed");
            }
        }
    }
}

pub struct Factory {
    st: Arc<Shared>,
}

impl Factory {
    pub fn new(slot: Arc<Slot>, files_in: bool) -> Self {
        Self {
            st: Arc::new(Shared {
                sender: Mutex::new(None),
                slot,
                session_text: Mutex::new(None),
                session_image: Mutex::new(None),
                files_in,
                xfer: Mutex::new(None),
                next_id: AtomicU32::new(1),
            }),
        }
    }
}

impl ServerEventSender for Factory {
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        *self.st.sender.lock().unwrap() = Some(sender);
    }
}

impl CliprdrBackendFactory for Factory {
    fn build_cliprdr_backend(&self) -> Box<dyn CliprdrBackend> {
        Box::new(Backend { st: self.st.clone(), ready_at: None, asked: ClipboardFormatId::CF_UNICODETEXT })
    }
}

impl CliprdrServerFactory for Factory {}

#[derive(Debug)]
struct Backend {
    st: Arc<Shared>,
    ready_at: Option<std::time::Instant>,
    /// The format the last request to the client was for (the answer does not say).
    asked: ClipboardFormatId,
}

/// How long after the channel is ready the client's clipboard is left alone. The Windows App announces
/// the Mac clipboard at connection time and then took up to a minute to answer the request for its text
/// (probably macOS gating a programmatic pasteboard read), which kept the connection at "Configuring
/// remote PC". Asking later keeps a slow answer from holding up the connection.
const SETTLE: std::time::Duration = std::time::Duration::from_secs(5);

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Shared")
    }
}

ironrdp_core::impl_as_any!(Backend);

fn image_format() -> ClipboardFormat {
    ClipboardFormat::new(ClipboardFormatId::CF_DIB)
}

fn text_format() -> ClipboardFormat {
    ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)
}

/// CF_UNICODETEXT: UTF-16LE, CRLF line ends, NUL terminated.
fn to_unicode_text(text: &str) -> Vec<u8> {
    let crlf = text.replace("\r\n", "\n").replace('\n', "\r\n");
    crlf.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

fn from_unicode_text(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units).replace("\r\n", "\n")
}

impl CliprdrBackend for Backend {
    fn temporary_directory(&self) -> &str {
        "/tmp"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        // The Windows App on macOS did not answer requests for the text without this one.
        let mut flags = ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES;
        if self.st.files_in {
            flags |= ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
                | ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA
                | ClipboardGeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS;
        }
        flags
    }

    fn on_ready(&mut self) {
        info!("clipboard channel ready");
        self.ready_at = Some(std::time::Instant::now());
        let Some(link) = self.st.slot.link() else {
            info!("clipboard: no session yet; the clipboard stays off for this connection");
            return;
        };
        let st = self.st.clone();
        link.set_clipboard_sink(Box::new(move |data| {
            let Ok(text) = String::from_utf8(data) else { return };
            info!(len = text.len(), "session clipboard changed; announcing to the client");
            *st.session_text.lock().unwrap() = Some(text);
            *st.session_image.lock().unwrap() = None;
            st.send(ClipboardMessage::SendInitiateCopy(vec![text_format()]));
        }));
        let st = self.st.clone();
        link.set_clipboard_image_sink(Box::new(move |png| {
            info!(len = png.len(), "session clipboard image changed; announcing to the client");
            *st.session_image.lock().unwrap() = Some(png);
            *st.session_text.lock().unwrap() = None;
            st.send(ClipboardMessage::SendInitiateCopy(vec![image_format()]));
        }));
        if self.st.files_in {
            let st = self.st.clone();
            link.set_files_sink(Box::new(move |event| match event {
                FilesEvent::Ready(id) => {
                    if let Some(t) = st.xfer.lock().unwrap().as_mut().filter(|t| t.id == id) {
                        t.ready = true;
                    }
                    st.request_next();
                }
                FilesEvent::Failed(id) => {
                    // The session already dropped it: no cancel to send back.
                    let mut x = st.xfer.lock().unwrap();
                    if x.as_ref().is_some_and(|t| t.id == id) {
                        info!(id, "the session refused or dropped the clipboard files");
                        *x = None;
                    }
                }
            }));
        }
        // The session reports its clipboard changes from now on.
        link.send(Down::ClipboardOn);
    }

    fn on_request_format_list(&mut self) {
        // Start of the session: offer what is already on the clipboard.
        if self.st.session_text.lock().unwrap().is_some() {
            self.st.send(ClipboardMessage::SendInitiateCopy(vec![text_format()]));
        } else if self.st.session_image.lock().unwrap().is_some() {
            self.st.send(ClipboardMessage::SendInitiateCopy(vec![image_format()]));
        }
    }

    fn on_process_negotiated_capabilities(&mut self, _capabilities: ClipboardGeneralCapabilityFlags) {}

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        // A new copy on the client ends a transfer of the old one.
        let old = self.st.xfer.lock().unwrap().as_ref().map(|t| t.id);
        if let Some(id) = old {
            self.st.fail_transfer(id, "the client copied something else");
        }
        // Files first (a copy of files carries no text), then text, then an image.
        let file_format = available_formats
            .iter()
            .find(|f| f.name().is_some_and(|n| n.value().eq_ignore_ascii_case("FileGroupDescriptorW")))
            .map(|f| f.id);
        let format = if let Some(id) = file_format.filter(|_| self.st.files_in) {
            id
        } else if available_formats.iter().any(|f| f.id == ClipboardFormatId::CF_UNICODETEXT) {
            ClipboardFormatId::CF_UNICODETEXT
        } else if available_formats.iter().any(|f| f.id == ClipboardFormatId::CF_DIB) {
            ClipboardFormatId::CF_DIB
        } else {
            debug!(formats = ?available_formats.iter().map(|f| f.id.0).collect::<Vec<_>>(), "client copied something other than text or an image; ignored");
            return;
        };
        self.asked = format;
        let wait = self.ready_at.map_or(SETTLE, |t| SETTLE.saturating_sub(t.elapsed()));
        if wait.is_zero() {
            info!(format = format.0, "client copied; asking for it");
            self.st.send(ClipboardMessage::SendInitiatePaste(format));
        } else {
            info!(?wait, "client copied during connection setup; asking for it a little later");
            let st = self.st.clone();
            std::thread::spawn(move || {
                std::thread::sleep(wait);
                st.send(ClipboardMessage::SendInitiatePaste(format));
            });
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        info!(format = request.format.0, "client asks for the session clipboard");
        if request.format == ClipboardFormatId::CF_DIB {
            let png = self.st.session_image.lock().unwrap().clone();
            let dib = png.and_then(|p| crate::clipimage::png_to_dib(&p));
            let msg = match dib {
                Some(dib) => {
                    info!(bytes = dib.len(), "sending the session clipboard image to the client");
                    FormatDataResponse::new_data(dib)
                }
                None => {
                    info!("cannot provide the image (none, or not acceptable)");
                    FormatDataResponse::new_error()
                }
            };
            self.st.send(ClipboardMessage::SendFormatData(msg));
            return;
        }
        let text = self.st.session_text.lock().unwrap().clone();
        let msg = match (request.format == ClipboardFormatId::CF_UNICODETEXT, text) {
            (true, Some(text)) => {
                info!(chars = text.chars().count(), "sending the session clipboard to the client");
                FormatDataResponse::new_data(to_unicode_text(&text))
            }
            (is_text, text) => {
                info!(is_text, has_text = text.is_some(), "cannot provide that format");
                FormatDataResponse::new_error()
            }
        };
        self.st.send(ClipboardMessage::SendFormatData(msg));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if response.is_error() {
            info!("the client could not provide the clipboard text");
            return;
        }
        if self.asked == ClipboardFormatId::CF_DIB {
            info!(bytes = response.data().len(), "client clipboard image received");
            if response.data().len() > 4 * MAX_CLIPBOARD_IMAGE {
                info!("client clipboard image refused: too big");
                return;
            }
            match crate::clipimage::dib_to_png(response.data()) {
                Some(png) if png.len() <= MAX_CLIPBOARD_IMAGE => match self.st.slot.link() {
                    Some(link) => link.send(Down::ClipboardImage { png }),
                    None => debug!("client clipboard image dropped: no session"),
                },
                _ => info!("client clipboard image refused (format, size or limits)"),
            }
            return;
        }
        let text = from_unicode_text(response.data());
        info!(bytes = response.data().len(), chars = text.chars().count(), "client clipboard text received");
        if text.is_empty() || text.len() > MAX_CLIPBOARD {
            return;
        }
        match self.st.slot.link() {
            Some(link) => link.send(Down::Clipboard { data: text.into_bytes() }),
            None => debug!("client clipboard text dropped: no session"),
        }
    }

    fn on_remote_file_list(&mut self, files: &[FileDescriptor], clip_data_id: Option<u32>) {
        if !self.st.files_in {
            return;
        }
        let Some(link) = self.st.slot.link() else { return };
        // Checked here to refuse early; the session checks again.
        let total: u64 = files.iter().filter_map(|f| f.file_size).fold(0, u64::saturating_add);
        let bad = files.is_empty()
            || files.len() > MAX_FILES
            || total > MAX_FILES_TOTAL
            || files.iter().any(|f| {
                f.file_size.is_none_or(|s| s > MAX_FILE_BYTES)
                    || f.relative_path.is_some()
                    || f.attributes.is_some_and(|a| a.contains(ClipboardFileAttributes::DIRECTORY))
                    || crate::sessionfiles::clean_name(&f.name).is_none()
            });
        if bad {
            info!(files = files.len(), total, "clipboard files refused: over the limits, a folder, or an unacceptable name");
            return;
        }
        let id = self.st.next_id.fetch_add(1, Ordering::Relaxed);
        let sizes: Vec<u64> = files.iter().map(|f| f.file_size.unwrap_or(0)).collect();
        let now = Instant::now();
        *self.st.xfer.lock().unwrap() =
            Some(Xfer { id, clip_data_id, sizes, index: 0, offset: 0, ready: false, in_flight: None, stream: 0, started: now, last: now });
        info!(id, files = files.len(), total, "clipboard files offered by the client");
        link.send(Down::FilesBegin { id, files: files.iter().map(|f| (f.name.clone(), f.file_size.unwrap_or(0))).collect() });
        // Watchdog: a client that stops answering must not hold the transfer (and the spool) for good.
        let st = self.st.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(2));
            let verdict = match st.xfer.lock().unwrap().as_ref() {
                Some(t) if t.id == id => (t.last.elapsed() > FILE_IDLE || t.started.elapsed() > FILE_TOTAL).then_some(true),
                _ => return,
            };
            if verdict.is_some() {
                st.fail_transfer(id, "timed out");
                return;
            }
        });
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, response: FileContentsResponse<'_>) {
        let step = {
            let mut guard = self.st.xfer.lock().unwrap();
            let Some(t) = guard.as_mut() else { return };
            let Some((stream, len)) = t.in_flight else { return };
            if response.stream_id() != stream {
                return;
            }
            t.in_flight = None;
            if response.is_error() || response.data().len() != len as usize {
                Err(t.id)
            } else {
                let (id, index, offset) = (t.id, t.index as u32, t.offset);
                t.offset += u64::from(len);
                t.last = Instant::now();
                Ok((id, index, offset, response.data().to_vec()))
            }
        };
        match step {
            Err(id) => self.st.fail_transfer(id, "the client could not give a range"),
            Ok((id, index, offset, data)) => {
                if let Some(link) = self.st.slot.link() {
                    link.send(Down::FilesData { id, index, offset, data });
                }
                self.st.request_next();
            }
        }
    }

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}
}
