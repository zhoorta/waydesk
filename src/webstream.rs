//! The browser stream: a second front end of the daemon, beside RDP, for the portal (`waydesk-web`). The browser draws the session itself:
//! H.264 frames go to its own decoder (WebCodecs) and onto a canvas, and what the person does (keys, mouse, window size) comes back as small
//! messages. Nothing of RDP is in between.
//!
//! The portal bridges a WebSocket to the daemon's gateway port and passes each message in a frame of `u32 length (little endian)` + message; it
//! does not look inside. A connection starts with the portal's line (see gateway.rs, tag `WAYDESK-STREAM`), which names the account and the
//! client's address and carries the helper's ticket for that account's sign-in (see tickets.rs); the first message of the browser is `Start`, the
//! size. The daemon redeems the ticket at the root helper (only for the account the portal named, from the address it was made for; no password
//! passes here), starts or finds the account's session and pumps.
//!
//! Everything the browser sends is untrusted: sizes and rates are checked here, key names are looked up in a table and never passed on as text.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tracing::info;

use crate::helperclient::{HelperConn, SessionRefused};
use crate::link::{Event, Link};
use crate::proto::{Down, FrameKind};

/// The longest message the browser may send, but for clipboard text.
pub const MAX_TO_SERVER: usize = 2048;
/// The one message that may be longer: clipboard text (the tag and up to the session's limit of text).
pub const MAX_CLIPBOARD_MESSAGE: usize = 1 + crate::proto::MAX_CLIPBOARD;
/// The most clipboard texts the browser may send in a second.
const MAX_CLIPBOARDS_PER_SECOND: u32 = 5;
/// How long the browser has to send `Start`.
const START_TIMEOUT: Duration = Duration::from_secs(10);
/// More messages than this in a second is not a person: the connection is closed.
const MAX_MESSAGES_PER_SECOND: u32 = 5000;

/// Why a connection ends, as the browser is told (`ToBrowser::Error`).
pub const ERR_LOGIN: u8 = 1;
pub const ERR_REFUSED: u8 = 2;
pub const ERR_SERVER: u8 = 3;

/// Browser to daemon.
#[derive(Debug, PartialEq)]
pub enum ToServer {
    Start { width: u16, height: u16, scale_percent: u16 },
    Resize { width: u16, height: u16, scale_percent: u16 },
    /// A key by its DOM `KeyboardEvent.code` (the physical key).
    Key { code: String, pressed: bool },
    Move { x: u32, y: u32 },
    /// A DOM `MouseEvent.button`: 0 left, 1 middle, 2 right, 3 back, 4 forward.
    Button { button: u8, pressed: bool },
    /// Wheel notches, positive = down/right as in the browser.
    Wheel { vertical: f32, horizontal: f32 },
    /// The browser has shown this many frames.
    Ack { frames: u16 },
    RequestFull,
    /// Text the browser's clipboard holds now (the whole rest of the message, UTF-8).
    Clipboard { text: String },
    Bye,
}

/// Daemon to browser.
#[derive(Debug, PartialEq)]
pub enum ToBrowser {
    Ready { width: u16, height: u16 },
    Resized { width: u16, height: u16 },
    /// One H.264 picture (Annex B) of the whole screen. `key`: the browser can start decoding here.
    Frame { key: bool, ts_ms: u32, data: Vec<u8> },
    Cursor(String),
    /// Text the desktop's clipboard holds now.
    Clipboard(String),
    /// A pointer picture an application drew: 32 bit BGRA, premultiplied alpha, rows from the top, at most 32 x 32 (the link checked).
    CursorImage { hot_x: u16, hot_y: u16, width: u16, height: u16, data: Vec<u8> },
    Error { code: u8, message: String },
}

struct In<'a>(&'a [u8]);

impl<'a> In<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn f32(&mut self) -> Option<f32> {
        Some(f32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn str(&mut self, max: usize) -> Option<String> {
        let n = usize::from(self.u16()?);
        if n > max {
            return None;
        }
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
    fn end(&self) -> bool {
        self.0.is_empty()
    }
}

impl ToServer {
    /// `None` for anything that is not exactly a message of this protocol.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        let limit = if buf.first() == Some(&9) { MAX_CLIPBOARD_MESSAGE } else { MAX_TO_SERVER };
        if buf.len() > limit {
            return None;
        }
        let mut i = In(buf);
        let msg = match i.u8()? {
            1 => ToServer::Start { width: i.u16()?, height: i.u16()?, scale_percent: i.u16()? },
            2 => ToServer::Resize { width: i.u16()?, height: i.u16()?, scale_percent: i.u16()? },
            3 => ToServer::Key { code: i.str(32)?, pressed: i.u8()? != 0 },
            4 => ToServer::Move { x: i.u32()?, y: i.u32()? },
            5 => ToServer::Button { button: i.u8()?, pressed: i.u8()? != 0 },
            6 => {
                let (vertical, horizontal) = (i.f32()?, i.f32()?);
                if !vertical.is_finite() || !horizontal.is_finite() {
                    return None;
                }
                ToServer::Wheel { vertical, horizontal }
            }
            7 => ToServer::Ack { frames: i.u16()? },
            8 => ToServer::RequestFull,
            9 => return String::from_utf8(i.0.to_vec()).ok().filter(|t| !t.is_empty()).map(|text| ToServer::Clipboard { text }),
            255 => ToServer::Bye,
            _ => return None,
        };
        i.end().then_some(msg)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        let str = |o: &mut Vec<u8>, s: &str| {
            o.extend_from_slice(&(s.len() as u16).to_le_bytes());
            o.extend_from_slice(s.as_bytes());
        };
        match self {
            ToServer::Start { width, height, scale_percent } => {
                o.push(1);
                for v in [width, height, scale_percent] {
                    o.extend_from_slice(&v.to_le_bytes());
                }
            }
            ToServer::Resize { width, height, scale_percent } => {
                o.push(2);
                for v in [width, height, scale_percent] {
                    o.extend_from_slice(&v.to_le_bytes());
                }
            }
            ToServer::Key { code, pressed } => {
                o.push(3);
                str(&mut o, code);
                o.push(u8::from(*pressed));
            }
            ToServer::Move { x, y } => {
                o.push(4);
                o.extend_from_slice(&x.to_le_bytes());
                o.extend_from_slice(&y.to_le_bytes());
            }
            ToServer::Button { button, pressed } => o.extend_from_slice(&[5, *button, u8::from(*pressed)]),
            ToServer::Wheel { vertical, horizontal } => {
                o.push(6);
                o.extend_from_slice(&vertical.to_le_bytes());
                o.extend_from_slice(&horizontal.to_le_bytes());
            }
            ToServer::Ack { frames } => {
                o.push(7);
                o.extend_from_slice(&frames.to_le_bytes());
            }
            ToServer::RequestFull => o.push(8),
            ToServer::Clipboard { text } => {
                o.push(9);
                o.extend_from_slice(text.as_bytes());
            }
            ToServer::Bye => o.push(255),
        }
        o
    }
}

impl ToBrowser {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        match self {
            ToBrowser::Ready { width, height } | ToBrowser::Resized { width, height } => {
                o.push(if matches!(self, ToBrowser::Ready { .. }) { 1 } else { 2 });
                o.extend_from_slice(&width.to_le_bytes());
                o.extend_from_slice(&height.to_le_bytes());
            }
            ToBrowser::Frame { key, ts_ms, data } => {
                o.reserve(6 + data.len());
                o.push(3);
                o.push(u8::from(*key));
                o.extend_from_slice(&ts_ms.to_le_bytes());
                o.extend_from_slice(data);
            }
            ToBrowser::Cursor(name) => {
                o.push(4);
                o.extend_from_slice(name.as_bytes());
            }
            ToBrowser::Clipboard(text) => {
                o.push(6);
                o.extend_from_slice(text.as_bytes());
            }
            ToBrowser::CursorImage { hot_x, hot_y, width, height, data } => {
                o.push(7);
                for v in [hot_x, hot_y, width, height] {
                    o.extend_from_slice(&v.to_le_bytes());
                }
                o.extend_from_slice(data);
            }
            ToBrowser::Error { code, message } => {
                o.push(5);
                o.push(*code);
                o.extend_from_slice(message.as_bytes());
            }
        }
        o
    }
}

/// The Linux evdev key code of a DOM `KeyboardEvent.code`.
pub fn evdev_for_dom(code: &str) -> Option<u32> {
    Some(match code {
        "Escape" => 1,
        "Digit1" => 2,
        "Digit2" => 3,
        "Digit3" => 4,
        "Digit4" => 5,
        "Digit5" => 6,
        "Digit6" => 7,
        "Digit7" => 8,
        "Digit8" => 9,
        "Digit9" => 10,
        "Digit0" => 11,
        "Minus" => 12,
        "Equal" => 13,
        "Backspace" => 14,
        "Tab" => 15,
        "KeyQ" => 16,
        "KeyW" => 17,
        "KeyE" => 18,
        "KeyR" => 19,
        "KeyT" => 20,
        "KeyY" => 21,
        "KeyU" => 22,
        "KeyI" => 23,
        "KeyO" => 24,
        "KeyP" => 25,
        "BracketLeft" => 26,
        "BracketRight" => 27,
        "Enter" => 28,
        "ControlLeft" => 29,
        "KeyA" => 30,
        "KeyS" => 31,
        "KeyD" => 32,
        "KeyF" => 33,
        "KeyG" => 34,
        "KeyH" => 35,
        "KeyJ" => 36,
        "KeyK" => 37,
        "KeyL" => 38,
        "Semicolon" => 39,
        "Quote" => 40,
        "Backquote" => 41,
        "ShiftLeft" => 42,
        "Backslash" => 43,
        "KeyZ" => 44,
        "KeyX" => 45,
        "KeyC" => 46,
        "KeyV" => 47,
        "KeyB" => 48,
        "KeyN" => 49,
        "KeyM" => 50,
        "Comma" => 51,
        "Period" => 52,
        "Slash" => 53,
        "ShiftRight" => 54,
        "NumpadMultiply" => 55,
        "AltLeft" => 56,
        "Space" => 57,
        "CapsLock" => 58,
        "F1" => 59,
        "F2" => 60,
        "F3" => 61,
        "F4" => 62,
        "F5" => 63,
        "F6" => 64,
        "F7" => 65,
        "F8" => 66,
        "F9" => 67,
        "F10" => 68,
        "NumLock" => 69,
        "ScrollLock" => 70,
        "Numpad7" => 71,
        "Numpad8" => 72,
        "Numpad9" => 73,
        "NumpadSubtract" => 74,
        "Numpad4" => 75,
        "Numpad5" => 76,
        "Numpad6" => 77,
        "NumpadAdd" => 78,
        "Numpad1" => 79,
        "Numpad2" => 80,
        "Numpad3" => 81,
        "Numpad0" => 82,
        "NumpadDecimal" => 83,
        "IntlBackslash" => 86,
        "F11" => 87,
        "F12" => 88,
        "NumpadEnter" => 96,
        "ControlRight" => 97,
        "NumpadDivide" => 98,
        "PrintScreen" => 99,
        "AltRight" => 100,
        "Home" => 102,
        "ArrowUp" => 103,
        "PageUp" => 104,
        "ArrowLeft" => 105,
        "ArrowRight" => 106,
        "End" => 107,
        "ArrowDown" => 108,
        "PageDown" => 109,
        "Insert" => 110,
        "Delete" => 111,
        "Pause" => 119,
        "MetaLeft" | "OSLeft" => 125,
        "MetaRight" | "OSRight" => 126,
        "ContextMenu" => 127,
        _ => return None,
    })
}

/// The evdev button code of a DOM `MouseEvent.button`.
pub fn button_for_dom(button: u8) -> Option<u32> {
    use crate::input::{BTN_EXTRA, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_SIDE};
    Some(match button {
        0 => BTN_LEFT,
        1 => BTN_MIDDLE,
        2 => BTN_RIGHT,
        3 => BTN_SIDE,
        4 => BTN_EXTRA,
        _ => return None,
    })
}

/// Whether an H.264 Annex B frame can start a decoder: it holds an IDR slice (NAL type 5) or the parameter sets (type 7), which streams that refresh
/// the picture in pieces send where a decoder may join.
pub fn is_key_frame(data: &[u8]) -> bool {
    let mut i = 0;
    while i + 3 < data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            let nal = data[i + 3] & 0x1f;
            if nal == 5 || nal == 7 {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

/// The credits to give the session back when the browser says it showed `acked` frames: never more than frames that were sent and not yet
/// acknowledged, so a browser cannot raise its own window by acknowledging what it was not sent.
pub fn credits_back(acked: u16, sent_unacked: u32) -> u32 {
    u32::from(acked).min(sent_unacked)
}

/// Counts what arrives in a second.
struct Rate {
    window: Instant,
    count: u32,
}

impl Rate {
    fn hit(&mut self, now: Instant) -> bool {
        self.hit_max(now, MAX_MESSAGES_PER_SECOND)
    }

    fn hit_max(&mut self, now: Instant, max: u32) -> bool {
        if now.duration_since(self.window) >= Duration::from_secs(1) {
            self.window = now;
            self.count = 0;
        }
        self.count += 1;
        self.count <= max
    }
}

async fn read_message<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read(&mut len[..1]).await? {
        0 => return Ok(None),
        _ => r.read_exact(&mut len[1..]).await?,
    };
    let len = u32::from_le_bytes(len) as usize;
    if len == 0 || len > MAX_CLIPBOARD_MESSAGE {
        bail!("a message of {len} bytes");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

async fn write_message<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, msg: &ToBrowser) -> std::io::Result<()> {
    let body = msg.encode();
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
    framed.extend_from_slice(&body);
    w.write_all(&framed).await
}

/// One browser, from its `Start` to the end of its connection. `stream` is past the portal's line already.
pub async fn serve(stream: tokio::net::TcpStream, ip: IpAddr, account: String, ticket: String, helper_socket: PathBuf, max_bitrate: u32) {
    use std::os::fd::AsRawFd as _;
    let started = Instant::now();
    // The socket to the portal: when the browser's link is slow the portal reads slowly and this socket's send queue fills, which is how the
    // link's capacity is seen (see `Flow`). The halves below keep the socket open as long as `run` lasts.
    let fd = stream.as_raw_fd();
    let (rd, mut wr) = stream.into_split();
    match run(rd, &mut wr, ip, &account, &ticket, &helper_socket, Some(fd), max_bitrate).await {
        Ok(()) => info!(%ip, account, seconds = started.elapsed().as_secs(), "browser stream ended"),
        Err(e) => {
            info!(%ip, account, seconds = started.elapsed().as_secs(), "browser stream ended: {e:#}");
            let _ = write_message(&mut wr, &ToBrowser::Error { code: ERR_SERVER, message: "The connection to the desktop ended.".into() }).await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run<R, W>(mut rd: R, wr: &mut W, ip: IpAddr, account: &str, ticket: &str, helper_socket: &std::path::Path, fd: Option<std::os::fd::RawFd>, max_bitrate: u32) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin,
{
    // 1. Start: the size.
    let first = tokio::time::timeout(START_TIMEOUT, read_message(&mut rd)).await.context("no Start in time")??.context("closed before Start")?;
    let Some(ToServer::Start { width, height, scale_percent }) = ToServer::decode(&first) else { bail!("the first message is not Start") };
    let (width, height) = crate::session::clamp_size(width, height);
    let scale = scale_percent.clamp(100, 500);

    // 2. The login, through the helper: the same check, delay and lockout as an RDP login.
    let path = helper_socket.to_owned();
    let helper = match tokio::task::spawn_blocking(move || HelperConn::connect(&path)).await {
        Ok(Ok(conn)) => Arc::new(conn),
        other => bail!("cannot reach the helper: {:?}", other.map(|r| r.err())),
    };
    let (h, user, source) = (helper.clone(), account.to_owned(), ip.to_string());
    let ok = tokio::task::spawn_blocking({ let ticket = ticket.to_owned(); move || h.redeem(&ticket, &user, &source) }).await.context("login task")??;
    if !ok {
        let _ = write_message(wr, &ToBrowser::Error { code: ERR_LOGIN, message: "Sign-in has ended. Sign in again.".into() }).await;
        bail!("login refused");
    }

    // 3. The session of the account (a running one is taken over).
    let h = helper.clone();
    let started = tokio::task::spawn_blocking(move || h.start_session()).await.context("session task")?;
    let session = match started {
        Ok(s) => s,
        Err(e) => {
            let message = match e.downcast_ref::<SessionRefused>() {
                Some(r) => format!("The server cannot start a desktop now: {}.", r.message),
                None => "The server could not start the desktop.".into(),
            };
            let _ = write_message(wr, &ToBrowser::Error { code: ERR_REFUSED, message }).await;
            return Err(e);
        }
    };
    let link = Link::from_helper(session, (width, height), 0).await.context("the session did not come up")?;
    let size = link.size();
    write_message(wr, &ToBrowser::Ready { width: size.0, height: size.1 }).await?;
    if scale != 100 {
        link.send(Down::Resize { width: size.0, height: size.1, scale_percent: scale });
    }
    link.send(Down::RequestFull);
    // The desktop's clipboard text comes back to the browser (the link has already bounded its size and speed).
    let (clip_tx, clip_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    link.set_clipboard_sink(Box::new(move |data| {
        let _ = clip_tx.send(data);
    }));
    link.send(Down::ClipboardOn);

    let result = pump(rd, wr, &link, clip_rx, fd, max_bitrate).await;
    link.shutdown().await;
    result
}

/// Reads the browser's messages in a task of its own (reading a message is not something a `select!` may cut short), checks their rate, and
/// passes them on; a read error or a message that is not of the protocol ends it with the reason.
fn read_browser<R: tokio::io::AsyncRead + Unpin + Send + 'static>(mut rd: R) -> tokio::sync::mpsc::Receiver<Result<ToServer, String>> {
    let (tx, rx) = tokio::sync::mpsc::channel(256);
    tokio::spawn(async move {
        let mut rate = Rate { window: Instant::now(), count: 0 };
        loop {
            let msg = match read_message(&mut rd).await {
                Ok(Some(body)) if !rate.hit(Instant::now()) => {
                    let _ = body;
                    Err(format!("more than {MAX_MESSAGES_PER_SECOND} messages in a second"))
                }
                Ok(Some(body)) => ToServer::decode(&body).ok_or_else(|| "a message that is not of the protocol".to_string()),
                Ok(None) => Ok(ToServer::Bye),
                Err(e) => Err(e.to_string()),
            };
            let end = !matches!(msg, Ok(ref m) if *m != ToServer::Bye);
            if tx.send(msg).await.is_err() || end {
                return;
            }
        }
    });
    rx
}

async fn pump<R, W>(rd: R, wr: &mut W, link: &Arc<Link>, mut clip_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>, fd: Option<std::os::fd::RawFd>, max_bitrate: u32) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut from_browser = read_browser(rd);
    let mut sent_unacked: u32 = 0;
    // Frames in flight and the encoder's bitrate follow the link, as with RDP (egfx.rs `Flow`): the browser acknowledges each frame it showed.
    let mut flow = crate::egfx::Flow::new();
    flow.reset();
    link.send(Down::Credit { frames: flow.window as u16 });
    let (mut next_id, mut acked_id) = (0u32, 0u32);
    let mut wanted: Option<(u16, u16, u16)> = None;
    let mut resize_at: Option<tokio::time::Instant> = None;
    let mut size = link.size();
    let started = Instant::now();
    let mut clip_rate = Rate { window: Instant::now(), count: 0 };
    loop {
        let resize_due = async {
            match resize_at {
                Some(t) => tokio::time::sleep_until(t).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            msg = from_browser.recv() => {
                let msg = match msg {
                    Some(Ok(m)) => m,
                    Some(Err(why)) => bail!("{why}"),
                    None => return Ok(()),
                };
                match msg {
                    ToServer::Start { .. } => bail!("a second Start"),
                    ToServer::Bye => return Ok(()),
                    ToServer::Resize { width, height, scale_percent } => {
                        let (w, h) = crate::session::clamp_size(width, height);
                        wanted = Some((w, h, scale_percent.clamp(100, 500)));
                        // Dragging a window edge sends many sizes: the last one counts, a moment after the last.
                        resize_at = Some(tokio::time::Instant::now() + Duration::from_millis(250));
                    }
                    ToServer::Key { code, pressed } => match evdev_for_dom(&code) {
                        Some(code) => link.send(Down::Key { code, pressed }),
                        None => tracing::debug!(code, "unmapped key"),
                    },
                    ToServer::Move { x, y } => link.send(Down::PointerMove { x: x.min(u32::from(size.0.saturating_sub(1))), y: y.min(u32::from(size.1.saturating_sub(1))) }),
                    ToServer::Button { button, pressed } => {
                        if let Some(code) = button_for_dom(button) {
                            link.send(Down::Button { code, pressed });
                        }
                    }
                    ToServer::Wheel { vertical, horizontal } => {
                        // Browser notches are positive downwards; the session takes RDP's, positive away from the user (up). At most a few notches a message.
                        link.send(Down::Wheel { vertical: -f64::from(vertical.clamp(-20.0, 20.0)), horizontal: f64::from(horizontal.clamp(-20.0, 20.0)) });
                    }
                    ToServer::Ack { frames } => {
                        let acks = credits_back(frames, sent_unacked);
                        sent_unacked -= acks;
                        let mut credits = 0u16;
                        for _ in 0..acks {
                            let info = fd.and_then(crate::tcpinfo::read);
                            let (give, bitrate) = flow.frame_acked(acked_id, max_bitrate, info);
                            acked_id = acked_id.wrapping_add(1);
                            credits = credits.saturating_add(give);
                            if let Some(bps) = bitrate {
                                info!(bps, "bitrate for the browser's link");
                                link.send(Down::Bitrate { bps });
                            }
                        }
                        if credits > 0 {
                            link.send(Down::Credit { frames: credits });
                        }
                    }
                    ToServer::RequestFull => link.send(Down::RequestFull),
                    ToServer::Clipboard { text } => {
                        if clip_rate.hit_max(Instant::now(), MAX_CLIPBOARDS_PER_SECOND) {
                            link.send(Down::Clipboard { data: text.into_bytes() });
                        }
                    }
                }
            }
            Some(data) = clip_rx.recv() => {
                if let Ok(text) = String::from_utf8(data) {
                    write_message(wr, &ToBrowser::Clipboard(text)).await?;
                }
            }
            event = async { link.events.lock().await.recv().await } => {
                match event.unwrap_or(Event::Closed) {
                    Event::Closed => return Ok(()),
                    Event::Frame { kind: FrameKind::H264, data, .. } => {
                        sent_unacked += 1;
                        flow.frame_sent(next_id, data.len());
                        next_id = next_id.wrapping_add(1);
                        let key = is_key_frame(&data);
                        write_message(wr, &ToBrowser::Frame { key, ts_ms: started.elapsed().as_millis() as u32, data }).await?;
                    }
                    // This front end asks for H.264 only: a bitmap would be a frame the browser cannot show, and its credit goes back.
                    Event::Frame { .. } => link.send(Down::Credit { frames: 1 }),
                    Event::Resized(w, h) => {
                        size = (w, h);
                        write_message(wr, &ToBrowser::Resized { width: w, height: h }).await?;
                        // A resize starts the session again from zero credits (the frames in flight died with the old size) and nothing else grants
                        // new ones: without this a picture that then stays still is never sent. The browser starts its decoder again too, so what
                        // it was sent before is no longer owed an acknowledgement.
                        sent_unacked = 0;
                        flow.reset();
                        acked_id = next_id;
                        link.send(Down::Credit { frames: flow.window as u16 });
                        link.send(Down::RequestFull);
                    }
                    Event::Cursor(name) => write_message(wr, &ToBrowser::Cursor(name)).await?,
                    Event::CursorImage { hot_x, hot_y, width, height, data } => write_message(wr, &ToBrowser::CursorImage { hot_x, hot_y, width, height, data }).await?,
                }
            }
            () = resize_due => {
                resize_at = None;
                if let Some((w, h, scale)) = wanted.take() {
                    if (w, h) != link.size() || scale != 100 {
                        link.send(Down::Resize { width: w, height: h, scale_percent: scale });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_the_browser_writes_the_daemon_reads() {
        let all = [
            ToServer::Start { width: 1680, height: 1050, scale_percent: 100 },
            ToServer::Resize { width: 800, height: 600, scale_percent: 200 },
            ToServer::Key { code: "KeyA".into(), pressed: true },
            ToServer::Move { x: 10, y: 20 },
            ToServer::Button { button: 2, pressed: false },
            ToServer::Wheel { vertical: 1.5, horizontal: -0.25 },
            ToServer::Ack { frames: 3 },
            ToServer::RequestFull,
            ToServer::Clipboard { text: "olá, mundo\n".into() },
            ToServer::Bye,
        ];
        for msg in all {
            assert_eq!(ToServer::decode(&msg.encode()).as_ref(), Some(&msg), "{msg:?}");
        }
    }

    #[test]
    fn anything_that_is_not_exactly_a_message_is_refused() {
        assert_eq!(ToServer::decode(&[]), None);
        assert_eq!(ToServer::decode(&[99]), None, "unknown tag");
        assert_eq!(ToServer::decode(&[8, 0]), None, "bytes after a message");
        assert_eq!(ToServer::decode(&[4, 1, 0, 0, 0]), None, "short");
        let mut long_key = vec![3];
        long_key.extend_from_slice(&40u16.to_le_bytes());
        long_key.extend_from_slice(&[b'a'; 40]);
        long_key.push(1);
        assert_eq!(ToServer::decode(&long_key), None, "a key name longer than any");
        let mut bad_utf8 = vec![3, 2, 0, 0xff, 0xfe, 1];
        assert_eq!(ToServer::decode(&bad_utf8), None);
        bad_utf8.clear();
        let nan = [6u8, 0, 0, 0xc0, 0x7f, 0, 0, 0, 0];
        assert_eq!(ToServer::decode(&nan), None, "a wheel that is not a number");
        let mut long_start = ToServer::Start { width: 1, height: 1, scale_percent: 100 }.encode();
        long_start.push(0);
        assert_eq!(ToServer::decode(&long_start), None, "bytes after Start");
        assert_eq!(ToServer::decode(&vec![8; MAX_TO_SERVER + 1]), None, "a message that is too long");
        assert_eq!(ToServer::decode(&[9]), None, "empty clipboard text");
        assert_eq!(ToServer::decode(&[9, 0xff, 0xfe]), None, "clipboard text that is not UTF-8");
        let mut big = vec![b'a'; MAX_CLIPBOARD_MESSAGE];
        big[0] = 9;
        assert!(ToServer::decode(&big).is_some(), "clipboard text up to the session's limit");
        big.push(b'a');
        assert_eq!(ToServer::decode(&big), None, "clipboard text over it");
    }

    #[test]
    fn keys_and_buttons_come_from_tables_only() {
        assert_eq!(evdev_for_dom("KeyA"), Some(30));
        assert_eq!(evdev_for_dom("Enter"), Some(28));
        assert_eq!(evdev_for_dom("ArrowUp"), Some(103));
        assert_eq!(evdev_for_dom("MetaLeft"), Some(125));
        assert_eq!(evdev_for_dom("F12"), Some(88));
        for bad in ["", "keya", "KeyAA", "../../etc", "Unidentified", "Dead"] {
            assert_eq!(evdev_for_dom(bad), None, "{bad}");
        }
        assert_eq!(button_for_dom(0), Some(crate::input::BTN_LEFT));
        assert_eq!(button_for_dom(2), Some(crate::input::BTN_RIGHT));
        assert_eq!(button_for_dom(5), None);
    }

    #[test]
    fn the_key_table_agrees_with_rdps() {
        // The scancodes of the main block are the evdev codes themselves, and the extended ones are in the table of input.rs.
        for (dom, rdp, extended) in [("KeyA", 0x1e, false), ("Space", 0x39, false), ("ShiftLeft", 0x2a, false), ("ControlRight", 0x1d, true), ("ArrowLeft", 0x4b, true), ("Delete", 0x53, true), ("MetaLeft", 0x5b, true)] {
            assert_eq!(evdev_for_dom(dom), crate::input::evdev_code(rdp, extended), "{dom}");
        }
    }

    #[test]
    fn key_frames_are_found_by_their_nal_units() {
        let idr = [0, 0, 0, 1, 0x65, 1, 2, 3];
        let sps = [0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x68, 9];
        let p = [0, 0, 0, 1, 0x41, 1, 2, 3, 4];
        assert!(is_key_frame(&idr));
        assert!(is_key_frame(&sps));
        assert!(!is_key_frame(&p));
        assert!(!is_key_frame(&[]));
        assert!(!is_key_frame(&[0, 0, 1]));
        assert!(is_key_frame(&[0, 0, 1, 0x65]), "a three byte start code");
    }

    #[test]
    fn a_browser_cannot_give_back_more_credits_than_it_was_sent_frames() {
        assert_eq!(credits_back(3, 2), 2, "three acknowledged, two were sent");
        assert_eq!(credits_back(100, 0), 0, "nothing was sent: nothing to give back");
        assert_eq!(credits_back(1, 1), 1);
        assert_eq!(credits_back(0, 5), 0);
    }

    #[test]
    fn a_pointer_picture_has_its_header_and_its_pixels() {
        let m = ToBrowser::CursorImage { hot_x: 1, hot_y: 2, width: 2, height: 1, data: vec![9; 8] }.encode();
        assert_eq!(&m[..9], &[7, 1, 0, 2, 0, 2, 0, 1, 0]);
        assert_eq!(m.len(), 17);
    }

    #[tokio::test]
    async fn messages_are_framed_and_a_bad_frame_ends_the_connection() {
        let mut buf = Vec::new();
        write_message(&mut buf, &ToBrowser::Cursor("text".into())).await.unwrap();
        assert_eq!(&buf[..4], &5u32.to_le_bytes());
        assert_eq!(&buf[4..], &[4, b't', b'e', b'x', b't']);
        let mut good = std::io::Cursor::new({
            let body = ToServer::RequestFull.encode();
            let mut v = (body.len() as u32).to_le_bytes().to_vec();
            v.extend_from_slice(&body);
            v
        });
        assert_eq!(read_message(&mut good).await.unwrap(), Some(vec![8]));
        assert_eq!(read_message(&mut good).await.unwrap(), None, "a clean end");
        let mut zero = std::io::Cursor::new(0u32.to_le_bytes().to_vec());
        assert!(read_message(&mut zero).await.is_err());
        let mut huge = std::io::Cursor::new(((MAX_CLIPBOARD_MESSAGE + 1) as u32).to_le_bytes().to_vec());
        assert!(read_message(&mut huge).await.is_err());
    }
}
