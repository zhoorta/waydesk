//! Stream protocol between the network daemon and a user's session process (milestone 2 of docs/MULTIUSER-DESIGN.md).
//!
//! A message on the wire is `u32 length (little endian)`, `u8 tag`, payload; `length` counts the tag and the payload.
//! Integers are little endian, byte strings are `u32 length` + bytes. Both ends refuse a length above `MAX_MESSAGE`
//! and any message that does not decode exactly, so a broken or hostile peer ends the connection instead of
//! making the other side allocate or guess.
//!
//! Not used by the server yet: this is the contract the split will be built against.
#![allow(dead_code)]

use std::io::{self, Read, Write};

/// Protocol version, sent in `Down::Hello`.
pub const VERSION: u16 = 1;

/// Largest message accepted (a full 4096x2304 BGRA bitmap is 36 MiB).
pub const MAX_MESSAGE: u32 = 48 * 1024 * 1024;

/// Longest string in a helper message (account names, passwords, addresses).
pub const MAX_STRING: u32 = 1024;
/// The longest JSON text a helper `Info` answer may carry (a status of a large machine is a few hundred KiB).
pub const MAX_INFO: u32 = 4 * 1024 * 1024;

#[derive(Debug, PartialEq)]
pub enum ProtoError {
    /// The message ended before all of its fields were read.
    Truncated,
    /// Bytes were left over after the last field.
    Trailing,
    UnknownTag(u8),
    /// A length above `MAX_MESSAGE`.
    TooLarge(u32),
    /// A string that is not valid UTF-8.
    BadString,
    Io(String),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::Truncated => write!(f, "message too short"),
            ProtoError::Trailing => write!(f, "unexpected bytes after message"),
            ProtoError::UnknownTag(t) => write!(f, "unknown message tag {t}"),
            ProtoError::TooLarge(n) => write!(f, "message of {n} bytes is too large"),
            ProtoError::BadString => write!(f, "string is not valid UTF-8"),
            ProtoError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProtoError {}

impl From<io::Error> for ProtoError {
    fn from(e: io::Error) -> Self {
        ProtoError::Io(e.to_string())
    }
}

/// What the picture data in an `Up::Frame` is.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FrameKind {
    /// H.264 (Annex B), for the graphics pipeline.
    H264 = 0,
    /// Raw BGRA of the rectangle, for the bitmap fallback.
    Bgra = 1,
}

/// Longest clipboard text either side relays (UTF-8 bytes).
pub const MAX_CLIPBOARD: usize = 1024 * 1024;

/// Longest clipboard image either side relays (a PNG, bytes).
pub const MAX_CLIPBOARD_IMAGE: usize = 16 * 1024 * 1024;

/// Clipboard files (client to session): most files in one transfer, largest file, largest total, and the chunk size.
pub const MAX_FILES: usize = 100;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_FILES_TOTAL: u64 = 256 * 1024 * 1024;
pub const FILE_CHUNK: u32 = 256 * 1024;
/// Clipboard files, session to client: the most bytes of one range the client may ask for.
pub const MAX_FILE_READ: u32 = 1024 * 1024;

/// From the network daemon to the session.
#[derive(Debug, PartialEq)]
pub enum Down {
    Hello { version: u16, width: u16, height: u16, scale_percent: u16, klid: u32 },
    Resize { width: u16, height: u16, scale_percent: u16 },
    Key { code: u32, pressed: bool },
    PointerMove { x: u32, y: u32 },
    Button { code: u32, pressed: bool },
    Wheel { vertical: f64, horizontal: f64 },
    /// The daemon can take this many more frames (flow control; replaces the EGFX backpressure check).
    Credit { frames: u16 },
    /// The bitrate the encoder should aim for from now on, bits per second (the link to the client got slower or faster).
    Bitrate { bps: u32 },
    /// Send the whole picture again.
    RequestFull,
    /// Prefer bitmaps: the client has no H.264.
    UseBitmaps,
    /// The client's clipboard text (UTF-8) for the session's clipboard.
    Clipboard { data: Vec<u8> },
    /// The client's clipboard image (PNG) for the session's clipboard.
    ClipboardImage { png: Vec<u8> },
    /// The client offers these files (name, size), in this order: make room for them. Answered by `Up::FilesReady` or `Up::FilesFailed`.
    FilesBegin { id: u32, files: Vec<(String, u64)> },
    /// The next bytes of file number `index` of transfer `id`; `offset` is where they go (always the end of what was written).
    FilesData { id: u32, index: u32, offset: u64, data: Vec<u8> },
    /// Drop transfer `id` and what was written of it.
    FilesCancel { id: u32 },
    /// The client may be offered the session's files: from now on report file lists on the session clipboard (`Up::FilesOffered`).
    FilesOut,
    /// Read `len` bytes at `offset` of file number `index` of the offer `id`. Answered by `Up::FilesData` or `Up::FilesReadFailed`.
    FilesRead { id: u32, index: u32, offset: u64, len: u32 },
    /// The client has a clipboard channel: start watching the session's clipboard.
    ClipboardOn,
    /// The client has a sound channel: record the session's speaker and send it as `Up::Audio`.
    AudioOn,
    /// The sound channel is closed: stop recording.
    AudioOff,
    /// The client has a microphone: make the session's virtual microphone (`audio::MIC_SOURCE`).
    MicOn,
    /// The microphone is off: remove the virtual microphone.
    MicOff,
    /// 20 ms of the client's microphone: 16 bit mono PCM, little endian, 48000 Hz (`audio::MIC_CHUNK` bytes).
    Mic { pcm: Vec<u8> },
    Bye,
}

/// From the session to the network daemon.
#[derive(Debug, PartialEq)]
pub enum Up {
    /// Session is running; the picture is this size.
    Ready { width: u16, height: u16 },
    /// A resize finished; later frames have this size.
    Resized { width: u16, height: u16 },
    Frame { x: u16, y: u16, w: u16, h: u16, kind: FrameKind, data: Vec<u8> },
    /// 20 ms chunk of 16-bit stereo PCM at 44.1 kHz.
    Audio { pcm: Vec<u8> },
    Clipboard { data: Vec<u8> },
    /// The session's clipboard holds this image (PNG).
    ClipboardImage { png: Vec<u8> },
    /// The session clipboard holds these files (name, size); offer `id` stays valid until the next one.
    FilesOffered { id: u32, files: Vec<(String, u64)> },
    /// The bytes asked for by `Down::FilesRead`.
    FilesData { id: u32, index: u32, offset: u64, data: Vec<u8> },
    /// `Down::FilesRead` could not be served (the file changed or is gone).
    FilesReadFailed { id: u32, index: u32, offset: u64 },
    /// Transfer `id` was accepted: the files can be sent.
    FilesReady { id: u32 },
    /// Transfer `id` was refused or broke off; nothing of it is left.
    FilesFailed { id: u32 },
    /// The shape of the mouse pointer: a cursor name (`text`, `ew-resize`, ...).
    Cursor { name: String },
    /// The picture of a pointer an application drew itself: width x height pixels of 32 bit BGRA (premultiplied, rows from the top).
    CursorImage { hot_x: u16, hot_y: u16, width: u16, height: u16, data: Vec<u8> },
    Bye,
}

// ---- encoding helpers ----

#[derive(Default)]
struct Out(Vec<u8>);

impl Out {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn f64(&mut self, v: f64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bool(&mut self, v: bool) {
        self.u8(v as u8);
    }
    fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
    }
    fn str(&mut self, v: &str) {
        self.bytes(v.as_bytes());
    }
}

struct In<'a>(&'a [u8]);

impl<'a> In<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.0.len() < n {
            return Err(ProtoError::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProtoError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, ProtoError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ProtoError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn f64(&mut self) -> Result<f64, ProtoError> {
        Ok(f64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bool(&mut self) -> Result<bool, ProtoError> {
        Ok(self.u8()? != 0)
    }
    fn bytes(&mut self) -> Result<Vec<u8>, ProtoError> {
        let n = self.u32()?;
        if n > MAX_MESSAGE {
            return Err(ProtoError::TooLarge(n));
        }
        Ok(self.take(n as usize)?.to_vec())
    }
    /// A UTF-8 string of at most `MAX_STRING` bytes.
    fn str(&mut self) -> Result<String, ProtoError> {
        let n = self.u32()?;
        if n > MAX_STRING {
            return Err(ProtoError::TooLarge(n));
        }
        String::from_utf8(self.take(n as usize)?.to_vec()).map_err(|_| ProtoError::BadString)
    }
    /// Like `str`, with a larger limit (for the helper's JSON answers).
    fn long_str(&mut self, max: u32) -> Result<String, ProtoError> {
        let n = self.u32()?;
        if n > max {
            return Err(ProtoError::TooLarge(n));
        }
        String::from_utf8(self.take(n as usize)?.to_vec()).map_err(|_| ProtoError::BadString)
    }
    fn finish(self) -> Result<(), ProtoError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ProtoError::Trailing)
        }
    }
}

impl Down {
    /// Tag byte followed by the payload (without the length prefix).
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Out::default();
        match self {
            Down::Hello { version, width, height, scale_percent, klid } => {
                o.u8(1);
                o.u16(*version);
                o.u16(*width);
                o.u16(*height);
                o.u16(*scale_percent);
                o.u32(*klid);
            }
            Down::Resize { width, height, scale_percent } => {
                o.u8(2);
                o.u16(*width);
                o.u16(*height);
                o.u16(*scale_percent);
            }
            Down::Key { code, pressed } => {
                o.u8(3);
                o.u32(*code);
                o.bool(*pressed);
            }
            Down::PointerMove { x, y } => {
                o.u8(4);
                o.u32(*x);
                o.u32(*y);
            }
            Down::Button { code, pressed } => {
                o.u8(5);
                o.u32(*code);
                o.bool(*pressed);
            }
            Down::Wheel { vertical, horizontal } => {
                o.u8(6);
                o.f64(*vertical);
                o.f64(*horizontal);
            }
            Down::Credit { frames } => {
                o.u8(7);
                o.u16(*frames);
            }
            Down::Bitrate { bps } => {
                o.u8(14);
                o.u32(*bps);
            }
            Down::RequestFull => o.u8(8),
            Down::UseBitmaps => o.u8(9),
            Down::ClipboardOn => o.u8(11),
            Down::AudioOn => o.u8(12),
            Down::AudioOff => o.u8(13),
            Down::MicOn => o.u8(21),
            Down::MicOff => o.u8(22),
            Down::Mic { pcm } => {
                o.u8(23);
                o.bytes(pcm);
            }
            Down::Clipboard { data } => {
                o.u8(10);
                o.bytes(data);
            }
            Down::FilesBegin { id, files } => {
                o.u8(16);
                o.u32(*id);
                o.u32(files.len() as u32);
                for (name, size) in files {
                    o.str(name);
                    o.u64(*size);
                }
            }
            Down::FilesData { id, index, offset, data } => {
                o.u8(17);
                o.u32(*id);
                o.u32(*index);
                o.u64(*offset);
                o.bytes(data);
            }
            Down::FilesCancel { id } => {
                o.u8(18);
                o.u32(*id);
            }
            Down::FilesOut => o.u8(19),
            Down::FilesRead { id, index, offset, len } => {
                o.u8(20);
                o.u32(*id);
                o.u32(*index);
                o.u64(*offset);
                o.u32(*len);
            }
            Down::ClipboardImage { png } => {
                o.u8(15);
                o.bytes(png);
            }
            Down::Bye => o.u8(255),
        }
        o.0
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut i = In(buf);
        let msg = match i.u8()? {
            1 => Down::Hello { version: i.u16()?, width: i.u16()?, height: i.u16()?, scale_percent: i.u16()?, klid: i.u32()? },
            2 => Down::Resize { width: i.u16()?, height: i.u16()?, scale_percent: i.u16()? },
            3 => Down::Key { code: i.u32()?, pressed: i.bool()? },
            4 => Down::PointerMove { x: i.u32()?, y: i.u32()? },
            5 => Down::Button { code: i.u32()?, pressed: i.bool()? },
            6 => Down::Wheel { vertical: i.f64()?, horizontal: i.f64()? },
            7 => Down::Credit { frames: i.u16()? },
            14 => Down::Bitrate { bps: i.u32()? },
            8 => Down::RequestFull,
            9 => Down::UseBitmaps,
            10 => Down::Clipboard { data: i.bytes()? },
            11 => Down::ClipboardOn,
            15 => Down::ClipboardImage { png: i.bytes()? },
            16 => {
                let (id, n) = (i.u32()?, i.u32()?);
                if n as usize > MAX_FILES {
                    return Err(ProtoError::TooLarge(n));
                }
                let mut files = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    files.push((i.str()?, i.u64()?));
                }
                Down::FilesBegin { id, files }
            }
            17 => Down::FilesData { id: i.u32()?, index: i.u32()?, offset: i.u64()?, data: i.bytes()? },
            18 => Down::FilesCancel { id: i.u32()? },
            19 => Down::FilesOut,
            20 => Down::FilesRead { id: i.u32()?, index: i.u32()?, offset: i.u64()?, len: i.u32()? },
            12 => Down::AudioOn,
            13 => Down::AudioOff,
            21 => Down::MicOn,
            22 => Down::MicOff,
            23 => Down::Mic { pcm: i.bytes()? },
            255 => Down::Bye,
            t => return Err(ProtoError::UnknownTag(t)),
        };
        i.finish()?;
        Ok(msg)
    }
}

impl Up {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Out::default();
        match self {
            Up::Ready { width, height } => {
                o.u8(1);
                o.u16(*width);
                o.u16(*height);
            }
            Up::Resized { width, height } => {
                o.u8(2);
                o.u16(*width);
                o.u16(*height);
            }
            Up::Frame { x, y, w, h, kind, data } => {
                o.u8(3);
                o.u16(*x);
                o.u16(*y);
                o.u16(*w);
                o.u16(*h);
                o.u8(*kind as u8);
                o.bytes(data);
            }
            Up::Audio { pcm } => {
                o.u8(4);
                o.bytes(pcm);
            }
            Up::Clipboard { data } => {
                o.u8(5);
                o.bytes(data);
            }
            Up::ClipboardImage { png } => {
                o.u8(8);
                o.bytes(png);
            }
            Up::FilesOffered { id, files } => {
                o.u8(11);
                o.u32(*id);
                o.u32(files.len() as u32);
                for (name, size) in files {
                    o.str(name);
                    o.u64(*size);
                }
            }
            Up::FilesData { id, index, offset, data } => {
                o.u8(12);
                o.u32(*id);
                o.u32(*index);
                o.u64(*offset);
                o.bytes(data);
            }
            Up::FilesReadFailed { id, index, offset } => {
                o.u8(13);
                o.u32(*id);
                o.u32(*index);
                o.u64(*offset);
            }
            Up::FilesReady { id } => {
                o.u8(9);
                o.u32(*id);
            }
            Up::FilesFailed { id } => {
                o.u8(10);
                o.u32(*id);
            }
            Up::Cursor { name } => {
                o.u8(6);
                o.str(name);
            }
            Up::CursorImage { hot_x, hot_y, width, height, data } => {
                o.u8(7);
                o.u16(*hot_x);
                o.u16(*hot_y);
                o.u16(*width);
                o.u16(*height);
                o.bytes(data);
            }
            Up::Bye => o.u8(255),
        }
        o.0
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut i = In(buf);
        let msg = match i.u8()? {
            1 => Up::Ready { width: i.u16()?, height: i.u16()? },
            2 => Up::Resized { width: i.u16()?, height: i.u16()? },
            3 => {
                let (x, y, w, h) = (i.u16()?, i.u16()?, i.u16()?, i.u16()?);
                let kind = match i.u8()? {
                    0 => FrameKind::H264,
                    1 => FrameKind::Bgra,
                    t => return Err(ProtoError::UnknownTag(t)),
                };
                Up::Frame { x, y, w, h, kind, data: i.bytes()? }
            }
            4 => Up::Audio { pcm: i.bytes()? },
            5 => Up::Clipboard { data: i.bytes()? },
            8 => Up::ClipboardImage { png: i.bytes()? },
            9 => Up::FilesReady { id: i.u32()? },
            11 => {
                let (id, n) = (i.u32()?, i.u32()?);
                if n as usize > MAX_FILES {
                    return Err(ProtoError::TooLarge(n));
                }
                let mut files = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    files.push((i.str()?, i.u64()?));
                }
                Up::FilesOffered { id, files }
            }
            12 => Up::FilesData { id: i.u32()?, index: i.u32()?, offset: i.u64()?, data: i.bytes()? },
            13 => Up::FilesReadFailed { id: i.u32()?, index: i.u32()?, offset: i.u64()? },
            10 => Up::FilesFailed { id: i.u32()? },
            6 => Up::Cursor { name: i.str()? },
            7 => Up::CursorImage { hot_x: i.u16()?, hot_y: i.u16()?, width: i.u16()?, height: i.u16()?, data: i.bytes()? },
            255 => Up::Bye,
            t => return Err(ProtoError::UnknownTag(t)),
        };
        i.finish()?;
        Ok(msg)
    }
}

// ---- daemon <-> root helper ----
//
// The network daemon runs without privileges and asks the helper for the two things only root can do: check a
// password (any account) and start a session process as that account. One helper connection serves one client
// connection: the helper remembers who authenticated on it and starts sessions only for that account, so the daemon
// cannot ask for a session of an account whose password it did not present.

/// From the daemon to the helper.
#[derive(Debug, PartialEq)]
pub enum HelperReq {
    Authenticate { user: String, password: String, source: String },
    /// Start the session of the account that authenticated on this connection. The answer carries the daemon's end of
    /// the session socket as a file descriptor (see `fdpass`). Nothing else is asked for: what runs, with which
    /// arguments, is the helper's own configuration, never the daemon's.
    StartSession,
    /// A ticket for the account that authenticated on this connection (see `tickets.rs`).
    IssueTicket,
    /// Log in as `user`, the account of a ticket (made for this `source`), instead of with a password.
    Redeem { ticket: String, user: String, source: String },
    /// The ticket is no longer wanted.
    RevokeTicket { ticket: String },
    /// Read-only information for the account that logged in on this connection: its own row, or everybody's when it is an administrator
    /// (`admininfo.rs`). Nothing is changed by it.
    Info { kind: InfoKind },
    /// A change an administrator asked for: JSON of one `adminaction::AdminAction` (at most 1 KiB). The helper checks the administrator and the
    /// action, then has the runner (`waydesk-admin serve-request`) do it; the answer is the runner's JSON (`HelperResp::Info`).
    Admin { json: String },
    /// The audit log, filtered, for an administrator (see `admininfo::AuditQuery`); the answer is a JSON list, newest first (`HelperResp::Info`).
    /// An empty text is "no filter"; `limit` is at most 500.
    Audit { since: String, user: String, event: String, outcome: String, limit: u16 },
    /// The account that logged in on this connection changes its own password: the helper checks `old` again (the same lockout as a login), then has the
    /// runner set `new`. Neither password is logged or kept.
    ChangePassword { old: String, new: String },
    /// A line for the audit log about something the portal did that the helper cannot see (an authenticator set up or taken away): `event` is
    /// one of `NOTE_*`, `target` an account name or empty. The line names the account that logged in on this connection and where it came from.
    AuditNote { event: u8, target: String },
    /// A ticket for `user` from `source`, without a password: for a server's agent, which opens a browser stream for a person the portal has
    /// signed in. Only a connection from root (the agent) may ask for it, and root may ask for nothing else; the account still has to be one that may
    /// log in (`PamPolicy::still_allowed`), and redeeming the ticket checks that again.
    IssueFor { user: String, source: String },
    Bye,
}

/// What `HelperReq::Info` asks for: the same JSON as `waydesk-admin users list|sessions list|status --json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoKind {
    Users,
    Sessions,
    /// Administrators only.
    Status,
    /// `{"admin":true|false}`: whether the account administers the machine (asked on every request, never kept).
    Role,
    /// `{"text":"..."}`: what `waydesk-admin access show` says (administrators only).
    Access,
    /// `{"text":"..."}`: what `waydesk-admin cert status` says (administrators only).
    Cert,
}

/// From the helper to the daemon.
#[derive(Debug, PartialEq)]
pub enum HelperResp {
    AuthOk,
    AuthFail,
    /// The session is running; a file descriptor follows (see `fdpass`).
    Started,
    Error { message: String },
    /// The machine will not take a new session now; `reason` is one of the `REFUSED_*` values, `message` is for the log.
    Refused { reason: u8, message: String },
    Ticket { ticket: String },
    /// The answer to `Info`: JSON text.
    Info { json: String },
}

/// `HelperReq::AuditNote` events.
pub const NOTE_TOTP_ENROLLED: u8 = 1;
pub const NOTE_TOTP_REMOVED: u8 = 2;
/// An administrator took the authenticator of `target` away.
pub const NOTE_TOTP_REMOVED_BY_ADMIN: u8 = 3;
/// An administrator added a server to the portal (a join code was made), made a new code for one, revoked its key, or removed it from the list.
/// `target` is the server's id. Only administrators may write these.
pub const NOTE_SERVER_ADDED: u8 = 4;
pub const NOTE_SERVER_CODE: u8 = 5;
pub const NOTE_SERVER_REVOKED: u8 = 6;
pub const NOTE_SERVER_REMOVED: u8 = 7;

/// Why a new session was refused (`HelperResp::Refused`).
pub const REFUSED_MEMORY: u8 = 1;
pub const REFUSED_USERS: u8 = 2;

impl HelperReq {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Out::default();
        match self {
            HelperReq::Authenticate { user, password, source } => {
                o.u8(1);
                o.str(user);
                o.str(password);
                o.str(source);
            }
            HelperReq::StartSession => o.u8(2),
            HelperReq::IssueTicket => o.u8(3),
            HelperReq::Redeem { ticket, user, source } => {
                o.u8(4);
                o.str(ticket);
                o.str(user);
                o.str(source);
            }
            HelperReq::RevokeTicket { ticket } => {
                o.u8(5);
                o.str(ticket);
            }
            HelperReq::Info { kind } => {
                o.u8(6);
                o.u8(match kind {
                    InfoKind::Users => 1,
                    InfoKind::Sessions => 2,
                    InfoKind::Status => 3,
                    InfoKind::Role => 4,
                    InfoKind::Access => 5,
                    InfoKind::Cert => 6,
                });
            }
            HelperReq::Admin { json } => {
                o.u8(7);
                o.str(json);
            }
            HelperReq::Audit { since, user, event, outcome, limit } => {
                o.u8(8);
                o.str(since);
                o.str(user);
                o.str(event);
                o.str(outcome);
                o.u16(*limit);
            }
            HelperReq::ChangePassword { old, new } => {
                o.u8(9);
                o.str(old);
                o.str(new);
            }
            HelperReq::AuditNote { event, target } => {
                o.u8(10);
                o.u8(*event);
                o.str(target);
            }
            HelperReq::IssueFor { user, source } => {
                o.u8(11);
                o.str(user);
                o.str(source);
            }
            HelperReq::Bye => o.u8(255),
        }
        o.0
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut i = In(buf);
        let msg = match i.u8()? {
            1 => HelperReq::Authenticate { user: i.str()?, password: i.str()?, source: i.str()? },
            2 => HelperReq::StartSession,
            3 => HelperReq::IssueTicket,
            4 => HelperReq::Redeem { ticket: i.str()?, user: i.str()?, source: i.str()? },
            5 => HelperReq::RevokeTicket { ticket: i.str()? },
            6 => HelperReq::Info {
                kind: match i.u8()? {
                    1 => InfoKind::Users,
                    2 => InfoKind::Sessions,
                    3 => InfoKind::Status,
                    4 => InfoKind::Role,
                    5 => InfoKind::Access,
                    6 => InfoKind::Cert,
                    t => return Err(ProtoError::UnknownTag(t)),
                },
            },
            7 => HelperReq::Admin { json: i.str()? },
            8 => HelperReq::Audit { since: i.str()?, user: i.str()?, event: i.str()?, outcome: i.str()?, limit: i.u16()? },
            9 => HelperReq::ChangePassword { old: i.str()?, new: i.str()? },
            10 => HelperReq::AuditNote { event: i.u8()?, target: i.str()? },
            11 => HelperReq::IssueFor { user: i.str()?, source: i.str()? },
            255 => HelperReq::Bye,
            t => return Err(ProtoError::UnknownTag(t)),
        };
        i.finish()?;
        Ok(msg)
    }
}

impl HelperResp {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Out::default();
        match self {
            HelperResp::AuthOk => o.u8(1),
            HelperResp::AuthFail => o.u8(2),
            HelperResp::Started => o.u8(3),
            HelperResp::Error { message } => {
                o.u8(4);
                // Never longer than a string may be.
                o.str(&message.chars().take(200).collect::<String>());
            }
            HelperResp::Refused { reason, message } => {
                o.u8(5);
                o.u8(*reason);
                o.str(&message.chars().take(200).collect::<String>());
            }
            HelperResp::Ticket { ticket } => {
                o.u8(6);
                o.str(ticket);
            }
            HelperResp::Info { json } => {
                o.u8(7);
                o.str(json);
            }
        }
        o.0
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut i = In(buf);
        let msg = match i.u8()? {
            1 => HelperResp::AuthOk,
            2 => HelperResp::AuthFail,
            3 => HelperResp::Started,
            4 => HelperResp::Error { message: i.str()? },
            5 => HelperResp::Refused { reason: i.u8()?, message: i.str()? },
            6 => HelperResp::Ticket { ticket: i.str()? },
            7 => HelperResp::Info { json: i.long_str(MAX_INFO)? },
            t => return Err(ProtoError::UnknownTag(t)),
        };
        i.finish()?;
        Ok(msg)
    }
}

// ---- framing ----

/// Writes one framed message (`body` is what `encode` returned).
pub fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> Result<(), ProtoError> {
    let len = u32::try_from(body.len()).map_err(|_| ProtoError::TooLarge(u32::MAX))?;
    if len > MAX_MESSAGE {
        return Err(ProtoError::TooLarge(len));
    }
    w.write_all(&len.to_le_bytes())?;
    w.write_all(body)?;
    Ok(())
}

/// Reads one framed message and returns its body (tag and payload). `Ok(None)` is a clean end of stream
/// before the first byte of a message.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>, ProtoError> {
    let mut len = [0u8; 4];
    match r.read(&mut len[..1])? {
        0 => return Ok(None),
        _ => r.read_exact(&mut len[1..])?,
    }
    let len = u32::from_le_bytes(len);
    if len > MAX_MESSAGE {
        return Err(ProtoError::TooLarge(len));
    }
    if len == 0 {
        return Err(ProtoError::Truncated);
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// `write_frame` for tokio streams.
pub async fn write_frame_async<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<(), ProtoError> {
    use tokio::io::AsyncWriteExt;
    let len = u32::try_from(body.len()).map_err(|_| ProtoError::TooLarge(u32::MAX))?;
    if len > MAX_MESSAGE {
        return Err(ProtoError::TooLarge(len));
    }
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

/// `read_frame` for tokio streams. Not cancel safe: read it in a task of its own, never inside `select!`.
pub async fn read_frame_async<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, ProtoError> {
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 4];
    if r.read(&mut len[..1]).await? == 0 {
        return Ok(None);
    }
    r.read_exact(&mut len[1..]).await?;
    let len = u32::from_le_bytes(len);
    if len > MAX_MESSAGE {
        return Err(ProtoError::TooLarge(len));
    }
    if len == 0 {
        return Err(ProtoError::Truncated);
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn async_framing_matches_sync_framing() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msg = Up::Frame { x: 1, y: 2, w: 3, h: 4, kind: FrameKind::H264, data: vec![9; 5000] };
        let body = msg.encode();
        let writer = tokio::spawn(async move {
            write_frame_async(&mut a, &body).await.unwrap();
        });
        let got = read_frame_async(&mut b).await.unwrap().unwrap();
        writer.await.unwrap();
        assert_eq!(Up::decode(&got).unwrap(), msg);
        assert_eq!(read_frame_async(&mut b).await.unwrap(), None);
    }

    fn down_samples() -> Vec<Down> {
        vec![
            Down::Hello { version: VERSION, width: 1680, height: 1050, scale_percent: 200, klid: 0x0816 },
            Down::Resize { width: 640, height: 480, scale_percent: 100 },
            Down::Key { code: 30, pressed: true },
            Down::PointerMove { x: 1, y: 2 },
            Down::Button { code: 0x110, pressed: false },
            Down::Wheel { vertical: -1.5, horizontal: 0.25 },
            Down::Credit { frames: 4 },
            Down::Bitrate { bps: 1_500_000 },
            Down::RequestFull,
            Down::UseBitmaps,
            Down::Clipboard { data: b"hello".to_vec() },
            Down::ClipboardImage { png: vec![0x89, b'P'] },
            Down::FilesBegin { id: 7, files: vec![("a.txt".into(), 5), ("b".into(), 0)] },
            Down::FilesData { id: 7, index: 0, offset: 0, data: vec![1, 2, 3] },
            Down::FilesCancel { id: 7 },
            Down::FilesOut,
            Down::FilesRead { id: 7, index: 1, offset: 4096, len: 65536 },
            Down::ClipboardOn,
            Down::AudioOn,
            Down::AudioOff,
            Down::MicOn,
            Down::MicOff,
            Down::Mic { pcm: vec![1; 1920] },
            Down::Bye,
        ]
    }

    fn up_samples() -> Vec<Up> {
        vec![
            Up::Ready { width: 1280, height: 800 },
            Up::Resized { width: 1920, height: 1080 },
            Up::Frame { x: 0, y: 0, w: 16, h: 16, kind: FrameKind::H264, data: vec![0, 0, 0, 1, 0x67] },
            Up::Frame { x: 3, y: 4, w: 1, h: 1, kind: FrameKind::Bgra, data: vec![1, 2, 3, 4] },
            Up::Audio { pcm: vec![0; 3528] },
            Up::Clipboard { data: Vec::new() },
            Up::ClipboardImage { png: vec![0x89, b'P'] },
            Up::FilesReady { id: 7 },
            Up::FilesFailed { id: 7 },
            Up::FilesOffered { id: 3, files: vec![("x.txt".into(), 9)] },
            Up::FilesData { id: 3, index: 0, offset: 0, data: vec![1, 2] },
            Up::FilesReadFailed { id: 3, index: 0, offset: 0 },
            Up::Cursor { name: "ew-resize".into() },
            Up::CursorImage { hot_x: 1, hot_y: 2, width: 2, height: 1, data: vec![1, 2, 3, 4, 5, 6, 7, 8] },
            Up::Bye,
        ]
    }

    #[test]
    fn every_message_round_trips() {
        for m in down_samples() {
            assert_eq!(Down::decode(&m.encode()).unwrap(), m);
        }
        for m in up_samples() {
            assert_eq!(Up::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn framing_round_trips_over_a_stream() {
        let mut wire = Vec::new();
        for m in up_samples() {
            write_frame(&mut wire, &m.encode()).unwrap();
        }
        let mut cur = io::Cursor::new(wire);
        for m in up_samples() {
            let body = read_frame(&mut cur).unwrap().unwrap();
            assert_eq!(Up::decode(&body).unwrap(), m);
        }
        assert_eq!(read_frame(&mut cur).unwrap(), None);
    }

    #[test]
    fn truncated_messages_are_refused() {
        for m in down_samples() {
            let b = m.encode();
            for cut in 0..b.len() {
                assert!(Down::decode(&b[..cut]).is_err(), "cut {cut} of {m:?}");
            }
        }
        for m in up_samples() {
            let b = m.encode();
            for cut in 0..b.len() {
                assert!(Up::decode(&b[..cut]).is_err(), "cut {cut} of {m:?}");
            }
        }
    }

    #[test]
    fn a_list_of_too_many_files_is_refused() {
        let mut b = vec![16u8];
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&(MAX_FILES as u32 + 1).to_le_bytes());
        assert_eq!(Down::decode(&b), Err(ProtoError::TooLarge(MAX_FILES as u32 + 1)));
    }

    #[test]
    fn helper_messages_round_trip_and_refuse_bad_input() {
        let reqs = [
            HelperReq::Authenticate { user: "alice".into(), password: "pä ss".into(), source: "10.0.0.1".into() },
            HelperReq::StartSession,
            HelperReq::IssueTicket,
            HelperReq::Redeem { ticket: "ab".repeat(32), user: "alice".into(), source: "10.0.0.1".into() },
            HelperReq::RevokeTicket { ticket: "ab".repeat(32) },
            HelperReq::Info { kind: InfoKind::Users },
            HelperReq::Info { kind: InfoKind::Sessions },
            HelperReq::Info { kind: InfoKind::Status },
            HelperReq::Info { kind: InfoKind::Role },
            HelperReq::Info { kind: InfoKind::Access },
            HelperReq::Info { kind: InfoKind::Cert },
            HelperReq::ChangePassword { old: "pä ss".into(), new: "x".repeat(20) },
            HelperReq::AuditNote { event: NOTE_TOTP_REMOVED_BY_ADMIN, target: "ana".into() },
            HelperReq::IssueFor { user: "ana".into(), source: "203.0.113.9".into() },
            HelperReq::Admin { json: r#"{"action":"user_add","name":"frida"}"#.into() },
            HelperReq::Audit { since: "7d".into(), user: "alice".into(), event: "admin".into(), outcome: "fail".into(), limit: 200 },
            HelperReq::Bye,
        ];
        for r in reqs {
            assert_eq!(HelperReq::decode(&r.encode()).unwrap(), r);
            let b = r.encode();
            for cut in 0..b.len() {
                assert!(HelperReq::decode(&b[..cut]).is_err());
            }
        }
        for r in [HelperResp::AuthOk, HelperResp::AuthFail, HelperResp::Started, HelperResp::Error { message: "no".into() }, HelperResp::Refused { reason: REFUSED_MEMORY, message: "full".into() }, HelperResp::Ticket { ticket: "cd".repeat(32) }, HelperResp::Info { json: "[1]".repeat(2000) }] {
            assert_eq!(HelperResp::decode(&r.encode()).unwrap(), r);
        }
        // a string longer than allowed
        let mut b = vec![1u8];
        b.extend_from_slice(&(MAX_STRING + 1).to_le_bytes());
        assert_eq!(HelperReq::decode(&b), Err(ProtoError::TooLarge(MAX_STRING + 1)));
        // not UTF-8
        let mut b = vec![1u8];
        b.extend_from_slice(&1u32.to_le_bytes());
        b.push(0xff);
        assert_eq!(HelperReq::decode(&b), Err(ProtoError::BadString));
        // an Info request with an unknown kind
        assert_eq!(HelperReq::decode(&[6, 9]), Err(ProtoError::UnknownTag(9)));
        // a long error message is cut, not refused
        let long = HelperResp::Error { message: "x".repeat(5000) };
        assert!(matches!(HelperResp::decode(&long.encode()), Ok(HelperResp::Error { .. })));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut b = Down::Credit { frames: 1 }.encode();
        b.push(0);
        assert_eq!(Down::decode(&b), Err(ProtoError::Trailing));
    }

    #[test]
    fn unknown_tags_are_refused() {
        assert_eq!(Down::decode(&[200]), Err(ProtoError::UnknownTag(200)));
        assert_eq!(Up::decode(&[200]), Err(ProtoError::UnknownTag(200)));
        // frame kind
        let mut b = Up::Frame { x: 0, y: 0, w: 1, h: 1, kind: FrameKind::Bgra, data: vec![] }.encode();
        b[9] = 7;
        assert_eq!(Up::decode(&b), Err(ProtoError::UnknownTag(7)));
    }

    #[test]
    fn oversized_lengths_are_refused_without_allocating() {
        // frame header claiming 2 GiB
        let mut cur = io::Cursor::new(0x8000_0000u32.to_le_bytes().to_vec());
        assert_eq!(read_frame(&mut cur), Err(ProtoError::TooLarge(0x8000_0000)));
        // byte string inside a message claiming more than the limit
        let mut b = vec![4u8];
        b.extend_from_slice(&(MAX_MESSAGE + 1).to_le_bytes());
        assert_eq!(Up::decode(&b), Err(ProtoError::TooLarge(MAX_MESSAGE + 1)));
    }

    #[test]
    fn zero_length_and_short_streams_are_errors() {
        let mut cur = io::Cursor::new(0u32.to_le_bytes().to_vec());
        assert_eq!(read_frame(&mut cur), Err(ProtoError::Truncated));
        let mut cur = io::Cursor::new(vec![5, 0, 0, 0, 1, 2]);
        assert!(matches!(read_frame(&mut cur), Err(ProtoError::Io(_))));
    }
}
