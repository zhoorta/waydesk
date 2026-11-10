//! The browser stream's bridge: a signed-in browser's WebSocket, passed on to the daemon's gateway port.
//!
//! The browser draws the desktop itself (see `src/webstream.rs` of the daemon): this only moves its messages. Each WebSocket message is one message
//! of the daemon's protocol; towards the daemon it gets a length in front (`u32`, little endian), and the other way the length is taken off. The
//! account the daemon is told is the one of the browser's cookie, never anything the browser says, and the first thing the daemon is sent is the
//! gateway's line (`WAYDESK-STREAM 1 KEY ACCOUNT IP`).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::limits::SessionGuard;
use crate::web::App;

/// What the browser may send in one message: a password, a key, a mouse position. The daemon refuses more than this too.
pub const MAX_FROM_BROWSER: usize = 2048;
/// Clipboard text (tag 9) may be as long as the daemon's session takes: 1 MiB and the tag.
pub const MAX_CLIPBOARD_FROM_BROWSER: usize = 1 + 1024 * 1024;
/// The most the daemon may send in one message: a whole H.264 picture.
pub const MAX_FROM_DAEMON: usize = 16 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PING_EVERY: Duration = Duration::from_secs(30);
const SILENCE_LIMIT: Duration = Duration::from_secs(120);

pub async fn run(mut ws: WebSocket, ip: IpAddr, account: String, ticket: String, app: Arc<App>, _guard: SessionGuard) {
    let started = Instant::now();
    match session(&mut ws, ip, &account, &ticket, &app).await {
        Ok((from_browser, to_browser)) => info!(%ip, account, seconds = started.elapsed().as_secs(), from_browser, to_browser, "stream ended"),
        Err(e) => info!(%ip, account, seconds = started.elapsed().as_secs(), "stream ended: {e}"),
    }
    let _ = ws.send(Message::Close(None)).await;
}

async fn session(ws: &mut WebSocket, ip: IpAddr, account: &str, ticket: &str, app: &App) -> Result<(u64, u64), String> {
    let Some(key) = &app.cfg.gateway_key else { return Err("no gateway key".into()) };
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&app.cfg.target)).await {
        Ok(Ok(s)) => s,
        _ => return Err(format!("cannot connect to {}", app.cfg.target)),
    };
    let _ = tcp.set_nodelay(true);
    let (mut rd, mut wr) = tcp.into_split();
    wr.write_all(crate::daemon_gateway::stream_line(key, account, ip, ticket).as_bytes()).await.map_err(|e| format!("cannot talk to the daemon: {e}"))?;

    // The daemon's messages are read in a task of its own: a read of a whole message is not something to cut short in a select.
    let (tx, mut from_daemon) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    let reader = tokio::spawn(async move {
        loop {
            let mut len = [0u8; 4];
            if rd.read_exact(&mut len).await.is_err() {
                return;
            }
            let len = u32::from_le_bytes(len) as usize;
            if len == 0 || len > MAX_FROM_DAEMON {
                return;
            }
            let mut body = vec![0u8; len];
            if rd.read_exact(&mut body).await.is_err() || tx.send(body).await.is_err() {
                return;
            }
        }
    });

    let (mut from_browser_bytes, mut to_browser_bytes) = (0u64, 0u64);
    let mut ping = tokio::time::interval(PING_EVERY);
    let mut last_heard = Instant::now();
    let result: Result<(), String> = loop {
        tokio::select! {
            m = ws.recv() => match m {
                Some(Ok(Message::Binary(b))) => {
                    last_heard = Instant::now();
                    if b.is_empty() || b.len() > if b[0] == 9 { MAX_CLIPBOARD_FROM_BROWSER } else { MAX_FROM_BROWSER } {
                        break Err(format!("a message of {} bytes from the browser", b.len()));
                    }
                    from_browser_bytes += b.len() as u64;
                    let mut framed = Vec::with_capacity(4 + b.len());
                    framed.extend_from_slice(&(b.len() as u32).to_le_bytes());
                    framed.extend_from_slice(&b);
                    if let Err(e) = wr.write_all(&framed).await { break Err(format!("write to the daemon: {e}")); }
                }
                Some(Ok(Message::Close(_))) | None => break Ok(()),
                Some(Ok(Message::Text(_))) => break Err("a text message from the browser".into()),
                Some(Ok(_)) => last_heard = Instant::now(),
                Some(Err(e)) => break Err(format!("the browser's connection failed: {e}")),
            },
            m = from_daemon.recv() => match m {
                Some(body) => {
                    to_browser_bytes += body.len() as u64;
                    if let Err(e) = ws.send(Message::Binary(body.into())).await { break Err(format!("write to the browser: {e}")); }
                }
                None => break Ok(()),
            },
            _ = ping.tick() => {
                if last_heard.elapsed() > SILENCE_LIMIT { break Err("the browser went silent".into()); }
                if ws.send(Message::Ping(Vec::new().into())).await.is_err() { break Ok(()); }
            }
        }
    };
    reader.abort();
    if let Err(e) = &result {
        warn!(%ip, account, "{e}");
    }
    result.map(|()| (from_browser_bytes, to_browser_bytes))
}
