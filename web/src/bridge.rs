//! The bridge between a browser and the RDP daemon, in the RDCleanPath protocol of the IronRDP web client.
//!
//! The browser cannot open a TCP connection, so it sends one WebSocket message with the first RDP packet and the session token; the gateway does
//! what the browser cannot (the plain first exchange, then TLS to the daemon), answers with the daemon's reply and its certificate, and from then on
//! only passes bytes in both directions. The RDP login happens inside that connection, between the client and the daemon: the gateway does not see it.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use ironrdp_rdcleanpath::{RDCleanPath, RDCleanPathErr, RDCleanPathPdu, EXPIRED_ERROR_CODE, GENERAL_ERROR_CODE, TARGET_UNREACHABLE_ERROR_CODE, TLS_HANDSHAKE_FAILED_ERROR_CODE, VERSION_1};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::limits::SessionGuard;
use crate::web::App;

/// The request is one X.224 packet and some text: a few hundred bytes. Anything bigger is not a client of ours.
const MAX_REQUEST: usize = 16 * 1024;
/// An X.224 connection confirm is tiny.
const MAX_X224: usize = 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// A ping every so often, and the connection is dropped when nothing at all came from the browser for this long (a browser answers a ping at once).
const PING_EVERY: Duration = Duration::from_secs(30);
const SILENCE_LIMIT: Duration = Duration::from_secs(120);

fn error_pdu(code: u16, http: Option<u16>) -> Vec<u8> {
    let pdu = RDCleanPathPdu {
        version: VERSION_1,
        error: Some(RDCleanPathErr { error_code: code, http_status_code: http, wsa_last_error: None, tls_alert_code: None }),
        ..RDCleanPathPdu::default()
    };
    pdu.to_der().unwrap_or_default()
}

async fn refuse(ws: &mut WebSocket, code: u16, http: Option<u16>) {
    let _ = ws.send(Message::Binary(error_pdu(code, http).into())).await;
    let _ = ws.send(Message::Close(None)).await;
}

pub async fn run(mut ws: WebSocket, ip: IpAddr, app: Arc<App>, _guard: SessionGuard) {
    let started = Instant::now();
    match session(&mut ws, ip, &app).await {
        Ok((user_in, user_out)) => info!(%ip, seconds = started.elapsed().as_secs(), from_browser = user_in, to_browser = user_out, "session ended"),
        Err(e) => info!(%ip, seconds = started.elapsed().as_secs(), "session ended: {e}"),
    }
}

async fn session(ws: &mut WebSocket, ip: IpAddr, app: &App) -> Result<(u64, u64), String> {
    // 1. The request.
    let first = match tokio::time::timeout(STEP_TIMEOUT, ws.recv()).await {
        Ok(Some(Ok(Message::Binary(b)))) if b.len() <= MAX_REQUEST => b,
        _ => return Err("no valid request".into()),
    };
    let request = match RDCleanPathPdu::from_der(&first).ok().and_then(|p| p.into_enum().ok()) {
        Some(RDCleanPath::Request { proxy_auth, x224_connection_request, .. }) => (proxy_auth, x224_connection_request.into_bytes()),
        _ => {
            refuse(ws, GENERAL_ERROR_CODE, Some(400)).await;
            return Err("not an RDCleanPath request".into());
        }
    };
    let (token, x224) = request;
    let Some(account) = app.tokens.consume(&token, ip, Instant::now()) else {
        refuse(ws, EXPIRED_ERROR_CODE, Some(401)).await;
        return Err("token missing, used, expired or from another address".into());
    };
    if x224.len() < 4 || x224[0] != 3 || x224.len() > MAX_X224 {
        refuse(ws, GENERAL_ERROR_CODE, Some(400)).await;
        return Err("the first packet is not a TPKT".into());
    }

    // 2. The plain exchange with the daemon, then TLS.
    let mut tcp = match tokio::time::timeout(STEP_TIMEOUT, TcpStream::connect(&app.cfg.target)).await {
        Ok(Ok(s)) => s,
        _ => {
            refuse(ws, TARGET_UNREACHABLE_ERROR_CODE, Some(502)).await;
            return Err(format!("cannot connect to {}", app.cfg.target));
        }
    };
    let _ = tcp.set_nodelay(true);
    // To a daemon that listens for gateways: who this is for. The daemon lets this connection log in as that account only, and records the client's
    // address instead of ours.
    if let Some(key) = &app.cfg.gateway_key {
        let line = crate::daemon_gateway::line(key, &account, ip);
        if tcp.write_all(line.as_bytes()).await.is_err() {
            refuse(ws, TARGET_UNREACHABLE_ERROR_CODE, Some(502)).await;
            return Err("cannot talk to the daemon".into());
        }
    }
    let confirm = match tokio::time::timeout(STEP_TIMEOUT, async {
        tcp.write_all(&x224).await?;
        let mut header = [0u8; 4];
        tcp.read_exact(&mut header).await?;
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if header[0] != 3 || !(4..=MAX_X224).contains(&len) {
            return Err(std::io::Error::other("the daemon's reply is not a TPKT"));
        }
        let mut confirm = header.to_vec();
        confirm.resize(len, 0);
        tcp.read_exact(&mut confirm[4..]).await?;
        Ok::<_, std::io::Error>(confirm)
    })
    .await
    {
        Ok(Ok(c)) => c,
        _ => {
            refuse(ws, TARGET_UNREACHABLE_ERROR_CODE, Some(502)).await;
            return Err("no X.224 answer from the daemon".into());
        }
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(&app.daemon_tls));
    let mut tls = match tokio::time::timeout(STEP_TIMEOUT, connector.connect(ServerName::try_from("localhost").expect("a valid name"), tcp)).await {
        Ok(Ok(s)) => s,
        other => {
            let why = match other {
                Ok(Err(e)) => e.to_string(),
                _ => "timeout".into(),
            };
            refuse(ws, TLS_HANDSHAKE_FAILED_ERROR_CODE, Some(502)).await;
            return Err(format!("TLS to the daemon failed: {why}"));
        }
    };
    let chain: Vec<Vec<u8>> = tls.get_ref().1.peer_certificates().unwrap_or_default().iter().map(|c| c.as_ref().to_vec()).collect();

    // 3. The answer.
    let answer = RDCleanPathPdu::new_response(app.cfg.target.clone(), confirm, chain).and_then(|p| p.to_der()).map_err(|e| format!("cannot encode the answer: {e}"))?;
    ws.send(Message::Binary(answer.into())).await.map_err(|e| e.to_string())?;

    // 4. Bytes in both directions.
    let (mut from_browser, mut to_browser) = (0u64, 0u64);
    let mut buf = vec![0u8; 32 * 1024];
    let mut ping = tokio::time::interval(PING_EVERY);
    let mut last_heard = Instant::now();
    let result: Result<(), String> = loop {
        tokio::select! {
            m = ws.recv() => match m {
                Some(Ok(Message::Binary(b))) => {
                    last_heard = Instant::now();
                    from_browser += b.len() as u64;
                    if let Err(e) = tls.write_all(&b).await { break Err(format!("write to the daemon: {e}")); }
                }
                Some(Ok(Message::Close(_))) | None => break Ok(()),
                Some(Ok(_)) => last_heard = Instant::now(),
                Some(Err(e)) => break Err(format!("the browser's connection failed: {e}")),
            },
            n = tls.read(&mut buf) => match n {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    to_browser += n as u64;
                    if let Err(e) = ws.send(Message::Binary(buf[..n].to_vec().into())).await { break Err(format!("write to the browser: {e}")); }
                }
                // The daemon ends a refused login, and a closed session, by closing the connection without a TLS close_notify.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break Ok(()),
                Err(e) => break Err(format!("read from the daemon: {e}")),
            },
            _ = ping.tick() => {
                if last_heard.elapsed() > SILENCE_LIMIT { break Err("the browser went silent".into()); }
                if ws.send(Message::Ping(Vec::new().into())).await.is_err() { break Ok(()); }
            }
        }
    };
    if let Err(e) = &result {
        warn!(%ip, "{e}");
    }
    let _ = ws.send(Message::Close(None)).await;
    result.map(|()| (from_browser, to_browser))
}
