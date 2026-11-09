# waydesk-web

Browser access to Waydesk: a small HTTPS server that serves the web client (the IronRDP browser client, a login page around it) and bridges the
client's WebSocket to the RDP daemon in the RDCleanPath protocol. A browser cannot open a TCP connection, so the gateway makes the plain first
exchange and the TLS connection to the daemon, and then only passes bytes. **The login is the daemon's**: the page sends the account and password
into the RDP connection, and the daemon checks them through PAM, as for any RDP client. The gateway ends the browser's connection and makes the TLS
connection to the daemon, so the RDP packets, the login among them, pass through its memory in the clear: it does not look at them, keep them or log
them, but it is a machine that has to be trusted as much as the daemon. Run it on the same machine as the daemon (the default).

## Sign-in (the portal's first step)

People sign in to the site first, then open their desktop. The sign-in is the account's password, checked by the daemon's **root helper** (the same
check, delay and lockout as RDP, so the web cannot be used to guess faster), plus the authenticator code when one is asked for. The gateway runs as the
daemon's account (`waydesk`) because only that account can open the helper's socket (`--helper-socket`, default `/run/waydesk/helper.sock`); it keeps
no password. A good sign-in sets a cookie (`__Host-waydesk`: `Secure`, `HttpOnly`, `SameSite=Strict`, random, kept in memory only, so a restart signs
everybody out) that ends after 30 minutes without a request (`--idle-minutes`) or 8 hours at most; every request that changes anything repeats a CSRF
token in a header. The password is checked before the code, so a wrong password never spends a code; a refusal says only "check the account, the
password and the code", and takes as long (about 4 s) whatever was wrong, so the time does not tell a right password from a wrong one.
Until the browser stream replaces RDP in the page, the RDP login inside the connection asks for the password again: the page keeps it in its memory
from the sign-in to the connection so that the person types it once.

## The browser stream (the desktop without RDP)

The page shows the desktop from the daemon's own browser stream (`src/webstream.rs`, `client/desk.js`): H.264 pictures go to the browser's decoder
(WebCodecs) and onto a canvas, and keys, mouse and the window size go back as small messages. The gateway only bridges them: `/stream` is a WebSocket
for a signed-in browser (the account is the cookie's, the `Origin` has to be this site's, and the cookie is `SameSite=Strict`), passed on to the
daemon's **gateway port** with the line `WAYDESK-STREAM 1 KEY ACCOUNT IP`. It needs `--gateway-key FILE` here and `--gateway-bind 127.0.0.1:3390
--gateway-key FILE` on the daemon (`--target 127.0.0.1:3390` here), and the daemon with `--auth helper`. The password is sent in the first message
and checked by the daemon through the root helper (same lockout as RDP). `?rdp=1` loads the IronRDP client instead, for comparing; a browser without
an H.264 decoder falls back to it when this install has it.

## Safe as shipped

- Listens on `127.0.0.1:8443` only: reach it with `ssh -N -L 8443:127.0.0.1:8443 ACCOUNT@SERVER` and open `https://localhost:8443/`.
- Source addresses are checked on accept, before TLS (`--allow-from`, the same list syntax as `WAYDESK_ALLOW_FROM`; non-loopback binds default to private networks).
- Starting a session needs a one-time token (30 s, one use, only from the address that asked), and every request that changes anything must carry an
  `Origin` of this host, so another web page cannot start a session from your browser.
- Per address: 10 tokens a minute, 3 sessions at once; 64 sessions in all (`--rate-per-minute`, `--max-per-ip`, `--max-total`). The daemon's own delay
  and lockout per account stay in force behind it.
- It serves HTTPS with the certificate of the RDP daemon (`/etc/waydesk/cert.pem`, `key.pem`; re-read when `waydesk-admin cert` replaces them), and
  connects to the daemon only if the daemon presents exactly that certificate.
- **A second factor**: one-time codes from an authenticator app (below). Without it, keep the gateway on loopback or behind a VPN, as with the RDP port.

## Behind a web server (a reverse proxy)

For access without a VPN or a tunnel, put the gateway behind the web server you already run (nginx, Caddy, Traefik, Apache), which holds the
public name and its certificate (Let's Encrypt). The gateway then serves plain HTTP on this machine only and believes the proxy about who the client is:

```
waydesk-web --plain-http --trusted-proxy 127.0.0.1 --public-origin https://waydesk.example.com
```

- `--trusted-proxy LIST`: the address(es) of the proxy. Only connections from there are believed when they say `X-Forwarded-For` (the client) and
  `X-Forwarded-Host` (the name the browser used). The header is read from the right, skipping the proxies named here, so an address a client
  writes into it itself is ignored. `any` is refused. `--plain-http` needs it: without a proxy in front, plain HTTP would send passwords in the clear.
- `--public-origin https://HOST`: the one address users open. A request from another page is refused, whatever `Host` the proxy passes on. Set
  it: it is the most robust way to keep the cross-site check right behind any proxy.
- Limits, the token and the address list (`--allow-from`) then work per real client, not per proxy.
- Keep the port reachable only by the proxy (loopback, or a firewall rule). **Still no second factor**: until there is one, use this only with
  long account passwords, a short `--allow-from`, or an authenticating layer in the proxy itself (basic auth, SSO).

nginx (use `$remote_addr`, which a client cannot influence, not `$proxy_add_x_forwarded_for`):

```
location / {
    proxy_pass http://127.0.0.1:8443;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;
}
```

Caddy:

```
waydesk.example.com {
    reverse_proxy 127.0.0.1:8443
}
```

## A second factor: one-time codes

The page asks for a code from an authenticator app (any TOTP app: Aegis, Google Authenticator, 1Password, Bitwarden; RFC 6238, six digits,
thirty seconds). The gateway checks it before it hands out the token that starts a session.

```
sudo waydesk-web totp add ana             # a QR code (with qrencode installed), the key, and eight one-time recovery codes
sudo waydesk-web totp recovery ana        # new recovery codes (the old ones stop working)
sudo waydesk-web totp remove ana
sudo waydesk-web totp list
```

`--totp off|optional|required` (default `off`):

- `optional`: an account that has an authenticator must give a code; the others sign in with the password alone.
- `required`: every account must have one; one without cannot start a session here.

What it does and does not do:

- **It needs the daemon's gateway port.** The gateway checks the code for the account the visitor names, but only the daemon sees which account is then
  logged in to. So the gateway tells the daemon which account the code was for, and the daemon lets that connection log in as that account only (and
  records the client's real address, which also fills the audit log). The gateway therefore refuses to start with `--totp optional|required` and no
  `--gateway-key`. On the daemon: `--gateway-bind 127.0.0.1:3390 --gateway-key /etc/waydesk/gateway.key`; on the gateway:
  `--target 127.0.0.1:3390 --gateway-key /etc/waydesk/gateway.key`. The key is one word of at least 16 characters, readable only by the `waydesk` account.
- **A code works once**, and a code seen by someone else cannot be used again within its half minute. Steps one before and one after the present are
  accepted, for clocks that differ a little; keep the server's clock right (chrony or systemd-timesyncd).
- **Guessing is limited**: 5 wrong codes from one address for one account, or 20 for one account from anywhere, within ten minutes, and the right code is
  refused too until it passes. (This also means that someone can lock a known account out for ten minutes; the token limits per address keep that slow.)
- **The answer is the same** whatever was wrong, so it does not say which accounts exist or have an authenticator.
- **Recovery codes** are kept as hashes and shown once. An administrator can always set an account up again with `totp add`.
- **It protects this way in, not the RDP port.** An account with an authenticator can still log in over RDP (3389) with the password alone, for anyone who
  can reach that port. Keep 3389 on loopback, or behind the VPN or the firewall.

## Build and test

```
cd web && cargo test          # 44 tests, including end-to-end ones (gateway, stand-in daemon, a client that acts like the browser)
cargo build --release         # builds anywhere Rust does; it shares no code with the daemon except src/allow.rs
```

The web client's files (`index.html`, `app.js`, `style.css` from `client/`, and the IronRDP browser client bundles) go in `/usr/share/waydesk/web`;
`.gz` files next to them are sent to browsers that accept gzip.
