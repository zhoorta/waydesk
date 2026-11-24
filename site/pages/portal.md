title: The portal: desktops in a browser
nav: Portal and browser access
seo_title: Waydesk portal: Linux desktops in a browser, several servers, one sign-in
description: Install and use the optional portal: first sign-in, adding servers, users, two-step sign-in, reaching it from other machines and behind a reverse proxy.
---
The portal is optional. Waydesk works without it: the RDP port and `waydesk-admin` are complete. The portal is for opening desktops **in a browser** (no client to install) and for managing **more than one server** from one place.

## What it does {bar: notes}
- **A desktop in a browser.** People sign in to a page and open their session. The picture is H.264 decoded by the browser, with keys, mouse, clipboard (text and pictures) and the window size going back. Sound is off until switched on.
- **Users and servers in one place.** The portal has its own users. An administrator assigns a user to servers, and the portal makes the account on each of them.
- **Administrator pages for each server:** Overview (sessions, memory, CPU, GPU), Accounts, Sessions (with an End button) and Audit, and a Servers list that shows every server at a glance.
- **App passwords** for people who prefer an RDP client such as the Windows App or Remmina.
- **Two-step sign-in** with an authenticator app, optional or required.

## Install {bar: terminal}
The portal is a package of its own, of the same version as the server, so a server that only needs RDP carries no web server.

```console
$ sudo apt install waydesk-portal            # Debian, Ubuntu
$ sudo pacman -S waydesk-portal              # Arch
$ sudo dnf install waydesk-server-portal     # Fedora
$ sudo systemctl enable --now waydesk-web.service
```

The package starts nothing by itself. The portal listens on `127.0.0.1:8443` only, and its settings are in `/etc/default/waydesk-web`.

## First sign-in {bar: terminal}
Make the first user on the portal's machine. The password is printed once.

```console
$ sudo waydesk-web people add NAME --admin --display "Full name"
$ ssh -N -L 8443:127.0.0.1:8443 USER@SERVER      # on the client computer
```

Then open `https://localhost:8443/`.

The certificate is the server's own, so the browser warns on the first visit: compare the fingerprint with `sudo waydesk-admin cert status`. Everything after this is done in the browser. `waydesk-web people list`, `passwd NAME` and `remove NAME` remain available on the command line, for example when the only administrator forgets the password.

The portal's own machine is also a server in the list ("This machine"), so a single server needs nothing else.

## Users {bar: notes}
The Users page makes, switches off and removes users and sets who is an administrator. **Servers** on a user assigns them to servers: the portal makes the account on each server through its agent, and the user opens it from **My desktop**, which shows one card per server with a thumbnail of the screen (and how old it is, when it is not current). The portal never takes over an account it did not make.

A user's **My account** page changes the password, turns two-step sign-in on or off and makes an **app password** for an RDP client. The Windows App and Remmina log in to the server's RDP port with that password.

## Adding a server {bar: notes}
A server dials **out** to the portal; the portal needs no way into the server.

1. On the portal, Servers, Add a server shows a join code (one use, one hour) and the portal's certificate pin.
2. On the server, as root:

```console
$ sudo waydesk-agent enrol https://PORTAL:8443 CODE --pin PIN
$ sudo systemctl restart waydesk
$ sudo systemctl enable --now waydesk-agent
```

`enrol` also makes the key that lets the portal reach the daemon's browser stream and adds the flags for it to `/etc/default/waydesk`, which is why the daemon is restarted. The agent keeps one link open to the portal and answers only a closed list of requests. A server that stops answering is noticed in about 12 seconds, and the pages say so instead of failing. `waydesk-agent status` shows the link from the server's side.

A server on another network needs the portal to be reachable from it: see the next section.

## Reaching the portal from other machines {bar: notes}
By default only the local machine can connect. For other machines or the internet, set these in `/etc/default/waydesk` (or `WAYDESK_WEB_BIND` in `/etc/default/waydesk-web`):

```console
WAYDESK_WEB_BIND=0.0.0.0:8443
WAYDESK_WEB_ARGS="--allow-from SERVER-ADDRESS,CLIENT-ADDRESS,loopback --totp required"
```

- `--allow-from` is checked on connect, before TLS. List the addresses of every joined server and of the administrators; an address that is not listed gets nothing.
- `--totp required` makes a two-step code the rule for every user (`optional` asks for one only from users who have one). Users get theirs on **My account**.
- The agents compare the portal's certificate with the pin, so a DNS name is not needed.
- Failed logins are answered after about 4 seconds whatever was wrong, and are locked out per account and per address.

## Behind a reverse proxy {bar: notes}
With a public name and a certificate from Let's Encrypt, the portal can sit behind nginx, Caddy, Traefik or Apache. The portal then serves plain HTTP on the same machine and believes the proxy about who the client is:

```console
$ waydesk-web --plain-http --trusted-proxy 127.0.0.1 \
    --public-origin https://desk.example.org
```

- `--trusted-proxy` names the proxy. Only connections from it are believed when they send `X-Forwarded-For`.
- `--public-origin` is the one address people open. A request from any other page is refused.
- The portal's port must be reachable only by the proxy.

nginx:

```console
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

```console
desk.example.org {
    reverse_proxy 127.0.0.1:8443
}
```

## Two-step sign-in {bar: notes}
Any authenticator app works (Aegis, Google Authenticator, 1Password, Bitwarden): six digits, thirty seconds. A user turns it on in **My account** and is shown eight recovery codes once. A code works once. Five wrong codes from one address for one account, or twenty for one account from anywhere, lock that account for ten minutes.

An administrator sees which users have it on the Settings page and can remove it when a phone is lost. Keep the server's clock right (chrony or systemd-timesyncd): codes one step either side of now are accepted.

Two-step sign-in protects the portal, not the RDP port. An account can still log in over RDP with its password for anyone who can reach port 3389, so keep that port on `127.0.0.1` or behind a VPN.

## What to know {bar: notes}
- **Native RDP is better on a bad link.** The browser stream was measured against the RDP client on lossy and slow connections and loses there; on a good link it is fine. [Measurements](/docs/measurements/) has the method.
- **Trust.** A portal reaches every server that joined it, so a compromised portal is a compromise of all of them. Run it on a machine as trusted as the servers, keep `--allow-from` short and require two-step sign-in.
- **Early software.** The portal is new in 0.6.0 and has had fewer hours of use than the RDP server. [Limits and status](/docs/limits/) says what was tried.

The complete reference, with every option, is [`web/README.md`](https://github.com/zhoorta/waydesk/blob/main/web/README.md) in the repository; the design and its reasons are in [`docs/PORTAL-DESIGN.md`](https://github.com/zhoorta/waydesk/blob/main/docs/PORTAL-DESIGN.md).
