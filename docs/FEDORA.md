# Waydesk on Fedora (RPM)

`waydesk-server` as an RPM: the RDP server, the root helper, the admin tools and the services, with sway sessions (Plasma, COSMIC and Hyprland
optional, as on Arch). The desktop of the Debian packages (shell, launcher, title-bar buttons) is not packaged for Fedora.

Build: `packaging/rpm/build.sh [RELEASE]` (Docker, a Fedora container; output in `packaging/out/rpm/<arch>/`).

The spec also ships `waydesk-agent` and its units (`waydesk-agent.service`, `waydesk-admin.socket`), enabled as in the other packages (written 2026-11-23, **not built yet**).

## After installing

```
sudo systemctl enable --now waydesk-helper.service waydesk.service
sudo waydesk-setup-admin
sudo firewall-cmd --add-service=waydesk --permanent && sudo firewall-cmd --reload   # only if the RDP port should be reachable
```

Each account's sessions need a sound server: `systemctl --user enable --now pipewire.socket pipewire-pulse.socket wireplumber.service`.

## Differences from Debian that the package deals with

- PAM: the server's service includes `system-auth` (`packaging/rpm/pam-waydesk-server`).
- The administrator group is `wheel`, not `sudo`: `waydesk-admin` uses `sudo` when that group exists and `wheel` otherwise.
- Users and groups come from `sysusers.d`, the certificate from the `%post` scriptlet. The services are not started or enabled by the install.
- firewalld: a `waydesk` service (3389/tcp) is shipped; nothing opens it.
- OpenH264: Fedora has it in the Cisco repository (`fedora-cisco-openh264`, enabled by default; the install on Fedora 44 found `openh264` 2.6.0): the package *recommends* `openh264`. Without it, GPUs encode in hardware and a
  machine without a GPU has no video. The server accepts 2.6 and 2.7 (`/usr/lib64/libopenh264.so.8`).

## The session's sway configuration

The package installs `/etc/xdg/waydesk/sway.conf` (a config file: your edits survive upgrades). Sessions use it instead of Fedora's own `/etc/sway/config`, which would
start a status bar with a shell loop in every account's session and tile the windows. This one is lean and Windows-like: windows float with title bars,
Alt+Tab switches, Alt+F4 closes, Super+Return opens `foot`, Super+D runs `wmenu-run`, Print takes a screenshot with `grim`, there is no bar, and
`/etc/sway/config.d/*` (Fedora's systemd integration) is included. An account replaces it with its own `~/.config/waydesk/config`
(docs/BRING-YOUR-OWN-CONFIG.md). The Debian desktop (bar, launcher, title-bar buttons) is not packaged for Fedora.

## SELinux

Tested 2026-11-05 on Fedora 44 (x86_64) with SELinux **enforcing**: the services and the whole session (sway, foot, swaybar, pipewire) run as
`unconfined_service_t`, because the binaries in `/usr/bin` have no policy of their own. SELinux does not restrict that domain, so there were no
denials (`ausearch -m avc` is empty) and no policy module is needed for the package to work. What is not done is a *confined* policy
(domains for the daemon, the helper and the session workers): a hardening project of its own, not a requirement.

## Repository

`packaging/repo/make-rpm-repo.sh OUTDIR` builds a signed dnf repository from the RPMs in `packaging/out/rpm` (every package is signed with `rpmsign`, a Fedora
container does the signing and `createrepo_c`; `repomd.xml` gets a detached `.asc` made on the Mac; the signatures are checked in a clean rpm database
before it finishes). The key is the one of the apt and Arch repositories (`WAYDESK_REPO_KEY`, `WAYDESK_GNUPGHOME`; a key with a passphrase needs
`WAYDESK_GPG_PASSPHRASE_FILE`, because the container cannot ask). `packaging/repo/publish-rpm.sh OUTDIR` uploads it: dry run first, `--really --key FINGERPRINT`
to publish; it never overwrites or deletes a package, and refuses a rebuild that has the same release number but other contents.

Layout: `RPM-GPG-KEY-waydesk`, `waydesk.repo`, `fedora/<release>/<arch>/` with the packages and `repodata/`. For a user:

```
sudo curl -o /etc/yum.repos.d/waydesk.repo https://waydesk.dev/rpm/waydesk.repo
sudo dnf install waydesk-server
```

The `.repo` file has `gpgcheck=1` and `repo_gpgcheck=1`; dnf asks to import the key on the first run (compare the fingerprint with the one on the site).
Tested 2026-11-05 with a throwaway key: make, publish (dry run, wrong key refused, real, repeated) and `dnf reinstall` from the published repository on Fedora 44.
Not published to waydesk.dev yet.

## Checked

2026-11-04, aarch64, Fedora 43 container (Docker on a Mac): `packaging/rpm/build.sh` builds the RPM and runs the test suite (58 + 2 + 114 passed, 3 ignored);
a clean `dnf install` creates the `waydesk` user and groups, `/etc/waydesk` (root:waydesk 0750) and the certificate; `rpm -V` is clean; `waydesk-admin` runs.

2026-11-05, x86_64, Fedora 44 (a Hetzner server, built natively with `rpmbuild`): `dnf install` of the RPM, `rpm -V` clean, services start, a login over RDP
(FreeRDP through an SSH tunnel) gives a sway session with the openh264 encoder, in SELinux permissive and then enforcing, without denials.

Not checked: Plasma, COSMIC and Hyprland sessions on Fedora, audio, clipboard and GPU paths, Fedora 43 on x86_64, a published repository.
