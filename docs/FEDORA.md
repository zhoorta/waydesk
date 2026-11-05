# Waydesk on Fedora (RPM)

`waydesk-server` as an RPM: the RDP server, the root helper, the admin tools and the services, with sway sessions (Plasma, COSMIC and Hyprland
optional, as on Arch). The desktop of the Debian packages (shell, launcher, title-bar buttons) is not packaged for Fedora.

Build: `packaging/rpm/build.sh [RELEASE]` (Docker, a Fedora container; output in `packaging/out/rpm/<arch>/`).

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
- OpenH264: Fedora only has it in Cisco's repository (`fedora-cisco-openh264`): the package *recommends* `openh264`. Without it, GPUs encode in hardware and a
  machine without a GPU has no video. The server accepts 2.6 and 2.7 (`/usr/lib64/libopenh264.so.8`).

## SELinux: NOT DONE

Nothing here has been run with SELinux enforcing. The root helper starts per-account session units and the daemon passes file descriptors to
them; expect denials. Until a policy module exists: test in permissive mode (`setenforce 0`), read `ausearch -m avc -ts recent`, and do not
call the package supported on a default Fedora install.

## Checked

2026-11-04, aarch64, Fedora 43 container (Docker on a Mac): `packaging/rpm/build.sh` builds the RPM and runs the test suite (58 + 2 + 114 passed, 3 ignored);
a clean `dnf install` creates the `waydesk` user and groups, `/etc/waydesk` (root:waydesk 0750) and the certificate; `rpm -V` is clean; `waydesk-admin` runs.

Not checked: the services (no systemd in the container), a login and a session, SELinux enforcing, x86_64, a signed repository.
