# Waydesk for Fedora: the RDP server, the root helper, the admin tools and the services. Build it with packaging/rpm/build.sh (a Fedora container).
# The desktop of the Debian packages (waydesk-desktop: shell, launcher, title-bar buttons) is not part of this: a session gets plain sway
# (/usr/share/waydesk/sway-minimal.conf) or, with WAYDESK_COMPOSITOR=hyprland, the account's own Hyprland (docs/HYPRLAND.md).
Name:           waydesk-server
Version:        0.5.0
# A snapshot (a build that is not a release): rpmbuild --define 'snap 20261105git1234567' makes the release 0.20261105git1234567, which sorts before 1 so that the release upgrades it.
Release:        %{?snap:0.%{snap}}%{!?snap:1}%{?dist}
Summary:        RDP server giving each account its own headless Wayland desktop
License:        AGPL-3.0-or-later
URL:            https://waydesk.stackcare.pt
Source0:        %{name}-%{version}.tar.gz
Source1:        waydesk.sysusers
Source2:        waydesk.tmpfiles
Source3:        pam-waydesk-server
Source4:        waydesk-firewalld.xml
ExclusiveArch:  x86_64 aarch64

# Rust: the debuginfo packages of a stripped static-heavy binary are not worth building here
%global debug_package %{nil}
# Not stripped of its build id for nothing: leave the binaries as cargo made them
%global _build_id_links none

BuildRequires:  cargo, rust, gcc, gcc-c++, make, cmake, clang, clang-devel, pkgconf-pkg-config
BuildRequires:  libva-devel, libdrm-devel, mesa-libgbm-devel, libxkbcommon-devel, openssl-devel, pam-devel
BuildRequires:  systemd-rpm-macros

Requires:       acl, sway, foot, pam, polkit, libva, libdrm, mesa-libgbm, mesa-dri-drivers, libxkbcommon, openssl, systemd
Requires:       pipewire, pipewire-pulseaudio, pulseaudio-utils, wireplumber, wl-clipboard
# H.264 in software needs OpenH264 2.6 or 2.7, which Fedora only offers from Cisco's repository (fedora-cisco-openh264, enabled by default on Workstation).
# Without it a GPU encodes in hardware and a machine without a GPU has no video.
Recommends:     openh264
Recommends:     grim, slurp, wmenu
Recommends:     zram-generator-defaults, wireguard-tools, qrencode
Suggests:       plasma-desktop, hyprland, intel-media-driver
%{?systemd_requires}
%{?sysusers_requires_compat}

%description
Accounts log in over RDP with their normal password and get a private, headless sway session that survives disconnects. A small root helper
checks passwords (PAM) and starts the sessions; the network-facing daemon runs as an unprivileged account. KDE Plasma, COSMIC and Hyprland
sessions are optional (docs in %{_docdir}/%{name}). Early software.

%prep
%autosetup -n %{name}-%{version}

%build
export CARGO_TARGET_DIR=target
cargo build --locked --release

%check
export CARGO_TARGET_DIR=target
cargo test --locked --release

%install
install -Dm755 target/release/waydesk-server target/release/waydesk-admin target/release/waydesk-passwd -t %{buildroot}%{_bindir}
install -Dm755 packaging/bin/waydesk-setup-admin %{buildroot}%{_bindir}/waydesk-setup-admin
install -Dm644 packaging/org.waydesk.admin.policy -t %{buildroot}%{_datadir}/polkit-1/actions

# services, and the memory and kernel settings that go with them
install -Dm644 packaging/systemd/waydesk.service packaging/systemd/waydesk-helper.service "packaging/systemd/waydesk-session@.service" \
    packaging/systemd/waydesk-cert-renew.service packaging/systemd/waydesk-cert-renew.timer -t %{buildroot}%{_unitdir}
install -Dm644 packaging/systemd/user-slice/10-waydesk.conf %{buildroot}%{_unitdir}/user-.slice.d/10-waydesk.conf
install -Dm644 packaging/systemd/zram/50-waydesk.conf %{buildroot}%{_prefix}/lib/systemd/zram-generator.conf.d/50-waydesk.conf
install -Dm644 packaging/systemd/sysctl/50-waydesk.conf %{buildroot}%{_sysctldir}/50-waydesk.conf
install -Dm644 packaging/systemd/modules-load/waydesk.conf %{buildroot}%{_prefix}/lib/modules-load.d/waydesk.conf
install -Dm644 %{SOURCE1} %{buildroot}%{_sysusersdir}/waydesk.conf
install -Dm644 %{SOURCE2} %{buildroot}%{_tmpfilesdir}/waydesk.conf

# waydesk-admin access, cert, vpn
install -Dm755 packaging/admin/access packaging/admin/cert packaging/admin/vpn -t %{buildroot}%{_prefix}/lib/waydesk/admin
install -Dm644 packaging/admin/common.sh -t %{buildroot}%{_prefix}/lib/waydesk/admin

# settings and PAM
install -Dm644 packaging/default-waydesk %{buildroot}%{_sysconfdir}/default/waydesk
install -Dm644 %{SOURCE3} %{buildroot}%{_sysconfdir}/pam.d/waydesk-server
install -Dm644 packaging/pam-waydesk-session %{buildroot}%{_sysconfdir}/pam.d/waydesk-session

# sessions: a minimal sway configuration, the blank cursor theme, the Mac keyboard layout, the GPU rules
install -Dm644 packaging/rpm/sway.conf %{buildroot}%{_sysconfdir}/xdg/waydesk/sway.conf
install -Dm644 packaging/sway-minimal.conf %{buildroot}%{_datadir}/waydesk/sway-minimal.conf
install -Dm644 packaging/sway-cosmic.conf %{buildroot}%{_datadir}/waydesk/sway-cosmic.conf
install -Dm644 packaging/sway-plasma.conf %{buildroot}%{_datadir}/waydesk/sway-plasma.conf
install -d %{buildroot}%{_datadir}/icons
cp -a packaging/cursors/waydesk-blank %{buildroot}%{_datadir}/icons/
install -Dm644 packaging/xkb/waydeskmac %{buildroot}%{_sysconfdir}/xkb/symbols/waydeskmac
# Hyprland sessions (Omarchy): see docs/HYPRLAND.md
install -Dm755 packaging/hyprland/bin/omarchy-theme-set-browser-policy packaging/hyprland/bin/omarchy-system-logout \
    packaging/hyprland/bin/omarchy-system-reboot packaging/hyprland/bin/omarchy-system-shutdown packaging/hyprland/bin/hyprshutdown -t %{buildroot}%{_prefix}/lib/waydesk/bin
install -Dm644 packaging/hyprland/waydesk.lua %{buildroot}%{_prefix}/lib/waydesk/hyprland.lua
install -Dm644 packaging/hyprland/starter.lua %{buildroot}%{_datadir}/waydesk/hyprland-starter.lua
install -Dm644 packaging/polkit/50-waydesk-no-power.rules -t %{buildroot}%{_datadir}/polkit-1/rules.d
install -Dm644 packaging/udev/70-waydesk-gpu.rules -t %{buildroot}%{_prefix}/lib/udev/rules.d
install -Dm644 packaging/udev/71-waydesk-hyprland-card.rules -t %{buildroot}%{_datadir}/waydesk/udev

# firewalld: the service exists, nothing opens the port by itself
install -Dm644 %{SOURCE4} %{buildroot}%{_prefix}/lib/firewalld/services/waydesk.xml

install -Dm644 README.md docs/MULTIUSER-DESIGN.md docs/WIREGUARD.md docs/ACCESS.md docs/THREAT-MODEL.md \
    docs/SECURITY-REVIEW.md docs/MEASUREMENTS.md docs/HYPRLAND.md docs/COSMIC.md docs/PLASMA.md docs/FEDORA.md docs/BRING-YOUR-OWN-CONFIG.md docs/REFERENCE.md \
    -t %{buildroot}%{_docdir}/%{name}

%pre
%sysusers_create_compat %{SOURCE1}

%post
systemd-tmpfiles --create waydesk.conf >/dev/null 2>&1 || true
if [ ! -f /etc/waydesk/key.pem ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$(cat /etc/hostname 2>/dev/null || echo waydesk)" \
        -keyout /etc/waydesk/key.pem -out /etc/waydesk/cert.pem >/dev/null 2>&1
    chown waydesk:waydesk /etc/waydesk/key.pem /etc/waydesk/cert.pem
    chmod 600 /etc/waydesk/key.pem
    echo "waydesk: made a self-signed certificate. Check this fingerprint in your RDP client on first connect:"
    openssl x509 -in /etc/waydesk/cert.pem -noout -fingerprint -sha256 | sed 's/^/    /'
fi
# tcp_bbr first, so that the sysctl file may list it; the GPU rule needs no reboot either
modprobe tcp_bbr >/dev/null 2>&1 || true
%{_prefix}/lib/systemd/systemd-sysctl %{_sysctldir}/50-waydesk.conf >/dev/null 2>&1 || true
udevadm control --reload >/dev/null 2>&1 || true
udevadm trigger --subsystem-match=drm --action=change >/dev/null 2>&1 || true
%systemd_post waydesk-helper.service waydesk.service
if [ "$1" -eq 1 ]; then
    cat <<MSG
waydesk: to start it:
    sudo systemctl enable --now waydesk-helper.service waydesk.service
Nobody can log in over RDP yet: members of the group waydesk-users may. Make the first administrator:
    sudo waydesk-setup-admin
The port is closed in firewalld until you add the service: sudo firewall-cmd --add-service=waydesk --permanent && sudo firewall-cmd --reload
Under SELinux read %{_docdir}/%{name}/FEDORA.md first.
Each account's sessions need a sound server: systemctl --user enable --now pipewire.socket pipewire-pulse.socket wireplumber.service
MSG
else
    echo "waydesk: restart the services to use the new version: sudo systemctl restart waydesk-helper.service waydesk.service"
    echo "         (sessions that are running keep the old version until their account logs out of them)"
fi

%preun
%systemd_preun waydesk-helper.service waydesk.service

%postun
%systemd_postun waydesk-helper.service waydesk.service

%files
%license LICENSE
%{_docdir}/%{name}
%config(noreplace) %{_sysconfdir}/xdg/waydesk/sway.conf
%{_bindir}/waydesk-server
%{_bindir}/waydesk-admin
%{_bindir}/waydesk-passwd
%{_bindir}/waydesk-setup-admin
%{_datadir}/polkit-1/actions/org.waydesk.admin.policy
%{_datadir}/polkit-1/rules.d/50-waydesk-no-power.rules
%{_unitdir}/waydesk*.service
%{_unitdir}/waydesk-cert-renew.timer
%{_unitdir}/user-.slice.d/10-waydesk.conf
%{_prefix}/lib/systemd/zram-generator.conf.d/50-waydesk.conf
%{_sysctldir}/50-waydesk.conf
%{_prefix}/lib/modules-load.d/waydesk.conf
%{_sysusersdir}/waydesk.conf
%{_tmpfilesdir}/waydesk.conf
%{_prefix}/lib/waydesk
%{_prefix}/lib/udev/rules.d/70-waydesk-gpu.rules
%{_prefix}/lib/firewalld/services/waydesk.xml
%{_datadir}/waydesk
%{_datadir}/icons/waydesk-blank
%config(noreplace) %{_sysconfdir}/default/waydesk
%config(noreplace) %{_sysconfdir}/pam.d/waydesk-server
%config(noreplace) %{_sysconfdir}/pam.d/waydesk-session
%config(noreplace) %{_sysconfdir}/xkb/symbols/waydeskmac

%changelog
* Wed Nov 04 2026 StackCare <jose@stackcare.pt> - 0.5.0-1
- First RPM
