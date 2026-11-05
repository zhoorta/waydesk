#!/bin/sh
# Builds the RPM from the committed tree, in a Fedora container (Docker). Output: packaging/out/rpm/<arch>/waydesk-server-<version>-<rel>.<dist>.<arch>.rpm
#   [WAYDESK_WORKTREE=1] packaging/rpm/build.sh [FEDORA_RELEASE]     default 43. The architecture is the one of the Docker host (arm64 Macs make aarch64 packages).
set -e
cd "$(dirname "$0")/../.."
rel=${1:-43}
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
out=packaging/out/rpm
mkdir -p "$out"
if [ -n "$WAYDESK_WORKTREE" ]; then
    # the working tree as it is (to test uncommitted changes); a release is built from the commit
    tar --exclude=./target --exclude=./site --exclude=./branding --exclude=./packaging/out --exclude=./.git -czf "$out/.tree.tgz" .
    rm -rf "$out/.tree" && mkdir -p "$out/.tree/waydesk-server-$ver" && tar -xzf "$out/.tree.tgz" -C "$out/.tree/waydesk-server-$ver"
    tar -czf "$out/waydesk-server-$ver.tar.gz" -C "$out/.tree" "waydesk-server-$ver" && rm -rf "$out/.tree" "$out/.tree.tgz"
else
    git archive --format=tar.gz --prefix="waydesk-server-$ver/" -o "$out/waydesk-server-$ver.tar.gz" HEAD -- . ':(exclude)site' ':(exclude)branding' ':(exclude)packaging/out'
fi
docker run --rm -v "$PWD/$out:/out" -v "$PWD/packaging/rpm:/rpm:ro" "fedora:$rel" sh -ec '
  dnf -y install rpm-build rpmdevtools dnf-plugins-core gcc gcc-c++ make cmake clang clang-devel pkgconf-pkg-config cargo rust \
      libva-devel libdrm-devel mesa-libgbm-devel libxkbcommon-devel openssl-devel pam-devel systemd-rpm-macros perl-FindBin perl-IPC-Cmd
  rpmdev-setuptree
  cp /out/waydesk-server-*.tar.gz /rpm/waydesk.sysusers /rpm/waydesk.tmpfiles /rpm/pam-waydesk-server /rpm/waydesk-firewalld.xml ~/rpmbuild/SOURCES/
  cp /rpm/waydesk-server.spec ~/rpmbuild/SPECS/
  rpmbuild -ba ~/rpmbuild/SPECS/waydesk-server.spec
  mkdir -p /out/$(uname -m) && cp ~/rpmbuild/RPMS/*/*.rpm ~/rpmbuild/SRPMS/*.rpm /out/$(uname -m)/
'
ls "$out"/*/*.rpm
