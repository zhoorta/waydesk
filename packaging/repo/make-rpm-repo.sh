#!/bin/sh
# Builds a signed dnf repository from the RPMs in packaging/out/rpm (packaging/rpm/build.sh makes them; docs/FEDORA.md).
#
#   packaging/repo/make-rpm-repo.sh OUTDIR
#
# Needs: Docker (a Fedora container with createrepo_c, rpm-sign and gpg: the Mac has none of them), gpg.
# Environment: WAYDESK_REPO_KEY  id of the signing key (required; the key of the apt and Arch repositories). WAYDESK_GNUPGHOME: its keyring (default ~/.gnupg).
# WAYDESK_GPG_PASSPHRASE_FILE: a file with the key's passphrase, used for the packages (the container has no way to ask) and for the metadata (a key without a passphrase needs nothing). Make the
# file for the run and delete it after (chmod 600; it is mounted read-only into the container, and the key ring is copied to a temporary folder that is removed).
# WAYDESK_RPM_URL: where the repository will be served (default https://waydesk.dev/rpm), written into waydesk.repo.
# Layout of OUTDIR (serve it as it is, any static web server): RPM-GPG-KEY-waydesk (public key, armored), waydesk.repo (for /etc/yum.repos.d),
# fedora/<release>/<arch>/<package>.rpm and fedora/<release>/<arch>/repodata/ (repomd.xml and repomd.xml.asc: dnf checks both, gpgcheck and repo_gpgcheck).
# <release> is read from the package's dist tag (fc44 -> 44), <arch> from its file name. Packages: every .rpm in packaging/out/rpm except the source and
# debug ones. Every package is signed here (rpmsign) and the signatures are checked against the exported key before this finishes.
# Order: make-rpm-repo.sh, then publish-rpm.sh.
set -eu
OUT=${1:?usage: make-rpm-repo.sh OUTDIR}
KEY=${WAYDESK_REPO_KEY:?set WAYDESK_REPO_KEY to the id of the signing key}
export GNUPGHOME=${WAYDESK_GNUPGHOME:-$HOME/.gnupg}
URL=${WAYDESK_RPM_URL:-https://waydesk.dev/rpm}
cd "$(dirname "$0")/../.."
SRC="$PWD/packaging/out/rpm"
OUT=$(mkdir -p "$OUT" && cd "$OUT" && pwd)
gpg --list-secret-keys "$KEY" >/dev/null 2>&1 || { echo "make-rpm-repo.sh: the secret key $KEY is not in $GNUPGHOME" >&2; exit 1; }
FPR=$(gpg --with-colons --fingerprint "$KEY" | awk -F: '/^fpr/ {print $10; exit}')
list=""
for f in "$SRC"/*/*.rpm; do
    [ -f "$f" ] || continue
    case "$f" in *.src.rpm|*-debuginfo-*|*-debugsource-*) continue ;; esac
    list="$list $f"
done
[ -n "$list" ] || { echo "make-rpm-repo.sh: no packages in $SRC" >&2; exit 1; }
# packages already signed with this key in OUT (put the published ones there first: curl them from the server) are kept as they are: signing again changes
# the bytes (the signature carries a time), and a published package must never change
old=$(mktemp -d); [ -d "$OUT/fedora" ] && find "$OUT/fedora" -name '*.rpm' -exec cp {} "$old/" \;
rm -rf "$OUT/fedora" "$OUT/RPM-GPG-KEY-waydesk" "$OUT/waydesk.repo"
for f in $list; do
    b=$(basename "$f")
    rel=$(printf '%s' "$b" | sed -n 's/.*\.fc\([0-9][0-9]*\)\.[^.]*\.rpm$/\1/p')
    arch=$(printf '%s' "$b" | sed -n 's/.*\.\([A-Za-z0-9_]*\)\.rpm$/\1/p')
    [ -n "$rel" ] && [ -n "$arch" ] || { echo "make-rpm-repo.sh: cannot read the release and architecture of $b" >&2; exit 1; }
    mkdir -p "$OUT/fedora/$rel/$arch"
    if [ -f "$old/$b" ]; then cp "$old/$b" "$OUT/fedora/$rel/$arch/$b"; else cp "$f" "$OUT/fedora/$rel/$arch/$b"; fi
done
gpg --armor --export "$KEY" > "$OUT/RPM-GPG-KEY-waydesk"

# signing and indexing in a Fedora container. The key ring is copied (not mounted: gpg-agent sockets in it, and the container must not change it)
job=$(mktemp -d); trap 'rm -rf "$job"' EXIT
mkdir "$job/gnupg" && chmod 700 "$job/gnupg"
for x in private-keys-v1.d pubring.kbx trustdb.gpg; do [ -e "$GNUPGHOME/$x" ] && cp -R "$GNUPGHOME/$x" "$job/gnupg/"; done
PASSMOUNT=""; EXTRA=""
if [ -n "${WAYDESK_GPG_PASSPHRASE_FILE:-}" ]; then
    cp "$WAYDESK_GPG_PASSPHRASE_FILE" "$job/pass" && chmod 600 "$job/pass"
    EXTRA="--batch --pinentry-mode loopback --passphrase-file /job/pass"
else
    EXTRA="--batch --pinentry-mode loopback --passphrase-file /dev/null"
fi
cat > "$job/run.sh" <<'EOF'
set -eu
dnf -y -q install createrepo_c rpm-sign gnupg2 rpm >/dev/null
export GNUPGHOME=/job/gnupg
echo allow-loopback-pinentry > /job/gnupg/gpg-agent.conf
cat > /root/.rpmmacros <<MAC
%_gpg_name $FPR
%_gpg_sign_cmd_extra_args $EXTRA
MAC
rpm --dbpath /tmp/db --import /r/RPM-GPG-KEY-waydesk
# a package that already verifies with the key is left alone
find /r/fedora -name '*.rpm' | sort | while read -r f; do
    case "$(rpm --dbpath /tmp/db -K "$f")" in *"digests signatures OK"*) echo "  kept $(basename "$f")" ;; *) rpmsign --addsign "$f" >/dev/null ;; esac
done
for d in /r/fedora/*/*; do createrepo_c -q --general-compress-type gz "$d"; done
# the signatures must verify with the exported public key, in a clean rpm database
bad=0
for f in $(find /r/fedora -name '*.rpm' | sort); do
    out=$(rpm --dbpath /tmp/db -K "$f") || bad=1
    echo "  $out"
    case "$out" in *"digests signatures OK"*) ;; *) bad=1 ;; esac
done
[ $bad = 0 ]
chown -R "$OWNER" /r
EOF
docker run --rm -e FPR="$FPR" -e EXTRA="$EXTRA" -e OWNER="$(id -u):$(id -g)" -v "$job:/job" -v "$OUT:/r" fedora:44 sh /job/run.sh
# the metadata is signed on this machine (pinentry works here): dnf's repo_gpgcheck asks for repomd.xml.asc
HOSTPASS=""
[ -n "${WAYDESK_GPG_PASSPHRASE_FILE:-}" ] && HOSTPASS="--pinentry-mode loopback --passphrase-file $WAYDESK_GPG_PASSPHRASE_FILE"
for m in "$OUT"/fedora/*/*/repodata/repomd.xml; do
    # shellcheck disable=SC2086
    gpg --batch --yes $HOSTPASS -u "$KEY" --detach-sign --armor -o "$m.asc" "$m"
    gpg --batch --verify "$m.asc" "$m" 2>/dev/null || { echo "make-rpm-repo.sh: $m.asc does not verify" >&2; exit 1; }
done
cat > "$OUT/waydesk.repo" <<EOF
[waydesk]
name=Waydesk
baseurl=$URL/fedora/\$releasever/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$URL/RPM-GPG-KEY-waydesk
EOF
rm -rf "$old"
find "$OUT" -name '._*' -delete
echo "made $OUT (key $FPR)"
( cd "$OUT" && find . -type f | sort | sed 's|^\./||' | grep -v "repodata/.*\(primary\|filelists\|other\)" | sed 's/^/  /' )
