#!/bin/sh
# Uploads a repository made by make-rpm-repo.sh to the web server (the folder behind https://waydesk.dev/rpm).
#
#   packaging/repo/publish-rpm.sh REPO-DIR                       dry run: reads from the server and says what it would do
#   packaging/repo/publish-rpm.sh REPO-DIR --really --key FINGERPRINT
#
# --really needs the fingerprint of the key you mean to publish, typed by you; it must be the key in REPO-DIR/RPM-GPG-KEY-waydesk and every repomd.xml.asc must
# verify with it (so that a test key can never be published by accident). Packages were signed by make-rpm-repo.sh, which checked them.
# Environment: WAYDESK_PUBLISH_HOST (required: ssh host or alias), WAYDESK_PUBLISH_RPM_DIR (folder behind /rpm, relative to the ssh account's home; default
# app/rpm), WAYDESK_PUBLISH_RPM_URL (default https://waydesk.dev/rpm, for the final check).
# Order: packages and the key (new files only; nothing already on the server is overwritten or deleted: an old package may still be named by the metadata a client
# has cached), then the repodata files (their names carry a checksum, so they are new files too), then repomd.xml and its .asc of each repository, last and in
# quick succession. Old repodata files stay: they are small, and clients holding an older repomd.xml still need them.
set -eu
SRC=${1:?usage: publish-rpm.sh REPO-DIR [--really --key FINGERPRINT]}
HOST=${WAYDESK_PUBLISH_HOST:?set WAYDESK_PUBLISH_HOST to the ssh host (or alias) of the web server}
DIR=${WAYDESK_PUBLISH_RPM_DIR:-app/rpm}
BASE=${WAYDESK_PUBLISH_RPM_URL:-https://waydesk.dev/rpm}
REAL=""; WANT=""
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --really) REAL=1; shift ;;
        --key) WANT=$(printf '%s' "${2:?--key needs a fingerprint}" | tr -d ' ' | tr a-f A-F); shift 2 ;;
        *) echo "publish-rpm.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
SRC=$(cd "$SRC" && pwd)
[ -f "$SRC/RPM-GPG-KEY-waydesk" ] && ls "$SRC"/fedora/*/*/repodata/repomd.xml.asc >/dev/null 2>&1 || { echo "publish-rpm.sh: $SRC does not look like a repository from make-rpm-repo.sh" >&2; exit 1; }
fp=$(gpg --show-keys --with-colons "$SRC/RPM-GPG-KEY-waydesk" 2>/dev/null | awk -F: '/^fpr/ {print $10; exit}')
echo "key in this repository: ${fp:-unknown}"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
gpg --homedir "$tmp" --batch --import "$SRC/RPM-GPG-KEY-waydesk" 2>/dev/null
gpg --homedir "$tmp" --export > "$tmp/k.gpg"
for a in "$SRC"/fedora/*/*/repodata/repomd.xml.asc; do gpgv --keyring "$tmp/k.gpg" "$a" "${a%.asc}" >/dev/null 2>&1 || { echo "publish-rpm.sh: $a does not verify with RPM-GPG-KEY-waydesk: refusing" >&2; exit 1; }; done
# every package the metadata names must be in REPO-DIR (a repository whose packages were removed after it was made would be published broken)
for r in $(cd "$SRC" && ls -d fedora/*/*); do
    for h in $(gzip -dc "$SRC/$r"/repodata/*-primary.xml.gz | sed -n 's/.*<location href="\([^"]*\)".*/\1/p'); do
        [ -f "$SRC/$r/$h" ] || { echo "publish-rpm.sh: the metadata of $r names $h, which is not in $SRC/$r: run make-rpm-repo.sh again" >&2; exit 1; }
    done
done
if [ -n "$REAL" ] && [ "$WANT" != "$fp" ]; then echo "publish-rpm.sh: --really needs --key $fp (the key you intend to publish, typed by you)" >&2; exit 1; fi
echo "target: $HOST:~/$DIR/   ${REAL:+(for real)}${REAL:-(dry run: nothing is changed)}"
# files by name and checksum: what is on the server and what is here, below fedora/ (the metadata files that are replaced are handled last)
ssh "$HOST" "mkdir -p '$DIR' && cd '$DIR' && find fedora -type f -exec sha256sum {} + 2>/dev/null | sed 's/  / /' | sort -k2" > "$tmp/remote.txt" || true
(cd "$SRC" && find fedora -type f | while read -r f; do printf '%s %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"; done | sort -k2) > "$tmp/local.txt"
notin() { awk 'FILENAME == ARGV[1] { seen[$0]; next } !($0 in seen)' "$2" "$1"; }   # the lines of $1 that are not in $2
notin "$tmp/local.txt" "$tmp/remote.txt" | cut -d' ' -f2- > "$tmp/upload.txt"
grep -v '/repodata/repomd\.xml' "$tmp/upload.txt" > "$tmp/first.txt" || true
grep '/repodata/repomd\.xml' "$tmp/upload.txt" > "$tmp/last.txt" || true
# a package that is on the server under the same name with other contents would be overwritten: that breaks the metadata clients have cached. Refuse.
cut -d' ' -f2- "$tmp/remote.txt" > "$tmp/remote-names.txt"
changed=$(grep '\.rpm$' "$tmp/first.txt" | awk 'FILENAME == ARGV[1] { seen[$0]; next } ($0 in seen)' "$tmp/remote-names.txt" - || true)
if [ -n "$changed" ]; then echo "publish-rpm.sh: these packages exist on the server with other contents (a rebuild with the same release number): raise the release, do not overwrite:" >&2; echo "$changed" | sed 's/^/  ! /' >&2; exit 1; fi
echo "new files: $(wc -l < "$tmp/first.txt" | tr -d ' ')   metadata replaced: $(wc -l < "$tmp/last.txt" | tr -d ' ') (repomd.xml, repomd.xml.asc)"
sed 's/^/  + /' "$tmp/first.txt" | grep -v repodata/ || true
echo "repositories: $(cd "$SRC" && ls -d fedora/*/* | tr '\n' ' '); also RPM-GPG-KEY-waydesk and waydesk.repo"
[ -n "$REAL" ] || { echo "dry run only. Add --really --key $fp to publish."; exit 0; }

# 1. packages, repodata files and the key
{ cat "$tmp/first.txt"; echo RPM-GPG-KEY-waydesk; echo waydesk.repo; } > "$tmp/first-all.txt"
COPYFILE_DISABLE=1 tar --exclude="._*" --exclude=.DS_Store -C "$SRC" -cf - -T "$tmp/first-all.txt" | ssh "$HOST" "cd '$DIR' && tar -xf - && find . -type d -exec chmod 755 {} + && find . -type f -exec chmod 644 {} +"
# 2. what the new metadata names must be on the server before it is switched: check by name and checksum
ssh "$HOST" "cd '$DIR' && find fedora -type f -exec sha256sum {} + | sed 's/  / /' | sort -k2" > "$tmp/remote2.txt"
grep -v '/repodata/repomd\.xml' "$tmp/local.txt" > "$tmp/local-nomd.txt" || true
notin "$tmp/local-nomd.txt" "$tmp/remote2.txt" > "$tmp/missing.txt"
if [ -s "$tmp/missing.txt" ]; then
    echo "publish-rpm.sh: $(wc -l < "$tmp/missing.txt" | tr -d ' ') file(s) are not on the server after the upload. The metadata was NOT switched:" >&2
    sed 's/^/  ! /' "$tmp/missing.txt" >&2; echo "Run it again: it uploads what is missing." >&2; exit 1
fi
# 3. repomd.xml and repomd.xml.asc: each repository's pair is unpacked next to the real ones, then moved in one ssh call
for r in $(cd "$SRC" && ls -d fedora/*/*); do
    ssh "$HOST" "cd '$DIR/$r/repodata' && rm -rf .incoming && mkdir .incoming"
    (cd "$SRC/$r/repodata" && COPYFILE_DISABLE=1 tar --exclude="._*" -cf - repomd.xml repomd.xml.asc) | ssh "$HOST" "cd '$DIR/$r/repodata/.incoming' && tar -xf - && chmod 644 * && cd .. && mv -f .incoming/repomd.xml .incoming/repomd.xml.asc . && rmdir .incoming"
done
# 4. what a client will do: ask the public URL for every file, and check the signature of the served metadata
echo "checking every file at $BASE ..."
(cd "$SRC" && find . -type f | sed 's|^\./||' | sort) | while read -r f; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/$(printf '%s' "$f" | sed 's/+/%2b/g')")
    [ "$code" = 200 ] || echo "  $code $f"
done > "$tmp/bad.txt"
if [ -s "$tmp/bad.txt" ]; then cat "$tmp/bad.txt" >&2; echo "publish-rpm.sh: the files above are not served" >&2; exit 1; fi
for r in $(cd "$SRC" && ls -d fedora/*/*); do
    curl -s "$BASE/$r/repodata/repomd.xml" > "$tmp/m.xml"; curl -s "$BASE/$r/repodata/repomd.xml.asc" > "$tmp/m.asc"
    gpgv --keyring "$tmp/k.gpg" "$tmp/m.asc" "$tmp/m.xml" >/dev/null 2>&1 || { echo "publish-rpm.sh: the served metadata of $r does not verify with the key" >&2; exit 1; }
done
echo "published; every file answers 200 and the served metadata verifies"
