#!/bin/bash
# check-open.sh [REF]: run it before `git push`. Checks a ref (default: HEAD) without checking it out and fails when it holds a test server
# address from the list below or when a commit message (since origin/main) carries a Claude attribution.
# Keep test servers' addresses out of the tree: use the placeholders SERVER-IP, CLIENT-IP and SITE-HOST.
set -u
ref=${1:-HEAD}
git rev-parse --verify -q "$ref" >/dev/null || { echo "no such ref: $ref"; exit 2; }
bad=0
fail() { echo "FAIL: $*"; bad=1; }
# Add every new test server here (dots written as [.]).
ips=$(git grep -lIE "95[.]216[.]66[.]172|77[.]42[.]21[.]31|5[.]9[.]138[.]21|2[.]29[.]128[.]91|128[.]140[.]64[.]73|91[.]99[.]155[.]107|2[.]28[.]140[.]203" "$ref" -- . ':!scripts/check-open.sh' 2>/dev/null | sed "s/^$ref://")
[ -n "$ips" ] && fail "test server addresses in: $(echo $ips)"
base=$(git rev-parse --verify -q origin/main || echo "$ref")
git log "$base..$ref" --format=%B 2>/dev/null | grep -qi "co-authored-by\|generated with" && fail "an attribution line in a commit message"
[ $bad = 0 ] && echo "$ref is clean"
exit $bad
