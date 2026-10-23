#!/usr/bin/env bash
# Runs the real secwatch binary inside real distro images against signed test
# bundles that reference packages present in those images. Used by CI.
#
#   scanner/testdata/integration/run.sh <secwatch-binary> <mkbundle-binary>
set -euo pipefail

BIN=$(readlink -f "$1")
MK=$(readlink -f "$2")
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILED=0

# Entry helpers: a version far above anything real (affected) and far below (fixed).
entries() { # key affected_version fixed_version
  cat <<EOF
{"$1": [
  {"id":"CVE-2099-1001","cve_ids":["CVE-2099-1001"],"status":"fixed","cvss":9.8,"severity":"CRITICAL","kev":true,
   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"$2"}]}],"ref":"https://example.invalid/CVE-2099-1001"},
  {"id":"CVE-2099-1002","cve_ids":["CVE-2099-1002"],"status":"fixed","cvss":5.0,"severity":"MEDIUM",
   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"$3"}]}],"ref":"https://example.invalid/CVE-2099-1002"}
]}
EOF
}

# check NAME IMAGE DISTRO RELEASE KEY PACKAGE AFFECTED FIXED EXPECTED_STATUS [PREP]
check() {
  local name=$1 image=$2 distro=$3 release=$4 key=$5 pkg=$6 affected=$7 fixed=$8 want=$9 prep=${10:-true}
  local dir="$WORK/$name"
  mkdir -p "$dir"
  entries "$pkg" "$affected" "$fixed" > "$dir/entries.json"
  local bundle
  bundle=$("$MK" -distro "$distro" -release "$release" -package-key "$key" -in "$dir/entries.json" -out "$dir")
  local file
  file=$(basename "$bundle")
  echo "::group::$name ($image)"
  set +e
  docker run --rm -v "$BIN:/usr/local/bin/secwatch:ro" -v "$dir:/data:ro" "$image" \
    sh -c "$prep >/dev/null 2>&1; secwatch scan --offline --bundle /data/$file --pubkey /data/key.pub --no-cache --format json" \
    > "$dir/report.json"
  local code=$?
  docker run --rm -v "$BIN:/usr/local/bin/secwatch:ro" -v "$dir:/data:ro" "$image" \
    sh -c "$prep >/dev/null 2>&1; secwatch scan --offline --bundle /data/$file --pubkey /data/key.pub --no-cache"
  set -e
  echo "::endgroup::"
  if msg=$(python3 "$HERE/assert.py" "$dir/report.json" "$code" "$want" "$pkg" 2>&1); then
    echo "::notice title=$name::ok"
  else
    echo "::error title=$name::$(echo "$msg" | tr '\n' ' ' | cut -c1-900)"
    FAILED=1
  fi
}

# Without apt lists (as shipped in images) origin cannot be verified.
check debian12-nolists debian:12 debian 12 source glibc "99:1-1" "0.1-1" POTENTIALLY_AFFECTED
check debian12        debian:12 debian 12 source glibc "99:1-1" "0.1-1" CONFIRMED_AFFECTED "apt-get update"
check debian13        debian:13 debian 13 source glibc "99:1-1" "0.1-1" CONFIRMED_AFFECTED "apt-get update"
check ubuntu2404      ubuntu:24.04 ubuntu 24.04 source glibc "99:1-1" "0.1-1" CONFIRMED_AFFECTED "apt-get update"
check ubuntu2204      ubuntu:22.04 ubuntu 22.04 source glibc "99:1-1" "0.1-1" CONFIRMED_AFFECTED "apt-get update"
check rocky9          rockylinux/rockylinux:9 rocky 9 source glibc "99:1-1" "0:0.1-1" CONFIRMED_AFFECTED
check alma9           almalinux:9 alma 9 binary glibc "99:1-1" "0:0.1-1" CONFIRMED_AFFECTED
check alpine322       alpine:3.22 alpine 3.22 origin musl "999.0-r0" "0.1-r0" CONFIRMED_AFFECTED

# L2, live: fake BaoTa nginx (with OpenSSL compiled in) and PHP owned by root,
# and a redis-server owned by an unprivileged user that must never be executed.
echo "::group::l2 live (debian:12)"
dir="$WORK/l2"
mkdir -p "$dir/out"
echo '{}' > "$dir/distro.json"
cat > "$dir/upstream.json" <<'JSON'
{
 "nginx": [{"id":"CVE-2026-95101","cve_ids":["CVE-2026-95101"],"status":"fixed","cvss":8.2,
   "ranges":[{"type":"UPSTREAM","events":[{"introduced":"1.31.0"},{"fixed":"1.31.7"}]},
             {"type":"UPSTREAM","events":[{"introduced":"1.30.0"},{"fixed":"1.30.6"}]},
             {"type":"UPSTREAM","events":[{"introduced":"1.25.0"},{"limit":"1.30.0"}]}],"ref":"https://example.invalid/n"}],
 "openssl": [{"id":"CVE-2026-0101","cve_ids":["CVE-2026-0101"],"status":"fixed","cvss":7.5,
   "ranges":[{"type":"UPSTREAM","events":[{"introduced":"1.1.1"},{"limit":"3.0.0"}]},
             {"type":"UPSTREAM","events":[{"introduced":"3.0.0"},{"fixed":"3.0.18"}]}],"ref":"https://example.invalid/o"}],
 "php": [{"id":"CVE-2026-109618","cve_ids":["CVE-2026-109618"],"status":"fixed","cvss":9.2,
   "ranges":[{"type":"UPSTREAM","events":[{"introduced":"8.3.0"},{"fixed":"8.3.36"}]}],"ref":"https://example.invalid/p"}]
}
JSON
mapfile -t bundles < <("$MK" -distro debian -release 12 -in "$dir/distro.json" -upstream-in "$dir/upstream.json" -out "$dir")
prep='set -e
mkdir -p /www/server/nginx/sbin /www/server/php/83/bin /usr/local/redis/bin
printf "#!/bin/sh\necho \"nginx version: nginx/1.28.0\" >&2\necho \"built with OpenSSL 1.1.1w  11 Sep 2023\" >&2\n" > /www/server/nginx/sbin/nginx
printf "#!/bin/sh\necho \"PHP 8.3.10 (cli) (NTS)\"\n" > /www/server/php/83/bin/php
printf "#!/bin/sh\ntouch /out/EXECUTED\necho \"Redis server v=7.0.0\"\n" > /usr/local/redis/bin/redis-server
chmod 755 /www/server/nginx/sbin/nginx /www/server/php/83/bin/php /usr/local/redis/bin/redis-server
chown nobody /usr/local/redis/bin/redis-server'
set +e
docker run --rm -v "$BIN:/usr/local/bin/secwatch:ro" -v "$dir:/data:ro" -v "$dir/out:/out" debian:12 sh -c "$prep
secwatch scan --offline --bundle /data/$(basename "${bundles[0]}") --upstream-bundle /data/$(basename "${bundles[1]}") --pubkey /data/key.pub --no-cache --format json > /out/report.json
secwatch scan --offline --bundle /data/$(basename "${bundles[0]}") --upstream-bundle /data/$(basename "${bundles[1]}") --pubkey /data/key.pub --no-cache"
set -e
echo "::endgroup::"
executed=no
[ -e "$dir/out/EXECUTED" ] && executed=yes
if msg=$(python3 "$HERE/assert_l2.py" "$dir/out/report.json" "$executed" 2>&1); then
  echo "::notice title=l2-live::ok"
else
  echo "::error title=l2-live::$(echo "$msg" | tr '\n' ' ' | cut -c1-900)"
  FAILED=1
fi

# Interoperability: a bundle signed by the real minisign CLI (as the server does).
echo "::group::minisign interop"
dir="$WORK/interop"
mkdir -p "$dir"
entries glibc "99:1-1" "0.1-1" > "$dir/entries.json"
bundle=$("$MK" -distro debian -release 12 -package-key source -in "$dir/entries.json" -out "$dir")
file=$(basename "$bundle")
rm -f "$bundle.minisig" "$dir/key.pub"
minisign -G -W -p "$dir/real.pub" -s "$dir/real.key" >/dev/null
kid=$(head -1 "$dir/real.pub" | awk '{print $NF}')
minisign -S -s "$dir/real.key" -m "$bundle" -x "$bundle.minisig" -t "secwatch schema=1 key_id=$kid file=$file" >/dev/null
set +e
docker run --rm -v "$BIN:/usr/local/bin/secwatch:ro" -v "$dir:/data:ro" debian:12 \
  sh -c "apt-get update >/dev/null 2>&1; secwatch scan --offline --bundle /data/$file --pubkey /data/real.pub --no-cache --format json" > "$dir/report.json"
code=$?
set -e
echo "::endgroup::"
if msg=$(python3 "$HERE/assert.py" "$dir/report.json" "$code" CONFIRMED_AFFECTED glibc 2>&1); then
  echo "::notice title=minisign-interop::ok"
else
  echo "::error title=minisign-interop::$(echo "$msg" | tr '\n' ' ' | cut -c1-900)"
  FAILED=1
fi

exit $FAILED
