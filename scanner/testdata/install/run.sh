#!/usr/bin/env bash
# Exercises install.sh against a local release directory: it must install a
# correctly signed release with each verifier, and refuse every tampered one.
#
#   testdata/install/run.sh DIST INSTALLER VERSION SIGTOOL
#
# DIST holds secwatch-linux-amd64, SHA256SUMS and SHA256SUMS.minisig signed by
# the key embedded in INSTALLER. Used by CI and by the release workflow.
set -uo pipefail

DIST=$(readlink -f "$1")
INSTALLER=$(readlink -f "$2")
VERSION=$3
SIGN=$(readlink -f "$4")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILED=0

ok() { echo "::notice title=install::$*"; }
bad() {
  echo "::error title=install::$*"
  FAILED=1
}

install_from() { # DIR MODE [extra env...] -> exit code; target in $WORK/bin
  local dir=$1 mode=$2
  shift 2
  rm -rf "$WORK/bin"
  env "$@" SECWATCH_DOWNLOAD_BASE="file://$dir" SECWATCH_INSTALL_DIR="$WORK/bin" \
    SECWATCH_VERIFY="$mode" sh "$INSTALLER" >"$WORK/out.txt" 2>&1
}

copy() { # NAME -> fresh copy of DIST
  rm -rf "$WORK/$1"
  cp -r "$DIST" "$WORK/$1"
  echo "$WORK/$1"
}

for mode in minisign openssl; do
  if [ "$mode" = minisign ] && ! command -v minisign >/dev/null; then
    bad "minisign is not installed; cannot test that verifier"
    continue
  fi
  if install_from "$DIST" "$mode" && [ "$("$WORK/bin/secwatch" version)" = "secwatch $VERSION" ]; then
    ok "$mode: installs a correctly signed release"
  else
    bad "$mode: valid release rejected: $(tr '\n' ' ' <"$WORK/out.txt")"
  fi
  if install_from "$DIST" "$mode" SECWATCH_VERSION="$VERSION"; then
    ok "$mode: pinned version accepted"
  else
    bad "$mode: pinned version rejected: $(tr '\n' ' ' <"$WORK/out.txt")"
  fi

  refuse() { # LABEL DIR [env...]
    local label=$1 dir=$2
    shift 2
    if install_from "$dir" "$mode" "$@" || [ -e "$WORK/bin/secwatch" ]; then
      bad "$mode: accepted $label"
    else
      ok "$mode: refused $label ($(tail -1 "$WORK/out.txt"))"
    fi
  }
  d=$(copy sums)
  echo "0000000000000000000000000000000000000000000000000000000000000000  extra" >>"$d/SHA256SUMS"
  refuse "modified SHA256SUMS" "$d"
  d=$(copy binary)
  printf 'x' >>"$d/secwatch-linux-amd64"
  refuse "modified binary" "$d"
  d=$(copy otherkey)
  "$SIGN" keygen -pub "$WORK/other.pub" -secret "$WORK/other.key" >/dev/null
  SIGTOOL_KEY=$(cat "$WORK/other.key") "$SIGN" sign -in "$d/SHA256SUMS" \
    -comment "secwatch release=$VERSION file=SHA256SUMS"
  refuse "signature by another key" "$d"
  # Same, but with the expected key id written into the signature.
  raw=$(sed -n "s/^KEY_ID_RAW='\(.*\)'$/\1/p" "$INSTALLER")
  python3 - "$d/SHA256SUMS.minisig" "$raw" <<'PY'
import base64, sys
path, raw = sys.argv[1], bytes.fromhex(sys.argv[2])
lines = open(path).read().split("\n")
sig = base64.b64decode(lines[1])
lines[1] = base64.b64encode(sig[:2] + raw + sig[10:]).decode()
open(path, "w").write("\n".join(lines))
PY
  refuse "another key's signature carrying our key id" "$d"
  refuse "a different version than requested" "$DIST" SECWATCH_VERSION=v9.9.9
  d=$(copy nosig)
  rm "$d/SHA256SUMS.minisig"
  refuse "missing signature" "$d"
done

# BusyBox userland (Alpine): no coreutils, OpenSSL from apk.
if command -v docker >/dev/null; then
  if docker run --rm -v "$DIST:/dist:ro" -v "$INSTALLER:/install.sh:ro" alpine:3.22 sh -c \
    "apk add -q --no-cache curl openssl >/dev/null && SECWATCH_DOWNLOAD_BASE=file:///dist \
     SECWATCH_INSTALL_DIR=/opt/bin sh /install.sh && /opt/bin/secwatch version" >"$WORK/out.txt" 2>&1 &&
    grep -qx "secwatch $VERSION" "$WORK/out.txt"; then
    ok "busybox (alpine): installs with openssl"
  else
    bad "busybox (alpine): $(tr '\n' ' ' <"$WORK/out.txt" | cut -c1-600)"
  fi
fi

exit $FAILED
