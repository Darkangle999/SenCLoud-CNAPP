#!/usr/bin/env bash
# Install a pinned, integrity-verified Trivy and record the installed binary's
# SHA256 so the app refuses to run it if it's ever swapped at runtime
# (supply-chain defense — see src/cloudsentinel/cloud/trivy_scanner.py).
#
# Used by the Dockerfile, and runnable standalone on a bare-metal Ubuntu host:
#   sudo TRIVY_SHA256=<sha> scripts/install-trivy.sh
# then point the service at the recorded hash:
#   export CLOUDSENTINEL_TRIVY_SHA256_FILE=/etc/cloudsentinel/trivy.sha256
#
# Env:
#   TRIVY_VERSION  release to install (default below — bump to the latest)
#   TRIVY_SHA256   sha256 of the Linux tarball, from the release's checksums.txt.
#                  Strict pin (recommended). If unset, the tarball is verified
#                  against the release's own checksums.txt and a warning is shown
#                  (that only catches transit corruption, not a poisoned release).
#   BIN_DIR        install dir            (default /usr/local/bin)
#   SHA_FILE       where to write the hash (default /etc/cloudsentinel/trivy.sha256)
set -euo pipefail

TRIVY_VERSION="${TRIVY_VERSION:-0.72.0}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
SHA_FILE="${SHA_FILE:-/etc/cloudsentinel/trivy.sha256}"

arch="$(dpkg --print-architecture 2>/dev/null || uname -m)"
case "$arch" in
  amd64 | x86_64) asset="Linux-64bit" ;;
  arm64 | aarch64) asset="Linux-ARM64" ;;
  *) echo "install-trivy: unsupported arch '$arch'" >&2; exit 1 ;;
esac

base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
tgz="$(mktemp)"
trap 'rm -f "$tgz"' EXIT
curl -fsSL -o "$tgz" "${base}/trivy_${TRIVY_VERSION}_${asset}.tar.gz"

if [ -n "${TRIVY_SHA256:-}" ]; then
  echo "${TRIVY_SHA256}  ${tgz}" | sha256sum -c -
else
  echo "install-trivy: WARNING — TRIVY_SHA256 not set; verifying against release checksums.txt only" >&2
  sums="$(mktemp)"
  curl -fsSL -o "$sums" "${base}/trivy_${TRIVY_VERSION}_checksums.txt"
  want="$(grep "trivy_${TRIVY_VERSION}_${asset}.tar.gz" "$sums" | awk '{print $1}')"
  rm -f "$sums"
  [ -n "$want" ] || { echo "install-trivy: asset not found in checksums.txt" >&2; exit 1; }
  echo "${want}  ${tgz}" | sha256sum -c -
fi

tar -xzf "$tgz" -C "$BIN_DIR" trivy
mkdir -p "$(dirname "$SHA_FILE")"
sha256sum "${BIN_DIR}/trivy" | awk '{print $1}' > "$SHA_FILE"
"${BIN_DIR}/trivy" --version   # self-check: fails the install if the binary is broken
echo "install-trivy: installed v${TRIVY_VERSION} to ${BIN_DIR}/trivy; runtime pin -> ${SHA_FILE}"
