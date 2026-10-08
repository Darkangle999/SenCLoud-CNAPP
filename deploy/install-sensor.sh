#!/usr/bin/env bash
# Install + start the CloudSentinel eBPF runtime sensor as a systemd service.
# Run with: sudo ./deploy/install-sensor.sh
set -euo pipefail

UNIT=cloudsentinel-sensor.service
SRC="$(cd "$(dirname "$0")" && pwd)/${UNIT}"
DEST="/etc/systemd/system/${UNIT}"

if [[ $EUID -ne 0 ]]; then
  echo "must run as root: sudo $0" >&2
  exit 1
fi

# Preflight: the things eBPF actually needs.
[[ -f /sys/kernel/btf/vmlinux ]] || { echo "missing kernel BTF (/sys/kernel/btf/vmlinux)"; exit 1; }
command -v clang >/dev/null   || { echo "missing clang (BCC compiles the program at load)"; exit 1; }

echo "installing ${DEST}"
cp "${SRC}" "${DEST}"
systemctl daemon-reload
systemctl enable --now "${UNIT}"
echo "started. follow logs:  journalctl -u ${UNIT} -f"
echo "events appear at:      http://localhost:5173/threats"
