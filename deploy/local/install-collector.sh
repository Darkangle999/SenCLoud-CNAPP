#!/usr/bin/env bash
# Install the CloudSentinel S3 collector as a *user* systemd service so it
# drains the eBPF S3 queue into the local API continuously and survives logout
# / reboot (via linger). No root needed except the optional linger enable.
#
# Usage:
#   ./deploy/local/install-collector.sh <bucket> [prefix] [region] [api-url] [interval]
set -euo pipefail

BUCKET="${1:?usage: install-collector.sh <bucket> [prefix] [region] [api-url] [interval]}"
PREFIX="${2:-ebpf/}"
REGION="${3:-us-east-1}"
API_URL="${4:-http://localhost:8000}"
INTERVAL="${5:-30}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# Pick an interpreter that actually has boto3 (the daemon needs it).
PYTHON=""
for P in python3 python; do
  if command -v "$P" >/dev/null && "$P" -c 'import boto3' 2>/dev/null; then
    PYTHON="$(command -v "$P")"; break
  fi
done
[ -n "$PYTHON" ] || { echo "no python with boto3 on PATH (pip install boto3)"; exit 1; }

UDIR="$HOME/.config/systemd/user"
CDIR="$HOME/.config/cloudsentinel"
mkdir -p "$UDIR" "$CDIR"

cat > "$CDIR/collector.env" <<EOF
BUCKET=$BUCKET
PREFIX=$PREFIX
REGION=$REGION
API_URL=$API_URL
INTERVAL=$INTERVAL
EOF

sed -e "s|@PYTHON@|$PYTHON|g" -e "s|@REPO@|$REPO|g" \
  "$HERE/cloudsentinel-collector.service" > "$UDIR/cloudsentinel-collector.service"

systemctl --user daemon-reload
systemctl --user enable --now cloudsentinel-collector.service

# Keep the user manager (and thus the collector) running across logout/reboot.
if ! loginctl enable-linger "$USER" 2>/dev/null; then
  echo "note: could not enable linger automatically — run:  sudo loginctl enable-linger $USER"
  echo "      (without it the collector stops when you log out)"
fi

echo "installed (python=$PYTHON)."
echo "status: systemctl --user status cloudsentinel-collector"
echo "logs:   journalctl --user -u cloudsentinel-collector -f"
