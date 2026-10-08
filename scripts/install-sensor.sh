#!/usr/bin/env bash
# Install the CloudSentinel eBPF runtime sensor as a systemd service.
# RHEL / Rocky / Amazon Linux 2023 (dnf|yum) and Debian / Ubuntu / Kali (apt).
# Run on the host directly or via SSM (see ssm-deploy.sh).
#
#   sudo ./install-sensor.sh <api-url> [host-id]
#
# The sensor POSTs batched, enriched events to <api-url>/api/internal/runtime-events/batch.
# Set CLOUDSENTINEL_API_KEY in the environment to have it sent as a bearer token.
set -euo pipefail

API_URL="${1:?Usage: install-sensor.sh <api-url> [host-id]}"
HOST_ID="${2:-}"
INSTALL_DIR="${INSTALL_DIR:-/opt/cloudsentinel}"
API_KEY="${CLOUDSENTINEL_API_KEY:-}"

# ── BPF toolchain (package names differ across distros) ─────────────
if command -v dnf &>/dev/null; then PKG=dnf; elif command -v yum &>/dev/null; then PKG=yum
elif command -v apt-get &>/dev/null; then PKG=apt; else echo "no supported package manager" >&2; exit 1; fi

if [ -f /sys/kernel/btf/vmlinux ]; then
  echo "BTF present — CO-RE mode"
  case "$PKG" in
    dnf|yum) "$PKG" install -y bcc bcc-tools python3-bcc ;;
    apt)     apt-get update -y && apt-get install -y bpfcc-tools python3-bpfcc python3-pip ;;
  esac
else
  echo "no BTF — installing kernel headers for the BCC fallback"
  case "$PKG" in
    dnf|yum) "$PKG" install -y bcc bcc-tools python3-bcc "kernel-devel-$(uname -r)" ;;
    apt)     apt-get update -y && apt-get install -y bpfcc-tools python3-bpfcc python3-pip "linux-headers-$(uname -r)" ;;
  esac
fi

# ── sensor code ─────────────────────────────────────────────────────
# The CloudSentinel package is expected at $INSTALL_DIR (git clone / rsync /
# SSM copy). Install it so `python3 -m cloudsentinel.sensor.ebpf_agent` resolves.
if [ ! -f "$INSTALL_DIR/pyproject.toml" ]; then
  echo "ERROR: CloudSentinel code not found at $INSTALL_DIR (sync it there first)" >&2
  exit 1
fi
python3 -m pip install -e "$INSTALL_DIR"

# ── credentials env file (mode 600) ─────────────────────────────────
install -d -m 700 /etc/cloudsentinel
: > /etc/cloudsentinel/sensor.env
chmod 600 /etc/cloudsentinel/sensor.env
[ -n "$API_KEY" ] && echo "CLOUDSENTINEL_API_KEY=${API_KEY}" >> /etc/cloudsentinel/sensor.env

# ── systemd unit ────────────────────────────────────────────────────
HOST_ARG=""
[ -n "$HOST_ID" ] && HOST_ARG="--host-id ${HOST_ID}"

cat > /etc/systemd/system/cloudsentinel-sensor.service <<EOF
[Unit]
Description=CloudSentinel eBPF Runtime Sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/cloudsentinel/sensor.env
ExecStart=/usr/bin/python3 -m cloudsentinel.sensor.ebpf_agent \\
  --api-url ${API_URL} ${HOST_ARG} \\
  --batch-size 50 --batch-ms 500 --learning-ms 300000
WorkingDirectory=${INSTALL_DIR}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
# eBPF without full root: load programs + open perf buffers.
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cloudsentinel-sensor
systemctl restart cloudsentinel-sensor
echo "Sensor installed and started — journalctl -u cloudsentinel-sensor -f"
