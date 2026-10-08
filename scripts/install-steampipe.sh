#!/usr/bin/env bash
# Install the compliance scoring stack: Steampipe (AWS data via Postgres FDW) +
# the AWS plugin + Powerpipe (runs the benchmarks) + the aws-compliance mod.
# Records each binary's SHA256 so a swapped binary is detectable (supply-chain
# defense — same posture as install-trivy.sh).
#
# As of aws-compliance v1.13.0 the benchmarks are Powerpipe mods (mod.pp) and
# `steampipe check` is deprecated, so the runner drives `powerpipe benchmark run`
# against a running steampipe service. See src/cloudsentinel/core/steampipe_runner.py.
# Linux only; runnable standalone on Ubuntu or via the Dockerfile.
#
# Binary installs need root (write BIN_DIR); the steampipe plugin/mod and the
# service must run as the *unprivileged* runtime user (steampipe refuses root),
# so run under sudo and the script drops to $SUDO_USER for those steps.
#
# Env:
#   STEAMPIPE_VERSION   release to install (default below)
#   POWERPIPE_VERSION   release to install (default below)
#   AWS_PLUGIN_VERSION  steampipe-plugin-aws version (mod v1.13.0 wants >=1.28.0)
#   COMPLIANCE_MOD_VERSION  steampipe-mod-aws-compliance tag (default 1.13.0)
#   STEAMPIPE_SHA256 / POWERPIPE_SHA256  sha256 of the linux tarball — strict pin
#                       (recommended). Unset -> warn only.
#   BIN_DIR   install dir              (default /usr/local/bin)
#   SHA_DIR   where to write hashes    (default /etc/cloudsentinel)
#   MOD_DIR   where the mod is cloned; runner runs `powerpipe benchmark run` here
#             (default /opt/steampipe/aws-compliance — match CLOUDSENTINEL_STEAMPIPE_MOD_DIR)
set -euo pipefail

STEAMPIPE_VERSION="${STEAMPIPE_VERSION:-0.24.2}"
POWERPIPE_VERSION="${POWERPIPE_VERSION:-1.5.2}"
AWS_PLUGIN_VERSION="${AWS_PLUGIN_VERSION:-1.28.0}"
COMPLIANCE_MOD_VERSION="${COMPLIANCE_MOD_VERSION:-1.13.0}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
SHA_DIR="${SHA_DIR:-/etc/cloudsentinel}"
MOD_DIR="${MOD_DIR:-/opt/steampipe/aws-compliance}"

arch="$(dpkg --print-architecture 2>/dev/null || uname -m)"
case "$arch" in
  amd64 | x86_64) sp_asset="linux_amd64"; pp_asset="linux.amd64" ;;
  arm64 | aarch64) sp_asset="linux_arm64"; pp_asset="linux.arm64" ;;
  *) echo "install-steampipe: unsupported arch '$arch'" >&2; exit 1 ;;
esac

mkdir -p "$SHA_DIR"

# fetch_verify_extract <url> <expected_sha-or-empty> <member> <label>
fetch_verify_extract() {
  local url="$1" want="$2" member="$3" label="$4" tgz
  tgz="$(mktemp)"
  curl -fsSL -o "$tgz" "$url"
  if [ -n "$want" ]; then
    echo "${want}  ${tgz}" | sha256sum -c -
  else
    echo "install-steampipe: WARNING — ${label}_SHA256 not set; integrity not pinned." >&2
  fi
  tar -xzf "$tgz" -C "$BIN_DIR" --overwrite "$member"
  sha256sum "${BIN_DIR}/${member}" | awk '{print $1}' > "${SHA_DIR}/${member}.sha256"
  rm -f "$tgz"
}

fetch_verify_extract \
  "https://github.com/turbot/steampipe/releases/download/v${STEAMPIPE_VERSION}/steampipe_${sp_asset}.tar.gz" \
  "${STEAMPIPE_SHA256:-}" steampipe STEAMPIPE
fetch_verify_extract \
  "https://github.com/turbot/powerpipe/releases/download/v${POWERPIPE_VERSION}/powerpipe.${pp_asset}.tar.gz" \
  "${POWERPIPE_SHA256:-}" powerpipe POWERPIPE

# Steampipe REFUSES to run as root (even --version, plugin install, service).
# Binary writes above needed root; every steampipe invocation now drops to the
# runtime user: SUDO_USER under sudo, else the current user.
run_user="${SUDO_USER:-$(id -un)}"
run_as() {
  if [ "$run_user" = "$(id -un)" ]; then
    "$@"
  elif command -v runuser >/dev/null 2>&1; then
    runuser -u "$run_user" -- "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "$run_user" "$@"
  else
    echo "install-steampipe: need runuser or sudo to switch to ${run_user}" >&2
    exit 1
  fi
}

run_as "${BIN_DIR}/steampipe" --version    # self-checks (fail install if broken)
"${BIN_DIR}/powerpipe" --version           # powerpipe tolerates root

# Plugin install auto-generates ~/.steampipe/config/aws.spc (default credential
# chain + AWS_REGION at runtime) — no hand-written config needed.
run_as "${BIN_DIR}/steampipe" plugin install "aws@${AWS_PLUGIN_VERSION}"

# Install the compliance mod by cloning it straight into MOD_DIR; the runner runs
# `powerpipe benchmark run` from here against this local mod. Simpler than
# `steampipe mod install` (resolves a dependency mod file, rejects some tag
# formats, deprecated).
mod_parent="$(dirname "$MOD_DIR")"
mkdir -p "$mod_parent"
chown "$run_user" "$mod_parent"   # so the runtime user owns the clone
run_as rm -rf "$MOD_DIR"
run_as git clone --depth 1 --branch "v${COMPLIANCE_MOD_VERSION}" \
  https://github.com/turbot/steampipe-mod-aws-compliance.git "$MOD_DIR"

echo "install-steampipe: steampipe v${STEAMPIPE_VERSION} + powerpipe v${POWERPIPE_VERSION} + aws@${AWS_PLUGIN_VERSION} + aws-compliance v${COMPLIANCE_MOD_VERSION}"
echo "install-steampipe: binary pins -> ${SHA_DIR}/{steampipe,powerpipe}.sha256; mod dir -> ${MOD_DIR}"
echo "install-steampipe: at runtime the backend user runs 'steampipe service start' (handled by steampipe_runner)."
