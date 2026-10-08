#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║   Odineyes v2.0 — Installer                                     ║
# ║   Supports: Arch Linux, Ubuntu/Debian, macOS, RHEL/Fedora       ║
# ║   Never modifies system Python — uses a dedicated venv          ║
# ╚══════════════════════════════════════════════════════════════════╝
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}  →${NC} $1"; }
success() { echo -e "${GREEN}  ✓${NC} $1"; }
warn()    { echo -e "${YELLOW}  ⚠${NC} $1"; }
err()     { echo -e "${RED}  ✗${NC} $1"; exit 1; }
step()    { echo -e "\n${BOLD}[$1]${NC} $2"; }

echo -e "${CYAN}"
echo "  ╔════════════════════════════════════════════════╗"
echo "  ║   🛡  Odineyes v2.0 — Installer                ║"
echo "  ║   Multicloud GRC Security Platform             ║"
echo "  ╚════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Python check ───────────────────────────────────────────
step "1/4" "Checking Python 3.9+..."
command -v python3 &>/dev/null || err "python3 not found"

PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
[ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 9 ] || err "Python 3.9+ required"
success "Python $(python3 --version)"

# ── 2. Create venv ────────────────────────────────────────────
step "2/4" "Creating virtual environment at $VENV_DIR..."

# Clean up any root-owned or stale build artifacts
if [ -d "$SCRIPT_DIR/src/odineyes.egg-info" ]; then
    rm -rf "$SCRIPT_DIR/src/odineyes.egg-info" 2>/dev/null || {
        warn "Cannot remove root-owned egg-info. Trying with chmod..."
        chmod -R u+w "$SCRIPT_DIR/src/odineyes.egg-info" 2>/dev/null
        rm -rf "$SCRIPT_DIR/src/odineyes.egg-info" 2>/dev/null || \
            warn "Please run: sudo rm -rf src/odineyes.egg-info"
    }
fi

if [ -d "$VENV_DIR" ]; then
    warn "Removing existing venv..."
    rm -rf "$VENV_DIR" 2>/dev/null || {
        chmod -R u+w "$VENV_DIR" 2>/dev/null
        rm -rf "$VENV_DIR" 2>/dev/null || \
            err "Cannot remove old venv. Run: sudo rm -rf $VENV_DIR"
    }
fi
python3 -m venv "$VENV_DIR" || err "Failed to create venv (install python3-venv?)"
source "$VENV_DIR/bin/activate"
pip install --upgrade pip --quiet
success "Virtual environment ready"

# ── 3. Install dependencies ───────────────────────────────────
step "3/4" "Installing Odineyes..."

# Always install core (no cloud SDKs — works offline)
pip install -e "$SCRIPT_DIR" --quiet
success "Odineyes core installed"

# Optional cloud SDKs
if [ -t 0 ]; then
    echo ""
    echo "  Cloud Provider SDKs (optional — needed for live scanning):"
    echo "  Skip any you don't need. Core scans work without them (simulated data)."
    echo ""

    read -r -p "  Install AWS SDK (boto3)? [Y/n] " ans
    [[ "${ans,,}" != "n" ]] && {
        pip install boto3 botocore --quiet && success "AWS SDK installed" || warn "AWS SDK failed"
    }

    read -r -p "  Install Azure SDK? [Y/n] " ans
    [[ "${ans,,}" != "n" ]] && {
        pip install azure-identity azure-mgmt-storage azure-mgmt-compute \
                    azure-mgmt-network azure-mgmt-authorization --quiet \
        && success "Azure SDK installed" || warn "Azure SDK failed"
    }

    read -r -p "  Install GCP SDK? [Y/n] " ans
    [[ "${ans,,}" != "n" ]] && {
        pip install google-cloud-storage google-auth google-api-python-client --quiet \
        && success "GCP SDK installed" || warn "GCP SDK failed"
    }
else
    # Non-interactive: install everything
    pip install boto3 botocore --quiet && success "AWS SDK installed" || warn "AWS SDK skipped"
    pip install azure-identity azure-mgmt-storage azure-mgmt-compute \
                azure-mgmt-network azure-mgmt-authorization --quiet \
    && success "Azure SDK installed" || warn "Azure SDK skipped"
    pip install google-cloud-storage google-auth google-api-python-client --quiet \
    && success "GCP SDK installed" || warn "GCP SDK skipped"
fi

# ── 4. Verify installation ────────────────────────────────────
step "4/4" "Verifying installation..."

"$VENV_DIR/bin/odineyes" --version || err "Installation failed — odineyes not callable"
success "odineyes command works"

# ── Done ──────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  ✅ Odineyes v2.0 installed successfully!${NC}"
echo ""
echo -e "${BOLD}  Activate the venv and start scanning:${NC}"
echo ""
echo -e "    ${CYAN}source $VENV_DIR/bin/activate${NC}"
echo -e "    ${CYAN}odineyes --help${NC}"
echo -e "    ${CYAN}odineyes list-checks${NC}"
echo -e "    ${CYAN}odineyes scan --provider aws --compliance CIS --format html${NC}"
echo -e "    ${CYAN}odineyes scan --all-providers --compliance CIS --compliance SOC2${NC}"
echo ""
echo -e "  ${BOLD}Or use make:${NC}"
echo -e "    ${CYAN}make scan${NC}"
echo -e "    ${CYAN}make list${NC}"
echo ""
echo -e "  ${BOLD}Venv path:${NC} ${CYAN}$VENV_DIR${NC}"
echo ""
