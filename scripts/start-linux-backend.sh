#!/usr/bin/env bash
# Run Odineyes API natively on Linux or WSL.
#
# This deliberately uses .venv-linux rather than .venv: a Windows virtual
# environment cannot run under WSL, even when both systems share the project
# directory. Tetragon/eBPF remains an optional Linux workload sensor and is
# not started by this API launcher.

set -euo pipefail

PORT=8000
BIND_ADDRESS="127.0.0.1"
AWS_PROFILE_NAME="${AWS_PROFILE:-default}"
DATABASE_PATH=""
INSTALL=0
NO_RELOAD=0

usage() {
  cat <<'EOF'
Usage: ./scripts/start-linux-backend.sh [options]

Options:
  --install                    Create the Linux virtual environment and install dependencies.
  --port <port>                API port. Default: 8000.
  --bind <address>             Bind address. Default: 127.0.0.1.
  --aws-profile <profile>      AWS shared-config profile. Default: AWS_PROFILE or default.
  --database <path>            SQLite database path. Default: $XDG_DATA_HOME/odineyes/odineyes.db.
  --no-reload                  Disable Uvicorn auto-reload.
  -h, --help                   Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install) INSTALL=1 ;;
    --port) PORT="${2:?Missing value for --port}"; shift ;;
    --bind) BIND_ADDRESS="${2:?Missing value for --bind}"; shift ;;
    --aws-profile) AWS_PROFILE_NAME="${2:?Missing value for --aws-profile}"; shift ;;
    --database) DATABASE_PATH="${2:?Missing value for --database}"; shift ;;
    --no-reload) NO_RELOAD=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$PROJECT_ROOT/.venv-linux"
PYTHON="$VENV/bin/python"

if [[ ! -x "$PYTHON" ]]; then
  if [[ "$INSTALL" != "1" ]]; then
    echo "Linux virtual environment missing. Re-run with --install." >&2
    exit 1
  fi
  command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 1; }
  python3 -m venv "$VENV"
fi

if [[ "$INSTALL" == "1" ]]; then
  "$PYTHON" -m pip install --upgrade pip
  "$PYTHON" -m pip install -e "$PROJECT_ROOT[aws,db,dev]"
fi

if [[ -z "$DATABASE_PATH" ]]; then
  DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
  DATABASE_PATH="$DATA_HOME/odineyes/odineyes.db"
fi

mkdir -p "$(dirname "$DATABASE_PATH")"
DATABASE_PATH="$(cd "$(dirname "$DATABASE_PATH")" && pwd)/$(basename "$DATABASE_PATH")"

export ODINEYES_DATABASE_URL="sqlite:///$DATABASE_PATH"
export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export AWS_SDK_LOAD_CONFIG=1

# Deployment settings that carry a secret (the onboarding token signing key)
# live in a gitignored .env.local rather than in this tracked script. Already
# exported values win, so CI and container runs are unaffected.
if [[ -f "$PROJECT_ROOT/.env.local" ]]; then
  while IFS= read -r line; do
    [[ -z "${line// }" || "${line#\#}" != "$line" ]] && continue
    name="${line%%=*}"
    value="${line#*=}"
    [[ -z "$name" || "$name" == "$line" ]] && continue
    if [[ -z "${!name:-}" ]]; then
      export "$name=${value%\"}"
    fi
  done < "$PROJECT_ROOT/.env.local"
  echo "Loaded $PROJECT_ROOT/.env.local"
fi

if [[ -n "$AWS_PROFILE_NAME" ]]; then
  export AWS_PROFILE="$AWS_PROFILE_NAME"
fi

cd "$PROJECT_ROOT"
ARGS=(-m uvicorn odineyes.api.server:app --host "$BIND_ADDRESS" --port "$PORT")
if [[ "$NO_RELOAD" != "1" ]]; then
  ARGS+=(--reload)
fi

echo "Odineyes API: http://$BIND_ADDRESS:$PORT"
echo "SQLite DB: $DATABASE_PATH"
echo "AWS profile: ${AWS_PROFILE:-not set}"
exec "$PYTHON" "${ARGS[@]}"
