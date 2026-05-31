#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT/backend"
uv run python - <<'PY'
from app.database import reset_telemetry_data

reset_telemetry_data()
print("OpenSMART IDS and Network Traffic databases reset complete.")
PY
