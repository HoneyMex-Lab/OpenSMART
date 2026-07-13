#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_STATUS="not checked"
FRONTEND_STATUS="not checked"
BACKEND_PID=""
COMMAND=""
HOST_EXPLICIT=0
PORT_EXPLICIT=0
PROD_EXPLICIT=0
BACKEND_LOG=""
BACKEND_PYTHON="3.13"
BIND_HOST="0.0.0.0"
BIND_PORT="8000"
PROD_MODE=0
STATE_FILE="${ROOT_DIR}/logs/run_app.state"
# How this script refers to itself in user-facing "run ... to do X" messages.
# opensmart.sh (a wrapper around this script) overrides this to "./opensmart.sh"
# when it invokes run_app.sh, so messages stay consistent with whichever
# entrypoint the operator actually used, instead of always naming this script.
RUN_APP_INVOKE_AS="${RUN_APP_INVOKE_AS:-./opensmart/scripts/run_app.sh}"
FIRST_RUN_MARKER="OpenSMART initial admin account created"
APP_VERSION="${OPENSMART_VERSION:-v0.3 beta}"
DB_PATH="${ROOT_DIR}/backend/opensmart.db"
NETWORK_IDS_DB_PATH="${ROOT_DIR}/backend/opensmart_network_ids.db"
NETWORK_TRAFFIC_DB_PATH="${ROOT_DIR}/backend/opensmart_network_traffic.db"

# Expected tables for schema validation (sorted).
# SYNC: must match the table list in backend/app/database.py init_db().
EXPECTED_TABLES=(
  audit_events
  login_attempts
  modules
  opensmart_modules
  resource_snapshots
  sessions
  settings
  users
)

# ── Helpers ───────────────────────────────────────────────────────────────────

usage() {
  cat <<'EOF'
Usage: ./scripts/run_app.sh <command> [options]

Commands:
  start                   Start OpenSMART.
  stop                    Stop a running instance started by this script.
  status                  Show whether OpenSMART is running and healthy.
  restart                 Stop (if running) and start again, reusing the previous
                          --host/--port/--prod unless overridden.
  reset-admin-password    Reset the admin password and print it. Does not start the app.
  reset-data-all          Delete all IDS and network traffic data; keep config and users. Does not start the app.
  reset-data-ids          Delete only IDS alert data; preserve network traffic data. Does not start the app.
  reset-data-network      Delete only network traffic data; preserve IDS alert data. Does not start the app.
  reset-all               Full reset: delete the entire database and reinitialize. Does not start the app.
  health                  Run health checks and print a pass/fail summary. Does not start the app.

Options (start/restart only):
  --host HOST             Address for the backend to bind to (default: 0.0.0.0).
  --port PORT             Port for the backend to bind to (default: 8000).
  --prod                  Production mode: build the frontend once and serve it from the
                          backend on a single port instead of running the Vite dev server,
                          and skip the interactive first-run password prompt.

  --help, -h              Show this help message.
EOF
}

print_banner() {
  local build
  build="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
  local ver="$APP_VERSION"
  # Fixed inner width of 42 chars (between the ║ borders)
  local w=42
  local blank="║$(printf '%*s' $w '')║"
  printf '\n'
  printf '  ╔%s╗\n' "$(printf '%0.s═' $(seq 1 $w))"
  printf '  %s\n' "$blank"
  printf '  ║  %-*s║\n' $(( w - 2 )) 'OpenSMART'
  printf '  ║  %-*s║\n' $(( w - 2 )) 'Network Security Operations'
  printf '  %s\n' "$blank"
  printf '  ║  %-*s║\n' $(( w - 2 )) "Version : ${ver}"
  printf '  ║  %-*s║\n' $(( w - 2 )) "Build   : ${build}"
  printf '  %s\n' "$blank"
  printf '  ╚%s╝\n' "$(printf '%0.s═' $(seq 1 $w))"
  printf '\n'
  printf '  Dev Team:\n'
  printf '  Mizton Labs & Honeynet Mexico Team\n'
  printf '  Javier Santillan (core dev)\n'
  printf '  2026\n'
  printf '\n'
  printf '      _   _   _   _\n'
  printf '     / \_/ \_/ \_/ \\\n'
  printf '     \_/ \_/ \_/ \_/\n'
  printf '     / \_/ \_/ \_/ \\\n'
  printf '     \_/ \_/ \_/ \_/\n'
  printf '\n'
}

print_password_box() {
  local title="$1"
  local username="$2"
  local password="$3"
  local footer="${4:-Save this password now. It will not be shown again.}"
  local line1="  Username : ${username}"
  local line2="  Password : ${password}"
  local line3="  ${footer}"
  local width=60
  for s in "$title" "$line1" "$line2" "$line3"; do
    local len=$(( ${#s} + 4 ))
    if (( len > width )); then width=$len; fi
  done
  local border
  border="$(printf '%0.s*' $(seq 1 $width))"
  printf '\n%s\n' "$border"
  printf '*%*s*\n' $(( width - 2 )) ''
  printf '*  %-*s*\n' $(( width - 4 )) "$title"
  printf '*%*s*\n' $(( width - 2 )) ''
  printf '*  %-*s*\n' $(( width - 4 )) "$line1"
  printf '*  %-*s*\n' $(( width - 4 )) "$line2"
  printf '*%*s*\n' $(( width - 2 )) ''
  printf '*  %-*s*\n' $(( width - 4 )) "$footer"
  printf '*%*s*\n' $(( width - 2 )) ''
  printf '%s\n\n' "$border"
}

print_summary() {
  printf '\nDependency summary:\n'
  printf 'Backend: %s\n' "$BACKEND_STATUS"
  printf 'Frontend: %s\n' "$FRONTEND_STATUS"
}

cleanup() {
  # Only touch the state file if THIS invocation actually started a backend
  # (BACKEND_PID is set once `start` confirms it's alive). Every invocation
  # of this script — including read-only `status`/`stop`/`health` calls —
  # goes through this same EXIT trap, so an unconditional rm here would wipe
  # out a *different*, still-running instance's state file.
  if [[ -n "$BACKEND_PID" ]]; then
    if kill -0 "$BACKEND_PID" 2>/dev/null; then
      kill "$BACKEND_PID" 2>/dev/null || true
      wait "$BACKEND_PID" 2>/dev/null || true
    fi
    rm -f "$STATE_FILE"
  fi
}

# ── start/stop/status state file ──────────────────────────────────────────────
#
# Tracks the backend PID plus the bind host/port/mode of the running instance,
# so a later, separate invocation of `stop`/`status`/`restart` can find and
# act on it (e.g. `docker exec <container> ./scripts/run_app.sh status`).

_state_get() {
  local key="$1"
  # Always exits 0: "no state file" / "key not found" are expected, not
  # errors — an unprotected non-zero here would trip `set -e` in the caller.
  [[ -f "$STATE_FILE" ]] || return 0
  grep "^${key}=" "$STATE_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true
}

_state_write() {
  mkdir -p "$(dirname "$STATE_FILE")"
  {
    printf 'PID=%s\n' "$BACKEND_PID"
    printf 'HOST=%s\n' "$BIND_HOST"
    printf 'PORT=%s\n' "$BIND_PORT"
    printf 'PROD=%s\n' "$PROD_MODE"
  } > "$STATE_FILE"
}

cmd_stop() {
  local pid
  pid="$(_state_get PID)"
  if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
    printf 'OpenSMART is not running.\n'
    rm -f "$STATE_FILE"
    return 0
  fi
  printf 'Stopping OpenSMART (pid %s)...\n' "$pid"
  kill -TERM "$pid" 2>/dev/null || true
  local waited=0
  while kill -0 "$pid" 2>/dev/null && (( waited < 15 )); do
    sleep 1
    waited=$(( waited + 1 ))
  done
  if kill -0 "$pid" 2>/dev/null; then
    printf 'Did not stop within 15s; sending SIGKILL.\n' >&2
    kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f "$STATE_FILE"
  printf 'Stopped.\n'
}

cmd_status() {
  local pid host port
  pid="$(_state_get PID)"
  if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
    printf 'Status : not running\n'
    return 0
  fi
  host="$(_state_get HOST)"
  port="$(_state_get PORT)"
  printf 'Status : running (pid %s)\n' "$pid"
  printf 'Bind   : %s:%s\n' "$host" "$port"
  if curl -sf --max-time 3 "http://localhost:${port}/api/health" 2>/dev/null | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
    printf 'Health : healthy (http://%s:%s/api/health)\n' "$host" "$port"
  else
    printf 'Health : unreachable\n'
  fi
}

require_command() {
  local command_name="$1"
  local install_hint="$2"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$command_name" >&2
    printf '%s\n' "$install_hint" >&2
    return 1
  fi
}

# Append a log entry to opensmart.log using the same format as the Python FileHandler:
#   timestamp LEVEL logger_name message
# source=run_script is embedded in the message so entries are grep-able.
# Silently skips if the log directory does not exist yet.
_log() {
  local level="${1:-INFO}"
  local msg="$2"
  local log_file="${ROOT_DIR}/logs/opensmart.log"
  local ts
  ts="$(date -u '+%Y-%m-%d %H:%M:%S,%3N' 2>/dev/null || date -u '+%Y-%m-%d %H:%M:%S,000')"
  if [[ -d "${ROOT_DIR}/logs" ]]; then
    printf '%s %s run_app_script source=run_script %s\n' "$ts" "$level" "$msg" >> "$log_file" 2>/dev/null || true
  fi
}

# Print a step description before executing it in reset blocks.
_step() {
  printf '  -> %s\n' "$*"
}

admin_account_missing() {
  if [[ ! -f "$DB_PATH" ]]; then
    return 0
  fi
  if ! command -v sqlite3 >/dev/null 2>&1; then
    return 1
  fi
  local count
  count="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users WHERE username='admin' AND role='admin';" 2>/dev/null || printf '')"
  [[ "$count" != "1" ]]
}

extract_initial_password() {
  if [[ ! -f "$BACKEND_LOG" ]]; then
    return 0
  fi
  sed -n 's/^Password: //p' "$BACKEND_LOG" | tail -n 1
}

wait_for_initial_password() {
  local timeout_seconds="${1:-30}"
  local waited=0
  while (( waited < timeout_seconds )); do
    if [[ -f "$BACKEND_LOG" ]] && grep -q "$FIRST_RUN_MARKER" "$BACKEND_LOG"; then
      return 0
    fi
    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
      return 1
    fi
    sleep 1
    waited=$(( waited + 1 ))
  done
  return 1
}

# ── Health check function ─────────────────────────────────────────────────────
# Usage: run_health_checks <full|prestart>
#   full     — all checks, prints every result, exits 0/1
#   prestart — critical checks only, prints failures only, returns exit code
run_health_checks() {
  local mode="${1:-full}"
  local _pass=0
  local _fail=0
  local _skip=0

  _hcheck() {
    # _hcheck <label> <ok|fail|skip> [detail] [critical:0|1]
    local label="$1"
    local result="$2"
    local detail="${3:-}"
    local critical="${4:-1}"
    case "$result" in
      ok)
        (( _pass++ )) || true
        if [[ "$mode" == "full" ]]; then
          printf '  [PASS] %s%s\n' "$label" "${detail:+  ($detail)}"
        fi
        ;;
      skip)
        (( _skip++ )) || true
        if [[ "$mode" == "full" ]]; then
          printf '  [SKIP] %s%s\n' "$label" "${detail:+  ($detail)}"
        fi
        ;;
      fail)
        if [[ "$critical" -eq 1 ]]; then
          (( _fail++ )) || true
          printf '  [FAIL] %s%s\n' "$label" "${detail:+  ($detail)}"
        else
          (( _skip++ )) || true
          if [[ "$mode" == "full" ]]; then
            printf '  [WARN] %s%s\n' "$label" "${detail:+  ($detail)}"
          fi
        fi
        ;;
    esac
  }

  if [[ "$mode" == "full" ]]; then
    printf 'OpenSMART health check\n'
    printf '%s\n' '────────────────────────────────────────'
  fi

  # 1. uv
  if command -v uv >/dev/null 2>&1; then
    _hcheck "uv available" ok "$(uv --version 2>/dev/null | head -1)" 1
  else
    _hcheck "uv available" fail "not found — install: curl -LsSf https://astral.sh/uv/install.sh | sh" 1
  fi

  # 2. Python
  if command -v uv >/dev/null 2>&1; then
    local _py_ver
    # --no-project: this only needs to confirm the interpreter itself is
    # available. Passing --project here (as before) made uv resolve and sync
    # the whole backend dependency set just to print a version string, so a
    # flaky network on first install could hang or fail this check even
    # though Python 3.13 was present the whole time (confirmed on the test
    # server: `uv python list` found it instantly, but this check hung for
    # minutes). The real dependency sync still happens further down via
    # `uv sync`, where a network failure is the correct thing to fail on.
    _py_ver="$(uv run --no-project --python "$BACKEND_PYTHON" python --version 2>/dev/null || true)"
    if [[ -n "$_py_ver" ]]; then
      _hcheck "Python ${BACKEND_PYTHON} available" ok "$_py_ver" 1
    else
      _hcheck "Python ${BACKEND_PYTHON} available" fail "not found via uv" 1
    fi
  else
    _hcheck "Python ${BACKEND_PYTHON} available" skip "uv not available" 1
  fi

  # 3. SQLite DB presence
  # Note: PRAGMA integrity_check intentionally skipped — it walks every page
  # of every table/index and can take many minutes on large DBs, blocking
  # startup. Operators who suspect corruption can run it manually:
  #   sqlite3 "$DB_PATH" 'PRAGMA integrity_check;'
  if [[ -f "$DB_PATH" ]]; then
    _hcheck "SQLite DB present" ok "$DB_PATH" 1
  else
    if [[ "$mode" == "prestart" ]]; then
      # First run — DB will be created by init_db on startup; not a blocking failure
      _hcheck "SQLite DB" skip "not found — will be created on first start" 0
    else
      _hcheck "SQLite DB exists" fail "$DB_PATH not found — start app once to initialise" 0
    fi
  fi

  # 4. Schema validation (full and prestart, only if DB exists and sqlite3 available)
  if [[ -f "$DB_PATH" ]] && command -v sqlite3 >/dev/null 2>&1; then
    local _actual_tables
    _actual_tables="$(sqlite3 "$DB_PATH" \
      "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;" 2>/dev/null || true)"
    local _missing=()
    local _t
    for _t in "${EXPECTED_TABLES[@]}"; do
      if ! printf '%s\n' "$_actual_tables" | grep -qx "$_t"; then
        _missing+=("$_t")
      fi
    done
    if [[ ${#_missing[@]} -eq 0 ]]; then
      _hcheck "Schema: all tables present" ok "${#EXPECTED_TABLES[@]} tables verified" 1
    else
      _hcheck "Schema: all tables present" fail "missing: ${_missing[*]}" 1
    fi
  fi

  # 5. Disk free >= 1 GB (critical)
  if command -v df >/dev/null 2>&1; then
    local _free_kb
    _free_kb="$(df -Pk "$ROOT_DIR" 2>/dev/null | awk 'NR==2{print $4}' || true)"
    if [[ -n "$_free_kb" ]]; then
      local _free_gb _free_mb
      _free_gb="$(( _free_kb / 1048576 ))"
      _free_mb="$(( (_free_kb % 1048576) / 1024 ))"
      if (( _free_kb >= 1048576 )); then
        _hcheck "Disk free (>= 1 GB)" ok "${_free_gb} GB free" 1
      else
        _hcheck "Disk free (>= 1 GB)" fail "${_free_gb}.${_free_mb} GB free — consider freeing space" 1
      fi
    fi
  fi

  # ── Full-mode-only checks ──────────────────────────────────────────────────

  # 6. Log directory writable (informational in full mode only)
  if [[ "$mode" == "full" ]]; then
    local _log_dir="${ROOT_DIR}/logs"
    if [[ -d "$_log_dir" ]]; then
      if touch "${_log_dir}/.write_test" 2>/dev/null; then
        rm -f "${_log_dir}/.write_test"
        _hcheck "Log directory writable" ok "$_log_dir" 0
      else
        _hcheck "Log directory writable" fail "cannot write to ${_log_dir}" 0
      fi
    else
      _hcheck "Log directory exists" fail "${_log_dir} not found — start app once to create it" 0
    fi
  fi

  # 7. Backend HTTP health (full mode only — not meaningful pre-start)
  if [[ "$mode" == "full" ]]; then
    if command -v curl >/dev/null 2>&1; then
      local _health_resp
      _health_resp="$(curl -sf --max-time 3 "http://localhost:${BIND_PORT}/api/health" 2>/dev/null || true)"
      if [[ "$_health_resp" == *'"ok":true'* ]]; then
        _hcheck "Backend HTTP /api/health" ok "http://localhost:${BIND_PORT}" 0
      else
        _hcheck "Backend HTTP /api/health" fail "not reachable (start the app first, or ignore if checking offline)" 0
      fi
    else
      _hcheck "Backend HTTP /api/health" fail "curl not available" 0
    fi
  fi

  # 8. eve.json readable (full mode only — informational)
  if [[ "$mode" == "full" ]] && [[ -f "$DB_PATH" ]] && command -v sqlite3 >/dev/null 2>&1; then
    local _eve_cfg _eve_path
    _eve_cfg="$(sqlite3 "$DB_PATH" "SELECT config FROM opensmart_modules WHERE name='Network IDS';" 2>/dev/null || true)"
    if [[ -n "$_eve_cfg" ]]; then
      _eve_path="$(printf '%s' "$_eve_cfg" | grep -oP '"eve_json_path"\s*:\s*"\K[^"]+' 2>/dev/null || true)"
      if [[ -n "$_eve_path" ]]; then
        if [[ -r "$_eve_path" ]]; then
          _hcheck "eve.json readable" ok "$_eve_path" 0
        else
          _hcheck "eve.json readable" fail "${_eve_path} not found or not readable" 0
        fi
      else
        _hcheck "eve.json configured" fail "Network IDS module has no eve_json_path set" 0
      fi
    fi
  fi

  if [[ "$mode" == "full" ]]; then
    printf '%s\n' '────────────────────────────────────────'
    printf 'Passed: %d  Failed: %d  Skipped/Warned: %d\n\n' "$_pass" "$_fail" "$_skip"
  fi

  return $(( _fail > 0 ? 1 : 0 ))
}

# ── Fast data reset via dump → unlink → recreate → restore ──────────────────
# Preserves users, settings, modules, opensmart_modules, audit_events.
# Wipes sessions, login_attempts, resource_snapshots. Module DBs are reset
# separately after the core DB is recreated.
#
# This is O(preserved-rows) regardless of operational data volume because the
# DB file is unlinked at the filesystem level (constant-time on any size) and
# the schema is recreated from a single source of truth: init_db() in
# backend/app/database.py — no DDL duplication in this script.
#
# On failure between unlink and successful restore, the sidecar SQL backup is
# left in place at: <DB_PATH>.preserve.<timestamp>.sql
# Operator can recover with: sqlite3 <DB_PATH> < <backup_file>
reset_data_fast() {
  local backup_file="${DB_PATH}.preserve.$(date -u +%Y%m%d%H%M%S).sql"

  _step "Dumping preserve tables to ${backup_file}..."
  if ! sqlite3 "$DB_PATH" > "$backup_file" <<'SQLITE_EOF'
.mode insert users
SELECT * FROM users;
.mode insert settings
SELECT * FROM settings;
.mode insert modules
SELECT * FROM modules;
.mode insert opensmart_modules
SELECT * FROM opensmart_modules;
.mode insert audit_events
SELECT * FROM audit_events;
SQLITE_EOF
  then
    printf 'Failed to dump preserve tables.\n' >&2
    rm -f "$backup_file"
    return 1
  fi

  _step "Removing database files (file-level unlink)..."
  rm -f "$DB_PATH" "${DB_PATH}-wal" "${DB_PATH}-shm" "${DB_PATH}-journal"

  _step "Recreating schema via init_db()..."
  if ! uv run --project backend --python "$BACKEND_PYTHON" python -c \
    "from backend.app.database import init_db; init_db(bootstrap_admin_user=False)"; then
    printf 'Schema recreation failed. Backup preserved at: %s\n' "$backup_file" >&2
    return 1
  fi

  _step "Clearing default-seeded preserve rows..."
  if ! sqlite3 "$DB_PATH" <<'SQLITE_EOF'
DELETE FROM users;
DELETE FROM settings;
DELETE FROM modules;
DELETE FROM opensmart_modules;
DELETE FROM audit_events;
SQLITE_EOF
  then
    printf 'Failed to clear default-seeded rows. Backup preserved at: %s\n' "$backup_file" >&2
    return 1
  fi

  _step "Restoring preserved data..."
  if ! sqlite3 "$DB_PATH" < "$backup_file"; then
    printf 'Restore failed. Backup preserved at: %s\n' "$backup_file" >&2
    return 1
  fi

  _step "Removing backup file..."
  rm -f "$backup_file"
}

# ── Granular module DB resets ────────────────────────────────────────────────

reset_telemetry_ids_fast() {
  _step "Removing IDS module database..."
  rm -f "$NETWORK_IDS_DB_PATH" "${NETWORK_IDS_DB_PATH}-wal" "${NETWORK_IDS_DB_PATH}-shm" "${NETWORK_IDS_DB_PATH}-journal"
  _step "Recreating IDS module schema..."
  uv run --project backend --python "$BACKEND_PYTHON" python -c \
    "from backend.app.database import init_network_ids_db; init_network_ids_db()"
}

reset_telemetry_network_fast() {
  _step "Removing Network Traffic module database..."
  rm -f "$NETWORK_TRAFFIC_DB_PATH" "${NETWORK_TRAFFIC_DB_PATH}-wal" "${NETWORK_TRAFFIC_DB_PATH}-shm" "${NETWORK_TRAFFIC_DB_PATH}-journal"
  _step "Recreating Network Traffic module schema..."
  uv run --project backend --python "$BACKEND_PYTHON" python -c \
    "from backend.app.database import init_network_traffic_db; init_network_traffic_db()"
}

# ── Argument parsing ──────────────────────────────────────────────────────────

trap cleanup EXIT INT TERM

cd "$ROOT_DIR"

# Banner shown on every invocation.
print_banner
_log INFO "run_app.sh started: args=${*:-none}"

case "${1:-}" in
  start|stop|status|restart|reset-admin-password|reset-data-all|reset-data-ids|reset-data-network|reset-all|health)
    COMMAND="$1"
    shift
    ;;
  --help|-h)
    usage
    exit 0
    ;;
  "")
    printf 'Missing command.\n' >&2
    usage >&2
    exit 1
    ;;
  *)
    printf 'Unknown command: %s\n' "$1" >&2
    usage >&2
    exit 1
    ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      BIND_HOST="${2:?--host requires a value}"
      HOST_EXPLICIT=1
      shift 2
      ;;
    --port)
      BIND_PORT="${2:?--port requires a value}"
      PORT_EXPLICIT=1
      shift 2
      ;;
    --prod)
      PROD_MODE=1
      PROD_EXPLICIT=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$COMMAND" != "start" && "$COMMAND" != "restart" ]] \
  && [[ "$HOST_EXPLICIT" -eq 1 || "$PORT_EXPLICIT" -eq 1 || "$PROD_EXPLICIT" -eq 1 ]]; then
  printf -- '--host/--port/--prod only apply to the start/restart commands.\n' >&2
  exit 1
fi

# ── stop / status ──────────────────────────────────────────────────────────────
if [[ "$COMMAND" == "stop" ]]; then
  cmd_stop
  exit 0
fi

if [[ "$COMMAND" == "status" ]]; then
  cmd_status
  exit 0
fi

# ── restart: stop the existing instance (reusing its bind/mode unless
# explicitly overridden), then fall through into the normal start flow ────────
if [[ "$COMMAND" == "restart" ]]; then
  if [[ "$HOST_EXPLICIT" -eq 0 ]]; then
    _prev_host="$(_state_get HOST)"
    if [[ -n "$_prev_host" ]]; then
      BIND_HOST="$_prev_host"
    fi
  fi
  if [[ "$PORT_EXPLICIT" -eq 0 ]]; then
    _prev_port="$(_state_get PORT)"
    if [[ -n "$_prev_port" ]]; then
      BIND_PORT="$_prev_port"
    fi
  fi
  if [[ "$PROD_EXPLICIT" -eq 0 ]]; then
    _prev_prod="$(_state_get PROD)"
    if [[ "$_prev_prod" == "1" ]]; then
      PROD_MODE=1
    fi
  fi
  cmd_stop
  COMMAND="start"
fi

# ── Explicit health check ─────────────────────────────────────────────────────
if [[ "$COMMAND" == "health" ]]; then
  run_health_checks full
  exit $?
fi

# ── Reset operations (all exit after completion) ──────────────────────────────

if ! require_command "uv" "Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh"; then
  BACKEND_STATUS="failed: uv missing"
  FRONTEND_STATUS="not checked"
  print_summary
  exit 1
fi

# ── Full reset ────────────────────────────────────────────────────────────────
if [[ "$COMMAND" == "reset-all" ]]; then
  printf '*** FULL RESET ***\n'
  printf 'This will DELETE the entire OpenSMART database, including all users,\n'
  printf 'config, IDS data, sessions, and audit events.\n'
  printf 'The application will be reinitialized with a fresh admin account.\n'
  printf '\nWARNING: This operation is NOT recoverable. All data will be permanently lost.\n\n'
  read -r -p 'Type FULL-RESET to confirm: ' confirmation
  if [[ "$confirmation" != "FULL-RESET" ]]; then
    printf 'Full reset cancelled.\n'
    _log INFO "full_reset cancelled by operator"
    exit 0
  fi
  _log INFO "full_reset started by operator"
  _step "Deleting database and reinitializing..."
  if ! uv run --project backend --python "$BACKEND_PYTHON" python -m backend.app.admin_tools --full-reset; then
    printf 'Full reset failed.\n' >&2
    _log ERROR "full_reset failed"
    exit 1
  fi
  _log INFO "full_reset completed"
  printf '\nDone. Run %s start to start OpenSMART.\n' "$RUN_APP_INVOKE_AS"
  exit 0
fi

# ── Data-all reset ────────────────────────────────────────────────────────────
if [[ "$COMMAND" == "reset-data-all" ]]; then
  printf '*** DATA RESET (ALL) ***\n'
  printf 'This will delete ALL IDS alerts, network traffic events, sessions, audit events, and login attempts.\n'
  printf 'Users, settings, and module config will be preserved.\n'
  printf '\nWARNING: This operation is NOT recoverable. Deleted data cannot be restored.\n\n'
  read -r -p 'Type RESET-DATA-ALL to confirm: ' confirmation
  if [[ "$confirmation" != "RESET-DATA-ALL" ]]; then
    printf 'Data reset cancelled.\n'
    _log INFO "reset_data_all cancelled by operator"
    exit 0
  fi
  _log INFO "reset_data_all started by operator"

  if ! command -v sqlite3 >/dev/null 2>&1; then
    _step "sqlite3 CLI not found — falling back to Python reset..."
    if ! uv run --project backend --python "$BACKEND_PYTHON" python -m backend.app.admin_tools --reset-data-all; then
      printf 'Data reset failed.\n' >&2
      _log ERROR "reset_data_all failed (python fallback)"
      exit 1
    fi
  else
    if [[ ! -f "$DB_PATH" ]]; then
      printf 'Database not found at %s — nothing to reset.\n' "$DB_PATH" >&2
      _log ERROR "reset_data_all failed: database not found at ${DB_PATH}"
      exit 1
    fi
    _step "Resetting main DB operational tables..."
    if ! reset_data_fast; then
      printf 'Main DB reset failed.\n' >&2
      _log ERROR "reset_data_all failed (main DB fast path)"
      exit 1
    fi
    _step "Wiping module databases..."
    rm -f "$NETWORK_IDS_DB_PATH" "${NETWORK_IDS_DB_PATH}-wal" "${NETWORK_IDS_DB_PATH}-shm" "${NETWORK_IDS_DB_PATH}-journal"
    rm -f "$NETWORK_TRAFFIC_DB_PATH" "${NETWORK_TRAFFIC_DB_PATH}-wal" "${NETWORK_TRAFFIC_DB_PATH}-shm" "${NETWORK_TRAFFIC_DB_PATH}-journal"
    _step "Recreating module schemas..."
    if ! uv run --project backend --python "$BACKEND_PYTHON" python -c \
      "from backend.app.database import init_network_ids_db, init_network_traffic_db; init_network_ids_db(); init_network_traffic_db()"; then
      printf 'Module DB recreation failed.\n' >&2
      _log ERROR "reset_data_all failed (module DB recreate)"
      exit 1
    fi
  fi

  _log INFO "reset_data_all completed"
  printf 'Done. Run %s start to start OpenSMART.\n' "$RUN_APP_INVOKE_AS"
  exit 0
fi

# ── IDS-only reset ────────────────────────────────────────────────────────────
if [[ "$COMMAND" == "reset-data-ids" ]]; then
  printf '*** IDS DATA RESET ***\n'
  printf 'This will delete all IDS alerts and artifacts. Network traffic data is preserved.\n'
  printf '\nWARNING: This operation is NOT recoverable. Deleted data cannot be restored.\n\n'
  read -r -p 'Type RESET-IDS to confirm: ' confirmation
  if [[ "$confirmation" != "RESET-IDS" ]]; then
    printf 'IDS data reset cancelled.\n'
    _log INFO "reset_data_ids cancelled by operator"
    exit 0
  fi
  _log INFO "reset_data_ids started by operator"

  if ! command -v sqlite3 >/dev/null 2>&1; then
    _step "sqlite3 CLI not found — falling back to Python reset..."
    if ! uv run --project backend --python "$BACKEND_PYTHON" python -m backend.app.admin_tools --reset-data-ids; then
      printf 'IDS data reset failed.\n' >&2
      _log ERROR "reset_data_ids failed (python fallback)"
      exit 1
    fi
  else
    if ! reset_telemetry_ids_fast; then
      printf 'IDS data reset failed.\n' >&2
      _log ERROR "reset_data_ids failed (fast path)"
      exit 1
    fi
  fi

  _log INFO "reset_data_ids completed"
  printf 'Done. IDS alerts cleared. Run %s start to start OpenSMART.\n' "$RUN_APP_INVOKE_AS"
  exit 0
fi

# ── Network-only reset ────────────────────────────────────────────────────────
if [[ "$COMMAND" == "reset-data-network" ]]; then
  printf '*** NETWORK TRAFFIC DATA RESET ***\n'
  printf 'This will delete all network traffic events. IDS alerts are preserved.\n'
  printf '\nWARNING: This operation is NOT recoverable. Deleted data cannot be restored.\n\n'
  read -r -p 'Type RESET-NETWORK to confirm: ' confirmation
  if [[ "$confirmation" != "RESET-NETWORK" ]]; then
    printf 'Network data reset cancelled.\n'
    _log INFO "reset_data_network cancelled by operator"
    exit 0
  fi
  _log INFO "reset_data_network started by operator"

  if ! command -v sqlite3 >/dev/null 2>&1; then
    _step "sqlite3 CLI not found — falling back to Python reset..."
    if ! uv run --project backend --python "$BACKEND_PYTHON" python -m backend.app.admin_tools --reset-data-network; then
      printf 'Network data reset failed.\n' >&2
      _log ERROR "reset_data_network failed (python fallback)"
      exit 1
    fi
  else
    if ! reset_telemetry_network_fast; then
      printf 'Network data reset failed.\n' >&2
      _log ERROR "reset_data_network failed (fast path)"
      exit 1
    fi
  fi

  _log INFO "reset_data_network completed"
  printf 'Done. Network traffic events cleared. Run %s start to start OpenSMART.\n' "$RUN_APP_INVOKE_AS"
  exit 0
fi

# ── Admin password reset ──────────────────────────────────────────────────────
if [[ "$COMMAND" == "reset-admin-password" ]]; then
  printf 'This will reset the admin password and invalidate existing admin sessions.\n'
  printf '\nWARNING: Existing admin sessions will be immediately invalidated.\n\n'
  read -r -p 'Type RESET to continue: ' confirmation
  if [[ "$confirmation" != "RESET" ]]; then
    printf 'Admin password reset cancelled.\n'
    _log INFO "reset_admin_password cancelled by operator"
    exit 0
  fi
  _log INFO "reset_admin_password started by operator"
  _step "Resetting admin password..."
  if ! uv run --project backend --python "$BACKEND_PYTHON" python -m backend.app.admin_tools; then
    printf 'Admin password reset failed. Start OpenSMART once to create the initial admin account, then retry.\n' >&2
    _log ERROR "reset_admin_password failed"
    exit 1
  fi
  _log INFO "reset_admin_password completed"
  printf '\nDone. Run %s start to start OpenSMART.\n' "$RUN_APP_INVOKE_AS"
  exit 0
fi

# ── Normal startup ────────────────────────────────────────────────────────────

# Pre-start health check — critical checks only; blocks startup on failure
printf 'Running pre-start checks...\n'
if ! run_health_checks prestart; then
  printf '\nPre-start health check failed. Fix the issues above before starting OpenSMART.\n'
  printf 'Run %s health for a full diagnostic report.\n\n' "$RUN_APP_INVOKE_AS"
  _log ERROR "pre-start health check failed: startup aborted"
  exit 1
fi
printf 'Pre-start checks passed.\n\n'

# ── Dependency sync ───────────────────────────────────────────────────────────
backend_venv_exists=0
if [[ -d "$ROOT_DIR/backend/.venv" ]]; then
  backend_venv_exists=1
fi

if uv sync --project backend --python "$BACKEND_PYTHON"; then
  if [[ "$backend_venv_exists" -eq 1 ]]; then
    BACKEND_STATUS="ok"
  else
    BACKEND_STATUS="installed/updated"
  fi
else
  BACKEND_STATUS="failed"
  print_summary
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  printf 'Missing required command: node\n' >&2
  printf 'Install Node.js from your OS package manager or https://nodejs.org/.\n' >&2
  FRONTEND_STATUS="failed: node missing"
  print_summary
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  printf 'Missing required command: npm\n' >&2
  printf 'Install npm with Node.js from your OS package manager or https://nodejs.org/.\n' >&2
  FRONTEND_STATUS="failed: npm missing"
  print_summary
  exit 1
fi

if [[ -d "$ROOT_DIR/frontend/node_modules" ]]; then
  FRONTEND_STATUS="ok"
else
  if npm install --prefix frontend; then
    FRONTEND_STATUS="installed"
  else
    FRONTEND_STATUS="failed"
    print_summary
    exit 1
  fi
fi

if [[ "$PROD_MODE" -eq 1 ]]; then
  if npm run build --prefix frontend; then
    FRONTEND_STATUS="built"
  else
    FRONTEND_STATUS="failed: build"
    print_summary
    exit 1
  fi
fi

print_summary

if [[ "$BACKEND_STATUS" == "ok" && "$FRONTEND_STATUS" == "ok" ]]; then
  printf '\nAll dependencies are OK. Starting OpenSMART...\n'
else
  printf '\nDependencies are ready. Starting OpenSMART...\n'
fi

if [[ "$PROD_MODE" -eq 1 ]]; then
  printf 'OpenSMART: http://%s:%s\n\n' "$BIND_HOST" "$BIND_PORT"
else
  printf 'Backend:  http://%s:%s\n' "$BIND_HOST" "$BIND_PORT"
  printf 'Frontend: http://localhost:5173\n\n'
fi

BACKEND_LOG="$(mktemp -t opensmart-backend.XXXXXX.log)"
CONSOLIDATED_LOG="${ROOT_DIR}/logs/opensmart.log"
mkdir -p "${ROOT_DIR}/logs"
FIRST_RUN_EXPECTED=0
if admin_account_missing; then
  FIRST_RUN_EXPECTED=1
fi
# --reload is dev-only. It was previously unconditional (including in
# --prod, i.e. the actual deployed container) — uvicorn's default reload
# watch scope is the whole CWD (confirmed via its own startup log: "Will
# watch for changes in these directories: ['.../opensmart']"), which
# includes opensmart/containers/run/*/ where provisioning legitimately
# writes files as normal operation (tool .env files, generated certs, VPN
# instance configs, ...). Every such write could trigger a full backend
# process restart mid-request, dropping the very connection that
# triggered it — confirmed live: provisioning several modules/tools in a
# row during a Wizard run produced 4 backend restarts in a 10-second
# window, and the front-door proxy step (which both writes its own .env
# and generates a fresh cert) is exactly the kind of step likely to race
# its own request this way. Even in dev mode, --reload-dir narrows the
# watch to just the actual Python source so the same class of self-
# inflicted restart can't happen there either.
declare -a RELOAD_FLAGS=()
if [[ "$PROD_MODE" -eq 0 ]]; then
  RELOAD_FLAGS=(--reload --reload-dir "$ROOT_DIR/backend/app")
fi
_log INFO "backend starting: uvicorn backend.app.main:app --host ${BIND_HOST} --port ${BIND_PORT} ${RELOAD_FLAGS[*]}"
uv run --project backend --python "$BACKEND_PYTHON" uvicorn backend.app.main:app --host "$BIND_HOST" --port "$BIND_PORT" "${RELOAD_FLAGS[@]}" > >(tee "$BACKEND_LOG") 2> >(tee -a "$BACKEND_LOG" >&2) &
BACKEND_PID=$!

sleep 2
if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
  printf 'Backend failed to start. Frontend will not be started.\n' >&2
  _log ERROR "backend process exited immediately after start"
  wait "$BACKEND_PID"
  exit 1
fi
_log INFO "backend started: pid=${BACKEND_PID}"
_state_write

# ── First-run: display prominent password box from backend log ────────────────
if [[ "$FIRST_RUN_EXPECTED" -eq 1 ]]; then
  wait_for_initial_password 30 || true
fi
if [[ -f "$BACKEND_LOG" ]] && grep -q "$FIRST_RUN_MARKER" "$BACKEND_LOG"; then
  _pw="$(extract_initial_password)"
  print_password_box \
    "OpenSMART - Initial Admin Account Created" \
    "admin" \
    "${_pw:-see backend log}" \
    "Change this password after first login."
  if [[ "$PROD_MODE" -eq 0 ]]; then
    printf 'Press Enter to start the frontend...'
    read -r
  fi
elif [[ "$FIRST_RUN_EXPECTED" -eq 1 ]]; then
  printf '\nWARNING: initial admin account was expected, but the password was not captured within 30 seconds.\n' >&2
  printf 'Check the backend output above before logging in.\n\n' >&2
fi

if [[ "$PROD_MODE" -eq 1 ]]; then
  _log INFO "prod mode: frontend served by backend; skipping Vite dev server"
  wait "$BACKEND_PID"
else
  _log INFO "frontend starting: npm --prefix frontend run dev"
  npm --prefix frontend run dev 2>&1 | tee -a "$CONSOLIDATED_LOG"
fi
