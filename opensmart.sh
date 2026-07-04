#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_NAME="opensmart"
NETWORK_SUBNET="172.250.250.0/24"
IMAGE_NAME="opensmart/web"
CONTAINER_NAME="opensmart"
FIRST_RUN_MARKER="OpenSMART initial admin account created"
LOG_DIR="$ROOT_DIR/logs"
INSTALL_LOG="$LOG_DIR/install.log"
STEP_TOTAL=9
STEP_NUM=0

usage() {
  cat <<'EOF'
Usage: ./opensmart.sh <command> [options]

Commands:
  start --bind ADDRESS:PORT [--prod]   Start the OpenSMART app bound to ADDRESS:PORT.
                                        --prod builds the frontend once and serves it
                                        from the backend on a single port instead of
                                        running the Vite dev server.
  --install                            Install Docker Engine (Debian/Ubuntu only),
                                        build the opensmart/web image, and run
                                        OpenSMART as a container. Requires root.
  --help, -h                           Show this help message.
EOF
}

print_banner() {
  local w=42
  local blank="║$(printf '%*s' $w '')║"
  printf '\n'
  printf '  ╔%s╗\n' "$(printf '%0.s═' $(seq 1 $w))"
  printf '  %s\n' "$blank"
  printf '  ║  %-*s║\n' $(( w - 2 )) 'OpenSMART'
  printf '  ║  %-*s║\n' $(( w - 2 )) 'Installer'
  printf '  %s\n' "$blank"
  printf '  ╚%s╝\n' "$(printf '%0.s═' $(seq 1 $w))"
  printf '\n'
  printf '  HoneyMex Lab & Mizton Labs\n'
  printf '\n'
  printf '      _   _   _   _\n'
  printf '     / \_/ \_/ \_/ \\\n'
  printf '     \_/ \_/ \_/ \_/\n'
  printf '     / \_/ \_/ \_/ \\\n'
  printf '     \_/ \_/ \_/ \_/\n'
  printf '\n'
}

cmd_start() {
  local bind=""
  local prod=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bind)
        bind="${2:?--bind requires an ADDRESS:PORT value}"
        shift 2
        ;;
      --prod)
        prod=1
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

  if [[ -z "$bind" ]]; then
    printf 'start requires --bind ADDRESS:PORT\n' >&2
    usage >&2
    exit 1
  fi

  local host="${bind%:*}"
  local port="${bind##*:}"
  if [[ -z "$host" || "$port" == "$bind" || ! "$port" =~ ^[0-9]+$ ]]; then
    printf 'Invalid --bind value: %s (expected ADDRESS:PORT)\n' "$bind" >&2
    exit 1
  fi

  if [[ "$prod" -eq 1 ]]; then
    exec "$ROOT_DIR/opensmart/scripts/run_app.sh" --host "$host" --port "$port" --prod
  else
    exec "$ROOT_DIR/opensmart/scripts/run_app.sh" --host "$host" --port "$port"
  fi
}

# ── --install helpers ─────────────────────────────────────────────────────────
#
# Terminal output is kept to one line per main step; every command's full
# (often noisy) output goes only to $INSTALL_LOG. On failure, the current
# step line is closed with "failed" and the log path is pointed out.

_log_init() {
  mkdir -p "$LOG_DIR"
  printf '\n===== opensmart.sh --install started %s =====\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$INSTALL_LOG"
}

_step() {
  STEP_NUM=$((STEP_NUM + 1))
  printf '➤ [%d/%d] %s... ' "$STEP_NUM" "$STEP_TOTAL" "$1"
  printf '[%s] STEP %d/%d: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$STEP_NUM" "$STEP_TOTAL" "$1" >> "$INSTALL_LOG"
}

_step_fail() {
  printf 'failed\n'
  printf '\n✘ %s\n' "$1" >&2
  printf 'See %s for the full command output.\n' "$INSTALL_LOG" >&2
  exit 1
}

_install_require_root() {
  _step "Checking root privileges"
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    _step_fail "opensmart.sh --install must be run as root. Try: sudo ./opensmart.sh --install"
  fi
  printf 'ok\n'
}

_install_check_distro() {
  _step "Detecting Linux distribution"
  if [[ ! -r /etc/os-release ]]; then
    _step_fail "Cannot detect the Linux distribution (/etc/os-release not found). opensmart.sh --install only supports Debian and Ubuntu."
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  local id="${ID:-}"
  local id_like="${ID_LIKE:-}"
  if [[ "$id" != "debian" && "$id" != "ubuntu" && "$id_like" != *debian* ]]; then
    _step_fail "Unsupported Linux distribution: ${PRETTY_NAME:-$id}. opensmart.sh --install only supports Debian and Ubuntu (apt-based)."
  fi
  DISTRO_ID="$id"
  printf '%s\n' "${PRETTY_NAME:-$id}"
}

_install_docker_engine() {
  _step "Installing Docker Engine"
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    printf 'already installed, skipping\n'
    return 0
  fi

  {
    apt-get update &&
    apt-get install -y ca-certificates curl &&
    install -m 0755 -d /etc/apt/keyrings &&
    curl -fsSL "https://download.docker.com/linux/${DISTRO_ID}/gpg" -o /etc/apt/keyrings/docker.asc &&
    chmod a+r /etc/apt/keyrings/docker.asc
  } >> "$INSTALL_LOG" 2>&1 || _step_fail "Failed to set up the Docker apt repository."

  local arch codename
  arch="$(dpkg --print-architecture)"
  codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
  cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${DISTRO_ID} ${codename} stable
EOF

  {
    apt-get update &&
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  } >> "$INSTALL_LOG" 2>&1 || _step_fail "Failed to install Docker Engine packages."

  if ! command -v docker >/dev/null 2>&1; then
    _step_fail 'Docker Engine install appears to have failed: "docker" command not found.'
  fi
  printf 'done\n'
}

_install_create_network() {
  _step "Creating Docker network \"$NETWORK_NAME\""
  if docker network inspect "$NETWORK_NAME" >> "$INSTALL_LOG" 2>&1; then
    printf 'already exists, skipping\n'
  else
    docker network create --driver bridge --subnet "$NETWORK_SUBNET" "$NETWORK_NAME" >> "$INSTALL_LOG" 2>&1 \
      || _step_fail "Failed to create the \"$NETWORK_NAME\" Docker network."
    printf 'created\n'
  fi
}

_install_build_image() {
  _step "Building $IMAGE_NAME image (this can take a few minutes)"
  docker build -t "$IMAGE_NAME" -f "$ROOT_DIR/containers/build/opensmart/Dockerfile" "$ROOT_DIR" >> "$INSTALL_LOG" 2>&1 \
    || _step_fail "Failed to build the $IMAGE_NAME image."
  printf 'done\n'
}

_install_fix_ownership() {
  # The whole repo is bind-mounted into the container, which runs as the
  # non-root "opensmart" user (uid 1000). If the host checkout is owned by
  # root (e.g. a root-run git clone), that user can't create backend/.venv,
  # frontend/node_modules, frontend/dist, the SQLite DBs, or write logs.
  # Same fix pattern already used by OpenSMART-Standalone/deploy.sh for its
  # bind-mounted volumes.
  _step "Setting file ownership for the container"
  chown -R 1000:1000 "$ROOT_DIR" >> "$INSTALL_LOG" 2>&1 \
    || _step_fail "Failed to set ownership of $ROOT_DIR to uid 1000."
  printf 'done\n'
}

_install_run_container() {
  _step "Starting the $CONTAINER_NAME container"
  (cd "$ROOT_DIR/containers/run/opensmart" && docker compose up -d) >> "$INSTALL_LOG" 2>&1 \
    || _step_fail "Failed to start the $CONTAINER_NAME container."
  printf 'done\n'
}

_install_wait_running() {
  _step "Waiting for the container to stabilize"
  local attempt restarts_before restarts_after
  for attempt in $(seq 1 30); do
    if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null)" == "true" ]]; then
      # A crash-looping container (restart: always) can appear "running" for
      # a brief window between crashes. Confirm it stays up and its restart
      # count doesn't tick over before declaring success.
      restarts_before="$(docker inspect -f '{{.RestartCount}}' "$CONTAINER_NAME" 2>/dev/null || echo 0)"
      sleep 5
      restarts_after="$(docker inspect -f '{{.RestartCount}}' "$CONTAINER_NAME" 2>/dev/null || echo 0)"
      if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null)" == "true" && "$restarts_after" == "$restarts_before" ]]; then
        printf 'stable\n'
        return 0
      fi
      _step_fail "Container \"$CONTAINER_NAME\" is stuck in a restart loop. Check logs with: docker logs $CONTAINER_NAME"
    fi
    sleep 1
  done
  _step_fail "Container \"$CONTAINER_NAME\" did not reach a running state. Check logs with: docker logs $CONTAINER_NAME"
}

_install_show_password() {
  # A genuinely fresh install has to uv-sync the backend, npm-install, and
  # npm-run-build the frontend inside the container before the app logs the
  # first-run marker — that routinely takes a couple of minutes on a cold
  # cache, well past a short window. Poll for up to 5 minutes.
  _step "Waiting for OpenSMART to become ready (first run can take a few minutes)"
  local attempt logs pw
  for attempt in $(seq 1 150); do
    logs="$(docker logs "$CONTAINER_NAME" 2>&1 || true)"
    if grep -q "$FIRST_RUN_MARKER" <<<"$logs"; then
      printf 'ready\n'
      {
        printf '[%s] container log at readiness:\n%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$logs"
      } >> "$INSTALL_LOG"
      pw="$(sed -n 's/^Password: //p' <<<"$logs" | tail -n 1)"
      printf '\n************************************************************\n'
      printf '*  OpenSMART - Initial Admin Account Created\n'
      printf '*\n'
      printf '*    Username : admin\n'
      printf '*    Password : %s\n' "${pw:-see: docker logs ${CONTAINER_NAME}}"
      printf '*\n'
      printf '*  Change this password after first login.\n'
      printf '************************************************************\n\n'
      return 0
    fi
    sleep 2
  done
  printf 'timed out\n'
  {
    printf '[%s] container log at timeout:\n%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$logs"
  } >> "$INSTALL_LOG"
  printf '\nCould not find the initial admin password in container logs within 5 minutes.\n' >&2
  printf 'See %s (or: docker logs %s) for details.\n' "$INSTALL_LOG" "$CONTAINER_NAME" >&2
}

cmd_install() {
  print_banner
  _log_init
  printf 'Full installer log: %s\n\n' "$INSTALL_LOG"
  _install_require_root
  _install_check_distro
  _install_docker_engine
  _install_create_network
  _install_build_image
  _install_fix_ownership
  _install_run_container
  _install_wait_running
  _install_show_password
  printf '✔ OpenSMART is running at http://0.0.0.0:8000\n'
}

case "${1:-}" in
  start)
    shift
    cmd_start "$@"
    ;;
  --install)
    cmd_install
    ;;
  --help|-h)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
