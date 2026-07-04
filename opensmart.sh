#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_NAME="opensmart"
NETWORK_SUBNET="172.250.250.0/24"
IMAGE_NAME="opensmart/web"
CONTAINER_NAME="opensmart"
FIRST_RUN_MARKER="OpenSMART initial admin account created"

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

_install_require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    printf 'opensmart.sh --install must be run as root. Try: sudo ./opensmart.sh --install\n' >&2
    exit 1
  fi
}

_install_check_distro() {
  if [[ ! -r /etc/os-release ]]; then
    printf 'Cannot detect the Linux distribution (/etc/os-release not found).\n' >&2
    printf 'opensmart.sh --install only supports Debian and Ubuntu.\n' >&2
    exit 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  local id="${ID:-}"
  local id_like="${ID_LIKE:-}"
  if [[ "$id" != "debian" && "$id" != "ubuntu" && "$id_like" != *debian* ]]; then
    printf 'Unsupported Linux distribution: %s\n' "${PRETTY_NAME:-$id}" >&2
    printf 'opensmart.sh --install only supports Debian and Ubuntu (apt-based).\n' >&2
    exit 1
  fi
  DISTRO_ID="$id"
}

_install_docker_engine() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    printf 'Docker Engine and the Compose plugin are already installed; skipping install.\n'
    return 0
  fi

  printf 'Installing Docker Engine (%s)...\n' "$DISTRO_ID"
  apt-get update
  apt-get install -y ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${DISTRO_ID}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  local arch codename
  arch="$(dpkg --print-architecture)"
  codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
  cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${DISTRO_ID} ${codename} stable
EOF

  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker Engine install appears to have failed: "docker" command not found.\n' >&2
    exit 1
  fi
}

_install_create_network() {
  if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    printf 'Docker network "%s" already exists; skipping.\n' "$NETWORK_NAME"
  else
    printf 'Creating docker network "%s" (%s)...\n' "$NETWORK_NAME" "$NETWORK_SUBNET"
    docker network create --driver bridge --subnet "$NETWORK_SUBNET" "$NETWORK_NAME"
  fi
}

_install_build_image() {
  printf 'Building %s image...\n' "$IMAGE_NAME"
  if ! docker build -t "$IMAGE_NAME" -f "$ROOT_DIR/containers/build/opensmart/Dockerfile" "$ROOT_DIR"; then
    printf 'Failed to build the %s image.\n' "$IMAGE_NAME" >&2
    exit 1
  fi
}

_install_fix_ownership() {
  # The whole repo is bind-mounted into the container, which runs as the
  # non-root "opensmart" user (uid 1000). If the host checkout is owned by
  # root (e.g. a root-run git clone), that user can't create backend/.venv,
  # frontend/node_modules, frontend/dist, the SQLite DBs, or write logs.
  # Same fix pattern already used by OpenSMART-Standalone/deploy.sh for its
  # bind-mounted volumes.
  printf 'Setting ownership of the app directory to uid 1000 (container user)...\n'
  chown -R 1000:1000 "$ROOT_DIR"
}

_install_run_container() {
  printf 'Starting the %s container...\n' "$CONTAINER_NAME"
  if ! (cd "$ROOT_DIR/containers/run/opensmart" && docker compose up -d); then
    printf 'Failed to start the %s container.\n' "$CONTAINER_NAME" >&2
    exit 1
  fi
}

_install_wait_running() {
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
        printf 'Container "%s" is running.\n' "$CONTAINER_NAME"
        return 0
      fi
      printf 'Container "%s" is stuck in a restart loop.\n' "$CONTAINER_NAME" >&2
      printf 'Check logs with: docker logs %s\n' "$CONTAINER_NAME" >&2
      exit 1
    fi
    sleep 1
  done
  printf 'Container "%s" did not reach a running state.\n' "$CONTAINER_NAME" >&2
  printf 'Check logs with: docker logs %s\n' "$CONTAINER_NAME" >&2
  exit 1
}

_install_show_password() {
  # A genuinely fresh install has to uv-sync the backend, npm-install, and
  # npm-run-build the frontend inside the container before the app logs the
  # first-run marker — that routinely takes a couple of minutes on a cold
  # cache, well past a 30-second window. Poll for up to 5 minutes.
  local attempt logs pw
  printf 'Waiting for the initial admin account (first run can take a few minutes to install dependencies and build the frontend)...\n'
  for attempt in $(seq 1 150); do
    logs="$(docker logs "$CONTAINER_NAME" 2>&1 || true)"
    if grep -q "$FIRST_RUN_MARKER" <<<"$logs"; then
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
  printf 'Could not find the initial admin password in container logs within 5 minutes.\n' >&2
  printf 'View it with: docker logs %s\n' "$CONTAINER_NAME" >&2
}

cmd_install() {
  _install_require_root
  _install_check_distro
  _install_docker_engine
  _install_create_network
  _install_build_image
  _install_fix_ownership
  _install_run_container
  _install_wait_running
  _install_show_password
  printf 'OpenSMART is running at http://0.0.0.0:8000\n'
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
