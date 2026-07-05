#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_MAJOR="v0.3"
NETWORK_NAME="opensmart"
NETWORK_SUBNET="172.250.250.0/24"
IMAGE_NAME="opensmart/web"
CONTAINER_NAME="opensmart"
FIRST_RUN_MARKER="OpenSMART initial admin account created"
LOG_DIR="$ROOT_DIR/logs"
INSTALL_LOG="$LOG_DIR/install.log"
STEP_TOTAL=10
STEP_NUM=0
# Tells run_app.sh to refer to *this* script in its own user-facing
# "run ... to do X" messages, instead of naming itself — keeps messages
# consistent for anyone using opensmart.sh, since it's meant to be a
# wrapper: exported so every host-side exec/invocation of run_app.sh below
# inherits it automatically; the docker-exec path passes it explicitly
# since docker exec starts a fresh environment, not inheriting the host's.
export RUN_APP_INVOKE_AS="./opensmart.sh"
# Host-path parity for the opensmart container's bind mount (see
# opensmart/containers/run/opensmart/docker-compose.yml): the repo root is
# mounted at this same absolute path inside the container, instead of a
# fixed /opt path. The container's CMD (./opensmart.sh) needs the repo root
# specifically, not just opensmart/, since that's where opensmart.sh lives;
# mounting the whole repo root also makes sibling-container bind mounts
# under opensmart/containers/run/*/ resolve against real host paths.
export OPENSMART_PROJECT_DIR="$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage: ./opensmart.sh <command> [options]

Commands:
  start [--bind ADDRESS:PORT] [--prod] If an "opensmart" container already exists,
                                        starts it (if not already running) and checks
                                        its integrity — --bind/--prod are ignored in
                                        that case, since the container's bind address
                                        is fixed by its docker-compose.yml. Otherwise
                                        runs the app directly on the host, defaulting
                                        to --bind 0.0.0.0:8000 when --bind is omitted.
  stop                                 Stop the OpenSMART container (docker compose stop).
  status                               Show the OpenSMART container state and whether the
                                        application inside it is responding.
  restart                              Restart the existing OpenSMART container and
                                        check its integrity afterward.
  recreate                             Rebuild the opensmart/web image from the current
                                        source, delete the existing OpenSMART container,
                                        and create a new one from the rebuilt image, then
                                        check its integrity. Asks for confirmation.
  install                              Install Docker Engine (Debian/Ubuntu only),
                                        build the opensmart/web image, and run
                                        OpenSMART as a container. Requires root.
  uninstall                            Stop and remove every container OpenSMART
                                        creates or manages (main app + proxy, and any
                                        tool containers ever started). Does not remove
                                        the "opensmart" network, images, or app data.
                                        Asks for confirmation.
  version                              Show the OpenSMART version (major version plus
                                        the current git commit).

  reset-admin-password                 Reset the admin password and print it.
  reset-data-all                       Delete all IDS and network traffic data; keep
                                        config and users.
  reset-data-ids                       Delete only IDS alert data; preserve network
                                        traffic data.
  reset-data-network                   Delete only network traffic data; preserve IDS
                                        alert data.
  reset-all                            Full reset: delete the entire database and
                                        reinitialize.
  health                               Run health checks and print a pass/fail summary.

  The reset-*/health commands run inside the "opensmart" container if one
  exists, or directly on the host otherwise — same as start.

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
  printf '  Mizton Labs & Honeynet Mexico Team\n'
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

  # If the "opensmart" container already exists, this is a container-managed
  # deployment: (re)start the existing container and verify it rather than
  # running the app directly on the host. --bind/--prod don't apply here —
  # the container's bind address is fixed by its docker-compose.yml. This
  # detection only makes sense on the HOST: since the container itself now
  # also has a `docker` CLI (for sibling-container provisioning, reaching
  # the Docker API through docker-socket-proxy), running this script *inside*
  # the opensmart container would otherwise see itself as "an existing
  # container" and loop trying to manage itself instead of actually starting
  # the app — /.dockerenv is the standard signal that we're inside one.
  if [[ ! -f /.dockerenv ]] && command -v docker >/dev/null 2>&1 && _container_exists; then
    if [[ -n "$bind" || "$prod" -eq 1 ]]; then
      printf 'Note: an "%s" container already exists; --bind/--prod are ignored (the\n' "$CONTAINER_NAME"
      printf 'container always runs in --prod mode on the port published by its\n'
      printf 'docker-compose.yml). Use ./opensmart.sh recreate to replace it.\n\n'
    fi
    _start_existing_container
    return
  fi

  if [[ -z "$bind" ]]; then
    bind="0.0.0.0:8000"
  fi

  local host="${bind%:*}"
  local port="${bind##*:}"
  if [[ -z "$host" || "$port" == "$bind" || ! "$port" =~ ^[0-9]+$ ]]; then
    printf 'Invalid --bind value: %s (expected ADDRESS:PORT)\n' "$bind" >&2
    exit 1
  fi

  if [[ "$prod" -eq 1 ]]; then
    exec "$ROOT_DIR/opensmart/scripts/run_app.sh" start --host "$host" --port "$port" --prod
  else
    exec "$ROOT_DIR/opensmart/scripts/run_app.sh" start --host "$host" --port "$port"
  fi
}

cmd_version() {
  local commit
  commit="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
  printf 'OpenSMART %s (commit %s)\n' "$VERSION_MAJOR" "$commit"
}

# ── stop / status helpers ─────────────────────────────────────────────────────
#
# These act on the containerized deployment created by install (container
# name "opensmart"). They report/act on two independent things: the Docker
# container's own state, and whether the application inside it is actually
# responding on its published port — a container can be "running" while the
# app inside is still starting up, crashed, or not yet reachable.

_container_exists() {
  docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1
}

_container_host_port() {
  # Host-side port mapped to the container's 8000/tcp, e.g. "8000". Empty if
  # the container isn't running or isn't published.
  docker port "$CONTAINER_NAME" 8000/tcp 2>/dev/null | head -n1 | sed -E 's/.*:([0-9]+)$/\1/'
}

_app_health() {
  local port
  port="$(_container_host_port)"
  if [[ -n "$port" ]] && curl -sf --max-time 3 "http://localhost:${port}/api/health" 2>/dev/null | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
    printf 'healthy'
  else
    printf 'unreachable'
  fi
}

# ── run_app.sh pass-through (reset-*, health) ─────────────────────────────────
#
# These operate on the app's own data/health, independent of how it's
# currently running. Forward to wherever it actually lives: inside the
# container (using its own uv/python environment) if one exists, or directly
# on the host otherwise.
#
# The reset-* commands prompt for a typed confirmation via `read -p`, and
# bash only *prints* a `read -p` prompt when stdin is an actual terminal —
# `docker exec -i` alone (no -t) keeps stdin open for input but allocates no
# pseudo-TTY, so the prompt text silently never appears even though the
# confirmation is still being read underneath (this is what made it look
# like "the prompt isn't shown"). Request a TTY with -t, but only when our
# own stdin actually is one ([[ -t 0 ]]) — otherwise `docker exec -it` errors
# with "the input device is not a TTY" for piped/scripted invocations.

_run_app_passthrough() {
  if [[ ! -f /.dockerenv ]] && command -v docker >/dev/null 2>&1 && _container_exists; then
    local -a exec_flags=(-i)
    if [[ -t 0 ]]; then
      exec_flags+=(-t)
    fi
    docker exec "${exec_flags[@]}" -e RUN_APP_INVOKE_AS="$RUN_APP_INVOKE_AS" "$CONTAINER_NAME" ./opensmart/scripts/run_app.sh "$@"
  else
    "$ROOT_DIR/opensmart/scripts/run_app.sh" "$@"
  fi
}

cmd_reset_admin_password() { _run_app_passthrough reset-admin-password; }
cmd_reset_data_all() { _run_app_passthrough reset-data-all; }
cmd_reset_data_ids() { _run_app_passthrough reset-data-ids; }
cmd_reset_data_network() { _run_app_passthrough reset-data-network; }
cmd_reset_all() { _run_app_passthrough reset-all; }
cmd_health() { _run_app_passthrough health; }

# ── shared integrity check (start/restart/recreate/install) ────────────
#
# _wait_stable / _wait_healthy are silent (return 0/1 only) so every caller
# can present the result in whatever format fits it (numbered install steps
# vs. plain lines for start/restart/recreate).

_wait_stable() {
  # Returns 0 once the container is running and stays running with an
  # unchanged restart count for 5s; 1 if it never reaches running or is
  # stuck in a restart loop (a crash-looping container with restart:always
  # can appear "running" for a brief window between crashes).
  local attempt restarts_before restarts_after
  for attempt in $(seq 1 30); do
    if [[ "$(docker container inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null)" == "true" ]]; then
      restarts_before="$(docker container inspect -f '{{.RestartCount}}' "$CONTAINER_NAME" 2>/dev/null || echo 0)"
      sleep 5
      restarts_after="$(docker container inspect -f '{{.RestartCount}}' "$CONTAINER_NAME" 2>/dev/null || echo 0)"
      [[ "$(docker container inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null)" == "true" && "$restarts_after" == "$restarts_before" ]]
      return $?
    fi
    sleep 1
  done
  return 1
}

_wait_healthy() {
  # Returns 0 once /api/health responds ok, polling for up to 5 minutes — a
  # cold start (no cached backend/.venv or frontend/node_modules) has to
  # uv-sync and npm-build inside the container first, which can take a while.
  local attempt port
  for attempt in $(seq 1 150); do
    port="$(_container_host_port)"
    if [[ -n "$port" ]] && curl -sf --max-time 3 "http://localhost:${port}/api/health" 2>/dev/null | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
      return 0
    fi
    sleep 2
  done
  return 1
}

_check_integrity() {
  printf 'Checking container stability... '
  if _wait_stable; then
    printf 'stable\n'
  else
    printf 'failed\n'
    printf '✘ Container "%s" is not stable (crash-looping, or never reached a running state). Check logs with: docker logs %s\n' "$CONTAINER_NAME" "$CONTAINER_NAME" >&2
    return 1
  fi

  printf 'Checking application health (a cold start can take a few minutes)... '
  if _wait_healthy; then
    printf 'healthy\n'
  else
    printf 'unreachable\n'
    printf '✘ Application did not respond within 5 minutes. Check logs with: docker logs %s\n' "$CONTAINER_NAME" >&2
    return 1
  fi
  return 0
}

_start_existing_container() {
  local state
  state="$(docker container inspect -f '{{.State.Status}}' "$CONTAINER_NAME")"
  if [[ "$state" == "running" ]]; then
    printf 'OpenSMART container is already running.\n'
  else
    printf 'Starting the OpenSMART container...\n'
    if ! (cd "$ROOT_DIR/opensmart/containers/run/opensmart" && docker compose start); then
      printf '✘ Failed to start the OpenSMART container.\n' >&2
      exit 1
    fi
  fi
  _check_integrity || exit 1
  printf '✔ OpenSMART is running at http://localhost:%s\n' "$(_container_host_port)"
}

cmd_status() {
  if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker is not installed. Run: sudo ./opensmart.sh install\n' >&2
    exit 1
  fi

  if ! _container_exists; then
    printf 'Container   : not found\n'
    printf 'Try: sudo ./opensmart.sh install\n'
    exit 1
  fi

  local state restarts
  state="$(docker container inspect -f '{{.State.Status}}' "$CONTAINER_NAME")"
  restarts="$(docker container inspect -f '{{.RestartCount}}' "$CONTAINER_NAME")"
  printf 'Container   : %s (restarts: %s)\n' "$state" "$restarts"

  case "$state" in
    running)
      printf 'Started     : %s\n' "$(docker container inspect -f '{{.State.StartedAt}}' "$CONTAINER_NAME")"
      local health port
      health="$(_app_health)"
      port="$(_container_host_port)"
      if [[ "$health" == "healthy" ]]; then
        printf 'Application : healthy (http://localhost:%s/api/health)\n' "${port:-8000}"
      else
        printf 'Application : unreachable (container is running, but the app is not responding yet — it may still be starting, or check: docker logs %s)\n' "$CONTAINER_NAME"
      fi
      ;;
    restarting)
      printf 'Application : crash-looping — check: docker logs %s\n' "$CONTAINER_NAME"
      ;;
    *)
      printf 'Application : not running\n'
      ;;
  esac
}

cmd_stop() {
  if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker is not installed; nothing to stop.\n' >&2
    exit 1
  fi

  if ! _container_exists; then
    printf 'No "%s" container found. Nothing to stop.\n' "$CONTAINER_NAME"
    exit 0
  fi

  local state
  state="$(docker container inspect -f '{{.State.Status}}' "$CONTAINER_NAME")"
  if [[ "$state" != "running" && "$state" != "restarting" ]]; then
    printf 'OpenSMART container is already %s.\n' "$state"
    exit 0
  fi

  printf 'Stopping OpenSMART container...\n'
  if (cd "$ROOT_DIR/opensmart/containers/run/opensmart" && docker compose stop); then
    printf '✔ OpenSMART container stopped.\n'
    printf 'Restart with: (cd opensmart/containers/run/opensmart && docker compose start)\n'
  else
    printf '✘ Failed to stop the OpenSMART container.\n' >&2
    exit 1
  fi
}

cmd_restart() {
  if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker is not installed.\n' >&2
    exit 1
  fi

  if ! _container_exists; then
    printf 'No "%s" container found. Run: sudo ./opensmart.sh install\n' "$CONTAINER_NAME" >&2
    exit 1
  fi

  printf 'Restarting the OpenSMART container...\n'
  if ! (cd "$ROOT_DIR/opensmart/containers/run/opensmart" && docker compose restart); then
    printf '✘ Failed to restart the OpenSMART container.\n' >&2
    exit 1
  fi
  _check_integrity || exit 1
  printf '✔ OpenSMART is running at http://localhost:%s\n' "$(_container_host_port)"
}

cmd_recreate() {
  if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker is not installed.\n' >&2
    exit 1
  fi

  if _container_exists; then
    printf 'This will rebuild the %s image from the current source and Dockerfile,\n' "$IMAGE_NAME"
    printf 'then stop and remove the existing "%s" container and create a new one\n' "$CONTAINER_NAME"
    printf 'from it. The app'"'"'s own data (SQLite DBs, logs, venvs, node_modules)\n'
    printf 'lives in the bind-mounted app directory and is not affected — only the\n'
    printf 'container and image are discarded and recreated.\n\n'
    read -r -p 'Type RECREATE to continue: ' confirmation
    if [[ "$confirmation" != "RECREATE" ]]; then
      printf 'Recreate cancelled.\n'
      exit 0
    fi

    printf 'Removing existing container...\n'
    if ! (cd "$ROOT_DIR/opensmart/containers/run/opensmart" && docker compose rm -f -s); then
      printf '✘ Failed to remove the existing container.\n' >&2
      exit 1
    fi
  else
    printf 'No existing "%s" container found; building and creating a new one.\n' "$CONTAINER_NAME"
  fi

  # Always rebuild first — recreate's whole point is "give me a fresh
  # instance from what's actually in the checkout right now". Without this,
  # `recreate` silently reused whatever image was already tagged
  # "$IMAGE_NAME" on the host, even after `git pull` brought in Dockerfile
  # changes (confirmed on the reference host: a fix landed in the Dockerfile but
  # a plain `recreate` kept running the pre-fix image until an explicit
  # rebuild). `docker build` still uses normal layer caching, so this is
  # fast when nothing actually changed.
  printf 'Rebuilding the %s image from the current source...\n' "$IMAGE_NAME"
  if ! docker build -t "$IMAGE_NAME" -f "$ROOT_DIR/containers/build/opensmart/Dockerfile" "$ROOT_DIR"; then
    printf '✘ Failed to rebuild the %s image.\n' "$IMAGE_NAME" >&2
    exit 1
  fi

  printf 'Creating the OpenSMART container...\n'
  if ! (cd "$ROOT_DIR/opensmart/containers/run/opensmart" && docker compose up -d); then
    printf '✘ Failed to create the OpenSMART container.\n' >&2
    exit 1
  fi
  _check_integrity || exit 1
  printf '✔ OpenSMART is running at http://localhost:%s\n' "$(_container_host_port)"
}

cmd_uninstall() {
  if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker is not installed; nothing to uninstall.\n' >&2
    exit 0
  fi

  printf 'This will stop and remove EVERY container OpenSMART creates or manages —\n'
  printf 'the main app (%s, %s-docker-proxy) and any tool containers ever started\n' "$CONTAINER_NAME" "$CONTAINER_NAME"
  printf 'under opensmart/containers/run/ (Suricata, Zeek, Arkime, OpenSearch,\n'
  printf 'WireGuard, OpenVPN, ...).\n\n'
  printf 'NOT removed: the "%s" Docker network, container images, and application\n' "$NETWORK_NAME"
  printf 'data (SQLite DBs, logs) in the bind-mounted app directory.\n\n'
  read -r -p 'Type UNINSTALL to continue: ' confirmation
  if [[ "$confirmation" != "UNINSTALL" ]]; then
    printf 'Uninstall cancelled.\n'
    exit 0
  fi

  mkdir -p "$LOG_DIR"
  local uninstall_log="$LOG_DIR/uninstall.log"
  printf '\n===== opensmart.sh uninstall started %s =====\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$uninstall_log"

  local dir name
  for dir in "$ROOT_DIR"/opensmart/containers/run/*/; do
    [[ -f "${dir}docker-compose.yml" ]] || continue
    name="$(basename "$dir")"
    printf 'Removing %s... ' "$name"
    if grep -q 'profiles:' "${dir}docker-compose.yml" 2>/dev/null; then
      # Only opensmart/containers/run/openvpn/ currently gates its service
      # behind a "manual" profile (see that file's own comments) — without
      # --profile manual, `down` won't see/remove it even if it was started.
      (cd "$dir" && docker compose --profile manual down) >> "$uninstall_log" 2>&1 \
        && printf 'done\n' || printf 'nothing to remove\n'
    else
      (cd "$dir" && docker compose down) >> "$uninstall_log" 2>&1 \
        && printf 'done\n' || printf 'nothing to remove\n'
    fi
  done

  printf '\n✔ OpenSMART containers removed. Full log: %s\n' "$uninstall_log"
  printf 'Run "sudo ./opensmart.sh install" to set it up again.\n'
}

# ── install helpers ─────────────────────────────────────────────────────────
#
# Terminal output is kept to one line per main step; every command's full
# (often noisy) output goes only to $INSTALL_LOG. On failure, the current
# step line is closed with "failed" and the log path is pointed out.

_log_init() {
  mkdir -p "$LOG_DIR"
  printf '\n===== opensmart.sh install started %s =====\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$INSTALL_LOG"
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
    _step_fail "opensmart.sh install must be run as root. Try: sudo ./opensmart.sh install"
  fi
  printf 'ok\n'
}

_install_check_path_traversable() {
  # The container runs as a non-root user (uid 1000) and needs every ancestor
  # directory of the bind-mounted checkout to be traversable (the "other"
  # execute bit) for it to reach anything inside — chowning the checkout
  # itself (see _install_fix_ownership) doesn't help if a directory ABOVE it
  # blocks traversal. Installing under /root (mode 700, root-only) is the
  # common way to hit this: the container starts, but its own entrypoint
  # gets "Permission denied" trying to exec anything inside the mount,
  # crash-looping with no indication of why. Confirmed twice against a real
  # Docker Engine before this check was added.
  _step "Checking the install path is reachable by the container's non-root user"
  local dir="$ROOT_DIR" perms
  while [[ "$dir" != "/" && -n "$dir" ]]; do
    perms="$(stat -c '%A' "$dir" 2>/dev/null)" || break
    if [[ "${perms:9:1}" != "x" ]]; then
      _step_fail "\"$dir\" is not traversable by the container's non-root user (permissions: $perms). The container will start but crash-loop with \"Permission denied\" trying to run anything inside the bind mount. This usually means installing under /root (mode 700, root-only). Move this checkout to a world-readable location (e.g. /opt, /srv, or a regular user's home directory) and re-run install from there."
    fi
    dir="$(dirname "$dir")"
  done
  printf 'ok\n'
}

_install_check_distro() {
  _step "Detecting Linux distribution"
  if [[ ! -r /etc/os-release ]]; then
    _step_fail "Cannot detect the Linux distribution (/etc/os-release not found). opensmart.sh install only supports Debian and Ubuntu."
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  local id="${ID:-}"
  local id_like="${ID_LIKE:-}"
  if [[ "$id" != "debian" && "$id" != "ubuntu" && "$id_like" != *debian* ]]; then
    _step_fail "Unsupported Linux distribution: ${PRETTY_NAME:-$id}. opensmart.sh install only supports Debian and Ubuntu (apt-based)."
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
  # This chown is exactly what makes a later `git pull` (typically run as
  # root, to fetch updates before `install --recreate`) fail with "detected
  # dubious ownership" — git refuses to operate in a repo it doesn't own
  # unless told to trust it explicitly. Register that trust now, as root,
  # so upgrading via git pull works without the operator hitting this and
  # having to work it out themselves. Best-effort: does not fail install if
  # git isn't installed or this isn't a git checkout.
  command -v git >/dev/null 2>&1 && git config --global --add safe.directory "$ROOT_DIR" >> "$INSTALL_LOG" 2>&1 || true
  printf 'done\n'
}

_install_run_container() {
  _step "Starting the $CONTAINER_NAME container"
  (cd "$ROOT_DIR/opensmart/containers/run/opensmart" && docker compose up -d) >> "$INSTALL_LOG" 2>&1 \
    || _step_fail "Failed to start the $CONTAINER_NAME container."
  printf 'done\n'
}

_install_wait_running() {
  _step "Waiting for the container to stabilize"
  if _wait_stable; then
    printf 'stable\n'
  else
    _step_fail "Container \"$CONTAINER_NAME\" did not reach a stable running state (crash-looping, or never started). Check logs with: docker logs $CONTAINER_NAME"
  fi
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
  return 1
}

cmd_install() {
  print_banner
  _log_init
  printf 'Full installer log: %s\n\n' "$INSTALL_LOG"
  _install_require_root
  _install_check_path_traversable
  _install_check_distro
  _install_docker_engine
  _install_create_network
  _install_build_image
  _install_fix_ownership
  _install_run_container
  _install_wait_running
  # A container that reaches a "stable" running state above can still crash
  # again shortly after — that check only confirms it wasn't caught
  # crash-looping during a short observation window, not that it will stay
  # up forever (e.g. a cold-start dependency sync that keeps failing on a
  # slow/unreliable network can crash-loop for much longer than that
  # window). Only print the unconditional success banner if the
  # first-run-password wait actually confirmed the app came up; otherwise
  # say so plainly instead of claiming success right after a timeout warning.
  if _install_show_password; then
    printf '✔ OpenSMART is running at http://0.0.0.0:8000\n'
  else
    printf '⚠ Install finished, but readiness could not be confirmed within 5 minutes.\n' >&2
    printf 'The container may still be starting (e.g. a slow network stalling the\n' >&2
    printf 'first-run dependency sync) or may be crash-looping. Check: docker ps,\n' >&2
    printf 'docker logs %s, and %s\n' "$CONTAINER_NAME" "$INSTALL_LOG" >&2
    exit 1
  fi
}

case "${1:-}" in
  start)
    shift
    cmd_start "$@"
    ;;
  stop)
    cmd_stop
    ;;
  status)
    cmd_status
    ;;
  restart)
    cmd_restart
    ;;
  recreate)
    cmd_recreate
    ;;
  install)
    cmd_install
    ;;
  uninstall)
    cmd_uninstall
    ;;
  reset-admin-password)
    cmd_reset_admin_password
    ;;
  reset-data-all)
    cmd_reset_data_all
    ;;
  reset-data-ids)
    cmd_reset_data_ids
    ;;
  reset-data-network)
    cmd_reset_data_network
    ;;
  reset-all)
    cmd_reset_all
    ;;
  health)
    cmd_health
    ;;
  version|--version|-v)
    cmd_version
    ;;
  --help|-h)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
