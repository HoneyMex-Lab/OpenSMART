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
STEP_TOTAL=16
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
  start [--bind ADDRESS:PORT]
        [--reverse-proxy http|https]   If an "opensmart" container already exists
                                        (the normal case), starts it (if not already
                                        running), checks its integrity, and brings up
                                        the nginx front-door reverse proxy — the ONLY
                                        externally-reachable entry point (the app
                                        container's own :8000 is loopback-only) —
                                        serving the app and the tool aliases
                                        (/arkime /wazuh /proxmox /opnsense) from one
                                        origin. --reverse-proxy picks how the proxy
                                        answers plain HTTP: "https" (default;
                                        self-signed cert, HTTP redirects to HTTPS) or
                                        "http" (no redirect). --bind ADDRESS:PORT sets
                                        the proxy's own bind address/port (whichever
                                        matches the active mode; default
                                        0.0.0.0:443). Both choices persist in the
                                        proxy's .env. --prod is ignored here (the
                                        container always runs in prod mode).
                                        Otherwise (no container — host/dev mode) runs
                                        the app directly at ADDRESS:PORT with NO
                                        proxy; --reverse-proxy doesn't apply there.
                                        [--prod] is also accepted in host/dev mode.
                                        Host-only mode defaults to --bind 0.0.0.0:8000.
  stop                                 Stop the OpenSMART container (docker compose stop).
  status                               Show the OpenSMART container state and whether the
                                        application inside it is responding.
  restart                              Restart the existing OpenSMART container and
                                        check its integrity afterward.
  recreate                             Rebuild the opensmart/web image from the current
                                        source, delete the existing OpenSMART container,
                                        and create a new one from the rebuilt image, then
                                        check its integrity. Asks for confirmation.
  install [--bind ADDRESS:PORT]
          [--reverse-proxy http|https] Install Docker Engine (Debian/Ubuntu only),
                                        build the opensmart/web image, and run
                                        OpenSMART as a container fronted by the nginx
                                        reverse proxy (see "start" above for what
                                        --bind/--reverse-proxy do here — same
                                        meaning). Requires root.
  uninstall                            Stop and remove every container OpenSMART
                                        creates or manages (main app + proxy, and any
                                        tool containers ever started). Prompts to
                                        choose containers-only (keeps the "opensmart"
                                        network, images, and app data) or full
                                        removal (also permanently deletes app data:
                                        databases, logs, PCAPs, indices, VPN certs).
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
  local proxy_mode=""
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
      --reverse-proxy)
        proxy_mode="${2:?--reverse-proxy requires http or https}"
        if [[ "$proxy_mode" != "http" && "$proxy_mode" != "https" ]]; then
          printf 'Invalid --reverse-proxy value: %s (expected http or https)\n' "$proxy_mode" >&2
          exit 1
        fi
        shift 2
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

  # Fail fast on a malformed --bind right after parsing, before doing
  # anything else — cheap up front, versus surfacing it after work has
  # already happened (matters more for `install`, see there; harmless to
  # check early here too for consistency). Skipped when bind is empty: each
  # branch below has its own default for that case.
  if [[ -n "$bind" ]]; then
    _require_valid_bind "$bind" "--bind"
  fi

  # If the "opensmart" container already exists, this is a container-managed
  # deployment: (re)start the existing container and verify it rather than
  # running the app directly on the host. This detection only makes sense on
  # the HOST: since the container itself now also has a `docker` CLI (for
  # sibling-container provisioning, reaching the Docker API through
  # docker-socket-proxy), running this script *inside* the opensmart
  # container would otherwise see itself as "an existing container" and loop
  # trying to manage itself instead of actually starting the app —
  # /.dockerenv is the standard signal that we're inside one.
  #
  # --bind means something DIFFERENT here than in host/dev mode below: the
  # app container's own :8000 is loopback-only (see containers/run/opensmart/
  # docker-compose.yml) — the front-door proxy is the only externally-
  # reachable entry point, so --bind sets the PROXY's own bind address:port
  # instead (whichever port matches --reverse-proxy's mode, https by
  # default). --prod has no effect here — the container always runs in prod
  # mode per its own docker-compose.yml.
  if [[ ! -f /.dockerenv ]] && command -v docker >/dev/null 2>&1 && _container_exists; then
    if [[ "$prod" -eq 1 ]]; then
      printf 'Note: an "%s" container already exists; --prod is ignored (the container\n' "$CONTAINER_NAME"
      printf 'always runs in --prod mode). Use ./opensmart.sh recreate to replace it.\n\n'
    fi
    _start_existing_container "$proxy_mode" "$bind"
    return
  fi

  # From here down the app runs directly on the host (dev mode) — the nginx
  # front-door proxies to the "opensmart" container by Docker DNS name,
  # which doesn't exist in this mode, so --reverse-proxy can't apply; --bind
  # reverts to its host-mode meaning below (run the app directly at
  # ADDRESS:PORT, no proxy).
  if [[ -n "$proxy_mode" ]]; then
    printf -- '--reverse-proxy needs the containerized deployment (run "sudo ./opensmart.sh install"\n' >&2
    printf 'first). In direct/host mode use --bind ADDRESS:PORT instead.\n' >&2
    exit 1
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

# Update-or-append KEY=VALUE in an env file without touching other keys
# (the same .env may hold user-set PROXMOX_UPSTREAM/OPNSENSE_UPSTREAM etc.).
_set_env_kv() {
  local file="$1" key="$2" value="$3"
  touch "$file" 2>/dev/null || return 1
  if grep -q "^${key}=" "$file" 2>/dev/null; then
    # sed -i with a temp file keeps this portable and atomic enough here.
    sed "s|^${key}=.*|${key}=${value}|" "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
  # This script runs as root (host-side install/start), but the app
  # container's own backend (uid 1000) also writes into some of these same
  # .env files (e.g. nginx's, for OPENSMART_HOSTNAME — see provisioning.py's
  # own _set_env_kv) — confirmed live: without this, root-created files were
  # unreadable-for-writing by that container, "Permission denied", same
  # unprivileged-UID-mapping story as this project's other cross-container
  # file exchanges. Not security-sensitive (operational config, no secrets).
  chmod 666 "$file" 2>/dev/null || true
}

# Validate an ADDRESS:PORT value, exiting with a clear error if malformed.
# Used to fail fast on a typo'd --bind right after argument parsing —
# before any heavy work — in addition to _start_front_proxy's own check
# right before it actually applies the value (belt and suspenders: a
# caller that skips the early check, e.g. a future one, still can't write
# a malformed value into the proxy's .env).
_require_valid_bind() {
  local bind="$1" label="$2"
  local addr="${bind%:*}" port="${bind##*:}"
  if [[ -z "$addr" || "$port" == "$bind" || ! "$port" =~ ^[0-9]+$ ]]; then
    printf 'Invalid %s value: %s (expected ADDRESS:PORT)\n' "$label" "$bind" >&2
    exit 1
  fi
}

# Read KEY's current value from an env file, or $3 if the file/key is absent.
_get_env_kv() {
  local file="$1" key="$2" default="$3" line
  if [[ -f "$file" ]]; then
    line="$(grep "^${key}=" "$file" 2>/dev/null | tail -n1)"
    if [[ -n "$line" ]]; then
      printf '%s' "${line#*=}"
      return
    fi
  fi
  printf '%s' "$default"
}

_start_front_proxy() {
  # Bring up (or reconcile) the nginx front-door that serves the app (with a
  # self-signed HTTPS certificate) and the tool path aliases (/arkime,
  # /wazuh, ...) from one origin — the ONLY externally-reachable entry point
  # now that the app container's own :8000 is published loopback-only (see
  # containers/run/opensmart/docker-compose.yml).
  #
  # $1 (optional): http|https — persisted into the proxy's .env so later
  # restarts (including ones triggered from inside the app via the socket
  # proxy) keep the chosen mode; empty keeps whatever the .env / compose
  # default (https) says.
  # $2 (optional): ADDRESS:PORT to bind the proxy's user-facing listener to
  # (whichever port matches the active mode — https by default, http if
  # mode is "http"); empty keeps the existing/default bind (0.0.0.0:443).
  # Also recomputes OPENSMART_HTTPS_REDIRECT_SUFFIX every call so the
  # http->https redirect target stays correct even if only $1 changed.
  #
  # Best-effort throughout: the proxy is additive, so a failure here must
  # never fail install/start of the core app — it just logs and moves on.
  # Any PROXMOX_UPSTREAM/OPNSENSE_UPSTREAM/OPENSMART_HOSTNAME already in the
  # environment or .env is inherited automatically.
  local mode="${1:-}"
  local bind="${2:-}"
  local dir="$ROOT_DIR/opensmart/containers/run/nginx"
  [[ -f "$dir/docker-compose.yml" ]] || return 0
  local env_file="$dir/.env"

  if [[ -n "$mode" ]]; then
    _set_env_kv "$env_file" "OPENSMART_PROXY_MODE" "$mode" || true
  fi

  if [[ -n "$bind" ]]; then
    _require_valid_bind "$bind" "--bind"
    local addr="${bind%:*}" port="${bind##*:}"
    local effective_mode
    effective_mode="${mode:-$(_get_env_kv "$env_file" OPENSMART_PROXY_MODE https)}"
    _set_env_kv "$env_file" "OPENSMART_PROXY_BIND" "$addr" || true
    if [[ "$effective_mode" == "http" ]]; then
      _set_env_kv "$env_file" "OPENSMART_PROXY_HTTP_PORT" "$port" || true
    else
      _set_env_kv "$env_file" "OPENSMART_PROXY_HTTPS_PORT" "$port" || true
    fi
  fi

  local https_port
  https_port="$(_get_env_kv "$env_file" OPENSMART_PROXY_HTTPS_PORT 443)"
  if [[ "$https_port" == "443" ]]; then
    _set_env_kv "$env_file" "OPENSMART_HTTPS_REDIRECT_SUFFIX" "" || true
  else
    _set_env_kv "$env_file" "OPENSMART_HTTPS_REDIRECT_SUFFIX" ":${https_port}" || true
  fi

  printf 'Starting the front-door reverse proxy (nginx)... '
  if (cd "$dir" && docker compose up -d) >/dev/null 2>&1; then
    printf 'done\n'
  else
    printf 'skipped (proxy unavailable; tool aliases will be off, app unaffected)\n'
  fi
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
  local proxy_mode="${1:-}"
  local proxy_bind="${2:-}"
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
  _start_front_proxy "$proxy_mode" "$proxy_bind"
  printf '✔ OpenSMART is running:\n'
  printf '    via the front-door proxy : https://<hostname>/  (tool aliases: /arkime /wazuh /proxmox /opnsense)\n'
  printf '    local only               : http://127.0.0.1:%s\n' "$(_container_host_port)"
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

  # Same reasoning as above: keep the native module images (Suricata, Zeek,
  # WireGuard, OpenVPN) in sync with the current checkout rather than
  # silently reusing whatever was tagged opensmart/base|suricata|zeek|
  # wireguard|openvpn from a previous install.
  printf 'Rebuilding native module images (base, Suricata, Zeek, WireGuard, OpenVPN)...\n'
  if ! _build_native_module_image base \
    || ! _build_native_module_image suricata \
    || ! _build_native_module_image zeek \
    || ! _build_native_module_image wireguard \
    || ! _build_native_module_image openvpn; then
    printf '✘ Failed to rebuild native module images.\n' >&2
    exit 1
  fi

  printf 'Creating the OpenSMART container...\n'
  if ! (cd "$ROOT_DIR/opensmart/containers/run/opensmart" && docker compose up -d); then
    printf '✘ Failed to create the OpenSMART container.\n' >&2
    exit 1
  fi
  _check_integrity || exit 1
  _start_front_proxy
  printf '✔ OpenSMART is running at http://localhost:%s\n' "$(_container_host_port)"
}

_uninstall_remove_containers() {
  # $1: log file to append docker compose output to.
  local log="$1" dir name
  # Depth 1: opensmart/containers/run/<tool>/docker-compose.yml (Suricata,
  # Zeek, Arkime, OpenSearch, WireGuard, OpenVPN, Wazuh, the main app, ...).
  for dir in "$ROOT_DIR"/opensmart/containers/run/*/; do
    [[ -f "${dir}docker-compose.yml" ]] || continue
    name="$(basename "$dir")"
    printf 'Removing %s... ' "$name"
    if grep -q 'profiles:' "${dir}docker-compose.yml" 2>/dev/null; then
      # Only opensmart/containers/run/openvpn/ currently gates its service
      # behind a "manual" profile (see that file's own comments) — without
      # --profile manual, `down` won't see/remove it even if it was started.
      (cd "$dir" && docker compose --profile manual down) >> "$log" 2>&1 \
        && printf 'done\n' || printf 'nothing to remove\n'
    else
      (cd "$dir" && docker compose down) >> "$log" 2>&1 \
        && printf 'done\n' || printf 'nothing to remove\n'
    fi
  done
  # Depth 2: opensmart/containers/run/vpn/<instance>/docker-compose.yml —
  # generated per-instance by the VPN module (backend/app/vpn.py), one
  # level deeper than every other tool, so the loop above never sees them.
  for dir in "$ROOT_DIR"/opensmart/containers/run/vpn/*/; do
    [[ -f "${dir}docker-compose.yml" ]] || continue
    name="vpn/$(basename "$dir")"
    printf 'Removing %s... ' "$name"
    (cd "$dir" && docker compose down) >> "$log" 2>&1 \
      && printf 'done\n' || printf 'nothing to remove\n'
  done
}

_uninstall_purge_data() {
  # $1: log file. Deletes every bind-mounted volumes/data/ (PCAPs,
  # OpenSearch/Wazuh indices, VPN certs and keys, capture logs), the
  # generated VPN instance directories themselves (matching vpn.py's own
  # delete_instance()), and the main app's SQLite databases — everything a
  # fresh install would otherwise find already sitting there and reuse.
  local log="$1" dir
  printf 'Deleting application data... '
  {
    for dir in "$ROOT_DIR"/opensmart/containers/run/*/volumes/data; do
      [[ -d "$dir" ]] && rm -rf "$dir"
    done
    [[ -d "$ROOT_DIR/opensmart/containers/run/vpn" ]] && rm -rf "$ROOT_DIR/opensmart/containers/run/vpn"
    rm -f "$ROOT_DIR"/opensmart/backend/opensmart*.db "$ROOT_DIR"/opensmart/backend/opensmart*.db-shm "$ROOT_DIR"/opensmart/backend/opensmart*.db-wal
  } >> "$log" 2>&1
  printf 'done\n'
}

cmd_uninstall() {
  if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker is not installed; nothing to uninstall.\n' >&2
    exit 0
  fi

  printf 'OpenSMART uninstall — choose how much to remove:\n\n'
  printf '  1) Containers only\n'
  printf '     Stops and removes EVERY container OpenSMART creates or manages —\n'
  printf '     the main app (%s, %s-docker-proxy) and any tool containers ever\n' "$CONTAINER_NAME" "$CONTAINER_NAME"
  printf '     started under opensmart/containers/run/ (Suricata, Zeek, Arkime,\n'
  printf '     OpenSearch, WireGuard, OpenVPN, Wazuh, VPN module instances, ...).\n'
  printf '     Kept: the "%s" Docker network, container images, and all\n' "$NETWORK_NAME"
  printf '     application data (SQLite databases, logs, PCAPs, indices,\n'
  printf '     certificates). Reinstalling later picks up right where you left off.\n\n'
  printf '  2) Full removal — containers AND all data\n'
  printf '     Everything in option 1, PLUS permanently deletes every tool'"'"'s\n'
  printf '     bind-mounted volumes/data/ (PCAPs, OpenSearch/Wazuh indices, VPN\n'
  printf '     certs and keys, capture logs), every generated VPN instance, the\n'
  printf '     main app'"'"'s SQLite databases, and logs/. THIS CANNOT BE UNDONE.\n\n'

  local choice
  read -r -p 'Choose an option [1/2, anything else cancels]: ' choice
  case "$choice" in
    1) ;;
    2) ;;
    *) printf 'Uninstall cancelled.\n'; exit 0 ;;
  esac

  if [[ "$choice" == "1" ]]; then
    read -r -p 'Type UNINSTALL to continue: ' confirmation
    if [[ "$confirmation" != "UNINSTALL" ]]; then
      printf 'Uninstall cancelled.\n'
      exit 0
    fi
  else
    printf '\nThis permanently destroys application data — PCAPs, security alerts,\n'
    printf 'indices, VPN certificates/keys, and the app'"'"'s own databases. There is no\n'
    printf 'undo and no backup is taken.\n\n'
    read -r -p 'Type DELETE ALL DATA to continue: ' confirmation
    if [[ "$confirmation" != "DELETE ALL DATA" ]]; then
      printf 'Uninstall cancelled.\n'
      exit 0
    fi
  fi

  mkdir -p "$LOG_DIR"
  local uninstall_log="$LOG_DIR/uninstall.log"
  printf '\n===== opensmart.sh uninstall started %s (option %s) =====\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$choice" >> "$uninstall_log"

  _uninstall_remove_containers "$uninstall_log"

  if [[ "$choice" == "1" ]]; then
    printf '\n✔ OpenSMART containers removed. Full log: %s\n' "$uninstall_log"
    printf 'Run "sudo ./opensmart.sh install" to set it up again.\n'
  else
    _uninstall_purge_data "$uninstall_log"
    printf '\n===== opensmart.sh uninstall finished %s =====\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$uninstall_log"
    rm -rf "$LOG_DIR"
    printf '\n✔ OpenSMART containers and all application data removed.\n'
    printf 'Run "sudo ./opensmart.sh install" to set it up again from scratch.\n'
  fi
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

_install_replace_existing_deployment() {
  # Sub-flow of _install_check_existing_deployment's "replace" choice.
  # Deliberately mirrors cmd_uninstall's own two-option + typed-confirmation
  # flow exactly (same wording, same safety net) rather than inventing a
  # separate path, and reuses its extracted helpers so there is exactly one
  # place that knows how to actually remove things.
  printf '\nReplace existing deployment — choose how much to remove first:\n\n'
  printf '  1) Containers only (keeps application data — PCAPs, alerts, VPN certs, DBs)\n'
  printf '  2) Full removal — containers AND all application data. THIS CANNOT BE UNDONE.\n\n'
  local choice
  read -r -p 'Choose an option [1/2, anything else cancels]: ' choice
  case "$choice" in
    1) ;;
    2) ;;
    *) printf 'Install cancelled.\n'; exit 0 ;;
  esac

  local confirmation
  if [[ "$choice" == "1" ]]; then
    read -r -p 'Type UNINSTALL to continue: ' confirmation
    if [[ "$confirmation" != "UNINSTALL" ]]; then
      printf 'Install cancelled.\n'
      exit 0
    fi
  else
    printf '\nThis permanently destroys application data — PCAPs, security alerts,\n'
    printf 'indices, VPN certificates/keys, and the app'"'"'s own databases. There is no\n'
    printf 'undo and no backup is taken.\n\n'
    read -r -p 'Type DELETE ALL DATA to continue: ' confirmation
    if [[ "$confirmation" != "DELETE ALL DATA" ]]; then
      printf 'Install cancelled.\n'
      exit 0
    fi
  fi

  printf '\n===== opensmart.sh install: replacing existing deployment %s (option %s) =====\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$choice" >> "$INSTALL_LOG"
  printf 'Removing existing deployment...\n'
  _uninstall_remove_containers "$INSTALL_LOG"
  if [[ "$choice" == "2" ]]; then
    _uninstall_purge_data "$INSTALL_LOG"
  fi
  printf '✔ Existing deployment removed. Continuing with a clean install...\n\n'
}

_install_confirm_proceed() {
  # A general pre-flight gate, separate from _install_check_existing_
  # deployment's own more specific prompt (which only fires when something
  # is already there) — this one always asks, even on a genuinely clean
  # host, since install does real host-level work before the operator sees
  # any of the numbered steps. Not step-numbered itself (parallels how
  # _install_check_existing_deployment's own interactive follow-up isn't
  # separately numbered from its stepped "found"/"none found" line).
  #
  # Non-interactive-safe: closed/empty stdin (read returns immediately)
  # defaults to "yes" — unattended/scripted installs (cloud-init, CI, a
  # fresh-VM setup script) must keep working exactly as before this gate
  # existed, matching the same philosophy as every other default in this
  # installer (see _install_check_existing_deployment, _start_front_proxy).
  printf 'This will set up OpenSMART on this host:\n'
  printf '  - Install Docker Engine if not already present (Debian/Ubuntu only)\n'
  printf '  - Apply host-level settings the bundled tools need (vm.max_map_count,\n'
  printf '    a /dev/net/tun device, ulimits for Wazuh)\n'
  printf '  - Build the OpenSMART images and run it as a set of Docker containers\n'
  printf '  - Bring up the front-door reverse proxy (self-signed HTTPS by default)\n\n'
  local confirmation
  read -r -p 'Continue with the install? [Y/n]: ' confirmation
  confirmation="${confirmation:-y}"
  case "$confirmation" in
    y|Y|yes|YES|Yes) ;;
    *)
      printf 'Install cancelled.\n'
      exit 0
      ;;
  esac
  printf '\n'
}

_install_check_existing_deployment() {
  # First thing install does (after confirming root) — before touching
  # anything, including installing Docker itself. Detects a deployment left
  # by a previous install/recreate via the same signal _start_existing_
  # container uses ($CONTAINER_NAME existing at all, running or not).
  # Never fails the install: an unattended/non-interactive run (closed or
  # /dev/null stdin — read returns empty immediately) falls through to the
  # same default this script always had before this check existed: keep
  # whatever is there and continue installing in place.
  _step "Checking for an existing OpenSMART deployment"
  if ! command -v docker >/dev/null 2>&1 || ! _container_exists; then
    printf 'none found\n'
    return
  fi
  printf 'found\n'

  local state
  state="$(docker container inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo unknown)"
  printf '\nAn existing OpenSMART deployment was found (container "%s": %s).\n' "$CONTAINER_NAME" "$state"
  printf 'Installing again will rebuild the image and update it IN PLACE — existing\n'
  printf 'containers, configuration, and application data are all kept — unless you\n'
  printf 'choose to replace it below.\n\n'
  printf '  1) Keep it — continue installing (updates in place)\n'
  printf '  2) Replace it — fully remove the existing deployment first, then install\n'
  printf '     clean (you will be asked whether to also delete application data,\n'
  printf '     same options as ./opensmart.sh uninstall)\n'
  printf '  3) Cancel\n\n'

  local choice
  read -r -p 'Choose an option [1/2/3, default 1 — keep and continue]: ' choice
  choice="${choice:-1}"
  case "$choice" in
    1)
      printf 'Keeping the existing deployment; continuing install.\n\n'
      ;;
    2)
      _install_replace_existing_deployment
      ;;
    *)
      printf 'Install cancelled.\n'
      exit 0
      ;;
  esac
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

_install_check_host_resources() {
  # Informational only — never fails the install; OpenSMART's core app runs
  # fine on modest hardware. This is specifically about the OPTIONAL tool
  # stack: Wazuh (manager+indexer+dashboard) and Arkime's own OpenSearch
  # dependency each run a JVM-based OpenSearch-family indexer, which is
  # what actually needs real resources — confirmed firsthand on this
  # project's reference host: both together OOM-loop repeatedly below ~8GB RAM,
  # and PCAP/index storage fills a tight disk fast.
  #
  # Two recommended tiers (kept in sync by hand with
  # opensmart/backend/app/provisioning.py's HOST_RESOURCE_TIERS — same
  # numbers, same reasoning, comment there points back here):
  #   "core"  (Suricata/Zeek/Network IDS+Traffic/VPN only): 2 CPU, ~4GB RAM, ~10GB disk
  #   "full"  (adds Wazuh + Arkime/OpenSearch):             4 CPU, ~8GB RAM, ~20GB disk
  #
  # The result is written into the OpenSMART app container's own .env
  # (OPENSMART_RESOURCE_* vars) so the backend can serve it to the Wizard,
  # which highlights the modules/tools this host's tier can't comfortably
  # run and leaves them out of the "recommended defaults" pre-selection —
  # the user can still enable them manually.
  _step "Checking host resources against recommended tiers"
  local cpu_count mem_total_mb disk_free_gb tier constrained_tools constrained_modules
  cpu_count="$(nproc 2>/dev/null || echo 1)"
  mem_total_mb="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
  disk_free_gb="$(df -BG --output=avail "$ROOT_DIR" 2>/dev/null | tail -1 | tr -dc '0-9')"
  disk_free_gb="${disk_free_gb:-0}"

  if [[ "$cpu_count" -ge 4 && "$mem_total_mb" -ge 7500 && "$disk_free_gb" -ge 18 ]]; then
    tier="full"; constrained_tools=""; constrained_modules=""
  elif [[ "$cpu_count" -ge 2 && "$mem_total_mb" -ge 3800 && "$disk_free_gb" -ge 9 ]]; then
    tier="core"; constrained_tools="Wazuh,Arkime"; constrained_modules="Threat Detection Alerts,Endpoint,Vulnerability Management"
  else
    tier="minimal"; constrained_tools="Wazuh,Arkime"; constrained_modules="Threat Detection Alerts,Endpoint,Vulnerability Management"
  fi

  printf 'detected: %s CPU, %s MB RAM, %s GB free disk -> tier: %s\n' "$cpu_count" "$mem_total_mb" "$disk_free_gb" "$tier"
  if [[ "$tier" == "full" ]]; then
    printf '  ✔ Sufficient for the full default tool set (Suricata, Zeek, Wazuh, Arkime, VPN).\n'
  else
    printf '  ⚠ Below the recommended "full" tier (4 CPU / ~8GB RAM / ~20GB disk).\n' >&2
    printf '  Wazuh and Arkime (both run a JVM-based OpenSearch-family indexer) are the\n' >&2
    printf '  most likely to be unstable on this host. The Wizard will flag them and leave\n' >&2
    printf '  them out of the recommended defaults; you can still enable them manually.\n' >&2
    if [[ "$tier" == "minimal" ]]; then
      printf '  This host is also below the minimal "core" tier (2 CPU / ~4GB RAM / ~10GB\n' >&2
      printf '  disk) — expect instability even for Suricata/Zeek/VPN under real traffic.\n' >&2
    fi
  fi

  local env_file="$ROOT_DIR/opensmart/containers/run/opensmart/.env"
  _set_env_kv "$env_file" "OPENSMART_RESOURCE_TIER" "$tier"
  _set_env_kv "$env_file" "OPENSMART_RESOURCE_CPU" "$cpu_count"
  _set_env_kv "$env_file" "OPENSMART_RESOURCE_MEM_MB" "$mem_total_mb"
  _set_env_kv "$env_file" "OPENSMART_RESOURCE_DISK_GB" "$disk_free_gb"
  _set_env_kv "$env_file" "OPENSMART_RESOURCE_CONSTRAINED_TOOLS" "$constrained_tools"
  _set_env_kv "$env_file" "OPENSMART_RESOURCE_CONSTRAINED_MODULES" "$constrained_modules"
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

_install_set_max_map_count() {
  # Standard requirement for any OpenSearch/Elasticsearch-family container
  # (mmapfs storage) — the Wazuh indexer (opensmart/containers/run/wazuh/)
  # needs this just like the existing "opensearch" container does. The
  # default on most distros (65530) is too low; Wazuh/OpenSearch/Elasticsearch
  # all document this same fix. Applied unconditionally (harmless if unused)
  # since provisioning.py runs as uid 1000 inside a container and can't touch
  # host sysctls itself — only this host-side, root install step can.
  local required=262144
  local current
  current="$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)"

  _step "Setting vm.max_map_count=$required (required by OpenSearch-family indexers)"

  if [[ "$current" -ge "$required" ]]; then
    printf 'already %s, skipping\n' "$current"
    return
  fi

  if {
    printf 'vm.max_map_count=%s\n' "$required" > /etc/sysctl.d/99-opensmart-indexer.conf &&
    sysctl -w "vm.max_map_count=$required"
  } >> "$INSTALL_LOG" 2>&1; then
    printf 'done\n'
    return
  fi

  # sysctl -w can fail with "permission denied" specifically when this host
  # is itself an unprivileged LXC container: vm.max_map_count isn't
  # namespaced, so writes to it are blocked from inside the container
  # regardless of root, even though /etc/sysctl.d writes still succeed.
  # That's a host-level (Proxmox) setting, not something this install step
  # can reach — so warn instead of hard-failing the whole install.
  if [[ "$(systemd-detect-virt 2>/dev/null)" == "lxc" ]]; then
    printf 'skipped (unprivileged LXC)\n'
    printf '  ⚠ Could not set vm.max_map_count from inside this LXC container (current: %s, required: %s).\n' "$current" "$required" >&2
    printf '  Run this on the Proxmox/LXC host itself, not inside the container:\n' >&2
    printf '    echo "vm.max_map_count=%s" > /etc/sysctl.d/99-opensmart-indexer.conf && sysctl -w vm.max_map_count=%s\n' "$required" "$required" >&2
    printf '  OpenSearch/Wazuh indexers will fail to start until this is set.\n' >&2
    return
  fi

  _step_fail "Failed to set vm.max_map_count."
}

_install_ensure_tun_device() {
  # OpenVPN instances (backend/app/vpn.py) need /dev/net/tun on the Docker
  # host. Bare-metal/VM hosts have it; unprivileged LXC hosts usually don't,
  # and creating it needs the LXC's device cgroup to allow c 10:200 — a
  # Proxmox-host-side setting we can't change from in here. Best-effort:
  # create it where permitted, warn with the exact host-side fix otherwise
  # (WireGuard instances don't need it, so this never fails the install).
  _step "Ensuring /dev/net/tun exists (needed by OpenVPN instances)"
  if [[ -c /dev/net/tun ]]; then
    printf 'already present\n'
    return
  fi
  if mkdir -p /dev/net && mknod /dev/net/tun c 10 200 2>/dev/null && chmod 666 /dev/net/tun; then
    printf 'created\n'
    printf '  Note: created at runtime — on an LXC this does not survive a reboot unless\n'
    printf '  the container config binds it (see the instructions below for permanence).\n'
    return
  fi
  printf 'skipped (not permitted)\n'
  printf '  ⚠ Could not create /dev/net/tun from inside this container/host.\n' >&2
  printf '  On a Proxmox LXC, add to /etc/pve/lxc/<VMID>.conf on the Proxmox host:\n' >&2
  printf '    lxc.cgroup2.devices.allow: c 10:200 rwm\n' >&2
  printf '    lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file\n' >&2
  printf '  then restart the LXC. Until then OpenVPN instances fail to start\n' >&2
  printf '  (clear error in the UI); WireGuard instances are unaffected.\n' >&2
}

_install_configure_wazuh_ulimits() {
  # Wazuh's manager/indexer (containers/run/wazuh/docker-compose.yml)
  # request unlimited memlock and 655360/65536 open files by default
  # (overridable via WAZUH_MEMLOCK_LIMIT/WAZUH_MANAGER_NOFILE_LIMIT/
  # WAZUH_INDEXER_NOFILE_LIMIT in that project's .env). Unprivileged LXC
  # hosts often cap both below what Wazuh asks for; runc then refuses to
  # even start the container ("error setting rlimit type 8/7: operation
  # not permitted"), leaving it stuck at "Created" forever — confirmed on
  # the reference host: memlock capped at 8MB, nofile hard limit 524288 (below
  # the manager's 655360 default).
  #
  # Unlike vm.max_map_count/tun (namespaced sysctl / device node this
  # process can't always touch), ulimit ceilings ARE directly readable
  # here — this shell runs inside the same LXC as the containers it
  # spawns, so its own `ulimit -H` reflects the real ceiling. So instead
  # of just warning, clamp Wazuh's requested limits to match reality,
  # written into containers/run/wazuh/.env (preserving any other keys
  # already there) — Wazuh starts working immediately instead of needing
  # someone to manually diagnose and hand-write these overrides.
  _step "Configuring Wazuh ulimits for this host's capabilities"
  local env_file="$ROOT_DIR/opensmart/containers/run/wazuh/.env"
  local memlock_kb nofile_hard wrote=0
  memlock_kb="$(ulimit -Hl)"
  if [[ "$memlock_kb" =~ ^[0-9]+$ ]]; then
    _set_env_kv "$env_file" "WAZUH_MEMLOCK_LIMIT" "$((memlock_kb * 1024))" && wrote=1
  fi
  nofile_hard="$(ulimit -Hn)"
  if [[ "$nofile_hard" =~ ^[0-9]+$ ]]; then
    if [[ "$nofile_hard" -lt 655360 ]]; then
      _set_env_kv "$env_file" "WAZUH_MANAGER_NOFILE_LIMIT" "$nofile_hard" && wrote=1
    fi
    if [[ "$nofile_hard" -lt 65536 ]]; then
      _set_env_kv "$env_file" "WAZUH_INDEXER_NOFILE_LIMIT" "$nofile_hard" && wrote=1
    fi
  fi
  if [[ "$wrote" -eq 1 ]]; then
    printf 'clamped to host limits (%s)\n' "$env_file"
  else
    printf 'host limits sufficient, no override needed\n'
  fi
}

_install_build_image() {
  _step "Building $IMAGE_NAME image (this can take a few minutes)"
  docker build -t "$IMAGE_NAME" -f "$ROOT_DIR/containers/build/opensmart/Dockerfile" "$ROOT_DIR" >> "$INSTALL_LOG" 2>&1 \
    || _step_fail "Failed to build the $IMAGE_NAME image."
  printf 'done\n'
}

# Builds one native module image (opensmart/<name>) from
# containers/build/<name>/Dockerfile, using that directory itself as the
# build context (these Dockerfiles COPY, if anything, only files that live
# alongside them — see containers/build/openvpn/Dockerfile).
_build_native_module_image() {
  local name="$1"
  docker build -t "opensmart/$name" -f "$ROOT_DIR/containers/build/$name/Dockerfile" "$ROOT_DIR/containers/build/$name"
}

_install_build_native_modules() {
  # Suricata, Zeek, WireGuard, and OpenVPN
  # (opensmart/containers/run/{suricata,zeek,wireguard,openvpn}/) ship as
  # Dockerfile templates, not pre-built/pullable images, so something has to
  # build them. That can't be the backend's own provisioning.py: it talks to
  # the host Docker daemon through the docker-socket-proxy sidecar, whose
  # allowlist deliberately excludes BUILD (see docs/architecture.md's
  # security section) — letting the app container build arbitrary images on
  # the host is exactly the privilege that proxy exists to withhold. So this
  # runs here instead, host-side, against the real daemon, once per
  # install/recreate; provisioning.py only ever starts/stops images that
  # already exist. All four build FROM opensmart/base, so it's built first.
  _step "Building native module images (base, Suricata, Zeek, WireGuard, OpenVPN)"
  {
    _build_native_module_image base &&
    _build_native_module_image suricata &&
    _build_native_module_image zeek &&
    _build_native_module_image wireguard &&
    _build_native_module_image openvpn
  } >> "$INSTALL_LOG" 2>&1 \
    || _step_fail "Failed to build native module images (base/Suricata/Zeek/WireGuard/OpenVPN)."
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
  #
  # bootstrap_admin() (opensmart/backend/app/database.py) only ever prints
  # FIRST_RUN_MARKER when no admin user exists yet — install/--recreate
  # against a host with a persisted DB (an admin already exists) never logs
  # it at all. Without a second success path this loop used to burn the
  # full 5 minutes and report a false "timed out" even though the container
  # had come up fine seconds in — so on every attempt this also polls
  # /api/health directly (same check as _wait_healthy) and treats a healthy
  # response with no marker as "already provisioned," not a failure.
  _step "Waiting for OpenSMART to become ready (first run can take a few minutes)"
  local attempt logs pw port
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
    port="$(_container_host_port)"
    if [[ -n "$port" ]] && curl -sf --max-time 3 "http://localhost:${port}/api/health" 2>/dev/null | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
      printf 'ready (existing install)\n'
      {
        printf '[%s] app healthy without a first-run marker — an admin account already exists.\n' "$(date '+%Y-%m-%d %H:%M:%S')"
      } >> "$INSTALL_LOG"
      printf '\nOpenSMART is up. An admin account already exists on this install, so no new\n'
      printf 'password was generated. Log in with your existing credentials.\n\n'
      return 0
    fi
    sleep 2
  done
  printf 'timed out\n'
  {
    printf '[%s] container log at timeout:\n%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$logs"
  } >> "$INSTALL_LOG"
  printf '\nOpenSMART did not become ready (no first-run marker and /api/health never responded) within 5 minutes.\n' >&2
  printf 'See %s (or: docker logs %s) for details.\n' "$INSTALL_LOG" "$CONTAINER_NAME" >&2
  return 1
}

cmd_install() {
  local bind=""
  local proxy_mode=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bind)
        bind="${2:?--bind requires an ADDRESS:PORT value}"
        shift 2
        ;;
      --reverse-proxy)
        proxy_mode="${2:?--reverse-proxy requires http or https}"
        if [[ "$proxy_mode" != "http" && "$proxy_mode" != "https" ]]; then
          printf 'Invalid --reverse-proxy value: %s (expected http or https)\n' "$proxy_mode" >&2
          exit 1
        fi
        shift 2
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

  # Fail fast on a malformed --bind before the (multi-minute) install even
  # starts, rather than only discovering it in the very last step.
  if [[ -n "$bind" ]]; then
    _require_valid_bind "$bind" "--bind"
  fi

  print_banner
  _log_init
  printf 'Full installer log: %s\n\n' "$INSTALL_LOG"
  _install_require_root
  _install_confirm_proceed
  _install_check_existing_deployment
  _install_check_path_traversable
  _install_check_host_resources
  _install_check_distro
  _install_docker_engine
  _install_create_network
  _install_set_max_map_count
  _install_ensure_tun_device
  _install_configure_wazuh_ulimits
  _install_build_image
  _install_build_native_modules
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
    _start_front_proxy "$proxy_mode" "$bind"
    printf '✔ OpenSMART is running:\n'
    printf '    via the front-door proxy : https://<hostname>/  (self-signed cert; tool aliases at /arkime /wazuh /proxmox /opnsense)\n'
    printf '    local only               : http://127.0.0.1:8000\n'
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
    shift
    cmd_install "$@"
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
