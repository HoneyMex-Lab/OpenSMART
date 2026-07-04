#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: ./opensmart.sh <command> [options]

Commands:
  start --bind ADDRESS:PORT   Start the OpenSMART app bound to ADDRESS:PORT.
  --install                   Install and run OpenSMART as a Docker container (not yet implemented).
  --help, -h                  Show this help message.
EOF
}

cmd_start() {
  local bind=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bind)
        bind="${2:?--bind requires an ADDRESS:PORT value}"
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

  exec "$ROOT_DIR/OpenSMART/scripts/run_app.sh" --host "$host" --port "$port"
}

case "${1:-}" in
  start)
    shift
    cmd_start "$@"
    ;;
  --install)
    printf 'opensmart.sh --install is not implemented yet (planned for a later phase).\n' >&2
    exit 1
    ;;
  --help|-h)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
