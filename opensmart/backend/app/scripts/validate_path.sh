#!/usr/bin/env bash
set -euo pipefail

path="${1:-}"
if [[ -z "$path" || "$path" == *$'\0'* ]]; then
  exit 1
fi
printf '%s\n' "$path"
