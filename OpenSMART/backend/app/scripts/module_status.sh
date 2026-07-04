#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="${SCRIPT_DIR}/../../opensmart.db"

probe_url() {
  local url="$1"
  if [[ -z "$url" ]]; then printf 'not-configured'; return; fi
  if curl --max-time 3 -sf "$url" -o /dev/null 2>/dev/null; then
    printf 'online'
  else
    printf 'offline'
  fi
}

json_str() {
  local json="$1" key="$2"
  printf '%s' "$json" | grep -oP "\"${key}\"\s*:\s*\"\K[^\"]+" 2>/dev/null || true
}

output='['
first=1

add_item() {
  local name="$1" enabled="$2" status="$3" detail="$4"
  if [[ "$first" -eq 1 ]]; then first=0; else output="${output},"; fi
  name="${name//\"/\\\"}"
  detail="${detail//\"/\\\"}"
  output="${output}{\"name\":\"${name}\",\"enabled\":${enabled},\"status\":\"${status}\",\"detail\":\"${detail}\"}"
}

# ── OpenSMART Modules ─────────────────────────────────────────────────────────

declare -A EVE_MODULES=( ["Network IDS"]=1 ["Network Traffic Monitoring"]=1 )
declare -A PLATFORM_MODULES=( ["Threat Detection Alerts"]=1 ["Network Traffic Monitoring"]=1 ["Network IDS"]=1 ["Endpoint"]=1 ["Vulnerability Management"]=1 ["Honeypot"]=1 ["Access VPN"]=1 ["LXC Manager"]=1 )

if command -v sqlite3 >/dev/null 2>&1 && [[ -f "$DB_PATH" ]]; then
  while IFS='|' read -r name enabled_int config_json; do
    [[ -n "${PLATFORM_MODULES[$name]+x}" ]] || continue
    enabled="false"
    [[ "$enabled_int" == "1" ]] && enabled="true"
    if [[ "$enabled_int" != "1" ]]; then
      add_item "$name" "$enabled" "disabled" "Module is disabled"
      continue
    fi
    if [[ -n "${EVE_MODULES[$name]+x}" ]]; then
      eve_path="$(json_str "$config_json" "eve_json_path")"
      if [[ -z "$eve_path" ]]; then
        add_item "$name" "$enabled" "not-configured" "eve.json path not set"
      elif [[ -r "$eve_path" ]]; then
        add_item "$name" "$enabled" "online" "eve.json readable: ${eve_path}"
      else
        add_item "$name" "$enabled" "offline" "eve.json not readable: ${eve_path}"
      fi
    else
      add_item "$name" "$enabled" "online" "Module enabled"
    fi
  done < <(sqlite3 "$DB_PATH" "SELECT name, enabled, config FROM opensmart_modules ORDER BY id;" 2>/dev/null || true)
else
  for name in 'Threat Detection Alerts' 'Network Traffic Monitoring' 'Network IDS' 'Endpoint' 'Vulnerability Management' 'Honeypot' 'Access VPN' 'LXC Manager'; do
    add_item "$name" "true" "not-configured" "Database not available"
  done
fi

# ── External Tools ────────────────────────────────────────────────────────────

declare -A TOOL_URL_KEYS=(
  ["OPNsense"]="tool_url_opnsense"
  ["NTOP"]="tool_url_ntop"
  ["Arkime"]="tool_url_arkime"
  ["Proxmox"]="tool_url_proxmox"
  ["Wazuh"]="tool_url_wazuh"
  ["Graylog"]="tool_url_graylog"
)
declare -A PLATFORM_TOOLS=( ["OPNsense"]=1 ["NTOP"]=1 ["Arkime"]=1 ["Proxmox"]=1 ["Wazuh"]=1 ["Graylog"]=1 )

if command -v sqlite3 >/dev/null 2>&1 && [[ -f "$DB_PATH" ]]; then
  while IFS='|' read -r name enabled_int; do
    [[ -n "${PLATFORM_TOOLS[$name]+x}" ]] || continue
    enabled="false"
    [[ "$enabled_int" == "1" ]] && enabled="true"
    url_key="${TOOL_URL_KEYS[$name]:-}"
    url=""
    if [[ -n "$url_key" ]]; then
      url="$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key = '${url_key}';" 2>/dev/null || true)"
    fi
    if [[ "$enabled_int" != "1" ]]; then
      add_item "$name" "$enabled" "disabled" "Tool is disabled"
    elif [[ -z "$url" ]]; then
      add_item "$name" "$enabled" "not-configured" "No URL configured"
    else
      status="$(probe_url "$url")"
      if [[ "$status" == "online" ]]; then
        add_item "$name" "$enabled" "online" "Reachable at ${url}"
      else
        add_item "$name" "$enabled" "offline" "Not reachable: ${url}"
      fi
    fi
  done < <(sqlite3 "$DB_PATH" "SELECT name, enabled FROM modules ORDER BY id;" 2>/dev/null || true)
else
  for name in OPNsense NTOP Arkime Proxmox Wazuh Graylog; do
    add_item "$name" "true" "not-configured" "Database not available"
  done
fi

output="${output}]"
printf '%s\n' "$output"
