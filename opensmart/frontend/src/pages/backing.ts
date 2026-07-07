// Which compose project(s) back each module/tool. Anything not listed here
// has no local containers (external tools reached by URL, or placeholders).
// Mirrors MODULE_CONTAINERS/TOOL_CONTAINERS in backend/app/provisioning.py.
export const MODULE_BACKING: Record<string, string[]> = {
  'Network Traffic Monitoring': ['suricata', 'zeek'],
  'Network IDS': ['suricata'],
  'Threat Detection Alerts': ['wazuh'],
  'Endpoint': ['wazuh'],
  'Vulnerability Management': ['wazuh'],
  'Access VPN': ['openvpn', 'wireguard'],
};

export const TOOL_BACKING: Record<string, string[]> = {
  Arkime: ['arkime'],
  Wazuh: ['wazuh'],
};

// Placeholders stay ONLY for these — everything else shows real state.
export const NOT_IMPLEMENTED = new Set(['Honeypot', 'LXC Manager', 'Graylog', 'NTOP']);

export const PROJECT_LABELS: Record<string, string> = {
  suricata: 'Suricata IDS',
  zeek: 'Zeek NSM',
  arkime: 'Arkime',
  opensearch: 'OpenSearch',
  wireguard: 'WireGuard VPN',
  openvpn: 'OpenVPN',
  wazuh: 'Wazuh SIEM',
};
