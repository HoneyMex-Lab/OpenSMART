export type ToolDefinition = {
  key: string;
  title: string;
  logo: string;
  // Whether the tool can be shown inside OpenSMART's iframe. Self-hosted
  // admin UIs like Arkime (X-Frame-Options: DENY), Wazuh and Proxmox
  // (X-Frame-Options: SAMEORIGIN + self-signed HTTPS the browser won't let
  // you bypass inside a frame) deliberately block framing for clickjacking
  // protection, so embedding only ever yields a blank/error area — those
  // open in a new tab instead. Defaults to true when omitted.
  embeddable?: boolean;
};

export const toolDefinitions: Record<string, ToolDefinition> = {
  OPNsense: { key: 'tool_url_opnsense', title: 'Firewall - OPNsense', logo: '/assets/tools/opnsense.svg' },
  NTOP: { key: 'tool_url_ntop', title: 'Traffic - NTOP', logo: '/assets/tools/ntop.svg' },
  Arkime: { key: 'tool_url_arkime', title: 'Traffic - Arkime', logo: '/assets/tools/arkime.svg', embeddable: false },
  Proxmox: { key: 'tool_url_proxmox', title: 'Assets - Proxmox', logo: '/assets/tools/proxmox.svg', embeddable: false },
  Wazuh: { key: 'tool_url_wazuh', title: 'SIEM - Wazuh', logo: '/assets/tools/wazuh.svg', embeddable: false },
  Graylog: { key: 'tool_url_graylog', title: 'SIEM - Graylog', logo: '/assets/tools/graylog.svg' },
};
