export const toolDefinitions: Record<string, { key: string; title: string; logo: string }> = {
  OPNsense: { key: 'tool_url_opnsense', title: 'Firewall - OPNsense', logo: '/assets/tools/opnsense.svg' },
  NTOP: { key: 'tool_url_ntop', title: 'Traffic - NTOP', logo: '/assets/tools/ntop.svg' },
  Arkime: { key: 'tool_url_arkime', title: 'Traffic - Arkime', logo: '/assets/tools/arkime.svg' },
  Proxmox: { key: 'tool_url_proxmox', title: 'Assets - Proxmox', logo: '/assets/tools/proxmox.svg' },
  Wazuh: { key: 'tool_url_wazuh', title: 'SIEM - Wazuh', logo: '/assets/tools/wazuh.svg' },
  Graylog: { key: 'tool_url_graylog', title: 'SIEM - Graylog', logo: '/assets/tools/graylog.svg' },
};
