import type { Settings, ToolConfig } from '../types';

export const toolDefinitions: Record<string, { key: string; title: string; logo: string }> = {
  OPNsense: { key: 'tool_url_opnsense', title: 'Firewall - OPNsense', logo: '/assets/tools/opnsense.svg' },
  NTOP: { key: 'tool_url_ntop', title: 'Traffic - NTOP', logo: '/assets/tools/ntop.svg' },
  Arkime: { key: 'tool_url_arkime', title: 'Traffic - Arkime', logo: '/assets/tools/arkime.svg' },
  Proxmox: { key: 'tool_url_proxmox', title: 'Assets - Proxmox', logo: '/assets/tools/proxmox.svg' },
  Wazuh: { key: 'tool_url_wazuh', title: 'SIEM - Wazuh', logo: '/assets/tools/wazuh.svg' },
  Graylog: { key: 'tool_url_graylog', title: 'SIEM - Graylog', logo: '/assets/tools/graylog.svg' },
};

export default function ToolsPage({ settings, tools, onSelect }: { settings: Settings; tools: ToolConfig[]; onSelect: (tool: ToolConfig) => void }) {
  return <section className="grid tools-grid">{tools.map((tool) => {
    const definition = toolDefinitions[tool.name] || { title: tool.name, logo: '/assets/tools/lxc-manager.svg', key: '' };
    const url = settings[definition.key] || '';
    const status = !tool.enabled ? 'disabled' : url ? 'enabled' : 'warning';
    return <button className={`tool-card status-card ${status}`} key={tool.id} onClick={() => onSelect(tool)}><img src={definition.logo} alt="" /><span>{definition.title}</span><small><i className={`status-dot ${status}`} /> {status === 'warning' ? 'URL required' : status}</small></button>;
  })}</section>;
}
