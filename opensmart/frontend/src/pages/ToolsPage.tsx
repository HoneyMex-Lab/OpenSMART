import type { Settings, ToolConfig } from '../types';
import { toolDefinitions } from './toolDefinitions';

export default function ToolsPage({ settings, tools, onSelect }: { settings: Settings; tools: ToolConfig[]; onSelect: (tool: ToolConfig) => void }) {
  return <section className="grid tools-grid">{tools.map((tool) => {
    const definition = toolDefinitions[tool.name] || { title: tool.name, logo: '/assets/tools/lxc-manager.svg', key: '' };
    const url = settings[definition.key] || '';
    const status = !tool.enabled ? 'disabled' : url ? 'enabled' : 'warning';
    return <button className={`tool-card status-card ${status}`} key={tool.id} onClick={() => onSelect(tool)}><img src={definition.logo} alt="" /><span>{definition.title}</span><small><i className={`status-dot ${status}`} /> {status === 'warning' ? 'URL required' : status}</small></button>;
  })}</section>;
}
