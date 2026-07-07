import { useEffect, useState } from 'react';
import AboutPage from '../pages/AboutPage';
import AccessPage from '../pages/AccessPage';
import AccountPage from '../pages/AccountPage';
import AuditPage from '../pages/AuditPage';
import SettingsPage from '../pages/SettingsPage';
import NetworkIdsPage from '../pages/NetworkIdsPage';
import VpnPage from '../pages/VpnPage';
import NetworkTrafficPage from '../pages/NetworkTrafficPage';
import StatusPage from '../pages/StatusPage';
import SummaryPage from '../pages/SummaryPage';
import ToolsPage from '../pages/ToolsPage';
import { toolDefinitions } from '../pages/toolDefinitions';
import { api } from '../api';
import type { OpenSmartModule, Settings, ToolConfig, User } from '../types';
import Sidebar, { PageKey } from './Sidebar';

type Props = {
  user: User;
  setUser: (user: User) => void;
  settings: Settings;
  setSettings: (settings: Settings) => void;
  onLogout: () => void;
};

const toolUrlKeys: Record<string, string> = {
  OPNsense: 'tool_url_opnsense',
  NTOP: 'tool_url_ntop',
  Arkime: 'tool_url_arkime',
  Proxmox: 'tool_url_proxmox',
  Wazuh: 'tool_url_wazuh',
  Graylog: 'tool_url_graylog',
};

export default function AppShell({ user, setUser, settings, setSettings, onLogout }: Props) {
  const [page, setPage] = useState<PageKey>('home');
  const [collapsed, setCollapsed] = useState(false);
  const [tools, setTools] = useState<ToolConfig[]>([]);
  const [modules, setModules] = useState<OpenSmartModule[]>([]);

  async function refreshCatalogs() {
    const [toolResult, moduleResult] = await Promise.all([api.tools(), api.openSmartModules()]);
    setTools(toolResult.tools);
    setModules(moduleResult.modules);
  }

  useEffect(() => { refreshCatalogs().catch(() => undefined); }, []);

  const pageTitles: Record<string, string> = { home: 'Home', 'webconsole-config': 'Settings', 'opensmart-modules': 'OpenSMART Modules' };
  const title = page.startsWith('tool:') ? toolDefinitions[tools.find((tool) => page === `tool:${tool.id}`)?.name || '']?.title || tools.find((tool) => page === `tool:${tool.id}`)?.name || 'Tool'
    : page.startsWith('module:') ? modules.find((module) => page === `module:${module.id}`)?.name || 'OpenSMART Module'
      : pageTitles[page] || page.split('-').map((part) => part[0].toUpperCase() + part.slice(1)).join(' ');

  function renderTool(tool: ToolConfig) {
    const title = toolDefinitions[tool.name]?.title || tool.name;
    if (!tool.enabled) return <StatusMessage title={title} status="Disabled" detail="Enable this tool in Configuration > Tools Config before loading its workspace." />;
    const url = settings[toolUrlKeys[tool.name] || ''] || '';
    if (!url) return <StatusMessage title={title} status="Warning" detail="This tool is enabled but no internal URL is configured. Add the URL in Configuration > Tools Config." />;
    return <section className="tool-view"><div className="section-actions"><h2>{title}</h2><p className="muted">{url}</p></div><iframe title={title} src={url} className="tool-iframe" /></section>;
  }

  function renderModule(module: OpenSmartModule) {
    if (!module.enabled) return <StatusMessage title={module.name} status="Disabled" detail="Enable and configure this OpenSMART module in Configuration > OpenSMART Config." />;
    if (module.name === 'Network Traffic Monitoring') return <NetworkTrafficPage settings={settings} />;
    if (module.name === 'Network IDS') return <NetworkIdsPage />;
    if (module.name === 'Access VPN') return <VpnPage />;
    const logo = modulesLogo(module.name);
    return <section className="card hero-card"><div className="detail-heading"><img src={logo} alt="" /><div><p className="status-label"><i className="status-dot enabled" /> enabled</p><h2>{module.name}</h2><p className="muted">Placeholder content for this OpenSMART module. Future releases can render live metrics, alerts, charts, and drill-down tables here.</p></div></div></section>;
  }

  function renderPage() {
    if (page === 'home') return <SummaryPage settings={settings} tools={tools} modules={modules} onNavigate={setPage} />;
    if (page === 'opensmart-modules') return <ModuleGrid modules={modules} onSelect={(module) => setPage(`module:${module.id}`)} />;
    if (page === 'tools') return <ToolsPage settings={settings} tools={tools} onSelect={(tool) => setPage(`tool:${tool.id}`)} />;
    if (page.startsWith('tool:')) {
      const tool = tools.find((item) => page === `tool:${item.id}`);
      return tool ? renderTool(tool) : <StatusMessage title="Tool" status="Unavailable" detail="Tool configuration is not loaded." />;
    }
    if (page.startsWith('module:')) {
      const module = modules.find((item) => page === `module:${item.id}`);
      return module ? renderModule(module) : <StatusMessage title="OpenSMART Module" status="Unavailable" detail="Module configuration is not loaded." />;
    }
    if (page === 'account') return <AccountPage user={user} onUserUpdate={setUser} />;
    if (page === 'status') return <StatusPage />;
    if (page === 'about') return <AboutPage settings={settings} />;
    if (page === 'webconsole-config') return <SettingsPage settings={settings} setSettings={setSettings} tools={tools} onToolsUpdate={setTools} modules={modules} onModulesUpdate={setModules} />;
    if (page === 'audit') return <AuditPage user={user} />;
    return <AccessPage />;
  }

  return (
    <div className="app-shell">
      <Sidebar user={user} settings={settings} tools={tools} modules={modules} current={page} collapsed={collapsed} onNavigate={setPage} onToggle={() => setCollapsed((value) => !value)} onLogout={onLogout} />
      <main className="content">
        <header className="topbar">
          <button className="mobile-menu" onClick={() => setCollapsed((value) => !value)}>Menu</button>
          <div className="title-block"><p className="eyebrow">Open Source Security Platform</p><h1>{title}</h1></div>
          <div className="user-pill">{user.role}</div>
        </header>
        {renderPage()}
      </main>
    </div>
  );
}

function StatusMessage({ title, status, detail }: { title: string; status: string; detail: string }) {
  return <section className="card hero-card"><p className="eyebrow">{status}</p><h2>{title}</h2><p className="muted">{detail}</p></section>;
}

function ModuleGrid({ modules, onSelect }: { modules: OpenSmartModule[]; onSelect: (module: OpenSmartModule) => void }) {
  return <section className="module-grid">{modules.map((item, index) => <button className={`summary-card status-card ${item.enabled ? 'enabled' : 'disabled'}`} key={item.id} onClick={() => onSelect(item)}><img src={modulesLogo(item.name)} alt="" /><span className="metric">0{index + 1}</span><h2>{item.name}</h2><p className="status-label"><i className={`status-dot ${item.enabled ? 'enabled' : 'disabled'}`} /> {item.enabled ? 'enabled' : 'disabled'}</p></button>)}</section>;
}

function modulesLogo(name: string) {
  const match: Record<string, string> = {
    'Threat Detection Alerts': '/assets/summary/threat-alerts.svg',
    'Network Traffic Monitoring': '/assets/summary/network-traffic.svg',
    'Network IDS': '/assets/summary/network-ids.svg',
    Endpoint: '/assets/summary/endpoint.svg',
    'Vulnerability Management': '/assets/summary/vulnerability.svg',
    Honeypot: '/assets/summary/honeypot.svg',
    'Access VPN': '/assets/tools/vpn.svg',
    'LXC Manager': '/assets/tools/lxc-manager.svg',
  };
  return match[name] || '/assets/summary/network-ids.svg';
}
