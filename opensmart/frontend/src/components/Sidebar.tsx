import { Activity, AlertTriangle, BarChart3, Boxes, Bug, ChevronsLeft, ChevronsRight, ClipboardList, Database, Flame, Home, KeyRound, Lock, Monitor, Network, Search, Server, ServerCog, Shield, ShieldAlert, Wrench, type LucideIcon } from 'lucide-react';
import type { OpenSmartModule, Settings, ToolConfig, User } from '../types';
import { toolDefinitions } from '../pages/toolDefinitions';
import { t } from '../i18n';

export type PageKey = string;
export type StatusLevel = 'enabled' | 'warning' | 'disabled';

type Props = {
  user: User;
  settings: Settings;
  tools: ToolConfig[];
  modules: OpenSmartModule[];
  current: PageKey;
  collapsed: boolean;
  onNavigate: (page: PageKey) => void;
  onToggle: () => void;
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

function toolStatus(tool: ToolConfig, settings: Settings): StatusLevel {
  if (!tool.enabled) return 'disabled';
  return settings[toolUrlKeys[tool.name] || ''] ? 'enabled' : 'warning';
}

function moduleStatus(module: OpenSmartModule): StatusLevel {
  return module.enabled ? 'enabled' : 'disabled';
}

const moduleIcons: Record<string, LucideIcon> = {
  'Threat Detection Alerts': AlertTriangle,
  'Network Traffic Monitoring': Activity,
  'Network IDS': ShieldAlert,
  Endpoint: Monitor,
  'Vulnerability Management': Bug,
  Honeypot: Flame,
  'Access VPN': KeyRound,
  'LXC Manager': Boxes,
};

const toolIcons: Record<string, LucideIcon> = {
  OPNsense: Shield,
  NTOP: Activity,
  Arkime: Search,
  Proxmox: Server,
  Wazuh: ShieldAlert,
  Graylog: Database,
};

function NavStatusIcon({ icon: Icon, status }: { icon: LucideIcon; status: StatusLevel }) {
  return <Icon className={`nav-status-icon ${status}`} size={15} strokeWidth={2.2} aria-hidden="true" />;
}

export default function Sidebar({ user, settings, tools, modules, current, collapsed, onNavigate, onToggle, onLogout }: Props) {
  const configItems = [
    { key: 'account', label: t(settings, 'nav.account', 'Account'), icon: Lock },
    { key: 'status', label: t(settings, 'nav.status', 'Status'), icon: Shield },
    ...(user.role === 'admin' ? [
      { key: 'webconsole-config', label: t(settings, 'nav.settings', 'Settings'), icon: ServerCog },
      { key: 'access', label: t(settings, 'nav.access', 'Access'), icon: Lock },
    ] : []),
    { key: 'audit', label: t(settings, 'nav.audit', 'Audit'), icon: ClipboardList },
    { key: 'about', label: t(settings, 'nav.about', 'About'), icon: ServerCog },
  ];

  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <button className="sidebar-header home-link" onClick={() => onNavigate('home')} title="OpenSMART home">
        <span className="logo-box">{settings.logo_url ? <img src={settings.logo_url} alt="Logo" /> : 'OS'}</span>
        {!collapsed && <span className="sidebar-brand-text"><small>{settings.platform_version}</small><strong>{settings.platform_title}</strong></span>}
      </button>
      <button className="collapse-btn" onClick={onToggle}>{collapsed ? <ChevronsRight size={18} /> : <ChevronsLeft size={18} />} {!collapsed && t(settings, 'nav.collapse', 'Collapse')}</button>
      <nav>
        <div className="nav-section"><hr />{!collapsed && <span>{t(settings, 'nav.home', 'Home')}</span>}</div>
        <button className={current === 'home' ? 'active' : ''} onClick={() => onNavigate('home')} title={t(settings, 'nav.home', 'Home')}><Home size={18} /> {!collapsed && t(settings, 'nav.home', 'Home')}</button>

        <div className="nav-section"><hr />{!collapsed && <span>{t(settings, 'nav.modules', 'OpenSMART Modules')}</span>}</div>
        <button className={`nav-home ${current === 'opensmart-modules' ? 'active' : ''}`} onClick={() => onNavigate('opensmart-modules')} title={t(settings, 'nav.modules', 'OpenSMART Modules')}><BarChart3 size={18} /> {!collapsed && t(settings, 'nav.modules', 'OpenSMART Modules')}</button>
        {modules.map((module) => { const status = moduleStatus(module); const Icon = moduleIcons[module.name] || Network; return <button className={`nav-child ${current === `module:${module.id}` ? 'active' : ''} ${!module.enabled ? 'disabled-nav-item' : ''}`} key={module.id} onClick={() => onNavigate(`module:${module.id}`)} title={module.name}><NavStatusIcon icon={Icon} status={status} />{!collapsed && <span className="nav-item-label">{module.name}</span>}{!collapsed && (!module.enabled ? <span className="nav-disabled-badge">{t(settings, 'nav.disabled', 'Disabled')}</span> : <span className="nav-badge-spacer" aria-hidden="true" />)}</button>; })}

        <div className="nav-section"><hr />{!collapsed && <span>{t(settings, 'nav.tools', 'Tools')}</span>}</div>
        <button className={`nav-home ${current === 'tools' ? 'active' : ''}`} onClick={() => onNavigate('tools')} title={t(settings, 'nav.tools', 'Tools')}><Wrench size={18} /> {!collapsed && t(settings, 'nav.tools', 'Tools')}</button>
        {tools.map((tool) => { const status = toolStatus(tool, settings); const Icon = toolIcons[tool.name] || Wrench; return <button className={`nav-child ${current === `tool:${tool.id}` ? 'active' : ''} ${!tool.enabled ? 'disabled-nav-item' : ''}`} key={tool.id} onClick={() => onNavigate(`tool:${tool.id}`)} title={toolDefinitions[tool.name]?.title || tool.name}><NavStatusIcon icon={Icon} status={status} />{!collapsed && <span className="nav-item-label">{toolDefinitions[tool.name]?.title || tool.name}</span>}{!collapsed && (!tool.enabled ? <span className="nav-disabled-badge">{t(settings, 'nav.disabled', 'Disabled')}</span> : <span className="nav-badge-spacer" aria-hidden="true" />)}</button>; })}

        <div className="nav-section"><hr />{!collapsed && <span>{t(settings, 'nav.configuration', 'Configuration')}</span>}</div>
        {configItems.map((item) => {
          const Icon = item.icon;
          return <button className={current === item.key ? 'active' : ''} key={item.key} onClick={() => onNavigate(item.key)} title={item.label}><Icon size={18} /> {!collapsed && item.label}</button>;
        })}
      </nav>
      <footer className="sidebar-footer">
        {!collapsed && <small>{settings.developed_by}</small>}
        <div className="footer-logos">
          <a href="https://miztonlabs.org" target="_blank" rel="noreferrer" title="Mizton Labs"><img src="/assets/branding/logo_miztonlabs.jpg" alt="Mizton Labs" /></a>
          <a href="https://honeynet.org.mx" target="_blank" rel="noreferrer" title="Honeynet Project México"><img src="/assets/branding/logo_honeynet_simple.png" alt="Honeynet Project México" /></a>
        </div>
        {!collapsed && <button className="logout" onClick={onLogout}><span>{t(settings, 'nav.logout', 'Logout')}</span><span className="logout-user-badge">{user.username}</span></button>}
      </footer>
    </aside>
  );
}
