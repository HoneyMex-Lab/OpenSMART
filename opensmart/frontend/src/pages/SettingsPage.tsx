import { useState } from 'react';
import { Bell, MonitorCog, Network, Puzzle, Wand2, Wrench } from 'lucide-react';
import { t } from '../i18n';
import type { OpenSmartModule, Settings, ToolConfig, User } from '../types';
import AdminConfigPage from './AdminConfigPage';
import NetworkConfigPage from './NetworkConfigPage';
import OpenSmartConfigPage from './OpenSmartConfigPage';
import NotificationsPage from './NotificationsPage';
import ToolsConfigPage from './ToolsConfigPage';
import WizardPage from './WizardPage';

type TabKey = 'web-interface' | 'network' | 'opensmart-modules' | 'tools' | 'notifications' | 'wizard';

const tabs: { key: TabKey; labelKey: string; fallback: string; icon: typeof MonitorCog }[] = [
  { key: 'web-interface', labelKey: 'settings.webInterface', fallback: 'Web Interface', icon: MonitorCog },
  { key: 'network', labelKey: 'settings.network', fallback: 'Network', icon: Network },
  { key: 'opensmart-modules', labelKey: 'settings.modules', fallback: 'OpenSMART Modules', icon: Puzzle },
  { key: 'tools', labelKey: 'settings.tools', fallback: 'Tools', icon: Wrench },
  { key: 'notifications', labelKey: 'settings.notifications', fallback: 'Notifications', icon: Bell },
  { key: 'wizard', labelKey: 'settings.wizard', fallback: 'Wizard', icon: Wand2 },
];

type Props = {
  settings: Settings;
  setSettings: (settings: Settings) => void;
  tools: ToolConfig[];
  onToolsUpdate: (tools: ToolConfig[]) => void;
  modules: OpenSmartModule[];
  onModulesUpdate: (modules: OpenSmartModule[]) => void;
  user: User;
};

export default function SettingsPage({ settings, setSettings, tools, onToolsUpdate, modules, onModulesUpdate, user }: Props) {
  const [tab, setActiveTab] = useState<TabKey>(() => {
    const active = (new URLSearchParams(window.location.search).get('settingsTab') as TabKey) || 'web-interface';
    return tabs.some((item) => item.key === active) ? active : 'web-interface';
  });

  function setTab(next: TabKey) {
    const url = new URL(window.location.href);
    url.searchParams.set('settingsTab', next);
    window.history.replaceState(null, '', url);
    setActiveTab(next);
  }

  return (
    <section className="settings-shell">
      <div className="settings-tabs" role="tablist" aria-label="Settings sections">
        {tabs.map((item) => {
          const Icon = item.icon;
          return <button className={tab === item.key ? 'active' : ''} key={item.key} onClick={() => setTab(item.key)} role="tab" aria-selected={tab === item.key}><Icon size={17} /> {t(settings, item.labelKey, item.fallback)}</button>;
        })}
      </div>
      {tab === 'web-interface' && <AdminConfigPage settings={settings} setSettings={setSettings} user={user} />}
      {tab === 'network' && <NetworkConfigPage />}
      {tab === 'opensmart-modules' && <OpenSmartConfigPage modules={modules} onModulesUpdate={onModulesUpdate} />}
      {tab === 'tools' && <ToolsConfigPage settings={settings} setSettings={setSettings} tools={tools} onToolsUpdate={onToolsUpdate} />}
      {tab === 'notifications' && <NotificationsPage settings={settings} setSettings={setSettings} />}
      {tab === 'wizard' && <WizardPage settings={settings} setSettings={setSettings} modules={modules} onModulesUpdate={onModulesUpdate} tools={tools} onToolsUpdate={onToolsUpdate} user={user} />}
    </section>
  );
}
