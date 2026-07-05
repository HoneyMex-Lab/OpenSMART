import { useEffect, useState } from 'react';
import { api, setCsrfToken } from './api';
import AppShell from './components/AppShell';
import ForceChangePasswordPage from './components/ForceChangePasswordPage';
import LoginPage from './components/LoginPage';
import { t } from './i18n';
import WizardPage from './pages/WizardPage';
import type { Settings, User } from './types';

const defaultSettings: Settings = {
  platform_title: 'OpenSMART',
  platform_version: 'v0.3 beta',
  platform_build: 'unknown',
  platform_language: 'en',
  logo_url: '',
  favicon_url: '/assets/branding/favicon.svg',
  developed_by: 'Developed by',
  // Assume already-set-up until real settings load, so an in-progress fetch
  // never flashes the first-run Wizard for an already-configured install.
  wizard_completed: 'true',
};

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [settings, setSettings] = useState<Settings>(defaultSettings);
  const [loading, setLoading] = useState(true);

  async function loadSettings() {
    try {
      const result = await api.settings();
      setSettings({ ...defaultSettings, ...result.settings });
    } catch {
      setSettings(defaultSettings);
    }
  }

  useEffect(() => {
    api.publicSettings()
      .then((result) => setSettings({ ...defaultSettings, ...result.settings }))
      .catch(() => setSettings(defaultSettings));
    api.me()
      .then(({ user }) => {
        setCsrfToken(user.csrfToken);
        setUser(user);
        return loadSettings();
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const href = settings.favicon_url || defaultSettings.favicon_url;
    let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
    if (!link) {
      link = document.createElement('link');
      link.rel = 'icon';
      document.head.appendChild(link);
    }
    link.href = href;
  }, [settings.favicon_url]);

  async function handleLogin(username: string, password: string) {
    const { user } = await api.login(username, password);
    const me = await api.me();
    setCsrfToken(me.user.csrfToken);
    setUser({ ...user, csrfToken: me.user.csrfToken });
    await loadSettings();
  }

  async function handleLogout() {
    await api.logout();
    setCsrfToken('');
    setUser(null);
  }

  async function handlePasswordChanged() {
    const me = await api.me();
    setUser({ ...me.user, csrfToken: me.user.csrfToken });
  }

  if (loading) return <div className="loading">{t(settings, 'common.loadingOpenSMART', 'Loading OpenSMART...')}</div>;
  if (!user) return <LoginPage settings={settings} onLogin={handleLogin} />;
  if (user.mustChangePassword) return <ForceChangePasswordPage settings={settings} onChanged={handlePasswordChanged} />;
  if (user.role === 'admin' && settings.wizard_completed !== 'true') return <WizardPage settings={settings} setSettings={setSettings} onComplete={loadSettings} />;
  return <AppShell user={user} setUser={setUser} settings={settings} setSettings={setSettings} onLogout={handleLogout} />;
}
