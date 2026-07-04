import { FormEvent, useState } from 'react';
import type { Settings } from '../types';

type Props = {
  settings: Settings;
  onLogin: (username: string, password: string) => Promise<void>;
};

export default function LoginPage({ settings, onLogin }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError('');
    setBusy(true);
    try {
      await onLogin(username, password);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Login failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-card">
        <div className="brand-mark">{settings.logo_url ? <img src={settings.logo_url} alt="OpenSMART logo" /> : <span>OS</span>}</div>
        <p className="eyebrow">Security Operations Framework</p>
        <p className="login-version">{settings.platform_version}</p>
        <h1>{settings.platform_title}</h1>
        <p className="muted">Sign in to manage monitoring, tooling, assets, and platform configuration.</p>
        <form onSubmit={submit} className="login-form">
          <label>
            Username
            <input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required />
          </label>
          <label>
            Password
            <input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required />
          </label>
          {error && <div className="error-box">{error}</div>}
          <button disabled={busy}>{busy ? 'Signing in...' : 'Sign in'}</button>
        </form>
      </section>
    </main>
  );
}
