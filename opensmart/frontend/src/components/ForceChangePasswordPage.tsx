import { FormEvent, useState } from 'react';
import { api } from '../api';
import type { Settings } from '../types';

type Props = {
  settings: Settings;
  onChanged: () => Promise<void>;
};

export default function ForceChangePasswordPage({ settings, onChanged }: Props) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError('');
    if (newPassword !== confirmPassword) {
      setError('New password and confirmation do not match.');
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      await onChanged();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Could not change password');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-card">
        <div className="brand-mark">{settings.logo_url ? <img src={settings.logo_url} alt="OpenSMART logo" /> : <span>OS</span>}</div>
        <h1>Change your password</h1>
        <p className="muted">Your password was reset by an administrator. You must set a new password before continuing.</p>
        <form onSubmit={submit} className="login-form">
          <label>
            Current password
            <input type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required />
          </label>
          <label>
            New password
            <input type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required />
          </label>
          <label>
            Confirm new password
            <input type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required />
          </label>
          {error && <div className="error-box">{error}</div>}
          <button disabled={busy}>{busy ? 'Updating...' : 'Update password'}</button>
        </form>
      </section>
    </main>
  );
}
