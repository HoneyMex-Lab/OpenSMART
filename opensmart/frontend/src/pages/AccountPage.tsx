import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api';
import { THEME_OPTIONS } from '../themes';
import type { LogonInfo, SessionInfo, User } from '../types';

type Props = {
  user: User;
  onUserUpdate: (user: User) => void;
};

export default function AccountPage({ user, onUserUpdate }: Props) {
  const [fullName, setFullName] = useState(user.fullName || '');
  const [email, setEmail] = useState(user.email || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [profileMessage, setProfileMessage] = useState('');
  const [passwordMessage, setPasswordMessage] = useState('');
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [logons, setLogons] = useState<LogonInfo[]>([]);

  async function refreshSessions() {
    api.accountSessions().then((result) => { setSessions(result.sessions); setLogons(result.logons); }).catch(() => undefined);
  }

  useEffect(() => {
    refreshSessions();
  }, []);

  async function terminateOtherSessions() {
    if (!window.confirm('Terminate all other sessions for this account?')) return;
    const result = await api.terminateOtherSessions();
    setSessions(result.sessions);
    setLogons(result.logons);
  }

  async function updateProfile(event: FormEvent) {
    event.preventDefault();
    setProfileMessage('');
    try {
      const result = await api.updateProfile(fullName, email);
      onUserUpdate({ ...user, ...result.user, csrfToken: user.csrfToken });
      setProfileMessage('Account info updated.');
    } catch (error) {
      setProfileMessage(error instanceof Error ? error.message : 'Could not update account info');
    }
  }

  async function changeTheme(theme: string) {
    // Apply optimistically (App reads user.theme live); revert on failure.
    const previous = user.theme || '';
    onUserUpdate({ ...user, theme });
    try {
      await api.setTheme(theme);
    } catch {
      onUserUpdate({ ...user, theme: previous });
    }
  }

  async function changePassword(event: FormEvent) {
    event.preventDefault();
    setPasswordMessage('');
    if (newPassword !== confirmPassword) {
      setPasswordMessage('New password and confirmation do not match.');
      return;
    }
    try {
      await api.changePassword(currentPassword, newPassword);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setPasswordMessage('Password changed.');
    } catch (error) {
      setPasswordMessage(error instanceof Error ? error.message : 'Could not change password');
    }
  }

  return (
    <section className="admin-stack">
      <div className="two-column">
      <article className="card">
        <h2>Account Info</h2>
        <p><strong>Username:</strong> {user.username}</p>
        <p><strong>Role:</strong> {user.role}</p>
        <form onSubmit={updateProfile} className="stack-form compact-form">
          <label>Name<input value={fullName} onChange={(event) => setFullName(event.target.value)} maxLength={120} /></label>
          <label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} maxLength={180} /></label>
          <button>Update account info</button>
          {profileMessage && <p className="muted">{profileMessage}</p>}
        </form>
        <label className="account-theme">Theme
          <select value={user.theme || ''} onChange={(event) => changeTheme(event.target.value)}>
            <option value="">Use default</option>
            {THEME_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
          <small className="muted">Applies to your account only, on every device.</small>
        </label>
      </article>
      <article className="card">
        <h2>Change Password</h2>
        <form onSubmit={changePassword} className="stack-form">
          <input type="password" placeholder="Current password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required />
          <input type="password" placeholder="New password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required />
          <input type="password" placeholder="Confirm new password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required />
          <button>Update password</button>
          {passwordMessage && <p className="muted">{passwordMessage}</p>}
        </form>
      </article>
      </div>
      <article className="card">
        <div className="section-actions"><h2>Sessions and Recent Logons</h2><button onClick={terminateOtherSessions}>Terminate other sessions</button></div>
        <div className="table-wrap"><table><thead><tr><th>Session Start</th><th>Expires</th><th>IP</th><th>User Agent</th><th>Current</th></tr></thead><tbody>{sessions.map((session, index) => <tr key={`${session.created_at}-${index}`}><td>{session.created_at}</td><td>{session.expires_at}</td><td>{session.ip_address}</td><td>{session.user_agent}</td><td>{session.current ? 'Yes' : 'No'}</td></tr>)}</tbody></table></div>
        <h2 className="subheading">Last 3 Logons</h2>
        <div className="table-wrap"><table><thead><tr><th>Date</th><th>IP</th><th>Detail</th></tr></thead><tbody>{logons.map((logon, index) => <tr key={`${logon.created_at}-${index}`}><td>{logon.created_at}</td><td>{logon.ip_address}</td><td>{logon.detail}</td></tr>)}</tbody></table></div>
      </article>
    </section>
  );
}
