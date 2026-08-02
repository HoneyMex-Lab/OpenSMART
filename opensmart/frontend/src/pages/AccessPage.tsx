import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api';
import { confirmDialog } from '../components/Dialog';
import type { Role, User } from '../types';

type UserForm = {
  username: string;
  password: string;
  role: Role;
  fullName: string;
  email: string;
};

type PasswordPanel = {
  userId: number;
  password: string;
  confirm: string;
};

export default function AccessPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [form, setForm] = useState<UserForm>({ username: '', password: '', role: 'user', fullName: '', email: '' });
  const [passwordPanel, setPasswordPanel] = useState<PasswordPanel | null>(null);
  const [message, setMessage] = useState('');

  async function refreshUsers() {
    try {
      const result = await api.users();
      setUsers(result.users);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not load users');
    }
  }

  useEffect(() => { refreshUsers(); }, []);

  async function create(event: FormEvent) {
    event.preventDefault();
    try {
      const result = await api.createUser(form);
      setUsers(result.users);
      setForm({ username: '', password: '', role: 'user', fullName: '', email: '' });
      setMessage('User created.');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not create user');
    }
  }

  async function updateUser(user: User, changes: Partial<User> & { password?: string }, confirmMessage?: string) {
    if (confirmMessage && !(await confirmDialog(confirmMessage))) return;
    const result = await api.updateUser({
      id: user.id,
      role: changes.role || user.role,
      fullName: changes.fullName ?? user.fullName,
      email: changes.email ?? user.email,
      enabled: changes.enabled ?? user.enabled ?? true,
      password: changes.password,
    });
    setUsers(result.users);
  }

  function openPasswordPanel(user: User) {
    setPasswordPanel({ userId: user.id, password: '', confirm: '' });
    setMessage('');
  }

  async function acceptPasswordChange(user: User) {
    if (!passwordPanel) return;
    if (passwordPanel.password !== passwordPanel.confirm) {
      setMessage('New password and confirmation do not match.');
      return;
    }
    try {
      await updateUser(user, { password: passwordPanel.password });
      setPasswordPanel(null);
      setMessage(`Password changed for ${user.username}. They must change it on next login.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not change password');
    }
  }

  async function toggleEnabled(user: User) {
    const nextEnabled = !(user.enabled ?? true);
    await updateUser(user, { enabled: nextEnabled }, `${nextEnabled ? 'Enable' : 'Disable'} ${user.username}?`);
    setMessage(`${user.username} ${nextEnabled ? 'enabled' : 'disabled'}.`);
  }

  async function remove(id: number) {
    if (!(await confirmDialog('Delete this user?', { danger: true }))) return;
    const result = await api.deleteUser(id);
    setUsers(result.users);
  }

  return (
    <section className="admin-grid">
      <article className="card">
        <h2>Create User</h2>
        <form onSubmit={create} className="stack-form">
          <input placeholder="Username" value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} required />
          <input type="password" placeholder="Password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} required />
          <select value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value as Role })}><option value="user">User</option><option value="admin">Admin</option></select>
          <input placeholder="Full name" value={form.fullName} onChange={(event) => setForm({ ...form, fullName: event.target.value })} />
          <input placeholder="Email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} />
          <button>Create</button>
          {message && <p className="muted">{message}</p>}
        </form>
      </article>
      <article className="card">
        <h2>Users</h2>
        <div className="table-wrap">
          <table>
            <thead><tr><th>User</th><th>Role</th><th>Email</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id}>
                  <td>{user.username}</td>
                  <td>{user.role}</td>
                  <td>{user.email}</td>
                  <td>{user.enabled === false ? 'Disabled' : 'Enabled'}</td>
                  <td className="action-cell"><button onClick={() => openPasswordPanel(user)}>Change password</button><button onClick={() => toggleEnabled(user)}>{user.enabled === false ? 'Enable' : 'Disable'}</button><button className="danger-btn" onClick={() => remove(user.id)}>Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {passwordPanel && (
          <div className="card password-panel">
            <h2>Change Password</h2>
            <p className="muted">User: {users.find((user) => user.id === passwordPanel.userId)?.username}</p>
            <div className="stack-form">
              <input type="password" placeholder="New password" value={passwordPanel.password} onChange={(event) => setPasswordPanel({ ...passwordPanel, password: event.target.value })} />
              <input type="password" placeholder="Confirm new password" value={passwordPanel.confirm} onChange={(event) => setPasswordPanel({ ...passwordPanel, confirm: event.target.value })} />
              <div className="confirm-actions"><button className="btn-secondary" onClick={() => setPasswordPanel(null)}>Cancel</button><button onClick={() => { const user = users.find((item) => item.id === passwordPanel.userId); if (user) acceptPasswordChange(user); }}>Accept</button></div>
            </div>
          </div>
        )}
      </article>
    </section>
  );
}
