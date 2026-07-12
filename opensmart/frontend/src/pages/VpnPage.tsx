import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api';
import type { VpnInstance, VpnUser } from '../types';

const LDAP_FIELDS: { key: string; label: string; placeholder: string; required?: boolean }[] = [
  { key: 'url', label: 'LDAP URL', placeholder: 'ldap://dc1.example.local', required: true },
  { key: 'base_dn', label: 'Base DN', placeholder: 'dc=example,dc=local', required: true },
  { key: 'bind_dn', label: 'Bind DN (optional)', placeholder: 'cn=vpn,cn=Users,dc=example,dc=local' },
  { key: 'bind_password', label: 'Bind password', placeholder: '' },
  { key: 'search_filter', label: 'Search filter', placeholder: '(sAMAccountName=%u)' },
];

function formatUptime(seconds: number | null): string {
  if (seconds === null || seconds === undefined) return '';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
}

export default function VpnPage() {
  const [instances, setInstances] = useState<VpnInstance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: '', vpn_type: 'openvpn', port: '1194', auth_mode: 'certs' });
  const [ldap, setLdap] = useState<Record<string, string>>({});
  const [expanded, setExpanded] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function refresh() {
    try {
      const result = await api.vpnInstances();
      setInstances(result.instances);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load VPN instances');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { refresh(); }, []);

  async function createInstance(event: FormEvent) {
    event.preventDefault();
    setCreating(true);
    setError('');
    try {
      await api.vpnCreateInstance({
        name: form.name.trim(),
        vpn_type: form.vpn_type,
        port: Number(form.port),
        auth_mode: form.vpn_type === 'openvpn' ? form.auth_mode : 'certs',
        ldap_config: form.auth_mode === 'ldap' ? ldap : {},
      });
      setShowCreate(false);
      setForm({ name: '', vpn_type: 'openvpn', port: '1194', auth_mode: 'certs' });
      setLdap({});
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create instance');
    } finally {
      setCreating(false);
    }
  }

  async function action(name: string, act: 'start' | 'stop' | 'restart') {
    setBusy(name);
    setError('');
    try {
      const result = await api.vpnInstanceAction(name, act);
      if (!result.ok) setError(`${name}: ${result.detail || `${act} failed`}`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : `${act} failed`);
    } finally {
      setBusy(null);
    }
  }

  async function remove(name: string) {
    if (!window.confirm(`Delete VPN instance '${name}'? All its certificates, keys and client configs are destroyed.`)) return;
    setBusy(name);
    setError('');
    try {
      await api.vpnDeleteInstance(name);
      if (expanded === name) setExpanded(null);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed');
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="admin-stack">
      <article className="card">
        <div className="section-actions">
          <div>
            <h2>Access VPN</h2>
            <p className="muted">OpenVPN and WireGuard server instances, each on its own port with its own users and certificates.</p>
          </div>
          <button onClick={() => setShowCreate((v) => !v)}>{showCreate ? 'Cancel' : 'New instance'}</button>
        </div>
        {error && <p className="error-text">{error}</p>}

        {showCreate && (
          <form className="vpn-create-form" onSubmit={createInstance}>
            <div className="vpn-form-grid">
              <label>Name<input value={form.name} maxLength={30} placeholder="office" pattern="[a-z0-9][a-z0-9-]*" title="lowercase letters, digits, dashes" required onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
              <label>Type<select value={form.vpn_type} onChange={(e) => setForm({ ...form, vpn_type: e.target.value, port: e.target.value === 'openvpn' ? '1194' : '51820' })}><option value="openvpn">OpenVPN</option><option value="wireguard">WireGuard</option></select></label>
              <label>UDP port<input type="number" min={1024} max={65535} value={form.port} required onChange={(e) => setForm({ ...form, port: e.target.value })} /></label>
              {form.vpn_type === 'openvpn' && (
                <label>Authentication<select value={form.auth_mode} onChange={(e) => setForm({ ...form, auth_mode: e.target.value })}><option value="certs">Local certificates</option><option value="ldap">LDAP / Samba AD + certs</option></select></label>
              )}
            </div>
            {form.vpn_type === 'openvpn' && form.auth_mode === 'ldap' && (
              <div className="vpn-form-grid">
                {LDAP_FIELDS.map((field) => (
                  <label key={field.key}>{field.label}<input type={field.key === 'bind_password' ? 'password' : 'text'} value={ldap[field.key] || ''} placeholder={field.placeholder} required={field.required} onChange={(e) => setLdap({ ...ldap, [field.key]: e.target.value })} /></label>
                ))}
              </div>
            )}
            <div className="config-save-bar">
              <button disabled={creating}>{creating ? 'Creating (generating keys)…' : 'Create instance'}</button>
            </div>
          </form>
        )}

        {loading && <p className="muted">Loading…</p>}
        {!loading && instances.length === 0 && !showCreate && (
          <p className="muted">No VPN instances yet. Create one to generate its server keys/PKI and publish its port.</p>
        )}
        {instances.length > 0 && (
          <table className="status-table containers-table">
            <thead><tr><th>Instance</th><th>Type</th><th>Port</th><th>Subnet</th><th>Auth</th><th>State</th><th>Users</th><th></th></tr></thead>
            <tbody>
              {instances.map((instance) => (
                <tr key={instance.name}>
                  <td><button className="text-button" onClick={() => setExpanded(expanded === instance.name ? null : instance.name)}>{instance.name}</button></td>
                  <td>{instance.vpn_type === 'openvpn' ? 'OpenVPN' : 'WireGuard'}</td>
                  <td>{instance.port}/udp</td>
                  <td>{instance.subnet}</td>
                  <td>{instance.auth_mode === 'ldap' ? 'LDAP' : 'Certs'}</td>
                  <td>
                    <span className={`badge ${instance.running ? 'ok' : 'muted'}`}>{instance.running ? 'Running' : instance.status === 'not created' ? 'Stopped' : instance.status}</span>
                    {instance.running && instance.uptime_seconds !== null && <small className="muted"> {formatUptime(instance.uptime_seconds)}</small>}
                  </td>
                  <td>{instance.users}</td>
                  <td className="vpn-actions">
                    {instance.running
                      ? <>
                          <button className="restart-btn" disabled={busy === instance.name} onClick={() => action(instance.name, 'restart')}>Restart</button>
                          <button className="restart-btn" disabled={busy === instance.name} onClick={() => action(instance.name, 'stop')}>Stop</button>
                        </>
                      : <button className="restart-btn" disabled={busy === instance.name} onClick={() => action(instance.name, 'start')}>Start</button>}
                    <button className="restart-btn danger" disabled={busy === instance.name} onClick={() => remove(instance.name)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </article>

      {expanded && <UsersPanel instance={instances.find((i) => i.name === expanded)} onChanged={refresh} />}
    </section>
  );
}

function UsersPanel({ instance, onChanged }: { instance?: VpnInstance; onChanged: () => void }) {
  const [users, setUsers] = useState<VpnUser[]>([]);
  const [error, setError] = useState('');
  const [username, setUsername] = useState('');
  const [serverHost, setServerHost] = useState(window.location.hostname);
  const [working, setWorking] = useState(false);

  async function refreshUsers() {
    if (!instance) return;
    try {
      const result = await api.vpnUsers(instance.name);
      setUsers(result.users);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users');
    }
  }

  useEffect(() => { refreshUsers(); /* eslint-disable-line react-hooks/exhaustive-deps */ }, [instance?.name]);

  if (!instance) return null;

  async function createUser(event: FormEvent) {
    event.preventDefault();
    setWorking(true);
    setError('');
    try {
      await api.vpnCreateUser(instance!.name, username.trim(), serverHost.trim());
      setUsername('');
      await refreshUsers();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create user');
    } finally {
      setWorking(false);
    }
  }

  async function revoke(name: string) {
    if (!window.confirm(`Revoke '${name}'? Their VPN access stops working${instance!.vpn_type === 'openvpn' ? ' (certificate added to the CRL)' : ''}.`)) return;
    setWorking(true);
    setError('');
    try {
      await api.vpnRevokeUser(instance!.name, name);
      await refreshUsers();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Revoke failed');
    } finally {
      setWorking(false);
    }
  }

  async function download(name: string) {
    setError('');
    try {
      const { filename, content } = await api.vpnUserConfig(instance!.name, name);
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Download failed');
    }
  }

  return (
    <article className="card">
      <h2>Users — {instance.name} ({instance.vpn_type === 'openvpn' ? 'OpenVPN' : 'WireGuard'})</h2>
      {instance.auth_mode === 'ldap' && <p className="muted">This instance also validates credentials against LDAP/Samba AD at connect time; certificates below remain the transport identity.</p>}
      {error && <p className="error-text">{error}</p>}
      <form className="vpn-form-grid vpn-user-form" onSubmit={createUser}>
        <label>User name<input value={username} maxLength={40} pattern="[A-Za-z0-9][A-Za-z0-9._-]*" title="letters, digits, dot, underscore, dash" required onChange={(e) => setUsername(e.target.value)} /></label>
        <label>Server host/IP in client config<input value={serverHost} required onChange={(e) => setServerHost(e.target.value)} /></label>
        <button disabled={working}>{working ? 'Working…' : 'Create user'}</button>
      </form>
      {users.length === 0
        ? <p className="muted">No users yet.</p>
        : (
          <table className="status-table containers-table">
            <thead><tr><th>Name</th><th>Status</th><th>Expires</th><th></th></tr></thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.name}>
                  <td>{user.name}</td>
                  <td><span className={`badge ${user.status === 'valid' ? 'ok' : user.status === 'revoked' ? 'danger' : 'warning'}`}>{user.status}</span></td>
                  <td>{user.expires_at ? user.expires_at.slice(0, 10) : '—'}</td>
                  <td className="vpn-actions">
                    {user.has_config && user.status === 'valid' && <button className="restart-btn" onClick={() => download(user.name)}>Download config</button>}
                    {user.status === 'valid' && <button className="restart-btn danger" disabled={working} onClick={() => revoke(user.name)}>Revoke</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
    </article>
  );
}
