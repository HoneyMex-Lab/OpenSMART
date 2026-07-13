import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api';
import type { VpnConnection, VpnInstance, VpnStatus, VpnUser } from '../types';

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

function formatBytes(n: number): string {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = n;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
  return `${value.toFixed(i > 0 && value < 10 ? 1 : 0)} ${units[i]}`;
}

function formatHandshake(unix: number): string {
  if (!unix) return 'never';
  const s = Math.floor(Date.now() / 1000) - unix;
  if (s < 0) return 'now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export default function VpnPage() {
  const [instances, setInstances] = useState<VpnInstance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: '', vpn_type: 'openvpn', port: '1194', auth_mode: 'certs', subnet: '', dns: '1.1.1.1', tunnel: 'full', routes: '' });
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
    const newName = form.name.trim();
    try {
      await api.vpnCreateInstance({
        name: newName,
        vpn_type: form.vpn_type,
        port: Number(form.port),
        auth_mode: form.vpn_type === 'openvpn' ? form.auth_mode : 'certs',
        ldap_config: form.auth_mode === 'ldap' ? ldap : {},
        subnet: form.subnet.trim() || undefined,
        settings: { dns: form.dns.trim(), tunnel: form.tunnel as 'full' | 'split', routes: form.tunnel === 'split' ? form.routes.trim() : '' },
      });
      setShowCreate(false);
      setForm({ name: '', vpn_type: 'openvpn', port: '1194', auth_mode: 'certs', subnet: '', dns: '1.1.1.1', tunnel: 'full', routes: '' });
      setLdap({});
      await refresh();
      setExpanded(newName);  // open the new instance straight into its management panel
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
            <p className="muted">OpenVPN and WireGuard server instances, each on its own port with its own users, live status and settings.</p>
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
            <div className="vpn-form-grid">
              <label>VPN network<input value={form.subnet} placeholder="auto (10.x.0.0/24)" pattern="\d{1,3}(\.\d{1,3}){3}/24" title="an IPv4 /24, e.g. 10.20.0.0/24 — leave blank to auto-assign" onChange={(e) => setForm({ ...form, subnet: e.target.value })} /></label>
              <label>Client DNS<input value={form.dns} placeholder="1.1.1.1, 9.9.9.9" onChange={(e) => setForm({ ...form, dns: e.target.value })} /></label>
              <label>Tunnel mode<select value={form.tunnel} onChange={(e) => setForm({ ...form, tunnel: e.target.value })}><option value="full">Full — all client traffic</option><option value="split">Split — only routed subnets</option></select></label>
              {form.tunnel === 'split' && <label>Routed subnets<input value={form.routes} placeholder="10.0.0.0/8, 192.168.1.0/24" onChange={(e) => setForm({ ...form, routes: e.target.value })} /></label>}
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
              {instances.map((instance) => {
                const open = expanded === instance.name;
                const toggle = () => setExpanded(open ? null : instance.name);
                return (
                <tr key={instance.name} className={open ? 'vpn-row-active' : ''}>
                  <td><button className="text-button vpn-name-toggle" aria-expanded={open} onClick={toggle}>{open ? '▾' : '▸'} {instance.name}</button></td>
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
                    <button className="restart-btn" onClick={toggle}>{open ? 'Close' : 'Manage'}</button>
                    {instance.running
                      ? <>
                          <button className="restart-btn" disabled={busy === instance.name} onClick={() => action(instance.name, 'restart')}>Restart</button>
                          <button className="restart-btn" disabled={busy === instance.name} onClick={() => action(instance.name, 'stop')}>Stop</button>
                        </>
                      : <button className="restart-btn" disabled={busy === instance.name} onClick={() => action(instance.name, 'start')}>Start</button>}
                    <button className="restart-btn danger" disabled={busy === instance.name} onClick={() => remove(instance.name)}>Delete</button>
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {instances.length > 0 && (
          <p className="muted">Select <strong>Manage</strong> on an instance to add / enable / disable / revoke its VPN users (separate from OpenSMART logins), watch live connections and traffic, edit server settings, and view logs.</p>
        )}
      </article>

      {expanded && <InstanceDetail instance={instances.find((i) => i.name === expanded)} onChanged={refresh} />}
    </section>
  );
}

type Tab = 'status' | 'users' | 'settings' | 'logs';

function InstanceDetail({ instance, onChanged }: { instance?: VpnInstance; onChanged: () => void }) {
  const [tab, setTab] = useState<Tab>('status');
  useEffect(() => { setTab('status'); }, [instance?.name]);
  if (!instance) return null;
  const TABS: { id: Tab; label: string }[] = [
    { id: 'status', label: 'Live status' },
    { id: 'users', label: 'Users' },
    { id: 'settings', label: 'Server settings' },
    { id: 'logs', label: 'Logs' },
  ];
  return (
    <article className="card">
      <h2>{instance.name} <small className="muted">({instance.vpn_type === 'openvpn' ? 'OpenVPN' : 'WireGuard'} · {instance.port}/udp · {instance.subnet})</small></h2>
      <div className="config-subtabs vpn-tabs">
        {TABS.map((t) => <button key={t.id} className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}>{t.label}</button>)}
      </div>
      {tab === 'status' && <StatusTab instance={instance} />}
      {tab === 'users' && <UsersTab instance={instance} onChanged={onChanged} />}
      {tab === 'settings' && <SettingsTab instance={instance} onChanged={onChanged} />}
      {tab === 'logs' && <LogsTab instance={instance} />}
    </article>
  );
}

function StatusTab({ instance }: { instance: VpnInstance }) {
  const [status, setStatus] = useState<VpnStatus | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const result = await api.vpnInstanceStatus(instance.name);
        if (active) { setStatus(result); setError(''); }
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : 'Failed to load status');
      }
    }
    load();
    const timer = setInterval(load, 5000);
    return () => { active = false; clearInterval(timer); };
  }, [instance.name]);

  if (error) return <p className="error-text">{error}</p>;
  if (!status) return <p className="muted">Loading status…</p>;
  if (!status.running) return <p className="muted">Instance is stopped — start it to see live connections.</p>;

  const online = status.connected.filter((c) => c.online).length;
  return (
    <>
      <div className="vpn-status-summary">
        <span className="badge ok">Running</span>
        <span className="muted">Uptime {formatUptime(status.uptime_seconds)}</span>
        <span className="muted">·</span>
        <span><strong>{online}</strong> online / {status.total_users} user{status.total_users === 1 ? '' : 's'}</span>
      </div>
      {status.connected.length === 0
        ? <p className="muted">No client sessions yet. Connected clients and their traffic appear here (refreshes every 5s).</p>
        : (
          <table className="status-table containers-table">
            <thead><tr><th>User</th><th>State</th><th>Endpoint</th><th>Assigned</th><th>Download</th><th>Upload</th><th>Last handshake</th></tr></thead>
            <tbody>
              {status.connected.map((c: VpnConnection) => (
                <tr key={c.name}>
                  <td>{c.name}</td>
                  <td><span className={`badge ${c.online ? 'ok' : 'muted'}`}>{c.online ? 'Online' : 'Idle'}</span></td>
                  <td className="muted">{c.endpoint || '—'}</td>
                  <td className="muted">{c.allowed_ips || '—'}</td>
                  <td>↓ {formatBytes(c.rx_bytes)}</td>
                  <td>↑ {formatBytes(c.tx_bytes)}</td>
                  <td className="muted">{instance.vpn_type === 'wireguard' ? formatHandshake(c.last_handshake) : 'connected'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
    </>
  );
}

function UsersTab({ instance, onChanged }: { instance: VpnInstance; onChanged: () => void }) {
  const [users, setUsers] = useState<VpnUser[]>([]);
  const [error, setError] = useState('');
  const [username, setUsername] = useState('');
  const [serverHost, setServerHost] = useState(window.location.hostname);
  const [working, setWorking] = useState(false);

  async function refreshUsers() {
    try {
      const result = await api.vpnUsers(instance.name);
      setUsers(result.users);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users');
    }
  }

  useEffect(() => { refreshUsers(); /* eslint-disable-line react-hooks/exhaustive-deps */ }, [instance.name]);

  async function createUser(event: FormEvent) {
    event.preventDefault();
    setWorking(true);
    setError('');
    try {
      await api.vpnCreateUser(instance.name, username.trim(), serverHost.trim());
      setUsername('');
      await refreshUsers();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create user');
    } finally {
      setWorking(false);
    }
  }

  async function toggle(name: string, enabled: boolean) {
    setWorking(true);
    setError('');
    try {
      await api.vpnSetUserEnabled(instance.name, name, enabled);
      await refreshUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update user');
    } finally {
      setWorking(false);
    }
  }

  async function revoke(name: string) {
    if (!window.confirm(`Revoke '${name}'? Their VPN access is permanently removed${instance.vpn_type === 'openvpn' ? ' (certificate added to the CRL)' : ''}.`)) return;
    setWorking(true);
    setError('');
    try {
      await api.vpnRevokeUser(instance.name, name);
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
      const { filename, content } = await api.vpnUserConfig(instance.name, name);
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
    <>
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
                  <td><span className={`badge ${user.status === 'valid' ? 'ok' : user.status === 'disabled' ? 'warning' : user.status === 'revoked' ? 'danger' : 'muted'}`}>{user.status}</span></td>
                  <td>{user.expires_at ? user.expires_at.slice(0, 10) : '—'}</td>
                  <td className="vpn-actions">
                    {user.has_config && user.status !== 'revoked' && <button className="restart-btn" onClick={() => download(user.name)}>Download config</button>}
                    {user.status === 'valid' && <button className="restart-btn" disabled={working} onClick={() => toggle(user.name, false)}>Disable</button>}
                    {user.status === 'disabled' && <button className="restart-btn" disabled={working} onClick={() => toggle(user.name, true)}>Enable</button>}
                    {user.status !== 'revoked' && <button className="restart-btn danger" disabled={working} onClick={() => revoke(user.name)}>Revoke</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
    </>
  );
}

function SettingsTab({ instance, onChanged }: { instance: VpnInstance; onChanged: () => void }) {
  const [dns, setDns] = useState(instance.settings?.dns ?? '1.1.1.1');
  const [tunnel, setTunnel] = useState<'full' | 'split'>(instance.settings?.tunnel ?? 'full');
  const [routes, setRoutes] = useState(instance.settings?.routes ?? '');
  const [ldap, setLdap] = useState<Record<string, string>>({});
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDns(instance.settings?.dns ?? '1.1.1.1');
    setTunnel(instance.settings?.tunnel ?? 'full');
    setRoutes(instance.settings?.routes ?? '');
  }, [instance.name, instance.settings]);

  async function save(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError('');
    setMessage('');
    try {
      const payload: { settings: { dns: string; tunnel: 'full' | 'split'; routes: string }; ldap_config?: Record<string, string> } = { settings: { dns, tunnel, routes } };
      if (instance.auth_mode === 'ldap' && Object.values(ldap).some((v) => v.trim())) payload.ldap_config = ldap;
      await api.vpnUpdateInstance(instance.name, payload);
      setMessage(`Saved.${instance.running ? ' Existing clients must re-download their config to pick up DNS/route changes.' : ''}`);
      setLdap({});
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className="stack-form" onSubmit={save}>
      <p className="muted">Server settings apply to new client configs immediately; existing WireGuard clients keep their keys but must re-download to change DNS/routes.</p>
      {error && <p className="error-text">{error}</p>}
      <div className="vpn-form-grid">
        <label>Client DNS<input value={dns} placeholder="1.1.1.1, 9.9.9.9" onChange={(e) => setDns(e.target.value)} /></label>
        <label>Tunnel mode<select value={tunnel} onChange={(e) => setTunnel(e.target.value as 'full' | 'split')}>
          <option value="full">Full — route all client traffic</option>
          <option value="split">Split — only the routes below</option>
        </select></label>
        {tunnel === 'split' && <label>Routed subnets<input value={routes} placeholder="10.0.0.0/8, 192.168.1.0/24" onChange={(e) => setRoutes(e.target.value)} /></label>}
      </div>
      {instance.auth_mode === 'ldap' && (
        <>
          <p className="muted">Update LDAP / Samba AD binding (leave blank to keep the current configuration):</p>
          <div className="vpn-form-grid">
            {LDAP_FIELDS.map((field) => (
              <label key={field.key}>{field.label}<input type={field.key === 'bind_password' ? 'password' : 'text'} value={ldap[field.key] || ''} placeholder={field.placeholder} onChange={(e) => setLdap({ ...ldap, [field.key]: e.target.value })} /></label>
            ))}
          </div>
        </>
      )}
      <div className="config-save-bar">
        <button disabled={saving}>{saving ? 'Saving…' : 'Save settings'}</button>
        {message && <span className="muted">{message}</span>}
      </div>
    </form>
  );
}

function LogsTab({ instance }: { instance: VpnInstance }) {
  const [logs, setLogs] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const result = await api.vpnInstanceLogs(instance.name, 300);
      setLogs(result.logs || '(no logs yet)');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load logs');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); /* eslint-disable-line react-hooks/exhaustive-deps */ }, [instance.name]);

  return (
    <>
      <div className="section-actions">
        <p className="muted">Server logs (connection and handshake events), most recent last.</p>
        <button className="restart-btn" disabled={loading} onClick={load}>{loading ? 'Refreshing…' : 'Refresh'}</button>
      </div>
      {error && <p className="error-text">{error}</p>}
      <pre className="vpn-logs">{logs}</pre>
    </>
  );
}
