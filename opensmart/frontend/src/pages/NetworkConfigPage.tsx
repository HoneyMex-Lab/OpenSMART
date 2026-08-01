import { useEffect, useState } from 'react';
import { api } from '../api';
import type { InterfaceRole, MtuApply, NetworkInterface } from '../types';

const ROLE_OPTIONS: { value: InterfaceRole; label: string }[] = [
  { value: '', label: '—' },
  { value: 'wan', label: 'WAN' },
  { value: 'lan', label: 'LAN' },
  { value: 'dmz', label: 'DMZ' },
  { value: 'mgmt', label: 'Management' },
  { value: 'monitor', label: 'Monitor' },
];

type RowDraft = { alias: string; description: string; role: InterfaceRole };

function draftFrom(iface: NetworkInterface): RowDraft {
  return { alias: iface.alias, description: iface.description, role: iface.role };
}

type MtuDialogState = { name: string; mtuValue: string; confirmSeconds: string };

function secondsLeft(expiresAt: string, now: number): number {
  return Math.max(0, Math.round((new Date(expiresAt).getTime() - now) / 1000));
}

export default function NetworkConfigPage() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [loading, setLoading] = useState(true);
  const [rescanning, setRescanning] = useState(false);
  const [showVirtual, setShowVirtual] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, RowDraft>>({});
  const [message, setMessage] = useState('');
  const [mtuDialog, setMtuDialog] = useState<MtuDialogState | null>(null);
  const [mtuError, setMtuError] = useState('');
  const [pendingApply, setPendingApply] = useState<MtuApply | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => { load(); }, []);

  // Poll the pending apply's outcome; also ticks `now` every second so the
  // countdown banner updates without a separate timer.
  useEffect(() => {
    if (!pendingApply || pendingApply.state !== 'pending') return;
    const interval = setInterval(async () => {
      setNow(Date.now());
      try {
        const result = await api.netMtuStatus(pendingApply.name);
        if (result.apply) {
          setPendingApply(result.apply);
          if (result.apply.state !== 'pending') load();
        }
      } catch { /* keep showing the last known state */ }
    }, 1500);
    return () => clearInterval(interval);
  }, [pendingApply]);

  function load() {
    setLoading(true);
    api.netInterfaces().then((result) => setInterfaces(result.interfaces)).catch(() => undefined).finally(() => setLoading(false));
  }

  async function rescan() {
    setRescanning(true);
    try {
      const result = await api.netRescan();
      setInterfaces(result.interfaces);
    } finally {
      setRescanning(false);
    }
  }

  function startEdit(iface: NetworkInterface) {
    setEditing(iface.name);
    setDrafts((prev) => ({ ...prev, [iface.name]: draftFrom(iface) }));
  }

  function cancelEdit() {
    setEditing(null);
  }

  async function saveEdit(name: string) {
    const draft = drafts[name];
    if (!draft) return;
    setMessage('');
    try {
      await api.netUpdateInterface(name, draft);
      setEditing(null);
      load();
      setMessage(`${name} updated.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : `Could not update ${name}.`);
    }
  }

  async function toggleMonitor(iface: NetworkInterface) {
    try {
      await api.netUpdateInterface(iface.name, { monitor: !iface.monitor });
      load();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : `Could not update ${iface.name}.`);
    }
  }

  function openMtuDialog(iface: NetworkInterface) {
    setMtuError('');
    setMtuDialog({ name: iface.name, mtuValue: String(iface.mtu ?? 1500), confirmSeconds: '60' });
  }

  function closeMtuDialog() {
    setMtuDialog(null);
    setMtuError('');
  }

  async function submitMtu() {
    if (!mtuDialog) return;
    const mtu = Number.parseInt(mtuDialog.mtuValue, 10);
    const confirmSeconds = Number.parseInt(mtuDialog.confirmSeconds, 10);
    if (!Number.isFinite(mtu) || !Number.isFinite(confirmSeconds)) {
      setMtuError('Enter valid numbers.');
      return;
    }
    try {
      const result = await api.netSetMtu(mtuDialog.name, mtu, confirmSeconds);
      setPendingApply({
        name: mtuDialog.name, token: result.token, old_mtu: result.old_mtu, new_mtu: result.new_mtu,
        state: 'pending', expires_at: result.expires_at, detail: '',
      });
      setMtuDialog(null);
    } catch (error) {
      setMtuError(error instanceof Error ? error.message : 'Could not start the MTU change.');
    }
  }

  async function confirmPending() {
    if (!pendingApply) return;
    await api.netConfirmMtu(pendingApply.name, pendingApply.token);
    setPendingApply(null);
    load();
  }

  async function revertPending() {
    if (!pendingApply) return;
    await api.netCancelMtu(pendingApply.name, pendingApply.token);
    setPendingApply(null);
    load();
  }

  async function remap(oldName: string) {
    const newName = window.prompt(`Which currently-detected interface should take over "${oldName}"'s alias, role, and monitor setting?`, '');
    if (!newName) return;
    try {
      await api.netRemapInterface(oldName, newName.trim());
      load();
      setMessage(`${oldName} remapped to ${newName.trim()}.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Remap failed.');
    }
  }

  const visible = interfaces.filter((iface) => showVirtual || !iface.virtual);
  const upCount = interfaces.filter((iface) => iface.present && iface.up).length;
  const monitorCount = interfaces.filter((iface) => iface.monitor).length;
  const hiddenVirtualCount = interfaces.filter((iface) => iface.virtual).length;

  return (
    <section className="admin-stack">
      {mtuDialog && (
        <div className="confirm-overlay">
          <div className="confirm-dialog card">
            <h3>Change MTU for {mtuDialog.name}</h3>
            <p className="muted">
              Applied immediately, live. If you don't click "Keep changes" within the confirm window, it reverts
              automatically — so a value that breaks your own connection to this box heals itself.
            </p>
            <label className="wizard-field">
              New MTU
              <input type="number" value={mtuDialog.mtuValue} onChange={(event) => setMtuDialog({ ...mtuDialog, mtuValue: event.target.value })} />
            </label>
            <label className="wizard-field">
              Confirm window (seconds)
              <input type="number" value={mtuDialog.confirmSeconds} onChange={(event) => setMtuDialog({ ...mtuDialog, confirmSeconds: event.target.value })} />
            </label>
            {mtuError && <p className="error-text">{mtuError}</p>}
            <div className="confirm-actions">
              <button className="btn-secondary" onClick={closeMtuDialog}>Cancel</button>
              <button onClick={submitMtu}>Apply</button>
            </div>
          </div>
        </div>
      )}

      {pendingApply && pendingApply.state === 'pending' && (
        <article className="card wizard-notice warning">
          <p>
            <strong>{pendingApply.name}</strong> MTU changed to {pendingApply.new_mtu} (was {pendingApply.old_mtu}) —
            reverting automatically in {secondsLeft(pendingApply.expires_at, now)}s unless confirmed.
          </p>
          <div className="config-save-bar">
            <button className="btn-secondary" onClick={revertPending}>Revert now</button>
            <button onClick={confirmPending}>Keep changes</button>
          </div>
        </article>
      )}
      {pendingApply && pendingApply.state !== 'pending' && (
        <article className="card wizard-notice">
          <p>
            {pendingApply.name}: MTU change {pendingApply.state === 'confirmed' ? 'kept' : pendingApply.state === 'reverted' ? 'was reverted automatically — connectivity was not confirmed in time.' : `failed (${pendingApply.detail})`}.
          </p>
        </article>
      )}

      <article className="card">
        <div className="section-actions">
          <div>
            <h2>Network interfaces</h2>
            <p className="muted">
              {interfaces.length} interface{interfaces.length === 1 ? '' : 's'} · {upCount} up · {monitorCount} monitored.
              Aliases and roles are labels only — modules always refer to the real interface name.
            </p>
          </div>
          <button className="btn-secondary" onClick={rescan} disabled={rescanning}>{rescanning ? 'Rescanning…' : 'Rescan'}</button>
        </div>

        {message && <p className="muted">{message}</p>}
        {loading && <p className="muted">Loading interfaces…</p>}

        {!loading && (
          <div className="table-wrap">
            <table className="status-table containers-table">
              <thead>
                <tr>
                  <th>Interface</th>
                  <th>State</th>
                  <th>MTU</th>
                  <th>Addresses</th>
                  <th>Role</th>
                  <th>Monitor</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {visible.map((iface) => {
                  const isEditing = editing === iface.name;
                  const draft = drafts[iface.name] ?? draftFrom(iface);
                  return (
                    <tr key={iface.name}>
                      <td className="status-table-name">
                        {isEditing ? (
                          <input value={draft.alias} placeholder="Alias" maxLength={60}
                            onChange={(event) => setDrafts((prev) => ({ ...prev, [iface.name]: { ...draft, alias: event.target.value } }))} />
                        ) : (
                          <>{iface.alias ? `${iface.alias} (${iface.name})` : iface.name}</>
                        )}
                        {iface.mac_drift && <small className="wizard-notice warning">MAC changed since last seen — check if this NIC was replaced.</small>}
                      </td>
                      <td>
                        {!iface.present ? <span className="badge muted">Not present</span>
                          : <span className={`badge ${iface.up ? 'ok-dim' : 'muted'}`}>{iface.up ? 'Up' : 'Down'}</span>}
                        {iface.virtual && <span className="badge muted" style={{ marginLeft: 6 }}>virtual</span>}
                      </td>
                      <td>
                        {iface.mtu ?? '—'}{iface.mtu_override != null && <small className="muted"> (override {iface.mtu_override})</small>}
                        {iface.present && !iface.virtual && (
                          <button className="text-button" onClick={() => openMtuDialog(iface)} disabled={!!pendingApply && pendingApply.state === 'pending'}>Change MTU…</button>
                        )}
                      </td>
                      <td className="status-table-detail">{iface.addresses.map((a) => a.address).join(', ') || '—'}</td>
                      <td>
                        {isEditing ? (
                          <select value={draft.role} onChange={(event) => setDrafts((prev) => ({ ...prev, [iface.name]: { ...draft, role: event.target.value as InterfaceRole } }))}>
                            {ROLE_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                          </select>
                        ) : (
                          ROLE_OPTIONS.find((option) => option.value === iface.role)?.label || '—'
                        )}
                      </td>
                      <td>
                        <button role="switch" aria-checked={iface.monitor} className={`toggle-switch ${iface.monitor ? 'on' : ''}`} onClick={() => toggleMonitor(iface)} disabled={!iface.present}>
                          <span className="toggle-thumb" />
                        </button>
                      </td>
                      <td>
                        {isEditing ? (
                          <div className="config-save-bar" style={{ margin: 0 }}>
                            <button className="btn-secondary" onClick={cancelEdit}>Cancel</button>
                            <button onClick={() => saveEdit(iface.name)}>Save</button>
                          </div>
                        ) : iface.present ? (
                          <button className="btn-secondary" onClick={() => startEdit(iface)}>Edit</button>
                        ) : (
                          <button className="btn-secondary" onClick={() => remap(iface.name)}>Remap…</button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {hiddenVirtualCount > 0 && (
          <button className="warning-toggle" onClick={() => setShowVirtual((value) => !value)}>
            {showVirtual ? 'Hide' : 'Show'} {hiddenVirtualCount} virtual interface{hiddenVirtualCount === 1 ? '' : 's'} (bridges, veth, tunnels)
          </button>
        )}
      </article>
    </section>
  );
}
