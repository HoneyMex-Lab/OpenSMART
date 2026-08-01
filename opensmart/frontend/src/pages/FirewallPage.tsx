import { useEffect, useState } from 'react';
import { api } from '../api';
import type { FirewallChain, FirewallProfile, FirewallRule, FirewallSummary, FirewallValidateResult } from '../types';

type Tab = 'overview' | 'rules' | 'advanced';

const CHAINS: FirewallChain[] = ['input', 'forward', 'output'];

function secondsLeft(expiresAt: string, now: number): number {
  return Math.max(0, Math.round((new Date(expiresAt).getTime() - now) / 1000));
}

export default function FirewallPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const [summary, setSummary] = useState<FirewallSummary | null>(null);
  const [error, setError] = useState('');
  const [now, setNow] = useState(() => Date.now());

  async function load() {
    try {
      setSummary(await api.fwSummary());
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load firewall summary');
    }
  }
  useEffect(() => { load(); }, []);

  // Poll while an apply is pending — server-driven (not a client flag), so a
  // page reload or a second admin still sees the same countdown/outcome.
  useEffect(() => {
    if (!summary?.pending_apply || summary.pending_apply.state !== 'pending') return;
    const interval = setInterval(() => { setNow(Date.now()); load(); }, 1500);
    return () => clearInterval(interval);
  }, [summary?.pending_apply?.state]);

  async function confirmPending() {
    if (!summary?.pending_apply) return;
    await api.fwConfirmApply(summary.pending_apply.token);
    await load();
  }

  async function revertPending() {
    if (!summary?.pending_apply) return;
    await api.fwCancelApply(summary.pending_apply.token);
    await load();
  }

  const TABS: { id: Tab; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'rules', label: 'Rules' },
    { id: 'advanced', label: 'Advanced' },
  ];

  const pending = summary?.pending_apply;

  return (
    <section className="ids-manager">
      <div className="section-actions">
        <div>
          <h3>Firewall (nftables)</h3>
          <p className="muted">
            Manage rule profiles for L3/L4 traffic control. Applying a profile always requires confirming the
            change within a countdown window — an unconfirmed apply reverts itself automatically.
          </p>
        </div>
        {summary?.live && <span className={`badge ${summary.live.applied ? 'ok' : 'muted'}`}>{summary.live.applied ? 'Live' : 'Not applied'}</span>}
      </div>

      {error && <p className="error-text">{error}</p>}

      {pending && pending.state === 'pending' && (
        <article className="card wizard-notice warning">
          <p>
            Applying profile #{pending.profile_id} — reverting automatically in {secondsLeft(pending.expires_at, now)}s unless confirmed.
          </p>
          <div className="config-save-bar">
            <button className="btn-secondary" onClick={revertPending}>Revert now</button>
            <button onClick={confirmPending}>Keep changes</button>
          </div>
        </article>
      )}
      {pending && pending.state !== 'pending' && pending.detail !== '' && (
        <article className="card wizard-notice">
          <p>
            Last apply {pending.state === 'confirmed' ? 'kept' : pending.state === 'reverted' ? 'was reverted automatically — connectivity was not confirmed in time.' : `failed (${pending.detail})`}.
          </p>
        </article>
      )}
      {summary?.live?.dirty && (
        <article className="card wizard-notice warning">
          <p>The active profile has unapplied changes — the live ruleset doesn't match its current rules. Apply to sync.</p>
        </article>
      )}

      {summary && (
        <div className="ids-status-strip">
          <span><strong>{summary.active_profile?.name || '—'}</strong> active profile</span>
          <span className="muted">·</span>
          <span><strong>{summary.rule_count}</strong> rule{summary.rule_count === 1 ? '' : 's'}</span>
          <span className="muted">·</span>
          <span>{summary.profiles.length} profile{summary.profiles.length === 1 ? '' : 's'} total</span>
        </div>
      )}

      <div className="config-subtabs ids-tabs">
        {TABS.map((t) => <button key={t.id} className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}>{t.label}</button>)}
      </div>

      {tab === 'overview' && <OverviewTab summary={summary} onChanged={load} applyBusy={!!pending && pending.state === 'pending'} />}
      {tab === 'rules' && summary?.active_profile && <RulesTab profileId={summary.active_profile.id} onChanged={load} />}
      {tab === 'rules' && !summary?.active_profile && <p className="muted">No active profile.</p>}
      {tab === 'advanced' && summary?.active_profile && <AdvancedTab profileId={summary.active_profile.id} />}
    </section>
  );
}

function OverviewTab({ summary, onChanged, applyBusy }: { summary: FirewallSummary | null; onChanged: () => void; applyBusy: boolean }) {
  const [error, setError] = useState('');
  const [newName, setNewName] = useState('');
  const [applying, setApplying] = useState<number | null>(null);

  if (!summary) return <p className="muted">Loading…</p>;

  async function createProfile() {
    if (!newName.trim()) return;
    setError('');
    try {
      await api.fwCreateProfile(newName.trim());
      setNewName('');
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create profile');
    }
  }

  async function cloneProfile(profile: FirewallProfile) {
    const name = window.prompt(`Name for the clone of "${profile.name}"?`, `${profile.name} copy`);
    if (!name) return;
    setError('');
    try {
      await api.fwCloneProfile(profile.id, name.trim());
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not clone profile');
    }
  }

  async function deleteProfile(profile: FirewallProfile) {
    if (!window.confirm(`Delete profile "${profile.name}"? This cannot be undone.`)) return;
    setError('');
    try {
      await api.fwDeleteProfile(profile.id);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete profile');
    }
  }

  async function applyProfile(profile: FirewallProfile) {
    if (!window.confirm(`Apply "${profile.name}"? You'll have a confirm window to keep or revert the change.`)) return;
    setApplying(profile.id);
    setError('');
    try {
      await api.fwApply(profile.id, 60);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Apply failed');
    } finally {
      setApplying(null);
    }
  }

  return (
    <article className="card">
      {error && <p className="error-text">{error}</p>}
      <h4>Profiles</h4>
      <table className="status-table">
        <thead><tr><th>Name</th><th>Status</th><th>Description</th><th></th></tr></thead>
        <tbody>
          {summary.profiles.map((profile) => (
            <tr key={profile.id}>
              <td className="status-table-name">{profile.name}</td>
              <td><span className={`badge ${profile.active ? 'ok-dim' : 'muted'}`}>{profile.active ? 'Active' : 'Inactive'}</span></td>
              <td className="status-table-detail muted">{profile.description || '—'}</td>
              <td>
                <div className="config-save-bar" style={{ margin: 0 }}>
                  {!profile.active && (
                    <button className="btn-secondary" onClick={() => applyProfile(profile)} disabled={applyBusy || applying === profile.id}>
                      {applying === profile.id ? 'Applying…' : 'Apply'}
                    </button>
                  )}
                  <button className="btn-secondary" onClick={() => cloneProfile(profile)}>Clone</button>
                  {!profile.active && <button className="btn-secondary" onClick={() => deleteProfile(profile)}>Delete</button>}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="config-save-bar">
        <input value={newName} placeholder="New profile name" maxLength={80} onChange={(event) => setNewName(event.target.value)} />
        <button onClick={createProfile}>Create profile</button>
      </div>
    </article>
  );
}

const CHAIN_LABEL: Record<FirewallChain, string> = { input: 'Input', forward: 'Forward', output: 'Output' };

const PROTOCOL_OPTIONS = ['any', 'tcp', 'udp', 'tcp+udp', 'icmp', 'icmpv6', 'esp', 'gre', 'ah'];
const CT_STATE_OPTIONS = ['new', 'established', 'related', 'invalid', 'untracked'];
const REJECT_WITH_OPTIONS = ['', 'tcp reset', 'icmp port-unreachable', 'icmp admin-prohibited', 'icmpv6 port-unreachable', 'icmpv6 admin-prohibited'];

type RuleDraft = Partial<FirewallRule>;

const EMPTY_DRAFT: RuleDraft = {
  chain: 'input', action: 'accept', protocol: 'any', family: 'inet',
  iif: '', oif: '', src: '', dst: '', sport: '', dport: '', ct_state: '',
  icmp_type: '', log: false, log_prefix: '', rate_limit: '', reject_with: '',
  src_negate: false, dst_negate: false, description: '',
};

function RulesTab({ profileId, onChanged }: { profileId: number; onChanged: () => void }) {
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState<RuleDraft | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);

  async function load() {
    try { setRules((await api.fwRules(profileId)).rules); setError(''); }
    catch (err) { setError(err instanceof Error ? err.message : 'Failed to load rules'); }
  }
  useEffect(() => { load(); }, [profileId]);

  async function toggleEnabled(rule: FirewallRule) {
    try {
      await api.fwUpdateRule(rule.id, { enabled: !rule.enabled });
      await load();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update rule');
    }
  }

  async function moveRule(rule: FirewallRule, direction: 'up' | 'down') {
    try {
      await api.fwMoveRule(rule.id, direction);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not reorder rule');
    }
  }

  async function deleteRule(rule: FirewallRule) {
    if (!window.confirm('Delete this rule?')) return;
    try {
      await api.fwDeleteRule(rule.id);
      await load();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete rule');
    }
  }

  function startCreate(chain: FirewallChain) {
    setEditingId(null);
    setEditing({ ...EMPTY_DRAFT, chain });
  }

  function startEdit(rule: FirewallRule) {
    setEditingId(rule.id);
    setEditing({ ...rule });
  }

  async function saveEditing() {
    if (!editing) return;
    setError('');
    try {
      if (editingId === null) {
        await api.fwCreateRule(profileId, editing);
      } else {
        await api.fwUpdateRule(editingId, editing);
      }
      setEditing(null);
      setEditingId(null);
      await load();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save rule');
    }
  }

  return (
    <article className="card">
      {error && <p className="error-text">{error}</p>}
      {editing && (
        <RuleEditor
          draft={editing}
          isNew={editingId === null}
          onChange={setEditing}
          onCancel={() => { setEditing(null); setEditingId(null); }}
          onSave={saveEditing}
        />
      )}
      {CHAINS.map((chain) => {
        const chainRules = rules.filter((rule) => rule.chain === chain);
        return (
          <div key={chain} className="config-item">
            <div className="section-actions">
              <h4 style={{ margin: 0 }}>{CHAIN_LABEL[chain]}</h4>
              <button className="btn-secondary" onClick={() => startCreate(chain)}>Add rule</button>
            </div>
            {chainRules.length === 0 ? <p className="muted">No rules.</p> : (
              <table className="status-table">
                <thead><tr><th>#</th><th>On</th><th>Action</th><th>Match</th><th>Description</th><th></th></tr></thead>
                <tbody>
                  {chainRules.map((rule, index) => (
                    <tr key={rule.id}>
                      <td>{rule.position}</td>
                      <td>
                        <button role="switch" aria-checked={rule.enabled} className={`toggle-switch ${rule.enabled ? 'on' : ''}`} onClick={() => toggleEnabled(rule)}>
                          <span className="toggle-thumb" />
                        </button>
                      </td>
                      <td><span className={`badge ${rule.action === 'accept' ? 'ok-dim' : rule.action === 'drop' ? 'muted' : 'warning'}`}>{rule.action}{rule.system_rule ? ' · system' : ''}</span></td>
                      <td className="status-table-detail muted">{ruleSummary(rule)}</td>
                      <td className="status-table-detail muted">{rule.description || '—'}</td>
                      <td>
                        <div className="config-save-bar" style={{ margin: 0 }}>
                          {!rule.system_rule && <button className="btn-secondary" onClick={() => moveRule(rule, 'up')} disabled={index === 0}>↑</button>}
                          {!rule.system_rule && <button className="btn-secondary" onClick={() => moveRule(rule, 'down')} disabled={index === chainRules.length - 1}>↓</button>}
                          {!rule.system_rule && <button className="btn-secondary" onClick={() => startEdit(rule)}>Edit</button>}
                          {!rule.system_rule && <button className="btn-secondary" onClick={() => deleteRule(rule)}>Delete</button>}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        );
      })}
    </article>
  );
}

function RuleEditor({ draft, isNew, onChange, onCancel, onSave }: {
  draft: RuleDraft; isNew: boolean;
  onChange: (draft: RuleDraft) => void; onCancel: () => void; onSave: () => void;
}) {
  const portsApplicable = draft.protocol === 'tcp' || draft.protocol === 'udp' || draft.protocol === 'tcp+udp';
  const icmpApplicable = draft.protocol === 'icmp' || draft.protocol === 'icmpv6';

  function set<K extends keyof RuleDraft>(key: K, value: RuleDraft[K]) {
    onChange({ ...draft, [key]: value });
  }

  return (
    <div className="confirm-overlay">
      <div className="confirm-dialog card" style={{ maxWidth: 640 }}>
        <h3>{isNew ? 'Add rule' : 'Edit rule'} — {draft.chain}</h3>
        <div className="stack-form">
          <label>Action
            <select value={draft.action} onChange={(event) => set('action', event.target.value as FirewallRule['action'])}>
              <option value="accept">accept</option>
              <option value="drop">drop</option>
              <option value="reject">reject</option>
            </select>
          </label>
          {draft.action === 'reject' && (
            <label>Reject with
              <select value={draft.reject_with || ''} onChange={(event) => set('reject_with', event.target.value)}>
                {REJECT_WITH_OPTIONS.map((option) => <option key={option} value={option}>{option || '(default)'}</option>)}
              </select>
            </label>
          )}
          <label>Protocol
            <select value={draft.protocol || 'any'} onChange={(event) => set('protocol', event.target.value)}>
              {PROTOCOL_OPTIONS.map((option) => <option key={option} value={option}>{option}</option>)}
            </select>
          </label>
          <label>Interface in (comma-separated, optional)
            <input value={draft.iif || ''} onChange={(event) => set('iif', event.target.value)} placeholder="eth0" />
          </label>
          <label>Interface out (comma-separated, optional)
            <input value={draft.oif || ''} onChange={(event) => set('oif', event.target.value)} placeholder="eth1" />
          </label>
          <label>Source address/CIDR (optional)
            <input value={draft.src || ''} onChange={(event) => set('src', event.target.value)} placeholder="10.0.0.0/8" />
          </label>
          <label className="vpn-inline-check"><input type="checkbox" checked={!!draft.src_negate} onChange={(event) => set('src_negate', event.target.checked)} /> Negate source</label>
          <label>Destination address/CIDR (optional)
            <input value={draft.dst || ''} onChange={(event) => set('dst', event.target.value)} placeholder="192.168.1.10" />
          </label>
          <label className="vpn-inline-check"><input type="checkbox" checked={!!draft.dst_negate} onChange={(event) => set('dst_negate', event.target.checked)} /> Negate destination</label>
          {portsApplicable && (
            <>
              <label>Source port(s) (optional)
                <input value={draft.sport || ''} onChange={(event) => set('sport', event.target.value)} placeholder="1024-2048" />
              </label>
              <label>Destination port(s) (optional)
                <input value={draft.dport || ''} onChange={(event) => set('dport', event.target.value)} placeholder="443" />
              </label>
            </>
          )}
          {icmpApplicable && (
            <label>ICMP type (optional)
              <input value={draft.icmp_type || ''} onChange={(event) => set('icmp_type', event.target.value)} placeholder="8" />
            </label>
          )}
          <label>Connection state (optional)
            <select value={draft.ct_state || ''} onChange={(event) => set('ct_state', event.target.value)}>
              <option value="">(any)</option>
              {CT_STATE_OPTIONS.map((option) => <option key={option} value={option}>{option}</option>)}
            </select>
          </label>
          <label className="vpn-inline-check"><input type="checkbox" checked={!!draft.log} onChange={(event) => set('log', event.target.checked)} /> Log matches</label>
          {draft.log && (
            <label>Log prefix
              <input value={draft.log_prefix || ''} onChange={(event) => set('log_prefix', event.target.value)} placeholder="my-rule: " />
            </label>
          )}
          <label>Rate limit (optional)
            <input value={draft.rate_limit || ''} onChange={(event) => set('rate_limit', event.target.value)} placeholder="10/second burst 20 packets" />
          </label>
          <label>Description
            <input value={draft.description || ''} onChange={(event) => set('description', event.target.value)} maxLength={300} />
          </label>
        </div>
        <div className="confirm-actions">
          <button className="btn-secondary" onClick={onCancel}>Cancel</button>
          <button onClick={onSave}>Save</button>
        </div>
      </div>
    </div>
  );
}

function ruleSummary(rule: FirewallRule): string {
  const parts: string[] = [];
  if (rule.iif) parts.push(`in:${rule.iif}`);
  if (rule.oif) parts.push(`out:${rule.oif}`);
  if (rule.protocol && rule.protocol !== 'any') parts.push(rule.protocol);
  if (rule.src) parts.push(`src ${rule.src_negate ? '!=' : ''}${rule.src}`);
  if (rule.dst) parts.push(`dst ${rule.dst_negate ? '!=' : ''}${rule.dst}`);
  if (rule.sport) parts.push(`sport ${rule.sport}`);
  if (rule.dport) parts.push(`dport ${rule.dport}`);
  if (rule.ct_state) parts.push(`state ${rule.ct_state}`);
  return parts.join(' ') || 'any traffic';
}

function AdvancedTab({ profileId }: { profileId: number }) {
  const [nft, setNft] = useState('');
  const [validation, setValidation] = useState<FirewallValidateResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [error, setError] = useState('');

  async function load() {
    try { setNft((await api.fwPreview(profileId)).nft); setError(''); }
    catch (err) { setError(err instanceof Error ? err.message : 'Failed to load generated ruleset'); }
  }
  useEffect(() => { load(); }, [profileId]);

  async function validate() {
    setValidating(true);
    setError('');
    try { setValidation(await api.fwValidate(profileId)); }
    catch (err) { setError(err instanceof Error ? err.message : 'Validation request failed'); }
    finally { setValidating(false); }
  }

  return (
    <article className="card">
      {error && <p className="error-text">{error}</p>}
      <div className="config-save-bar">
        <button className="btn-secondary" onClick={load}>Refresh</button>
        <button onClick={validate} disabled={validating}>{validating ? 'Validating…' : 'Validate now (nft -c)'}</button>
      </div>
      {validation && (
        <div className={validation.ok ? 'wizard-summary-ok' : 'error-box'} role={validation.ok ? undefined : 'alert'}>
          <p>{validation.ok ? 'Syntax check passed.' : `Syntax check failed: ${validation.detail}`}</p>
          {validation.warnings.length > 0 && (
            <ul>
              {validation.warnings.map((warning) => <li key={warning}>{warning}</li>)}
            </ul>
          )}
        </div>
      )}
      <label className="subheading">
        Generated ruleset (read-only — this is exactly what would be applied)
        <textarea className="ids-editor" value={nft} readOnly rows={20} />
      </label>
    </article>
  );
}
