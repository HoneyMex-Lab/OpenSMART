import { ChangeEvent, useEffect, useState } from 'react';
import { api } from '../api';
import { confirmDialog, promptDialog } from '../components/Dialog';
import type { FirewallAlias, FirewallChain, FirewallEngine, FirewallImportDraft, FirewallImportDraftRule, FirewallProfile, FirewallRule, FirewallSummary, FirewallValidateResult, NetworkInterface } from '../types';

type Tab = 'overview' | 'rules' | 'aliases' | 'advanced';

type ServicePreset = { label: string; protocol: string; dport: string };

const SERVICE_PRESETS: ServicePreset[] = [
  { label: 'HTTP', protocol: 'tcp', dport: '80' },
  { label: 'HTTPS', protocol: 'tcp', dport: '443' },
  { label: 'DNS', protocol: 'tcp+udp', dport: '53' },
  { label: 'SSH', protocol: 'tcp', dport: '22' },
  { label: 'RDP', protocol: 'tcp', dport: '3389' },
  { label: 'SMB', protocol: 'tcp', dport: '445' },
];

const CHAINS: FirewallChain[] = ['input', 'forward', 'output'];

function secondsLeft(expiresAt: string, now: number): number {
  return Math.max(0, Math.round((new Date(expiresAt).getTime() - now) / 1000));
}

export default function FirewallPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const [summary, setSummary] = useState<FirewallSummary | null>(null);
  const [error, setError] = useState('');
  const [now, setNow] = useState(() => Date.now());
  // Lockout-risk warnings from the apply() call that started the current
  // pending apply — kept in local state (not persisted server-side) since
  // they only need to reach the same admin, in the same session, who's
  // about to decide whether to confirm. Cleared once the apply resolves.
  const [applyWarnings, setApplyWarnings] = useState<string[]>([]);
  const [warningsAcked, setWarningsAcked] = useState(false);

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
    setApplyWarnings([]);
    setWarningsAcked(false);
    await load();
  }

  async function revertPending() {
    if (!summary?.pending_apply) return;
    await api.fwCancelApply(summary.pending_apply.token);
    setApplyWarnings([]);
    setWarningsAcked(false);
    await load();
  }

  function onApplied(warnings: string[]) {
    setApplyWarnings(warnings);
    setWarningsAcked(false);
    load();
  }

  const TABS: { id: Tab; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'rules', label: 'Rules' },
    { id: 'aliases', label: 'Aliases' },
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
          {applyWarnings.length > 0 && (
            <div className="error-box" role="alert">
              <p><strong>Possible lockout risk:</strong></p>
              <ul>
                {applyWarnings.map((warning) => <li key={warning}>{warning}</li>)}
              </ul>
              <label className="vpn-inline-check">
                <input type="checkbox" checked={warningsAcked} onChange={(event) => setWarningsAcked(event.target.checked)} />
                I understand the risk above and still want to keep this change
              </label>
            </div>
          )}
          <div className="config-save-bar">
            <button className="btn-secondary" onClick={revertPending}>Revert now</button>
            <button onClick={confirmPending} disabled={applyWarnings.length > 0 && !warningsAcked}>Keep changes</button>
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

      {tab === 'overview' && <OverviewTab summary={summary} onChanged={load} onApplied={onApplied} applyBusy={!!pending && pending.state === 'pending'} />}
      {tab === 'rules' && summary?.active_profile && <RulesTab profileId={summary.active_profile.id} onChanged={load} />}
      {tab === 'rules' && !summary?.active_profile && <p className="muted">No active profile.</p>}
      {tab === 'aliases' && <AliasesTab />}
      {tab === 'advanced' && summary?.active_profile && <AdvancedTab profileId={summary.active_profile.id} engine={summary.active_profile.engine} onImported={load} />}
    </section>
  );
}

function OverviewTab({ summary, onChanged, onApplied, applyBusy }: { summary: FirewallSummary | null; onChanged: () => void; onApplied: (warnings: string[]) => void; applyBusy: boolean }) {
  const [error, setError] = useState('');
  const [newName, setNewName] = useState('');
  const [newEngine, setNewEngine] = useState<FirewallProfile['engine']>('nftables');
  const [applying, setApplying] = useState<number | null>(null);

  if (!summary) return <p className="muted">Loading…</p>;

  async function createProfile() {
    if (!newName.trim()) return;
    setError('');
    try {
      await api.fwCreateProfile(newName.trim(), '', newEngine);
      setNewName('');
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create profile');
    }
  }

  async function cloneProfile(profile: FirewallProfile) {
    const name = await promptDialog(`Name for the clone of "${profile.name}"?`, `${profile.name} copy`);
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
    if (!(await confirmDialog(`Delete profile "${profile.name}"? This cannot be undone.`, { danger: true }))) return;
    setError('');
    try {
      await api.fwDeleteProfile(profile.id);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete profile');
    }
  }

  async function applyProfile(profile: FirewallProfile) {
    if (!(await confirmDialog(`Apply "${profile.name}"? You'll have a confirm window to keep or revert the change.`))) return;
    setApplying(profile.id);
    setError('');
    try {
      const result = await api.fwApply(profile.id, 60);
      onApplied(result.warnings);
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
        <thead><tr><th>Name</th><th>Engine</th><th>Status</th><th>Description</th><th></th></tr></thead>
        <tbody>
          {summary.profiles.map((profile) => (
            <tr key={profile.id}>
              <td className="status-table-name">{profile.name}</td>
              <td><span className="badge muted">{profile.engine}</span></td>
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
        <select value={newEngine} onChange={(event) => setNewEngine(event.target.value as FirewallProfile['engine'])}>
          <option value="nftables">nftables</option>
          <option value="iptables">iptables</option>
        </select>
        <button onClick={createProfile}>Create profile</button>
      </div>
      <p className="muted" style={{ fontSize: '0.85em' }}>A profile's engine is fixed once created — clone it to make an editable copy on the same engine.</p>
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
    if (!(await confirmDialog('Delete this rule?', { danger: true }))) return;
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
                  {chainRules.map((rule, index) => {
                    const isAllowlist = rule.system_rule === 2 || rule.system_rule === 3;
                    return (
                    <tr key={rule.id} className={rule.system_rule ? 'status-table-management-row' : ''}>
                      <td>{rule.position}</td>
                      <td>
                        {isAllowlist ? (
                          <span className="badge muted" title="Management rules can't be turned off — edit the allowed network instead">Always on</span>
                        ) : (
                          <button role="switch" aria-checked={rule.enabled} className={`toggle-switch ${rule.enabled ? 'on' : ''}`} onClick={() => toggleEnabled(rule)}>
                            <span className="toggle-thumb" />
                          </button>
                        )}
                      </td>
                      <td>
                        <span className={`badge ${rule.action === 'accept' ? 'ok-dim' : rule.action === 'drop' ? 'muted' : 'warning'}`}>{rule.action}</span>
                        {isAllowlist && <span className="badge management-badge">{rule.system_rule === 3 ? 'management · SSH' : 'management · Web'}</span>}
                        {!isAllowlist && rule.system_rule === 1 && <span className="badge management-badge">management</span>}
                      </td>
                      <td className="status-table-detail muted">{ruleSummary(rule)}</td>
                      <td className="status-table-detail muted">{rule.description || '—'}</td>
                      <td>
                        <div className="config-save-bar" style={{ margin: 0 }}>
                          {!rule.system_rule && <button className="btn-secondary" onClick={() => moveRule(rule, 'up')} disabled={index === 0}>↑</button>}
                          {!rule.system_rule && <button className="btn-secondary" onClick={() => moveRule(rule, 'down')} disabled={index === chainRules.length - 1}>↓</button>}
                          {(!rule.system_rule || isAllowlist) && <button className="btn-secondary" onClick={() => startEdit(rule)}>Edit</button>}
                          {!rule.system_rule && <button className="btn-secondary" onClick={() => deleteRule(rule)}>Delete</button>}
                        </div>
                      </td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        );
      })}
    </article>
  );
}

function csvToList(value?: string): string[] {
  return (value || '').split(',').map((v) => v.trim()).filter(Boolean);
}

function listToCsv(values: string[]): string {
  return values.join(',');
}

function InterfaceMultiSelect({ label, value, onChange, interfaces }: {
  label: string; value?: string; onChange: (value: string) => void; interfaces: NetworkInterface[];
}) {
  const selected = csvToList(value);
  const known = new Set(interfaces.map((iface) => iface.name));
  const orphans = selected.filter((name) => !known.has(name));
  return (
    <label>{label}
      <select
        multiple
        size={Math.min(Math.max(interfaces.length + orphans.length, 1), 5)}
        value={selected}
        onChange={(event) => onChange(listToCsv(Array.from(event.target.selectedOptions, (option) => option.value)))}
      >
        {interfaces.map((iface) => (
          <option key={iface.name} value={iface.name}>
            {(iface.alias ? `${iface.alias} (${iface.name})` : iface.name) + (iface.present ? '' : ' — not present')}
          </option>
        ))}
        {orphans.map((name) => (
          <option key={name} value={name}>{name} — unknown interface</option>
        ))}
      </select>
      <span className="muted" style={{ fontSize: '0.85em' }}>Ctrl/Cmd-click to select multiple. Leave empty to match any interface.</span>
    </label>
  );
}

function RuleEditor({ draft, isNew, onChange, onCancel, onSave }: {
  draft: RuleDraft; isNew: boolean;
  onChange: (draft: RuleDraft) => void; onCancel: () => void; onSave: () => void;
}) {
  const portsApplicable = draft.protocol === 'tcp' || draft.protocol === 'udp' || draft.protocol === 'tcp+udp';
  const icmpApplicable = draft.protocol === 'icmp' || draft.protocol === 'icmpv6';
  const [aliases, setAliases] = useState<FirewallAlias[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);

  useEffect(() => { api.fwAliases().then((result) => setAliases(result.aliases)).catch(() => undefined); }, []);
  useEffect(() => { api.netInterfaces().then((result) => setInterfaces(result.interfaces)).catch(() => undefined); }, []);

  const addressAliases = aliases.filter((alias) => alias.kind === 'address');
  const portAliases = aliases.filter((alias) => alias.kind === 'port');

  function set<K extends keyof RuleDraft>(key: K, value: RuleDraft[K]) {
    onChange({ ...draft, [key]: value });
  }

  function applyPreset(label: string) {
    const preset = SERVICE_PRESETS.find((p) => p.label === label);
    if (!preset) return;
    onChange({ ...draft, protocol: preset.protocol, dport: preset.dport });
  }

  // Allowlist-managed rules (the initial-Wizard's dedicated SSH/443 rules):
  // only src/src_negate are editable server-side — everything else,
  // including enabled/disabled, is rejected by firewall.update_rule().
  // Show a reduced form rather than a full editor whose other fields
  // would silently fail to save. Tier 2 (Web/443) and tier 3 (SSH/22)
  // have OPPOSITE empty-network defaults — see firewall.py's
  // _effective_rules() — so the copy below is tailored per tier rather
  // than shared, to avoid telling an admin editing the SSH rule that an
  // empty network "allows every network" when it actually blocks SSH
  // entirely.
  if (draft.system_rule === 2 || draft.system_rule === 3) {
    const restrictive = draft.system_rule === 3;
    return (
      <div className="confirm-overlay">
        <div className="confirm-dialog card" style={{ maxWidth: 640 }}>
          <h3>Edit allowlist — {draft.description}</h3>
          <p className="muted">
            This rule is managed by the Firewall's allowlist feature — only the allowed network can be changed here,
            and it can't be turned off. {restrictive
              ? 'Leave it empty and NO SSH connections are allowed (safe default); adding a network restricts SSH to just that network.'
              : 'Leave it empty to allow every network (today\'s default); adding a network restricts this rule to just that network.'}
            {' '}Clone the profile if you need to customize the chain, protocol, or port.
          </p>
          <div className="stack-form">
            <label>Allowed network/host ({restrictive ? 'optional — empty means "block all SSH"' : 'optional — empty means "allow any"'})
              <input value={draft.src || ''} onChange={(event) => set('src', event.target.value)} placeholder="10.0.0.0/8" />
            </label>
            <label className="vpn-inline-check"><input type="checkbox" checked={!!draft.src_negate} onChange={(event) => set('src_negate', event.target.checked)} /> Negate (allow everyone EXCEPT this network)</label>
          </div>
          <div className="confirm-actions">
            <button className="btn-secondary" onClick={onCancel}>Cancel</button>
            <button onClick={onSave}>Save</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="confirm-overlay">
      <div className="confirm-dialog card" style={{ maxWidth: 640 }}>
        <h3>{isNew ? 'Add rule' : 'Edit rule'} — {draft.chain}</h3>
        <div className="stack-form">
          <label>Service preset (optional shortcut)
            <select value="" onChange={(event) => applyPreset(event.target.value)}>
              <option value="">— pick a common service —</option>
              {SERVICE_PRESETS.map((preset) => <option key={preset.label} value={preset.label}>{preset.label}</option>)}
            </select>
          </label>
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
          <InterfaceMultiSelect label="Interface in (optional)" value={draft.iif} onChange={(value) => set('iif', value)} interfaces={interfaces} />
          <InterfaceMultiSelect label="Interface out (optional)" value={draft.oif} onChange={(value) => set('oif', value)} interfaces={interfaces} />
          <label>Source address/CIDR (optional)
            <input value={draft.src || ''} onChange={(event) => set('src', event.target.value)} placeholder="10.0.0.0/8" />
          </label>
          {addressAliases.length > 0 && (
            <label>Or insert a saved address alias
              <select value="" onChange={(event) => event.target.value && set('src', event.target.value)}>
                <option value="">— select alias —</option>
                {addressAliases.map((alias) => <option key={alias.id} value={alias.values_csv}>{alias.name}</option>)}
              </select>
            </label>
          )}
          <label className="vpn-inline-check"><input type="checkbox" checked={!!draft.src_negate} onChange={(event) => set('src_negate', event.target.checked)} /> Negate source</label>
          <label>Destination address/CIDR (optional)
            <input value={draft.dst || ''} onChange={(event) => set('dst', event.target.value)} placeholder="192.168.1.10" />
          </label>
          {addressAliases.length > 0 && (
            <label>Or insert a saved address alias
              <select value="" onChange={(event) => event.target.value && set('dst', event.target.value)}>
                <option value="">— select alias —</option>
                {addressAliases.map((alias) => <option key={alias.id} value={alias.values_csv}>{alias.name}</option>)}
              </select>
            </label>
          )}
          <label className="vpn-inline-check"><input type="checkbox" checked={!!draft.dst_negate} onChange={(event) => set('dst_negate', event.target.checked)} /> Negate destination</label>
          {portsApplicable && (
            <>
              <label>Source port(s) (optional)
                <input value={draft.sport || ''} onChange={(event) => set('sport', event.target.value)} placeholder="1024-2048" />
              </label>
              <label>Destination port(s) (optional)
                <input value={draft.dport || ''} onChange={(event) => set('dport', event.target.value)} placeholder="443" />
              </label>
              {portAliases.length > 0 && (
                <label>Or insert a saved port alias (destination)
                  <select value="" onChange={(event) => event.target.value && set('dport', event.target.value)}>
                    <option value="">— select alias —</option>
                    {portAliases.map((alias) => <option key={alias.id} value={alias.values_csv}>{alias.name}</option>)}
                  </select>
                </label>
              )}
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

function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function AdvancedTab({ profileId, engine, onImported }: { profileId: number; engine: FirewallEngine; onImported: () => void }) {
  const [nft, setNft] = useState('');
  const [validation, setValidation] = useState<FirewallValidateResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [error, setError] = useState('');
  const [customNft, setCustomNft] = useState('');
  const [customDirty, setCustomDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [profileName, setProfileName] = useState('');

  async function load() {
    try {
      setNft((await api.fwPreview(profileId)).nft);
      const profile = (await api.fwProfiles()).profiles.find((p) => p.id === profileId);
      setCustomNft(profile?.custom_nft || '');
      setProfileName(profile?.name || 'profile');
      setCustomDirty(false);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load generated ruleset');
    }
  }
  useEffect(() => { load(); }, [profileId]);

  function exportRuleset() {
    const extension = engine === 'iptables' ? 'iptables' : 'nft';
    downloadText(`${profileName || 'firewall-profile'}.${extension}`, nft);
  }

  async function validate() {
    setValidating(true);
    setError('');
    try { setValidation(await api.fwValidate(profileId)); }
    catch (err) { setError(err instanceof Error ? err.message : 'Validation request failed'); }
    finally { setValidating(false); }
  }

  async function saveCustomNft() {
    setSaving(true);
    setError('');
    try {
      await api.fwUpdateProfile(profileId, { custom_nft: customNft });
      setCustomDirty(false);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save custom nft snippet');
    } finally {
      setSaving(false);
    }
  }

  return (
    <article className="card">
      {error && <p className="error-text">{error}</p>}
      <div className="config-save-bar">
        <button className="btn-secondary" onClick={load}>Refresh</button>
        <button onClick={validate} disabled={validating}>{validating ? 'Validating…' : `Validate now (${engine === 'iptables' ? 'iptables-restore --test' : 'nft -c'})`}</button>
        <button className="btn-secondary" onClick={exportRuleset}>Export ruleset</button>
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
      {engine === 'nftables' ? (
        <>
          <label className="subheading">
            Custom nft snippet (advanced — appended verbatim inside the generated table, validated with the rest)
            <textarea
              className="ids-editor"
              value={customNft}
              rows={6}
              onChange={(event) => { setCustomNft(event.target.value); setCustomDirty(true); }}
            />
          </label>
          {customDirty && (
            <div className="config-save-bar">
              <button onClick={saveCustomNft} disabled={saving}>{saving ? 'Saving…' : 'Save snippet'}</button>
            </div>
          )}
        </>
      ) : (
        <p className="muted">The custom-snippet escape hatch is nftables-only in this release.</p>
      )}
      <label className="subheading">
        Generated ruleset (read-only — this is exactly what would be applied)
        <textarea className="ids-editor" value={nft} readOnly rows={20} />
      </label>

      <ImportPanel onImported={onImported} />
      <p className="muted">Firewall log matches have moved to Audit &gt; Firewall Log.</p>
    </article>
  );
}

function ImportPanel({ onImported }: { onImported: () => void }) {
  const [importEngine, setImportEngine] = useState<FirewallEngine>('iptables');
  const [fileText, setFileText] = useState('');
  const [fileName, setFileName] = useState('');
  const [draft, setDraft] = useState<FirewallImportDraft | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [interfaceMap, setInterfaceMap] = useState<Record<string, string>>({});
  const [newProfileName, setNewProfileName] = useState('');
  const [parsing, setParsing] = useState(false);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<{ created: number; profileName: string } | null>(null);

  useEffect(() => { api.netInterfaces().then((res) => setInterfaces(res.interfaces)).catch(() => undefined); }, []);

  function pickFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => setFileText(String(reader.result || ''));
    reader.readAsText(file);
  }

  async function parseFile() {
    if (!fileText.trim()) return;
    setParsing(true);
    setError('');
    setResult(null);
    try {
      const parsed = await api.fwImportParse(importEngine, fileText);
      setDraft(parsed);
      const known = new Set(interfaces.map((iface) => iface.name));
      const initialMap: Record<string, string> = {};
      parsed.interfaces_found.forEach((name) => { if (!known.has(name)) initialMap[name] = ''; });
      setInterfaceMap(initialMap);
      setNewProfileName(`Imported ${importEngine} profile`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not parse the file');
    } finally {
      setParsing(false);
    }
  }

  function toggleSkip(index: number) {
    if (!draft) return;
    const rules = draft.rules.map((rule, i) => (i === index ? { ...rule, skip: !rule.skip } : rule));
    setDraft({ ...draft, rules });
  }

  async function confirmImport() {
    if (!draft || !newProfileName.trim()) return;
    setImporting(true);
    setError('');
    try {
      const res = await api.fwImportConfirm(importEngine, newProfileName.trim(), `Imported from ${fileName || 'uploaded file'}`, draft.rules, interfaceMap);
      setResult({ created: res.created, profileName: res.profile.name });
      setDraft(null);
      setFileText('');
      setFileName('');
      onImported();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import failed');
    } finally {
      setImporting(false);
    }
  }

  const knownInterfaceNames = new Set(interfaces.map((iface) => iface.name));
  const unknownInterfaces = draft ? draft.interfaces_found.filter((name) => !knownInterfaceNames.has(name)) : [];

  return (
    <div className="config-item">
      <h4>Import ruleset</h4>
      <p className="muted">
        Reads an existing ruleset file, parses it into a reviewable draft, and — after you confirm — creates a{' '}
        <strong>new</strong> profile from it (never merges into an existing one). Anything this importer doesn't
        recognize is listed below rather than guessed at.
      </p>
      <label>Source engine
        <select value={importEngine} onChange={(event) => { setImportEngine(event.target.value as FirewallEngine); setDraft(null); }}>
          <option value="iptables">iptables (iptables-save format)</option>
          <option value="nftables">nftables (nft -j list ruleset JSON)</option>
        </select>
      </label>
      <label>Ruleset file
        <input type="file" accept=".txt,.json,.rules,.nft,.iptables" onChange={pickFile} />
      </label>
      {fileName && <p className="muted">Selected: {fileName}</p>}
      <div className="config-save-bar">
        <button onClick={parseFile} disabled={parsing || !fileText.trim()}>{parsing ? 'Parsing…' : 'Parse'}</button>
      </div>
      {error && <p className="error-text">{error}</p>}
      {result && <p className="wizard-summary-ok">Imported {result.created} rule(s) into new profile "{result.profileName}". Review and apply it from the Overview tab when ready.</p>}

      {draft && (
        <>
          <p className="muted">
            Parsed {draft.rules.length} rule(s). {draft.unsupported.length > 0 && `${draft.unsupported.length} line(s) were not recognized and won't be imported.`}
          </p>
          {draft.warnings.length > 0 && (
            <ul>{draft.warnings.map((warning) => <li key={warning} className="muted">{warning}</li>)}</ul>
          )}
          {draft.unsupported.length > 0 && (
            <table className="status-table">
              <thead><tr><th>Line</th><th>Reason</th></tr></thead>
              <tbody>
                {draft.unsupported.map((item, index) => (
                  <tr key={index}><td className="status-table-detail muted">{item.line}</td><td className="status-table-detail muted">{item.reason}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          {unknownInterfaces.length > 0 && (
            <>
              <h4>Map unknown interfaces</h4>
              <p className="muted">These interface names appear in the import but aren't in this platform's interface registry. Map each to an existing interface, or leave blank to drop that interface from its rule(s).</p>
              {unknownInterfaces.map((name) => (
                <label key={name}>{name}
                  <select value={interfaceMap[name] || ''} onChange={(event) => setInterfaceMap({ ...interfaceMap, [name]: event.target.value })}>
                    <option value="">— drop (match any interface) —</option>
                    {interfaces.map((iface) => <option key={iface.name} value={iface.name}>{iface.alias ? `${iface.alias} (${iface.name})` : iface.name}</option>)}
                  </select>
                </label>
              ))}
            </>
          )}
          <table className="status-table">
            <thead><tr><th>Import</th><th>Chain</th><th>Action</th><th>Match</th><th>Description</th></tr></thead>
            <tbody>
              {draft.rules.map((rule, index) => (
                <tr key={index}>
                  <td><input type="checkbox" checked={!rule.skip} onChange={() => toggleSkip(index)} /></td>
                  <td>{rule.chain}</td>
                  <td>{rule.action}</td>
                  <td className="status-table-detail muted">{ruleSummary(rule as FirewallRule)}</td>
                  <td className="status-table-detail muted">{rule.description || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <label>New profile name
            <input value={newProfileName} onChange={(event) => setNewProfileName(event.target.value)} maxLength={80} />
          </label>
          <div className="config-save-bar">
            <button onClick={confirmImport} disabled={importing || !newProfileName.trim()}>{importing ? 'Importing…' : 'Create profile from import'}</button>
          </div>
        </>
      )}
    </div>
  );
}

function AliasesTab() {
  const [aliases, setAliases] = useState<FirewallAlias[]>([]);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [kind, setKind] = useState<'address' | 'port'>('address');
  const [values, setValues] = useState('');
  const [description, setDescription] = useState('');

  async function load() {
    try { setAliases((await api.fwAliases()).aliases); setError(''); }
    catch (err) { setError(err instanceof Error ? err.message : 'Failed to load aliases'); }
  }
  useEffect(() => { load(); }, []);

  async function create() {
    if (!name.trim() || !values.trim()) return;
    setError('');
    try {
      await api.fwCreateAlias(name.trim(), kind, values.trim(), description.trim());
      setName(''); setValues(''); setDescription('');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create alias');
    }
  }

  async function remove(alias: FirewallAlias) {
    if (!(await confirmDialog(`Delete alias "${alias.name}"?`, { danger: true }))) return;
    try {
      await api.fwDeleteAlias(alias.id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete alias');
    }
  }

  return (
    <article className="card">
      <p className="muted">
        Saved groups of addresses or ports you can reuse across rules — picking one in the rule editor fills the
        field in with these values (not a live nftables set; editing an alias here doesn't retroactively change
        rules that already copied its values).
      </p>
      {error && <p className="error-text">{error}</p>}
      <table className="status-table">
        <thead><tr><th>Name</th><th>Kind</th><th>Values</th><th>Description</th><th></th></tr></thead>
        <tbody>
          {aliases.map((alias) => (
            <tr key={alias.id}>
              <td className="status-table-name">{alias.name}</td>
              <td>{alias.kind}</td>
              <td className="status-table-detail muted">{alias.values_csv}</td>
              <td className="status-table-detail muted">{alias.description || '—'}</td>
              <td><button className="btn-secondary" onClick={() => remove(alias)}>Delete</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="stack-form">
        <label>Name<input value={name} onChange={(event) => setName(event.target.value)} maxLength={60} /></label>
        <label>Kind
          <select value={kind} onChange={(event) => setKind(event.target.value as 'address' | 'port')}>
            <option value="address">Address / CIDR</option>
            <option value="port">Port</option>
          </select>
        </label>
        <label>Values (comma-separated)
          <input value={values} onChange={(event) => setValues(event.target.value)} placeholder={kind === 'address' ? '10.0.0.0/8, 192.168.1.1' : '80, 443, 8000'} />
        </label>
        <label>Description<input value={description} onChange={(event) => setDescription(event.target.value)} maxLength={300} /></label>
        <button onClick={create}>Create alias</button>
      </div>
    </article>
  );
}
