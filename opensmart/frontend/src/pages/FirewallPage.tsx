import { useEffect, useState } from 'react';
import { api } from '../api';
import type { FirewallChain, FirewallRule, FirewallSummary, FirewallValidateResult } from '../types';

type Tab = 'overview' | 'rules' | 'advanced';

const CHAINS: FirewallChain[] = ['input', 'forward', 'output'];

export default function FirewallPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const [summary, setSummary] = useState<FirewallSummary | null>(null);
  const [error, setError] = useState('');

  async function load() {
    try {
      setSummary(await api.fwSummary());
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load firewall summary');
    }
  }
  useEffect(() => { load(); }, []);

  const TABS: { id: Tab; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'rules', label: 'Rules' },
    { id: 'advanced', label: 'Advanced' },
  ];

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

      {tab === 'overview' && <OverviewTab summary={summary} />}
      {tab === 'rules' && summary?.active_profile && <RulesTab profileId={summary.active_profile.id} onChanged={load} />}
      {tab === 'rules' && !summary?.active_profile && <p className="muted">No active profile.</p>}
      {tab === 'advanced' && summary?.active_profile && <AdvancedTab profileId={summary.active_profile.id} />}
    </section>
  );
}

function OverviewTab({ summary }: { summary: FirewallSummary | null }) {
  if (!summary) return <p className="muted">Loading…</p>;
  return (
    <article className="card">
      <h4>Profiles</h4>
      <table className="status-table">
        <thead><tr><th>Name</th><th>Status</th><th>Description</th></tr></thead>
        <tbody>
          {summary.profiles.map((profile) => (
            <tr key={profile.id}>
              <td className="status-table-name">{profile.name}</td>
              <td><span className={`badge ${profile.active ? 'ok-dim' : 'muted'}`}>{profile.active ? 'Active' : 'Inactive'}</span></td>
              <td className="status-table-detail muted">{profile.description || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted">
        Rule authoring (add/edit rules, switch active profile) lands in a follow-up phase. For now, rules are
        viewable per-chain in the Rules tab and the generated ruleset is inspectable in Advanced.
      </p>
    </article>
  );
}

function RulesTab({ profileId, onChanged }: { profileId: number; onChanged: () => void }) {
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [error, setError] = useState('');

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

  return (
    <article className="card">
      {error && <p className="error-text">{error}</p>}
      {CHAINS.map((chain) => {
        const chainRules = rules.filter((rule) => rule.chain === chain);
        return (
          <div key={chain} className="config-item">
            <h4 style={{ textTransform: 'capitalize' }}>{chain}</h4>
            {chainRules.length === 0 ? <p className="muted">No rules.</p> : (
              <table className="status-table">
                <thead><tr><th>#</th><th>On</th><th>Action</th><th>Match</th><th>Description</th></tr></thead>
                <tbody>
                  {chainRules.map((rule) => (
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
