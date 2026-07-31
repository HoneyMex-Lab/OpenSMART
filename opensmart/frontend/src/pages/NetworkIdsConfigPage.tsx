import { useEffect, useState } from 'react';
import { api } from '../api';
import type { IdsSource, IdsSummary } from '../types';

type Tab = 'rulesets' | 'detection' | 'classification' | 'advanced';

export default function NetworkIdsConfigPage() {
  const [tab, setTab] = useState<Tab>('rulesets');
  const [summary, setSummary] = useState<IdsSummary | null>(null);
  const [needsRestart, setNeedsRestart] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [banner, setBanner] = useState('');

  async function refreshSummary() {
    try { setSummary(await api.idsManageSummary()); } catch { /* not provisioned yet */ }
  }
  useEffect(() => { refreshSummary(); }, []);

  async function restart() {
    setRestarting(true);
    setBanner('');
    try {
      const r = await api.idsRestart();
      setBanner(r.ok ? 'Sensor restarted — changes are now live.' : `Restart failed: ${r.detail}`);
      if (r.ok) setNeedsRestart(false);
      await refreshSummary();
    } catch (err) {
      setBanner(err instanceof Error ? err.message : 'Restart failed');
    } finally {
      setRestarting(false);
    }
  }

  const TABS: { id: Tab; label: string }[] = [
    { id: 'rulesets', label: 'Rulesets' },
    { id: 'detection', label: 'Detection' },
    { id: 'classification', label: 'Classification' },
    { id: 'advanced', label: 'Advanced' },
  ];

  return (
    <section className="ids-manager">
        <div className="section-actions">
          <div>
            <h3>Suricata detection engine</h3>
            <p className="muted">Manage rulesets, detection variables, classification and the raw Suricata configuration. Edits are validated with <code>suricata -T</code> before they can take the sensor down.</p>
          </div>
          {summary && <span className={`badge ${summary.running ? 'ok' : 'muted'}`}>{summary.running ? 'Running' : 'Stopped'}</span>}
        </div>
        {summary && !summary.provisioned && <p className="muted">Suricata isn't provisioned yet — start the Network IDS module first.</p>}
        {summary && summary.provisioned && (
          <div className="ids-status-strip">
            <span><strong>{summary.enabled_rules.toLocaleString()}</strong> active rules</span>
            <span className="muted">·</span>
            <span><strong>{summary.enabled_sources.length}</strong> enabled source{summary.enabled_sources.length === 1 ? '' : 's'}</span>
            <span className="muted">·</span>
            <span><strong>{summary.custom_rules}</strong> custom rule{summary.custom_rules === 1 ? '' : 's'}</span>
          </div>
        )}
        {needsRestart && (
          <div className="ids-restart-banner">
            <span>Changes are saved to disk but not yet loaded by the running sensor.</span>
            <button className="restart-btn" disabled={restarting} onClick={restart}>{restarting ? 'Restarting…' : 'Restart sensor to apply'}</button>
          </div>
        )}
        {banner && <p className="muted">{banner}</p>}

        <div className="config-subtabs ids-tabs">
          {TABS.map((t) => <button key={t.id} className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}>{t.label}</button>)}
        </div>

        {tab === 'rulesets' && <RulesetsTab onChanged={() => { setNeedsRestart(true); refreshSummary(); }} />}
        {tab === 'detection' && <DetectionTab onChanged={() => setNeedsRestart(true)} />}
        {tab === 'classification' && <FileEditor kind="classification" label="classification.config" hint="Alert classtypes and their priorities. One classification per line." onChanged={() => setNeedsRestart(true)} />}
        {tab === 'advanced' && <AdvancedTab onChanged={() => setNeedsRestart(true)} />}
    </section>
  );
}

function RulesetsTab({ onChanged }: { onChanged: () => void }) {
  const [sources, setSources] = useState<IdsSource[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [updateResult, setUpdateResult] = useState('');

  async function load() {
    try { setSources((await api.idsSources()).sources); setError(''); }
    catch (err) { setError(err instanceof Error ? err.message : 'Failed to load sources'); }
  }
  useEffect(() => { load(); }, []);

  async function toggle(source: IdsSource) {
    setError('');
    let params: Record<string, string> = {};
    if (!source.enabled && source.subscription) {
      const code = window.prompt(`"${source.name}" is a subscription ruleset. Enter its access code / secret-code (leave blank if none):`, '');
      if (code === null) return;
      if (code.trim()) params = { 'secret-code': code.trim() };
    }
    setBusy(source.name);
    try {
      await api.idsSourceAction(source.enabled ? 'disable' : 'enable', source.name, params);
      await load();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update source');
    } finally {
      setBusy('');
    }
  }

  async function updateRules() {
    setBusy('__update');
    setError('');
    setUpdateResult('');
    try {
      const r = await api.idsUpdateRules();
      setUpdateResult(r.detail || (r.ok ? 'Rules updated.' : 'Update failed.'));
      if (r.ok) onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Update failed');
    } finally {
      setBusy('');
    }
  }

  return (
    <>
      <div className="section-actions">
        <p className="muted">Enable the ruleset sources you want, then fetch and rebuild the rules. et/open is used by default when nothing is enabled.</p>
        <button disabled={busy === '__update'} onClick={updateRules}>{busy === '__update' ? 'Updating rules…' : 'Update rules'}</button>
      </div>
      {error && <p className="error-text">{error}</p>}
      {updateResult && <pre className="ids-editor ids-update-log">{updateResult}</pre>}
      <table className="status-table containers-table">
        <thead><tr><th>Source</th><th>Vendor</th><th>License</th><th>State</th><th></th></tr></thead>
        <tbody>
          {sources.map((s) => (
            <tr key={s.name}>
              <td><strong>{s.name}</strong><br /><small className="muted">{s.summary}</small></td>
              <td>{s.vendor}</td>
              <td>{s.license}{s.subscription && <><br /><small className="muted">subscription</small></>}</td>
              <td><span className={`badge ${s.enabled ? 'ok' : 'muted'}`}>{s.enabled ? 'Enabled' : 'Off'}</span></td>
              <td><button className="restart-btn" disabled={busy === s.name} onClick={() => toggle(s)}>{s.enabled ? 'Disable' : 'Enable'}</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      <h3 className="ids-subhead">Custom rules</h3>
      <FileEditor kind="local_rules" label="local.rules" hint="Your own Suricata rules, one per line. Validated before saving; use unique sids ≥ 1000000." onChanged={onChanged} />
    </>
  );
}

function DetectionTab({ onChanged }: { onChanged: () => void }) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => { api.idsDetection().then((r) => setValues(r.settings)).catch(() => undefined); }, []);

  async function save() {
    setSaving(true);
    setError('');
    setMessage('');
    try {
      await api.idsUpdateDetection(values);
      setMessage('Saved.');
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="stack-form">
      <p className="muted">Detection variables define what Suricata treats as your network vs. the outside. These map to <code>vars → address-groups</code> in suricata.yaml.</p>
      {error && <p className="error-text">{error}</p>}
      <label>HOME_NET<input value={values.HOME_NET ?? ''} placeholder="[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]" onChange={(e) => setValues({ ...values, HOME_NET: e.target.value })} /></label>
      <label>EXTERNAL_NET<input value={values.EXTERNAL_NET ?? ''} placeholder="!$HOME_NET" onChange={(e) => setValues({ ...values, EXTERNAL_NET: e.target.value })} /></label>
      <div className="config-save-bar">
        <button disabled={saving} onClick={save}>{saving ? 'Validating…' : 'Save detection settings'}</button>
        {message && <span className="muted">{message}</span>}
      </div>
    </div>
  );
}

function AdvancedTab({ onChanged }: { onChanged: () => void }) {
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState('');
  async function test() {
    setTesting(true);
    setTestResult('');
    try {
      const r = await api.idsTestConfig();
      setTestResult((r.ok ? '✓ Configuration is valid.\n' : '✗ Configuration test failed.\n') + r.detail);
    } catch (err) {
      setTestResult(err instanceof Error ? err.message : 'Test failed');
    } finally {
      setTesting(false);
    }
  }
  return (
    <>
      <div className="section-actions">
        <p className="muted"><strong>Advanced.</strong> Edit the raw Suricata files. Every save is validated with <code>suricata -T</code> and rolled back automatically if it fails.</p>
        <button className="restart-btn" disabled={testing} onClick={test}>{testing ? 'Testing…' : 'Test current config'}</button>
      </div>
      {testResult && <pre className="ids-editor ids-update-log">{testResult}</pre>}
      <FileEditor kind="suricata_yaml" label="suricata.yaml" hint="The full Suricata configuration." large onChanged={onChanged} />
      <h3 className="ids-subhead">threshold.config</h3>
      <FileEditor kind="threshold" label="threshold.config" hint="Event thresholds and rate filters." onChanged={onChanged} />
    </>
  );
}

function FileEditor({ kind, label, hint, large, onChanged }: { kind: string; label: string; hint: string; large?: boolean; onChanged: () => void }) {
  const [content, setContent] = useState('');
  const [original, setOriginal] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  async function load() {
    setLoading(true);
    try {
      const r = await api.idsReadFile(kind);
      setContent(r.content);
      setOriginal(r.content);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { load(); /* eslint-disable-line react-hooks/exhaustive-deps */ }, [kind]);

  async function save() {
    setSaving(true);
    setError('');
    setMessage('');
    try {
      await api.idsWriteFile(kind, content);
      setOriginal(content);
      setMessage('Saved and validated.');
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <p className="muted">Loading {label}…</p>;
  const dirty = content !== original;
  return (
    <div className="ids-file-editor">
      <p className="muted">{hint}</p>
      {error && <pre className="error-text ids-error">{error}</pre>}
      <textarea className={`ids-editor ${large ? 'ids-editor-large' : ''}`} spellCheck={false} value={content} onChange={(e) => setContent(e.target.value)} />
      <div className="config-save-bar">
        <button disabled={saving || !dirty} onClick={save}>{saving ? 'Validating…' : `Save ${label}`}</button>
        {dirty && !saving && <button className="btn-secondary" onClick={() => setContent(original)}>Revert</button>}
        {message && <span className="muted">{message}</span>}
      </div>
    </div>
  );
}
