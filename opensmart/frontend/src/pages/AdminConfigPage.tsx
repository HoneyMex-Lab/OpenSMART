import { ChangeEvent, useEffect, useState } from 'react';
import { api } from '../api';
import { languageOptions, t } from '../i18n';
import { DEFAULT_THEME, THEME_OPTIONS } from '../themes';
import type { Settings } from '../types';

const platformFields = ['platform_title', 'platform_version', 'sensor_name', 'platform_language', 'developed_by', 'failed_login_limit', 'lockout_minutes', 'tool_base_path'];

const passwordPolicyOptions: { value: string; label: string }[] = [
  { value: 'strict', label: 'Strict (12+ chars, upper/lower/digit/symbol)' },
  { value: 'moderate', label: 'Moderate (10+ chars, 3 of 4 character classes)' },
  { value: 'low', label: 'Low (8+ chars, no complexity requirement)' },
  { value: 'disabled', label: 'Disabled (no complexity or length requirement)' },
];

const metricFields: { key: string; label: string }[] = [
  { key: 'dashboard_ids_alerts_critical', label: 'Threat Detection: critical alerts (24h)' },
  { key: 'dashboard_ids_alerts_high', label: 'Threat Detection: high alerts (24h)' },
  { key: 'dashboard_ids_alerts_medium', label: 'Threat Detection: medium alerts (24h)' },
  { key: 'dashboard_ids_alerts_low', label: 'Threat Detection: low alerts (24h)' },
  { key: 'dashboard_ids_severity_critical', label: 'Network IDS: critical severity (24h)' },
  { key: 'dashboard_ids_severity_high', label: 'Network IDS: high severity (24h)' },
  { key: 'dashboard_ids_severity_medium', label: 'Network IDS: medium severity (24h)' },
  { key: 'dashboard_ids_severity_low', label: 'Network IDS: low severity (24h)' },
  { key: 'dashboard_fw_blocked_packets_24h', label: 'FW blocked packets (24h)' },
  { key: 'dashboard_fw_allowed_packets_24h', label: 'FW allowed packets (24h)' },
  { key: 'dashboard_fw_blocked_ips_24h', label: 'FW blocked IPs (24h)' },
  { key: 'dashboard_endpoints_total', label: 'Endpoints total' },
  { key: 'dashboard_vulnerabilities_critical', label: 'Critical vulnerabilities' },
  { key: 'dashboard_vulnerabilities_high', label: 'High vulnerabilities' },
  { key: 'dashboard_vulnerabilities_medium', label: 'Medium vulnerabilities' },
  { key: 'dashboard_vulnerabilities_open', label: 'Open vulnerabilities' },
  { key: 'dashboard_vpn_users', label: 'VPN users' },
  { key: 'dashboard_lxc_assets', label: 'Virtualized assets / LXC servers' },
];

type ImageField = 'logo_url' | 'favicon_url';

const imageFields: { key: ImageField; label: string; hint: string }[] = [
  { key: 'logo_url', label: 'Main logo', hint: 'Used in sidebar and login.' },
  { key: 'favicon_url', label: 'Favicon', hint: 'Browser tab icon. Defaults to the generated hexagon icon.' },
];

type DiffEntry = { field: string; from: string; to: string };

function computeDiff(original: Settings, draft: Settings): DiffEntry[] {
  const keys = new Set([...Object.keys(original), ...Object.keys(draft)]);
  const result: DiffEntry[] = [];
  keys.forEach((key) => {
    const from = original[key] ?? '';
    const to = draft[key] ?? '';
    if (from !== to) result.push({ field: key, from: summarizeSetting(key, from), to: summarizeSetting(key, to) });
  });
  return result;
}

function summarizeSetting(key: string, value: string): string {
  if (key.includes('logo') || key.includes('favicon') || value.startsWith('data:image/')) {
    return value ? 'image configured' : 'empty';
  }
  if (value.length > 80) return `${value.slice(0, 77)}...`;
  return value || 'empty';
}

function ConfirmDialog({ diff, onConfirm, onCancel }: { diff: DiffEntry[]; onConfirm: () => void; onCancel: () => void }) {
  return (
    <div className="confirm-overlay">
      <div className="confirm-dialog card">
        <h3>Review changes</h3>
        {diff.length === 0 ? (
          <p className="muted">No changes detected.</p>
        ) : (
          <div className="confirm-diff">
            {diff.map((entry) => (
              <div className="diff-row" key={entry.field}>
                <span className="diff-field">{entry.field}</span>
                <span className="diff-from">{entry.from || <em>empty</em>}</span>
                <span className="diff-arrow">→</span>
                <span className="diff-to">{entry.to || <em>empty</em>}</span>
              </div>
            ))}
          </div>
        )}
        <div className="confirm-actions">
          <button className="btn-secondary" onClick={onCancel}>Cancel</button>
          <button onClick={onConfirm}>Confirm</button>
        </div>
      </div>
    </div>
  );
}

export default function AdminConfigPage({ settings, setSettings }: { settings: Settings; setSettings: (settings: Settings) => void }) {
  const [draft, setDraft] = useState<Settings>(settings);
  const [message, setMessage] = useState('');
  const [pendingDiff, setPendingDiff] = useState<DiffEntry[] | null>(null);
  useEffect(() => { setDraft(settings); }, [settings]);

  function requestSave() {
    const diff = computeDiff(settings, draft);
    setPendingDiff(diff);
  }

  async function confirmSave() {
    setPendingDiff(null);
    const result = await api.saveSettings(draft);
    setSettings(result.settings);
      setMessage(t(draft, 'settings.saved', 'Settings saved.'));
  }

  function uploadImage(field: ImageField, event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setDraft((current) => ({ ...current, [field]: String(reader.result || '') }));
    reader.readAsDataURL(file);
  }

  return (
    <section className="admin-stack">
      {pendingDiff !== null && <ConfirmDialog diff={pendingDiff} onConfirm={confirmSave} onCancel={() => setPendingDiff(null)} />}

      <div className="admin-grid">
        <article className="card">
          <h2>{t(draft, 'settings.platformParameters', 'Platform Parameters')}</h2>
          <div className="stack-form">
            {platformFields.map((field) => field === 'platform_language'
              ? <label key={field}>{t(draft, 'field.platform_language', 'Platform language')}<select value={draft[field] || 'en'} onChange={(event) => setDraft({ ...draft, [field]: event.target.value })}>{languageOptions.map((option) => <option key={option.value} value={option.value}>{t(draft, option.labelKey, option.fallback)}</option>)}</select></label>
              : <label key={field}>{t(draft, `field.${field}`, field)}<input value={draft[field] || ''} onChange={(event) => setDraft({ ...draft, [field]: event.target.value })} /></label>)}
            <label>
              {t(draft, 'field.theme', 'Default theme')}
              <select value={draft.theme || DEFAULT_THEME} onChange={(event) => setDraft({ ...draft, theme: event.target.value })}>
                {THEME_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
              </select>
              <small className="muted">Applies to the login page and any user who hasn't picked their own theme.</small>
            </label>
          </div>
        </article>
        <article className="card">
          <h2>Branding Assets</h2>
          <div className="logo-upload-grid">
            {imageFields.map((field) => <label key={field.key}>{field.label}<span className="muted">{field.hint}</span><span className="logo-preview">{draft[field.key] ? <img src={draft[field.key]} alt={field.label} /> : 'No image'}</span><input type="file" accept="image/*,.svg" onChange={(event) => uploadImage(field.key, event)} /></label>)}
          </div>
        </article>
      </div>

      <article className="card">
        <h2>Password Policy</h2>
        <p className="muted">Applies to new user passwords, admin-triggered resets, and self-service password changes.</p>
        <div className="stack-form">
          <label>
            Complexity profile
            <select value={draft.password_policy || 'strict'} onChange={(event) => setDraft({ ...draft, password_policy: event.target.value })}>
              {passwordPolicyOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </select>
          </label>
        </div>
        {(draft.password_policy === 'low' || draft.password_policy === 'disabled') && (
          <div className="error-box" role="alert">
            Warning: this profile significantly weakens account security. Passwords will be easier to guess or brute-force. Only use this if you understand the risk.
          </div>
        )}
      </article>

      <article className="card">
        <div className="section-actions">
          <div><h2>{t(draft, 'settings.homeDashboard', 'Home Dashboard')}</h2><p className="muted">{t(draft, 'settings.dashboardHelp', 'Demo metric values and display options for the landing dashboard.')}</p></div>
        </div>
        <div className="dashboard-option-row">
          <label className="toggle-label">
            {t(draft, 'settings.demoDisabled', 'Fill disabled module panels with demo data')}
            <span className="muted">{t(draft, 'settings.demoDisabledHelp', 'When enabled, panels for disabled modules/tools show demo values and a DEMO badge.')}</span>
          </label>
          <Toggle
            checked={draft.dashboard_use_demo_for_disabled === 'true'}
            onChange={(checked) => setDraft({ ...draft, dashboard_use_demo_for_disabled: checked ? 'true' : 'false' })}
          />
        </div>
        <div className="metric-config-grid" style={{ marginTop: '16px' }}>
          {metricFields.map((field) => <label key={field.key}>{field.label}<input type="number" min="0" value={draft[field.key] || '0'} onChange={(event) => setDraft({ ...draft, [field.key]: event.target.value })} /></label>)}
        </div>
        <label className="subheading">{t(draft, 'settings.feedJson', 'Internal feed JSON')}<textarea value={draft.dashboard_feed_json || '[]'} onChange={(event) => setDraft({ ...draft, dashboard_feed_json: event.target.value })} /></label>
      </article>

      <div className="config-save-bar">
        {message && <p className="save-message">{message}</p>}
        <button onClick={requestSave}>{t(draft, 'settings.saveSettings', 'Save settings')}</button>
      </div>
    </section>
  );
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      className={`toggle-switch ${checked ? 'on' : ''}`}
      onClick={() => onChange(!checked)}
    >
      <span className="toggle-thumb" />
    </button>
  );
}
