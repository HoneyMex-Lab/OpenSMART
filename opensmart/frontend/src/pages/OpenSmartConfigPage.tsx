import { useEffect, useState } from 'react';
import { api } from '../api';
import type { OpenSmartModule } from '../types';

type DiffEntry = { field: string; from: string; to: string };

const SUGGESTED_EXCLUSIONS = [
  { key: 'stats',    label: 'Stats',    defaultExclude: true,  help: 'Suricata system statistics — very high volume, not security events.' },
  { key: 'drop',     label: 'Drop',     defaultExclude: true,  help: 'Dropped-packet records — operational noise.' },
  { key: 'internal', label: 'Internal', defaultExclude: true,  help: 'Internal Suricata events — not security data.' },
  { key: 'pcap',     label: 'PCAP',     defaultExclude: true,  help: 'Packet capture metadata — not application-layer.' },
  { key: 'ntp',      label: 'NTP',      defaultExclude: false, help: 'Time-sync protocol — rarely actionable.' },
  { key: 'snmp',     label: 'SNMP',     defaultExclude: false, help: 'Management protocol — operational noise.' },
  { key: 'dnp3',     label: 'DNP3',     defaultExclude: false, help: 'ICS/SCADA protocol — irrelevant on IT-only networks.' },
  { key: 'modbus',   label: 'Modbus',   defaultExclude: false, help: 'ICS/SCADA protocol — irrelevant on IT-only networks.' },
];

function computeModuleDiff(original: OpenSmartModule[], draft: OpenSmartModule[]): DiffEntry[] {
  const result: DiffEntry[] = [];
  draft.forEach((item) => {
    const orig = original.find((o) => o.id === item.id);
    if (!orig) return;
    if (orig.enabled !== item.enabled) result.push({ field: `${item.name}: status`, from: orig.enabled ? 'Enabled' : 'Disabled', to: item.enabled ? 'Enabled' : 'Disabled' });
    if (orig.config !== item.config) result.push({ field: `${item.name}: configuration`, from: 'current configuration', to: summarizeConfigChange(orig.config, item.config) });
  });
  return result;
}

function summarizeConfigChange(fromRaw: string, toRaw: string): string {
  const from = parseConfig(fromRaw);
  const to = parseConfig(toRaw);
  const keys = new Set([...Object.keys(from), ...Object.keys(to)]);
  const changed = [...keys].filter((key) => String(from[key] ?? '') !== String(to[key] ?? '')).length;
  return changed ? `${changed} setting${changed === 1 ? '' : 's'} updated` : 'configuration updated';
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
            {diff.map((entry, i) => (
              <div className="diff-row" key={i}>
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

function Toggle({ checked, onChange }: { checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <button role="switch" aria-checked={checked} className={`toggle-switch ${checked ? 'on' : ''}`} onClick={() => onChange(!checked)}>
      <span className="toggle-thumb" />
    </button>
  );
}

export default function OpenSmartConfigPage({ modules, onModulesUpdate }: { modules: OpenSmartModule[]; onModulesUpdate: (modules: OpenSmartModule[]) => void }) {
  const [draft, setDraft] = useState<OpenSmartModule[]>(modules);
  const [visibleJson, setVisibleJson] = useState<Record<number, boolean>>({});
  const [message, setMessage] = useState('');
  const [pendingDiff, setPendingDiff] = useState<DiffEntry[] | null>(null);
  const [activeId, setActiveId] = useState<number | null>(modules[0]?.id ?? null);
  useEffect(() => {
    setDraft(modules);
    setActiveId((prev) => (prev === null && modules.length > 0 ? modules[0].id : prev));
  }, [modules]);

  function requestSave() {
    setPendingDiff(computeModuleDiff(modules, draft));
  }

  async function confirmSave() {
    setPendingDiff(null);
    const result = await api.saveOpenSmartModules(draft);
    onModulesUpdate(result.modules);
    setMessage('OpenSMART module configuration saved.');
  }

  function updateConfig(id: number, key: string, value: string) {
    setDraft(draft.map((item) => {
      if (item.id !== id) return item;
      const config = parseConfig(item.config);
      return { ...item, config: JSON.stringify({ ...config, [key]: value }, null, 2) };
    }));
  }

  const activeModule = draft.find((m) => m.id === activeId) ?? draft[0];

  return (
    <section className="config-card-list">
      {pendingDiff !== null && <ConfirmDialog diff={pendingDiff} onConfirm={confirmSave} onCancel={() => setPendingDiff(null)} />}

      <div className="config-subtabs">
        {draft.map((module) => (
          <button key={module.id} className={activeId === module.id ? 'active' : ''} onClick={() => setActiveId(module.id)}>
            {module.name}
          </button>
        ))}
      </div>

      {activeModule && (() => {
        const module = activeModule;
        const config = parseConfig(module.config);
        return (
          <article className="card config-item" key={module.id}>
            <div className="config-toggle-row">
              <div>
                <h2>{module.name}</h2>
                <p className="muted">{module.description}</p>
              </div>
              <Toggle checked={module.enabled} onChange={(checked) => setDraft(draft.map((item) => item.id === module.id ? { ...item, enabled: checked } : item))} />
            </div>
            {module.name === 'Network IDS' && (
              <>
                <div className="config-field-table">
                  <label><span>eve.json path</span><input placeholder="/var/log/suricata/eve.json" value={config.eve_json_path || ''} onChange={(event) => updateConfig(module.id, 'eve_json_path', event.target.value)} /></label>
                  <label><span>Summary refresh minutes</span><input type="number" min="1" value={config.summary_refresh_minutes || '5'} onChange={(event) => updateConfig(module.id, 'summary_refresh_minutes', event.target.value)} /></label>
                  <label><span>Initial ingestion size</span><input type="number" min="0" step="0.1" value={config.initial_ingestion_gb ?? '2'} onChange={(event) => updateConfig(module.id, 'initial_ingestion_gb', event.target.value)} /></label>
                  <p className="config-field-hint">Value is in GB. 0 ingests the full file initially and may take a long time on large eve.json files.</p>
                  <label><span>Default Top N</span><input type="number" min="1" max="500" value={config.default_top_n || '10'} onChange={(event) => updateConfig(module.id, 'default_top_n', event.target.value)} /></label>
                  <label><span>Alert page size</span><input type="number" min="1" max="1000" value={config.analysis_page_size || '30'} onChange={(event) => updateConfig(module.id, 'analysis_page_size', event.target.value)} /></label>
                  <label><span>GeoIP DB path</span><input placeholder="/opt/opensmart/geoip/GeoLite2-City.mmdb" value={config.geoip_db_path || ''} onChange={(event) => updateConfig(module.id, 'geoip_db_path', event.target.value)} /></label>
                  <p className="config-field-hint">Optional MaxMind GeoLite2 City MMDB. Download it separately from MaxMind and configure the local path for Attack Map geolocation.</p>
                </div>
                <div className="checkbox-row">
                  <Toggle checked={String(config.keep_empty_alerts || 'false').toLowerCase() === 'true'} onChange={(checked) => updateConfig(module.id, 'keep_empty_alerts', checked ? 'true' : 'false')} />
                  <span>
                    Keep empty alert events
                    <small className="muted">eve.json sometimes contains alert-typed records without a signature_id (internal/stats events). When off (default), these are dropped from ingest. When on, they are kept and shown as alerts.</small>
                  </span>
                </div>
                <div className="checkbox-row">
                  <Toggle checked={String(config.index_payload_printable ?? 'true').toLowerCase() !== 'false'} onChange={(checked) => updateConfig(module.id, 'index_payload_printable', checked ? 'true' : 'false')} />
                  <span>
                    Index Payload Printable
                    <small className="muted">When on (default), decoded payload is stored at ingest and searchable via the alert search box. When off, only the raw payload is stored and decoded on-the-fly at query time (smaller DB, but search by decoded text is disabled).</small>
                  </span>
                </div>
                <div className="checkbox-row">
                  <Toggle checked={String(config.fast_alert_prefilter ?? 'true').toLowerCase() !== 'false'} onChange={(checked) => updateConfig(module.id, 'fast_alert_prefilter', checked ? 'true' : 'false')} />
                  <span>
                    Fast Alert Prefilter
                    <small className="muted">When on (default), each eve.json line is scanned for an alert marker before JSON decoding. Skips flow/dns/http/stats records cheaply and yields ~3-5x faster ingest on alert-sparse logs. Turn off only if your eve.json uses non-standard formatting that hides the marker.</small>
                  </span>
                </div>
                <div className="checkbox-row">
                  <Toggle checked={(config.track_critical_alerts || 'off') !== 'off'} onChange={(checked) => updateConfig(module.id, 'track_critical_alerts', checked ? (config.track_critical_alerts === 'full' ? 'full' : 'simple') : 'off')} />
                  <span>
                    Track Critical alerts
                    <small className="muted">Show new critical-alert indicators until alerts are checked.</small>
                  </span>
                </div>
                {(config.track_critical_alerts || 'off') !== 'off' && <label>Tracking mode<select value={config.track_critical_alerts || 'simple'} onChange={(event) => updateConfig(module.id, 'track_critical_alerts', event.target.value)}><option value="simple">Simple tracking</option><option value="full">Full tracking</option></select><small className="muted">Simple marks critical alerts checked when opening critical lists. Full requires acknowledging each critical alert in the alert table.</small></label>}
                <RetentionFields config={config} id={module.id} updateConfig={updateConfig} />
              </>
            )}
            {module.name === 'Network Traffic Monitoring' && (
              <>
                <div className="traffic-source-card">
                  <h3>Network log source</h3>
                  <label className="radio-option"><input type="radio" name={`traffic-source-${module.id}`} checked={(config.log_source || 'eve_json') === 'eve_json'} onChange={() => updateConfig(module.id, 'log_source', 'eve_json')} /><span><strong>eve.json</strong><small className="muted">Requires the Network IDS module to be enabled. Uses the configured Network IDS eve.json file.</small></span></label>
                  <label className="radio-option"><input type="radio" name={`traffic-source-${module.id}`} checked={config.log_source === 'zeek_json'} onChange={() => updateConfig(module.id, 'log_source', 'zeek_json')} /><span><strong>Zeek (JSON)</strong><small className="muted">Uses telemetry from a Zeek JSON file. Ingestion will be implemented later.</small></span></label>
                  {config.log_source === 'zeek_json' && <label className="zeek-path-field">Zeek JSON path<input placeholder="/var/log/zeek/current/conn.log" value={config.zeek_json_path || ''} onChange={(event) => updateConfig(module.id, 'zeek_json_path', event.target.value)} /></label>}
                </div>
                <p className="muted">Select which Suricata eve.json network event families are indexed during shared ingestion when eve.json is selected.</p>
                {[
                  ['index_dns', 'DNS Log', 'Details DNS queries and responses.'],
                  ['index_http', 'HTTP Log', 'Logs HTTP requests and responses including URLs and user agents.'],
                  ['index_tls', 'TLS Log', 'Captures TLS handshake information such as SNI and certificates.'],
                  ['index_flow', 'Flow Log', 'Records flow metadata including duration, endpoints, ports, packets, and bytes.'],
                  ['index_fileinfo', 'File Information', 'Logs file extraction metadata and checksums such as MD5/SHA256.'],
                  ['index_smb', 'SMB', 'Indexes SMB protocol events.'],
                  ['index_other_app_layer', 'Other Application Layer protocols', 'Indexes other supported app-layer protocols such as SSH, SMTP, FTP, RDP, SIP, DHCP, MQTT, Kerberos, IKEv2, NFS, and TFTP.'],
                  ['index_all_suricata_protocols', 'All Suricata supported protocols', 'Indexes all currently recognized Suricata eve.json protocol events. Overrides the individual protocol toggles.'],
                ].map(([key, label, help]) => (
                  <div className="checkbox-row" key={key}>
                    <Toggle checked={String(config[key] ?? (['index_dns', 'index_http', 'index_tls', 'index_flow'].includes(key) ? 'true' : 'false')).toLowerCase() === 'true'} onChange={(checked) => updateConfig(module.id, key, checked ? 'true' : 'false')} />
                    <span>
                      {label}
                      <small className="muted">{help}</small>
                    </span>
                  </div>
                ))}
                {String(config.index_all_suricata_protocols ?? 'false').toLowerCase() === 'true' && (
                  <ExclusionList config={config} id={module.id} updateConfig={updateConfig} />
                )}
                <RetentionFields config={config} id={module.id} updateConfig={updateConfig} />
              </>
            )}
            <button className="text-button" onClick={() => setVisibleJson({ ...visibleJson, [module.id]: !visibleJson[module.id] })}>{visibleJson[module.id] ? 'Hide JSON config' : 'Show JSON config'}</button>
            {visibleJson[module.id] && <label>JSON Configuration<textarea value={module.config} onChange={(event) => setDraft(draft.map((item) => item.id === module.id ? { ...item, config: event.target.value } : item))} /></label>}
          </article>
        );
      })()}

      <div className="config-save-bar">
        {message && <p className="save-message">{message}</p>}
        <button onClick={requestSave}>Save OpenSMART configuration</button>
      </div>
    </section>
  );
}

function ExclusionList({ config, id, updateConfig }: { config: Record<string, string>; id: number; updateConfig: (id: number, key: string, value: string) => void }) {
  let excludeSet: Set<string>;
  try {
    const parsed = JSON.parse(config.exclude_event_types || '["stats","drop","internal","pcap"]');
    excludeSet = new Set(Array.isArray(parsed) ? parsed : []);
  } catch {
    excludeSet = new Set(['stats', 'drop', 'internal', 'pcap']);
  }

  function toggle(key: string, checked: boolean) {
    const next = new Set(excludeSet);
    if (checked) next.add(key); else next.delete(key);
    updateConfig(id, 'exclude_event_types', JSON.stringify([...next].sort()));
  }

  return (
    <div className="exclusion-list">
      <p className="muted" style={{ marginBottom: 8 }}>Exclude noisy event types from the all-protocols catch-all. ★ = excluded by default.</p>
      {SUGGESTED_EXCLUSIONS.map(({ key, label, defaultExclude, help }) => (
        <div className="checkbox-row" key={key}>
          <Toggle checked={excludeSet.has(key)} onChange={(checked) => toggle(key, checked)} />
          <span>
            {label}{defaultExclude ? ' ★' : ''}
            <small className="muted">{help}</small>
          </span>
        </div>
      ))}
    </div>
  );
}

function RetentionFields({ config, id, updateConfig }: { config: Record<string, string>; id: number; updateConfig: (id: number, key: string, value: string) => void }) {
  const enabled = String(config.retention_enabled ?? 'true').toLowerCase() !== 'false';
  return (
    <>
      <div className="checkbox-row">
        <Toggle checked={enabled} onChange={(checked) => updateConfig(id, 'retention_enabled', checked ? 'true' : 'false')} />
        <span>
          Data Retention
          <small className="muted">Automatically delete data older than the configured period. Runs daily at the specified time.</small>
        </span>
      </div>
      {enabled && (
        <div className="metric-config-grid">
          <label>Retain data (days)<input type="number" min="1" value={config.retention_days || '90'} onChange={(event) => updateConfig(id, 'retention_days', event.target.value)} /></label>
          <label>Run cleanup at (HH:MM)<input type="time" value={config.retention_time || '02:00'} onChange={(event) => updateConfig(id, 'retention_time', event.target.value)} /></label>
        </div>
      )}
    </>
  );
}

function parseConfig(raw: string): Record<string, string> {
  try {
    return JSON.parse(raw || '{}');
  } catch {
    return {};
  }
}
