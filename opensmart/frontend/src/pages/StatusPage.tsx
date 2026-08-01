import { Fragment, useEffect, useRef, useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronRight, RefreshCw, RotateCcw } from 'lucide-react';
import { api } from '../api';
import type { ContainerDetail, DataInfo, ProjectOverview, ProvisioningOverview, ResourcePoint, ResourceStatus, SchemaCheckResult, StatusItem } from '../types';
import { MODULE_BACKING, NOT_IMPLEMENTED, PROJECT_LABELS, TOOL_BACKING } from './backing';

const TIMEFRAMES = ['1h', '8h', '1d', '3d', '7d', '1w', '1m'];

const MODULE_NAMES = new Set([
  'Threat Detection Alerts', 'Network Traffic Monitoring', 'Network IDS',
  'Endpoint', 'Vulnerability Management', 'Honeypot', 'Access VPN', 'LXC Manager',
  'Firewall',
]);
const TOOL_NAMES = new Set(['OPNsense', 'NTOP', 'Arkime', 'Proxmox', 'Wazuh', 'Graylog']);

export default function StatusPage() {
  const [items, setItems] = useState<StatusItem[]>([]);
  const [overview, setOverview] = useState<ProvisioningOverview | null>(null);
  const [resources, setResources] = useState<ResourceStatus | null>(null);
  const [history, setHistory] = useState<ResourcePoint[]>([]);
  const [timeframe, setTimeframe] = useState('1h');
  const [histLoading, setHistLoading] = useState(false);
  const [dataInfo, setDataInfo] = useState<DataInfo | null>(null);
  const [schema, setSchema] = useState<SchemaCheckResult | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    runCheck();
    api.dataInfo().then(setDataInfo).catch(() => undefined);
    loadResources();
    const interval = setInterval(loadResources, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => { loadHistory(timeframe); }, [timeframe]);

  async function runCheck() {
    setChecking(true);
    try {
      const [statusResult, schemaResult, overviewResult] = await Promise.all([
        api.status().catch(() => ({ modules: [] as StatusItem[] })),
        api.schemaCheck().catch(() => null),
        api.provisionOverview().catch(() => null),
      ]);
      setItems(statusResult.modules);
      setSchema(schemaResult);
      setOverview(overviewResult);
    } finally {
      setChecking(false);
    }
  }

  async function loadResources() {
    try { setResources(await api.resources()); } catch { /* ignore */ }
  }

  async function loadHistory(tf: string) {
    setHistLoading(true);
    try { setHistory((await api.resourcesHistory(tf)).points); } catch { setHistory([]); }
    finally { setHistLoading(false); }
  }

  const modules = items.filter((i) => MODULE_NAMES.has(i.name));
  const tools = items.filter((i) => TOOL_NAMES.has(i.name));
  const projectMap = new Map((overview?.projects ?? []).map((p) => [p.project, p]));

  return (
    <section className="status-page">
      <ResourcesPanel resources={resources} history={history} timeframe={timeframe} setTimeframe={setTimeframe} histLoading={histLoading} />

      <div className="card">
        <div className="status-header">
          <div>
            <h2>Module &amp; Tool Status</h2>
            <p className="muted">Live health from the containers backing each module and tool.</p>
          </div>
          <button className="ids-run-btn" onClick={runCheck} disabled={checking}>
            <RefreshCw size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} />
            {checking ? 'Checking...' : 'Run Check'}
          </button>
        </div>

        {schema && (
          <div className={`schema-check-banner ${schema.ok ? 'ok' : 'warn'}`}>
            {schema.ok
              ? <span>Schema check: <strong>OK</strong> — all expected tables present.</span>
              : <>
                  <span>Schema check: <strong>Issues found</strong></span>
                  {schema.missing_tables.length > 0 && <span>Missing: {schema.missing_tables.join(', ')}</span>}
                  {schema.extra_tables.length > 0 && <span>Extra: {schema.extra_tables.join(', ')}</span>}
                </>
            }
          </div>
        )}
      </div>

      <BackedStatusCard title="OpenSMART Modules" items={modules} backing={MODULE_BACKING} projectMap={projectMap} overview={overview} checking={checking} />
      <BackedStatusCard title="Tools" items={tools} backing={TOOL_BACKING} projectMap={projectMap} overview={overview} checking={checking} />

      {overview && <ContainersPanel overview={overview} onChanged={runCheck} />}

      {dataInfo && <DataRetentionPanel info={dataInfo} />}
    </section>
  );
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function imageVersion(image?: string): string {
  if (!image) return '—';
  const tag = image.includes(':') ? image.slice(image.lastIndexOf(':') + 1) : 'latest';
  return tag;
}

function statusBadge(status: string): { label: string; cls: string } {
  switch (status) {
    case 'online':         return { label: 'OK',             cls: 'ok' };
    case 'offline':        return { label: 'Critical',       cls: 'danger' };
    case 'warning':        return { label: 'Warning',        cls: 'warning' };
    case 'not-configured': return { label: 'Not Configured', cls: 'muted' };
    case 'disabled':       return { label: 'Disabled',       cls: 'muted' };
    default:               return { label: status,           cls: '' };
  }
}

function containerHealth(projects: ProjectOverview[]): { label: string; cls: string; detail: string } {
  const total = projects.reduce((acc, p) => acc + p.total, 0);
  const running = projects.reduce((acc, p) => acc + p.running, 0);
  const anyCreated = projects.some((p) => p.containers.some((c) => c.exists));
  if (!anyCreated) return { label: 'Not Provisioned', cls: 'muted', detail: 'Containers not created yet — provision from Configuration or the Wizard.' };
  if (running === total) return { label: 'Running', cls: 'ok', detail: `${running}/${total} containers running` };
  if (running > 0) return { label: 'Degraded', cls: 'warning', detail: `${running}/${total} containers running` };
  return { label: 'Stopped', cls: 'danger', detail: `0/${total} containers running` };
}

function BackedStatusCard({ title, items, backing, projectMap, overview, checking }: {
  title: string;
  items: StatusItem[];
  backing: Record<string, string[]>;
  projectMap: Map<string, ProjectOverview>;
  overview: ProvisioningOverview | null;
  checking: boolean;
}) {
  return <div className="card">
    <h2>{title}</h2>
    <p className="muted">{title === 'Tools' ? 'Integrated services and their containers.' : 'OpenSMART platform modules.'}</p>
    <table className="status-table">
      <thead>
        <tr><th>Component</th><th>Status</th><th>Health</th><th>Details</th></tr>
      </thead>
      <tbody>
        {items.length === 0 && !checking
          ? <tr><td colSpan={4} className="muted" style={{ padding: '10px 12px' }}>No data — click Run Check.</td></tr>
          : items.map((item) => {
              const projects = (backing[item.name] ?? []).map((p) => projectMap.get(p)).filter((p): p is ProjectOverview => Boolean(p));
              if (NOT_IMPLEMENTED.has(item.name)) {
                return (
                  <tr key={item.name}>
                    <td className="status-table-name">{item.name}</td>
                    <td><span className="badge muted">Planned</span></td>
                    <td><span className="badge muted">Not Implemented</span></td>
                    <td className="muted status-table-detail">This module is not implemented yet.</td>
                  </tr>
                );
              }
              if (projects.length === 0 || !overview) {
                const health = statusBadge(item.status);
                return (
                  <tr key={item.name}>
                    <td className="status-table-name">{item.name}</td>
                    <td><span className={`badge ${item.enabled ? 'ok-dim' : 'muted'}`}>{item.enabled ? 'Enabled' : 'Disabled'}</span></td>
                    <td><span className={`badge ${health.cls}`}>{health.label}</span></td>
                    <td className="muted status-table-detail">{item.detail}</td>
                  </tr>
                );
              }
              const health = item.enabled ? containerHealth(projects) : { label: 'Disabled', cls: 'muted', detail: 'Module is disabled.' };
              const detailParts: string[] = [health.detail];
              if (item.name === 'Access VPN' && overview.vpn) {
                const v = overview.vpn;
                const vpnBits: string[] = [];
                if (v.openvpn.configured) vpnBits.push(`OpenVPN: ${v.openvpn.valid_certs} user cert${v.openvpn.valid_certs === 1 ? '' : 's'}${v.openvpn.revoked_certs ? `, ${v.openvpn.revoked_certs} revoked` : ''}`);
                if (v.wireguard.configured) vpnBits.push(`WireGuard: ${v.wireguard.peers} peer${v.wireguard.peers === 1 ? '' : 's'}`);
                if (vpnBits.length) detailParts.push(vpnBits.join(' · '));
              }
              return (
                <tr key={item.name}>
                  <td className="status-table-name">{item.name}</td>
                  <td><span className={`badge ${item.enabled ? 'ok-dim' : 'muted'}`}>{item.enabled ? 'Enabled' : 'Disabled'}</span></td>
                  <td><span className={`badge ${health.cls}`}>{health.label}</span></td>
                  <td className="muted status-table-detail">{detailParts.join(' — ')}</td>
                </tr>
              );
            })
        }
      </tbody>
    </table>
  </div>;
}

function containerBadge(c: ContainerDetail): { label: string; cls: string } {
  if (!c.exists) return { label: 'Not Created', cls: 'muted' };
  switch (c.status) {
    case 'running':    return { label: 'Running', cls: 'ok' };
    case 'restarting': return { label: 'Restarting', cls: 'danger' };
    case 'exited':     return { label: 'Stopped', cls: 'muted' };
    case 'paused':     return { label: 'Paused', cls: 'warning' };
    default:           return { label: c.status, cls: '' };
  }
}

function ContainersPanel({ overview, onChanged }: { overview: ProvisioningOverview; onChanged: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<{ project: string; ok: boolean; detail: string } | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const withContainers = overview.projects.filter((p) => p.containers.some((c) => c.exists));
  if (withContainers.length === 0) return null;

  async function restart(project: string) {
    setBusy(project);
    setResult(null);
    try {
      const r = await api.provisionRestart(project);
      setResult({ project, ok: r.ok, detail: r.ok ? 'Restarted successfully.' : (r.detail || 'Restart failed.') });
      onChanged();
    } catch (error) {
      setResult({ project, ok: false, detail: error instanceof Error ? error.message : 'Restart failed.' });
    } finally {
      setBusy(null);
    }
  }

  function toggle(name: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  }

  return (
    <div className="card">
      <h2>Containers</h2>
      <p className="muted">Every provisioned container, with live state read from the Docker engine. Click a warning count to see the details.</p>
      <table className="status-table containers-table">
        <thead>
          <tr><th>Service</th><th>Container</th><th>State</th><th>Version</th><th>Uptime</th><th>Restarts</th><th>Warnings</th><th></th></tr>
        </thead>
        <tbody>
          {withContainers.map((project) => project.containers.map((c, idx) => {
            const badge = containerBadge(c);
            const warnings = c.warnings ?? [];
            const isExpanded = expanded.has(c.name);
            return (
              <Fragment key={c.name}>
                <tr>
                  <td className="status-table-name">{idx === 0 ? (PROJECT_LABELS[project.project] ?? project.project) : ''}</td>
                  <td className="muted">{c.name}</td>
                  <td><span className={`badge ${badge.cls}`}>{badge.label}</span></td>
                  <td className="muted">{imageVersion(c.image)}</td>
                  <td className="muted">{c.uptime_seconds != null ? formatUptime(c.uptime_seconds) : '—'}</td>
                  <td className="muted">{c.restart_count ?? 0}</td>
                  <td>
                    {warnings.length > 0
                      ? <button className="text-button warning-toggle" onClick={() => toggle(c.name)}>
                          <AlertTriangle size={13} style={{ verticalAlign: 'text-bottom', marginRight: 4 }} />
                          {warnings.length} {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                        </button>
                      : <span className="muted">—</span>}
                  </td>
                  <td>
                    {idx === 0 && (
                      <button className="btn-secondary restart-btn" disabled={busy === project.project} onClick={() => restart(project.project)}>
                        <RotateCcw size={13} style={{ verticalAlign: 'text-bottom', marginRight: 4 }} />
                        {busy === project.project ? 'Restarting…' : 'Restart'}
                      </button>
                    )}
                  </td>
                </tr>
                {isExpanded && warnings.length > 0 && (
                  <tr className="warning-detail-row">
                    <td colSpan={8}>
                      <ul className="warning-list">
                        {warnings.map((w) => <li key={w}>{w}</li>)}
                      </ul>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          }))}
        </tbody>
      </table>
      {result && (
        <p className={`save-message ${result.ok ? '' : 'error-text'}`}>
          {PROJECT_LABELS[result.project] ?? result.project}: {result.detail}
        </p>
      )}
    </div>
  );
}

function ModuleRetention({ label, m }: { label: string; m: DataInfo['ids'] }) {
  return (
    <div className="data-retention-col">
      <h3>{label}</h3>
      <div className="data-retention-row"><span className="muted">Retention</span><span className={`badge ${m.retention_enabled ? '' : 'warning'}`}>{m.retention_enabled ? `${m.retention_days}d` : 'Disabled'}</span></div>
      {m.retention_enabled && <div className="data-retention-row"><span className="muted">Cleanup at</span><span>{m.retention_time || '02:00'}</span></div>}
      <div className="data-retention-row"><span className="muted">Earliest event</span><span>{m.earliest_event ? m.earliest_event.slice(0, 19).replace('T', ' ') : '—'}</span></div>
      <div className="data-retention-row"><span className="muted">Total records</span><span>{m.total.toLocaleString()}</span></div>
    </div>
  );
}

function DataRetentionPanel({ info }: { info: DataInfo }) {
  return (
    <div className="card">
      <h2>Data Retention &amp; Coverage</h2>
      <div className="data-retention-grid">
        <ModuleRetention label="Network IDS" m={info.ids} />
        <ModuleRetention label="Network Traffic" m={info.network} />
      </div>
    </div>
  );
}

function GaugeRing({ percent, color, size = 110 }: { percent: number; color: string; size?: number }) {
  const r = (size - 16) / 2; const circ = 2 * Math.PI * r;
  const dash = (Math.min(100, Math.max(0, percent)) / 100) * circ; const cx = size / 2;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={cx} cy={cx} r={r} fill="none" stroke="rgba(255,255,255,.08)" strokeWidth="10" />
      <circle cx={cx} cy={cx} r={r} fill="none" stroke={color} strokeWidth="10"
        strokeDasharray={`${dash} ${circ - dash}`} strokeLinecap="round" transform={`rotate(-90 ${cx} ${cx})`} />
    </svg>
  );
}

function ResourceGauge({ label, percent, used, total, unit, color }: { label: string; percent: number; used: number; total: number; unit: string; color: string }) {
  return (
    <div className="resource-gauge">
      <div className="gauge-ring-wrap"><GaugeRing percent={percent} color={color} /><div className="gauge-center"><strong>{Math.round(percent)}%</strong></div></div>
      <div className="gauge-label">{label}</div>
      <div className="gauge-detail">{used}{unit} / {total}{unit}</div>
    </div>
  );
}

function ResourcesPanel({ resources, history, timeframe, setTimeframe, histLoading }: {
  resources: ResourceStatus | null; history: ResourcePoint[]; timeframe: string; setTimeframe: (tf: string) => void; histLoading: boolean;
}) {
  return (
    <div className="card resources-panel">
      <h2>Server Resources</h2>
      <p className="muted">Live server metrics — refreshes every 10 seconds.</p>
      {resources ? (
        <div className="resource-gauges">
          <ResourceGauge label="CPU" percent={resources.cpu_percent} used={resources.cpu_percent} total={100} unit="%" color="#58d7ff" />
          <ResourceGauge label="Memory" percent={resources.memory_percent} used={resources.memory_used_gb} total={resources.memory_total_gb} unit=" GB" color="#63e6be" />
          <ResourceGauge label="Disk" percent={resources.disk_percent} used={resources.disk_used_gb} total={resources.disk_total_gb} unit=" GB" color="#ffc857" />
          <div className="resource-gauge">
            <div className="uptime-card"><strong>{formatUptime(resources.uptime_seconds)}</strong><span>uptime</span></div>
            <div className="gauge-label">System</div>
            <div className="gauge-detail">{resources.cpu_count} logical CPUs</div>
          </div>
        </div>
      ) : <p className="muted">Loading resource data…</p>}
      <div className="resource-chart-section">
        <div className="resource-chart-header">
          <h3>Resource Usage History</h3>
          <div className="timeframe-group">
            {TIMEFRAMES.map((tf) => <button key={tf} className={timeframe === tf ? 'active' : ''} onClick={() => setTimeframe(tf)}>{tf}</button>)}
          </div>
        </div>
        <div className="resource-chart-legend">
          <span className="legend-cpu">&#9632; CPU</span>
          <span className="legend-mem">&#9632; Memory</span>
          <span className="legend-disk">&#9632; Disk</span>
        </div>
        {histLoading ? <div className="resource-chart-placeholder">Loading…</div>
          : history.length < 2 ? <div className="resource-chart-placeholder">Collecting data — snapshots are taken every 60 seconds.</div>
          : <ResourceLineChart points={history} />}
      </div>
    </div>
  );
}

function ResourceLineChart({ points }: { points: ResourcePoint[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver(() => { if (containerRef.current) setWidth(containerRef.current.clientWidth); });
    observer.observe(containerRef.current);
    setWidth(containerRef.current.clientWidth);
    return () => observer.disconnect();
  }, []);
  const H = 180; const PAD_LEFT = 32; const PAD_BOTTOM = 24; const PAD_TOP = 8;
  const chartW = width - PAD_LEFT - 4; const chartH = H - PAD_BOTTOM - PAD_TOP; const n = points.length;
  function toX(i: number) { return PAD_LEFT + (i / (n - 1)) * chartW; }
  function toY(v: number) { return PAD_TOP + (1 - Math.min(100, Math.max(0, v)) / 100) * chartH; }
  function makePath(getter: (p: ResourcePoint) => number) {
    return points.map((p, i) => `${i === 0 ? 'M' : 'L'}${toX(i).toFixed(1)},${toY(getter(p)).toFixed(1)}`).join(' ');
  }
  const labelCount = Math.min(6, n);
  const labelIndexes = Array.from({ length: labelCount }, (_, i) => Math.round((i / (labelCount - 1)) * (n - 1)));
  const xLabels = labelIndexes.map((idx) => ({ x: toX(idx), label: new Date(points[idx].t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }));
  const gridYs = [0, 25, 50, 75, 100];
  return (
    <div ref={containerRef} className="resource-chart-container">
      <svg width={width} height={H} viewBox={`0 0 ${width} ${H}`}>
        {gridYs.map((v) => (
          <g key={v}>
            <line x1={PAD_LEFT} y1={toY(v)} x2={width - 4} y2={toY(v)} stroke="rgba(255,255,255,.06)" strokeWidth="1" />
            <text x={PAD_LEFT - 4} y={toY(v)} dominantBaseline="middle" textAnchor="end" fontSize="8" fill="#4a6278">{v}</text>
          </g>
        ))}
        {xLabels.map((item) => <text key={item.x} x={item.x} y={H - 4} textAnchor="middle" fontSize="8" fill="#4a6278">{item.label}</text>)}
        <path d={makePath((p) => p.cpu)} fill="none" stroke="#58d7ff" strokeWidth="1.5" strokeLinejoin="round" />
        <path d={makePath((p) => p.memory)} fill="none" stroke="#63e6be" strokeWidth="1.5" strokeLinejoin="round" />
        <path d={makePath((p) => p.disk)} fill="none" stroke="#ffc857" strokeWidth="1.5" strokeLinejoin="round" />
      </svg>
    </div>
  );
}
