import { useEffect, useRef, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { api } from '../api';
import type { DataInfo, ResourcePoint, ResourceStatus, SchemaCheckResult, StatusItem } from '../types';

const TIMEFRAMES = ['1h', '8h', '1d', '3d', '7d', '1w', '1m'];

const MODULE_NAMES = new Set([
  'Threat Detection Alerts', 'Network Traffic Monitoring', 'Network IDS',
  'Endpoint', 'Vulnerability Management', 'Honeypot', 'Access VPN', 'LXC Manager',
]);
const TOOL_NAMES = new Set(['OPNsense', 'NTOP', 'Arkime', 'Proxmox', 'Wazuh', 'Graylog']);

export default function StatusPage() {
  const [items, setItems] = useState<StatusItem[]>([]);
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
      const [statusResult, schemaResult] = await Promise.all([
        api.status().catch(() => ({ modules: [] as StatusItem[] })),
        api.schemaCheck().catch(() => null),
      ]);
      setItems(statusResult.modules);
      setSchema(schemaResult);
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

  return (
    <section className="status-page">
      <ResourcesPanel resources={resources} history={history} timeframe={timeframe} setTimeframe={setTimeframe} histLoading={histLoading} />

      <div className="card">
        <div className="status-header">
          <div>
            <h2>Module &amp; Tool Status</h2>
            <p className="muted">Health of connected tools and OpenSMART modules.</p>
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

      <StatusCard title="OpenSMART Modules" items={modules} checking={checking} />
      <StatusCard title="Tools" items={tools} checking={checking} />

      {dataInfo && <DataRetentionPanel info={dataInfo} />}
    </section>
  );
}

function StatusCard({ title, items, checking }: { title: string; items: StatusItem[]; checking: boolean }) {
  return <div className="card">
    <h2>{title}</h2>
    <p className="muted">{title === 'Tools' ? 'Integrated external services.' : 'OpenSMART platform modules.'}</p>
        <table className="status-table">
          <thead>
            <tr><th>Component</th><th>Status</th><th>Health</th><th>Details</th></tr>
          </thead>
          <tbody>
            {items.length === 0 && !checking
              ? <tr><td colSpan={4} className="muted" style={{ padding: '10px 12px' }}>No data — click Run Check.</td></tr>
              : items.map((item) => <StatusRow key={item.name} item={item} />)
            }
          </tbody>
        </table>
  </div>;
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

function StatusRow({ item }: { item: StatusItem }) {
  const health = statusBadge(item.status);
  return (
    <tr>
      <td className="status-table-name">{item.name}</td>
      <td><span className={`badge ${item.enabled ? 'ok-dim' : 'muted'}`}>{item.enabled ? 'Enabled' : 'Disabled'}</span></td>
      <td><span className={`badge ${health.cls}`}>{health.label}</span></td>
      <td className="muted status-table-detail">{item.detail}</td>
    </tr>
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

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
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
