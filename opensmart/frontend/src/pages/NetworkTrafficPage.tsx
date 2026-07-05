import { useEffect, useRef, useState } from 'react';
import { Activity, Database, Info } from 'lucide-react';
import { api } from '../api';
import TimeframeFilterBar from '../components/TimeframeFilterBar';
import { t } from '../i18n';
import { networkTrafficStore } from '../store/networkTrafficStore';
import type { NetworkTrafficConfig, NetworkTrafficRow, NetworkTrafficSummary, Settings } from '../types';

const detailTables: Record<string, string> = {
  all_events: 'All events',
  dns: 'DNS',
  http: 'HTTP / HTTP2',
  tls: 'TLS',
  flow: 'Flow / Netflow',
  fileinfo: 'File info',
  smb: 'SMB',
  ssh: 'SSH',
  smtp: 'SMTP',
  ftp: 'FTP',
  dhcp: 'DHCP',
  ntp: 'NTP',
  rdp: 'RDP',
  sip: 'SIP',
  mqtt: 'MQTT',
  krb5: 'Kerberos',
};

const protocolColors = ['#58d7ff', '#63e6be', '#ffc857', '#b99cff', '#ff8f5a', '#7CFC9A'];
const codeLikeFields = new Set(['domain', 'domain_source', 'dns_rrname', 'http_hostname', 'url', 'http_url', 'uri', 'command', 'query', 'rrname', 'hostname', 'user_agent', 'http_user_agent', 'filename', 'file_name', 'file_hash', 'file_md5', 'file_sha1', 'file_sha256', 'md5', 'sha1', 'sha256', 'sni', 'tls_sni', 'tls_sni_raw', 'subject', 'issuer', 'fingerprint', 'summary', 'answers']);

type Tab = 'summary' | 'details';
type DetailFilter = { table: string; field: string; value: string };

export default function NetworkTrafficPage({ settings }: { settings: Settings }) {
  const _init = networkTrafficStore.get();
  const [tab, setTab] = useState<Tab>(_init.tab as Tab);
  const [config, setConfig] = useState<NetworkTrafficConfig | null>(null);
  const [summary, setSummary] = useState<NetworkTrafficSummary | null>(null);
  const [summaryLoaded, setSummaryLoaded] = useState(false);
  const [summaryError, setSummaryError] = useState('');
  const [timeframe, setTimeframe] = useState(_init.timeframe);
  const [customStart, setCustomStart] = useState(_init.customStart);
  const [customEnd, setCustomEnd] = useState(_init.customEnd);
  const [q, setQ] = useState(_init.q);
  const [topN, setTopN] = useState(_init.topN);
  const [loading, setLoading] = useState(true);
  const [loadingAction, setLoadingAction] = useState('Loading Network Traffic summary');
  const [moduleBusy, setModuleBusy] = useState(false);
  const [detailsTable, setDetailsTable] = useState(_init.detailsTable === 'events' ? 'all_events' : _init.detailsTable);
  const [detailsRows, setDetailsRows] = useState<Record<string, unknown>[]>([]);
  const [detailsTotal, setDetailsTotal] = useState(0);
  const [detailsPage, setDetailsPage] = useState(0);
  const [detailsPageSize, setDetailsPageSize] = useState(100);
  const [detailsMaxRows, setDetailsMaxRows] = useState(1000);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailsLoaded, setDetailsLoaded] = useState(false);
  const [detailsFilter, setDetailsFilter] = useState<DetailFilter>({ table: detailsTable, field: '', value: '' });
  const summaryQueryIdRef = useRef('');
  const summaryAbortRef = useRef<AbortController | null>(null);
  const detailsQueryIdRef = useRef('');
  const detailsAbortRef = useRef<AbortController | null>(null);
  const moduleBusyRef = useRef(false);

  const filterStateRef = useRef({ tab, timeframe, customStart, customEnd, q, topN, detailsTable });
  filterStateRef.current = { tab, timeframe, customStart, customEnd, q, topN, detailsTable };
  const active = summary ?? config;
  const firstIngestionActive = Boolean(active?.first_ingestion_required || (active?.refresh_status === 'running' && !active?.last_updated));
  const firstIngestionReason = 'Queries will be allowed after first ingestion is complete.';

  useEffect(() => {
    return () => {
      summaryAbortRef.current?.abort();
      detailsAbortRef.current?.abort();
      if (summaryQueryIdRef.current) api.cancelNetworkTrafficSummary(summaryQueryIdRef.current).catch(() => undefined);
      if (detailsQueryIdRef.current) api.cancelNetworkTrafficDetails(detailsQueryIdRef.current).catch(() => undefined);
      networkTrafficStore.set(filterStateRef.current);
    };
  }, []);

  useEffect(() => {
    // Runs once on mount; loadSummary is recreated every render and would
    // otherwise trigger a refetch loop.
    setLoading(true);
    setLoadingAction('Loading Network Traffic summary');
    api.networkTrafficConfig().then((result) => setConfig(result.config)).catch(() => undefined);
    loadSummary(false, {}, true).catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if ((summary ?? config)?.refresh_status !== 'running') return;
    const id = window.setInterval(() => {
      api.networkTrafficConfig().then((result) => {
        setConfig(result.config);
        if (result.config.refresh_status !== 'running') loadSummary(false);
      }).catch(() => undefined);
    }, 2000);
    return () => window.clearInterval(id);
    // Deps intentionally narrowed to refresh_status fields, not the full
    // config/summary objects (which change every tick) — using the full
    // objects would tear down and recreate the interval every 2s.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [summary?.refresh_status, config?.refresh_status]);

  useEffect(() => {
    if (tab !== 'details' || !detailsTable || detailsLoaded || detailsLoading || moduleBusyRef.current || firstIngestionActive) return;
    runDetailsQuery({ table: detailsTable, field: '', value: '' }, detailsMaxRows).catch(() => undefined);
  }, [tab, detailsTable, detailsLoaded, detailsLoading, firstIngestionActive, detailsMaxRows, runDetailsQuery]);

  function params(extra: Record<string, string | number | boolean | undefined> = {}) {
    const result: Record<string, string | number | boolean | undefined> = { timeframe, q, top_n: topN, ...extra };
    if (timeframe === 'custom') {
      if (customStart) result.start_time = new Date(customStart).toISOString();
      if (customEnd) result.end_time = new Date(customEnd).toISOString();
    }
    return result;
  }

  async function loadSummary(refresh = false, overrides: Record<string, string | number | boolean | undefined> = {}, force = false) {
    if (moduleBusyRef.current && !force) return;
    if (force) {
      summaryAbortRef.current?.abort();
      summaryQueryIdRef.current = '';
      moduleBusyRef.current = false;
    }
    moduleBusyRef.current = true;
    setModuleBusy(true);
    summaryAbortRef.current?.abort();
    const controller = new AbortController();
    summaryAbortRef.current = controller;
    setLoading(true);
    setSummaryError('');
    setLoadingAction(refresh ? 'Requesting Network Traffic pull' : 'Loading Network Traffic summary');
    const queryId = `traffic-summary-${Date.now()}`;
    summaryQueryIdRef.current = queryId;
    try {
      const result = await api.networkTrafficSummary(params({ refresh, query_id: queryId, ...overrides }), { signal: controller.signal });
      setSummary(result);
      setSummaryLoaded(true);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) {
        setSummaryLoaded(true);
        setSummaryError(error instanceof Error ? error.message : 'Could not load Network Traffic summary.');
      }
    } finally {
      setLoading(false);
      setLoadingAction('Idle');
      summaryQueryIdRef.current = '';
      summaryAbortRef.current = null;
      moduleBusyRef.current = false;
      setModuleBusy(false);
    }
  }

  function cancelSummary() {
    const queryId = summaryQueryIdRef.current;
    summaryAbortRef.current?.abort();
    if (queryId) api.cancelNetworkTrafficSummary(queryId).catch(() => undefined);
    summaryQueryIdRef.current = '';
    summaryAbortRef.current = null;
    setLoading(false);
    setLoadingAction('Idle');
    moduleBusyRef.current = false;
    setModuleBusy(false);
  }

  function clearSearch() {
    setQ('');
    if (firstIngestionActive) return;
    loadSummary(false, { q: '' }).catch(() => undefined);
  }

  function openDetails(table: string, field = '', value = '') {
    if (firstIngestionActive) return;
    const next = { table, field, value };
    setDetailsTable(table);
    setDetailsFilter(next);
    setDetailsPage(0);
    setDetailsLoaded(false);
    setTab('details');
    runDetailsQuery(next, detailsMaxRows).catch(() => undefined);
  }

  async function runDetailsQuery(filter = detailsFilter, maxRows = detailsMaxRows) {
    if (firstIngestionActive) return;
    if (moduleBusyRef.current) return;
    moduleBusyRef.current = true;
    setModuleBusy(true);
    detailsAbortRef.current?.abort();
    const controller = new AbortController();
    const queryId = `traffic-details-${Date.now()}`;
    detailsAbortRef.current = controller;
    detailsQueryIdRef.current = queryId;
    setDetailsLoading(true);
    setLoadingAction('Loading Network Traffic details');
    try {
      const result = await api.networkTrafficDetails(params({ table: filter.table || detailsTable, field: filter.field, value: filter.value, limit: maxRows, query_id: queryId }) as Record<string, string | number | undefined>, { signal: controller.signal });
      setDetailsRows(result.rows);
      setDetailsTotal(result.total);
      setDetailsPage(0);
      setDetailsLoaded(true);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) throw error;
    } finally {
      setDetailsLoading(false);
      setLoadingAction('Idle');
      detailsQueryIdRef.current = '';
      detailsAbortRef.current = null;
      moduleBusyRef.current = false;
      setModuleBusy(false);
    }
  }

  function clearDetailsFilter() {
    const next = { table: detailsTable || 'all_events', field: '', value: '' };
    setDetailsTable(next.table);
    setDetailsFilter(next);
    setDetailsPage(0);
    setDetailsLoaded(false);
    runDetailsQuery(next, detailsMaxRows).catch(() => undefined);
  }

  function cancelDetails() {
    const queryId = detailsQueryIdRef.current;
    detailsAbortRef.current?.abort();
    if (queryId) api.cancelNetworkTrafficDetails(queryId).catch(() => undefined);
    setDetailsLoading(false);
    setLoadingAction('Idle');
    detailsQueryIdRef.current = '';
    detailsAbortRef.current = null;
    moduleBusyRef.current = false;
    setModuleBusy(false);
  }

  return (
    <section className="ids-page network-traffic-page">
      <div className="ids-tabs">
        <button className={tab === 'summary' ? 'active' : ''} onClick={() => setTab('summary')}><Activity size={17} /> {t(settings, 'traffic.summary', 'Summary')}</button>
        <button className={tab === 'details' ? 'active' : ''} onClick={() => setTab('details')}><Database size={17} /> {t(settings, 'traffic.details', 'Details')}</button>
      </div>
      <TimeframeFilterBar status={active} timeframe={timeframe} setTimeframe={setTimeframe} customStart={customStart} setCustomStart={setCustomStart} customEnd={customEnd} setCustomEnd={setCustomEnd} q={q} setQ={setQ} topN={topN} setTopN={setTopN} topNMax={100} busy={moduleBusy || (loading && !summaryLoaded)} queryRunning={moduleBusy} loadingAction={loadingAction} queryDisabled={firstIngestionActive} queryDisabledReason={firstIngestionReason} searchPlaceholder="IP, domain, URL, SNI, user agent" onRun={() => loadSummary(false)} onClear={clearSearch} onRefresh={() => loadSummary(true)} onCancel={detailsLoading ? cancelDetails : cancelSummary} />
      {firstIngestionActive && <FirstIngestionNotice status={active} />}
      {config && (!config.readable || config.log_source === 'zeek_json') && <div className="error-box">{config.detail || 'Configure a readable network log source.'} Current path: {config.eve_json_path || config.zeek_json_path || 'not configured'}</div>}
      {tab === 'summary' && <TrafficSummary summary={summary} loading={loading || !summaryLoaded} loaded={summaryLoaded} error={summaryError} onRetry={() => loadSummary(false, {}, true)} onDetails={openDetails} settings={settings} />}
      {tab === 'details' && detailsLoading && detailsRows.length === 0 && <LoadingPanel text={t(settings, 'traffic.loadingDetails', 'Loading Network Traffic details...')} />}
      {tab === 'details' && <TrafficDetails table={detailsTable} setTable={(table) => { setDetailsTable(table); setDetailsFilter({ table, field: '', value: '' }); setDetailsLoaded(false); }} rows={detailsRows} total={detailsTotal} loading={detailsLoading} queryDisabled={firstIngestionActive || moduleBusy} page={detailsPage} setPage={setDetailsPage} pageSize={detailsPageSize} setPageSize={setDetailsPageSize} maxRows={detailsMaxRows} setMaxRows={(value) => { setDetailsMaxRows(value); setDetailsLoaded(false); }} filter={detailsFilter} setFilter={setDetailsFilter} onRun={() => runDetailsQuery()} onCancel={cancelDetails} onClearFilter={clearDetailsFilter} />}
    </section>
  );
}

function LoadingPanel({ text }: { text: string }) {
  return <article className="card ids-loading-panel"><b className="tiny-loader" /> {text}</article>;
}

function TrafficSummary({ summary, loading, loaded, error, onRetry, onDetails, settings }: { summary: NetworkTrafficSummary | null; loading: boolean; loaded: boolean; error: string; onRetry: () => void; onDetails: (table: string, field?: string, value?: string) => void; settings: Settings }) {
  if (loading && !summary) return <LoadingPanel text={t(settings, 'traffic.loadingSummary', 'Loading Network Traffic summary...')} />;
  if (error && !summary) return <article className="card ids-loading-panel error"><strong>Could not load Network Traffic summary.</strong><span>{error}</span><button type="button" onClick={onRetry}>Retry</button></article>;
  if (!summary && loaded) return <div className="card">{t(settings, 'traffic.noData', 'No Network Traffic Monitoring data available.')}</div>;
  if (!summary) return <LoadingPanel text={t(settings, 'traffic.loadingSummary', 'Loading Network Traffic summary...')} />;
  const counters = summary.counters;
  const events = summary.tables.event_counts || summary.tables.protocols || [];
  return <div className="ids-summary">
    <div className="traffic-counter-row">
      <Counter label="Total Events" value={counters.total_events} highlight />
      <EventBadgePanel title="Events" rows={events} onDetails={onDetails} />
      <ProtocolBadges rows={summary.tables.protocols || []} onDetails={onDetails} />
      <Counter label="Source IPs" value={counters.sources} />
      <Counter label="Destination IPs" value={counters.destinations} />
    </div>
    <div className="ids-chart-row"><ProtocolTrend rows={summary.tables.trend || []} /><VolumeTrend rows={summary.tables.volume || []} /></div>
    <div className="ids-table-grid ids-table-grid-3"><TrafficTable title="Event Types" rows={events} field="event_type" onDetails={onDetails} /><TrafficTable title="Source IPs" rows={summary.tables.sources || []} field="src_ip" onDetails={onDetails} /><TrafficTable title="Destination IPs" rows={summary.tables.destinations || []} field="dest_ip" onDetails={onDetails} /></div>
    <div className="ids-table-grid ids-table-grid-3"><TrafficTable title="DNS / Domains" rows={summary.tables.domains || []} field="domain" onDetails={onDetails} /><TrafficTable title="HTTP URLs" rows={summary.tables.urls || []} field="url" onDetails={onDetails} /><TrafficTable title="User Agents" rows={summary.tables.user_agents || []} field="user_agent" onDetails={onDetails} /></div>
    <div className="ids-table-grid ids-table-grid-3"><TrafficTable title="Files / Hashes" rows={summary.tables.files || []} field="file_artifact" onDetails={onDetails} /><TalkersTable rows={summary.tables.top_talkers || []} onDetails={onDetails} /><TrafficTable title="TLS SNI" rows={summary.tables.tls_sni || []} field="tls_sni" onDetails={onDetails} /></div>
  </div>;
}

function FirstIngestionNotice({ status }: { status: NetworkTrafficSummary | NetworkTrafficConfig | null }) {
  return <div className="ids-info-panel first-ingestion-panel"><Info size={16} /><div><strong>First ingestion in progress</strong> <span className="first-ingest-size-badge">{initialIngestionLabel(status?.initial_ingestion_gb)}</span> This may take a moment depending on the size of your eve.json file. Queries will be allowed after ingestion is complete.<span className="ids-info-progress"> {status?.progress_percent || 0}% · {status?.last_check_network_read || 0} network events read · {status?.last_check_bytes_read || 0}/{status?.last_check_bytes_total || 0} bytes</span></div></div>;
}

function initialIngestionLabel(value: string | number | undefined) {
  const size = Number(value ?? 2);
  return size > 0 ? `Max Last ${Number.isInteger(size) ? size : size.toFixed(1)} GB` : 'Full file';
}

function Counter({ label, value, highlight = false }: { label: string; value?: number; highlight?: boolean }) {
  return <article className={`card ids-table-card compact ids-summary-counter ${highlight ? 'highlight' : ''}`}><h2>{label}</h2><strong>{Number(value || 0).toLocaleString()}</strong></article>;
}

function TableTitle({ title, onShowDetails }: { title: string; onShowDetails: () => void }) {
  return <div className="ids-table-title-row"><h2>{title}</h2><button className="ids-show-full-btn" type="button" onClick={onShowDetails}>Show Full List</button></div>;
}

function TrafficTable({ title, rows, field, onDetails }: { title: string; rows: NetworkTrafficRow[]; field: string; onDetails: (table: string, field?: string, value?: string) => void }) {
  return <article className="card ids-table-card compact"><TableTitle title={title} onShowDetails={() => onDetails('all_events')} /><div className="table-wrap"><table className="ids-summary-table"><thead><tr><th>#</th><th>Value</th><th>Events</th></tr></thead><tbody>{rows.map((row, index) => { const value = String(row[field] || ''); const filterField = String(row.field || field); return <tr key={`${value}-${index}`}><td>{index + 1}</td><td><button className="text-button" onClick={() => onDetails('all_events', filterField, value)}>{value || 'unknown'}</button></td><td>{Number(row.events || 0).toLocaleString()}</td></tr>; })}</tbody></table></div></article>;
}

function ProtocolBadges({ rows, onDetails }: { rows: NetworkTrafficRow[]; onDetails: (table: string, field?: string, value?: string) => void }) {
  return <article className="card ids-table-card compact traffic-events-panel"><h2>Protocols</h2><div className="traffic-badge-list compact">{rows.slice(0, 12).map((row, index) => { const value = String(row.protocol || 'unknown'); const field = String(row.field || 'app_proto'); return <button key={`${field}-${value}`} className={`traffic-count-badge tone-${index % 8}`} onClick={() => onDetails('all_events', field, value)}><span>{value}</span><strong>{Number(row.events || 0).toLocaleString()}</strong></button>; })}</div></article>;
}

function EventBadgePanel({ title, rows, onDetails }: { title: string; rows: NetworkTrafficRow[]; onDetails: (table: string, field?: string, value?: string) => void }) {
  return <article className="card ids-table-card compact traffic-events-panel"><h2>{title}</h2><div className="traffic-badge-list compact">{rows.slice(0, 12).map((row, index) => { const value = String(row.event_type || 'unknown'); return <button key={value} className={`traffic-count-badge tone-${index % 8}`} onClick={() => onDetails('all_events', 'event_type', value)}><span>{value}</span><strong>{Number(row.events || 0).toLocaleString()}</strong></button>; })}</div></article>;
}

function TalkersTable({ rows, onDetails }: { rows: NetworkTrafficRow[]; onDetails: (table: string, field?: string, value?: string) => void }) {
  return <article className="card ids-table-card compact"><TableTitle title="Top Talkers" onShowDetails={() => onDetails('all_events')} /><table className="ids-summary-table"><thead><tr><th>#</th><th>Source</th><th>Events</th><th>Bytes</th></tr></thead><tbody>{rows.map((row, index) => <tr key={`${row.src_ip}-${index}`}><td>{index + 1}</td><td><button className="text-button" onClick={() => onDetails('all_events', 'src_ip', String(row.src_ip || ''))}>{String(row.src_ip || '')}</button></td><td>{Number(row.events || 0).toLocaleString()}</td><td>{Number(row.bytes || 0).toLocaleString()}</td></tr>)}</tbody></table></article>;
}

function ProtocolTrend({ rows }: { rows: NetworkTrafficRow[] }) {
  const keys = [...new Set(rows.flatMap((row) => Object.keys(row).filter((key) => key !== 'bucket')))].slice(0, 6);
  const max = Math.max(1, ...rows.map((row) => keys.reduce((sum, key) => sum + Number(row[key] || 0), 0)));
  return <article className="card ids-table-card compact"><h2>Protocol events over time</h2><div className="traffic-legend">{keys.map((key, index) => <span key={key}><i style={{ background: protocolColors[index % protocolColors.length] }} />{key}</span>)}</div><div className="ids-severity-timechart traffic-timechart">{rows.map((row, index) => <div key={index} title={String(row.bucket)}>{keys.map((key, keyIndex) => <i key={key} style={{ height: `${(Number(row[key] || 0) / max) * 100}%`, background: protocolColors[keyIndex % protocolColors.length] }} />)}<small>{String(row.bucket).slice(-5)}</small></div>)}</div></article>;
}

function VolumeTrend({ rows }: { rows: NetworkTrafficRow[] }) {
  const W = 400, H = 180, left = 36, bottom = 22, top = 8;
  const chartW = W - left - 4, chartH = H - bottom - top;
  const max = Math.max(1, ...rows.flatMap((row) => [Number(row.inbound || 0), Number(row.outbound || 0)]));
  const toX = (i: number) => rows.length <= 1 ? left + chartW / 2 : left + (i / (rows.length - 1)) * chartW;
  const toY = (v: number) => top + (1 - v / max) * chartH;
  const path = (key: 'inbound' | 'outbound') => rows.map((row, i) => `${i === 0 ? 'M' : 'L'}${toX(i).toFixed(1)},${toY(Number(row[key] || 0)).toFixed(1)}`).join(' ');
  const area = (key: 'inbound' | 'outbound') => rows.length ? `${path(key)} L${toX(rows.length - 1).toFixed(1)},${toY(0).toFixed(1)} L${toX(0).toFixed(1)},${toY(0).toFixed(1)} Z` : '';
  return <article className="card ids-table-card compact"><h2>Traffic volume inbound / outbound</h2><div className="traffic-legend"><span><i style={{ background: '#63e6be' }} />Inbound</span><span><i style={{ background: '#58d7ff' }} />Outbound</span></div><svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="traffic-area-chart">{rows.length > 0 && <><path d={area('inbound')} fill="rgba(99,230,190,.22)" /><path d={area('outbound')} fill="rgba(88,215,255,.18)" /><path d={path('inbound')} fill="none" stroke="#63e6be" strokeWidth="1.8" /><path d={path('outbound')} fill="none" stroke="#58d7ff" strokeWidth="1.8" />{rows.map((row, i) => i % Math.max(1, Math.ceil(rows.length / 6)) === 0 ? <text key={i} x={toX(i)} y={H - 4} textAnchor="middle" fontSize="7" fill="#7890a8">{String(row.bucket).slice(-5)}</text> : null)}</>}</svg></article>;
}

function TrafficDetails({ table, setTable, rows, total, loading, queryDisabled, page, setPage, pageSize, setPageSize, maxRows, setMaxRows, filter, setFilter, onRun, onCancel, onClearFilter }: { table: string; setTable: (table: string) => void; rows: Record<string, unknown>[]; total: number; loading: boolean; queryDisabled: boolean; page: number; setPage: (page: number) => void; pageSize: number; setPageSize: (size: number) => void; maxRows: number; setMaxRows: (rows: number) => void; filter: DetailFilter; setFilter: (filter: DetailFilter) => void; onRun: () => void; onCancel: () => void; onClearFilter: () => void }) {
  const [searchText, setSearchText] = useState('');
  const clearFilters = () => { setSearchText(''); setPage(0); if (!queryDisabled) onClearFilter(); };
  const filteredRows = rows.filter((row) => !searchText || Object.values(row).some((value) => String(value ?? '').toLowerCase().includes(searchText.toLowerCase())));
  const pageCount = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = filteredRows.slice(safePage * pageSize, (safePage + 1) * pageSize);
  const columns = rows.length ? Object.keys(rows[0]) : [];
  if (queryDisabled || loading) {
    return <div className="ids-analysis ids-details"><article className="card ids-details-controls"><div className="ids-details-bar"><label>Table<select value={table} onChange={(event) => { setTable(event.target.value); setFilter({ table: event.target.value, field: '', value: '' }); }}><option value="">— select a table —</option>{Object.entries(detailTables).map(([key, label]) => <option value={key} key={key}>{label}</option>)}</select></label><label>Max rows<input type="number" min="1" max="10000" value={maxRows} onChange={(event) => setMaxRows(Number(event.target.value) || 1000)} /></label><label>Page size<input type="number" min="1" max="1000" value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value) || 100); setPage(0); }} /></label><label>Filter<input value={searchText} onChange={(event) => { setSearchText(event.target.value); setPage(0); }} placeholder="Filter all loaded fields" /></label><button className="ids-run-query" disabled>Run query</button><button className="ids-cancel-btn" disabled={!loading} onClick={onCancel}>Cancel query</button><button className="ids-clear-filter-btn" disabled>Clear filter</button>{queryDisabled && <span className="badge warning">Queries allowed after first ingestion</span>}{loading && <span className="badge warning"><b className="tiny-loader" /> Loading Network Traffic details</span>}</div></article></div>;
  }
  return <div className="ids-analysis ids-details"><article className="card ids-details-controls"><div className="ids-details-bar"><label>Table<select value={table} onChange={(event) => { setTable(event.target.value); setFilter({ table: event.target.value, field: '', value: '' }); }}><option value="">— select a table —</option>{Object.entries(detailTables).map(([key, label]) => <option value={key} key={key}>{label}</option>)}</select></label><label>Max rows<input type="number" min="1" max="10000" value={maxRows} onChange={(event) => setMaxRows(Number(event.target.value) || 1000)} /></label><label>Page size<input type="number" min="1" max="1000" value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value) || 100); setPage(0); }} /></label><label>Filter<input value={searchText} onChange={(event) => { setSearchText(event.target.value); setPage(0); }} placeholder="Filter all loaded fields" /></label><button className="ids-run-query" disabled={loading || !table} onClick={onRun}>Run query</button><button className="ids-cancel-btn" disabled={!loading} onClick={onCancel}>Cancel query</button><button className="ids-clear-filter-btn" disabled={loading || (!filter.value && !searchText)} onClick={clearFilters}>Clear filter</button>{loading && <span className="badge warning"><b className="tiny-loader" /> Loading...</span>}</div></article>{!loading && filter.value && <DetailsQueryStatus total={total} filter={filter} />}{table && !loading && rows.length === 0 && <div className="card"><p className="muted">No data for this table.</p></div>}{rows.length > 0 && <article className="card ids-alert-card"><div className="ids-details-pagination"><button disabled={safePage === 0} onClick={() => setPage(Math.max(0, safePage - 1))}>Previous</button><span>{safePage + 1} / {pageCount}</span><button disabled={safePage + 1 >= pageCount} onClick={() => setPage(safePage + 1)}>Next</button><span className="muted">Showing {pageRows.length} of {filteredRows.length} filtered rows ({rows.length} loaded)</span></div><div className="ids-alert-scroll" role="region" aria-label="Network traffic details table"><table className="ids-alert-table traffic-details-table"><thead><tr><th>#</th>{columns.map((column) => <th key={column} className={detailColumnClass(column)}>{column}</th>)}</tr></thead><tbody>{pageRows.map((row, index) => <tr key={index}><td>{safePage * pageSize + index + 1}</td>{columns.map((column) => <td key={column} className={detailColumnClass(column)}>{renderDetailValue(column, row[column])}</td>)}</tr>)}</tbody></table></div></article>}</div>;
}

function DetailsQueryStatus({ total, filter }: { total: number; filter: DetailFilter }) {
  return <article className="card details-query-card"><span className="details-query-status"><span className="details-query-badge count">{total.toLocaleString()} rows loaded</span><span>contains</span><span className="details-query-badge field">{filter.field}</span><span className="details-query-badge term">{filter.value}</span></span></article>;
}

function detailColumnClass(column: string) {
  const longFields = new Set(['domain', 'domain_source', 'dns_rrname', 'http_hostname', 'tls_sni', 'tls_sni_raw', 'url', 'http_url', 'user_agent', 'http_user_agent', 'file_name', 'filename', 'file_hash', 'file_md5', 'file_sha1', 'file_sha256', 'summary', 'event_json', 'answers']);
  return [longFields.has(column) ? 'payload-printable-col' : '', codeLikeFields.has(column) ? 'artifact-value-col' : '', ['src_ip', 'dest_ip'].includes(column) ? 'ip-address-col' : '', column === 'event_type' ? 'event-type-col' : ''].filter(Boolean).join(' ') || undefined;
}

function eventTone(value: unknown) {
  const text = String(value || 'unknown');
  let hash = 0;
  for (let i = 0; i < text.length; i += 1) hash = (hash + text.charCodeAt(i)) % 8;
  return hash;
}

function renderDetailValue(column: string, value: unknown) {
  if (column === 'event_type') return <span className={`event-type-badge tone-${eventTone(value)}`}>{String(value || 'unknown')}</span>;
  if (value && typeof value === 'object') return JSON.stringify(value);
  return String(value ?? '');
}
