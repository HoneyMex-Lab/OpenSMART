import { useEffect, useRef, useState } from 'react';
import { Activity, Database, Info, List, Map, ShieldAlert } from 'lucide-react';
import { api } from '../api';
import TimeframeFilterBar from '../components/TimeframeFilterBar';
import { idsStore } from '../store/idsStore';
import type { NetworkIdsAlert, NetworkIdsAttackMap, NetworkIdsConfig, NetworkIdsSummary, NetworkIdsSummaryRow } from '../types';

const alertFields = ['timestamp', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'severity', 'category', 'signature', 'signature_id', 'signature_source', 'confidence', 'payload_printable', 'payload', 'gid', 'action', 'metadata', 'flow_id', 'app_proto', 'in_iface', 'host', 'community_id', 'tx_id', 'packet_info_linktype'];
const visibleAlertColumns = [
  { key: 'timestamp', label: 'timestamp' },
  { key: 'src_ip', label: 'src_ip' },
  { key: 'src_port', label: 'src_port' },
  { key: 'dest_ip', label: 'dest_ip' },
  { key: 'dest_port', label: 'dest_port' },
  { key: 'proto', label: 'proto' },
  { key: 'severity', label: 'severity' },
  { key: 'category', label: 'category' },
  { key: 'signature', label: 'signature' },
  { key: 'payload_printable', label: 'payload_printable', className: 'payload-printable-col' },
  { key: 'payload', label: 'payload', className: 'payload-col' },
];

const DETAIL_TABLE_LABELS: Record<string, string> = {
  top_categories: 'Top categories',
  top_protocols: 'Top protocols',
  top_ports: 'Top ports',
  top_src_ips: 'Top source IPs',
  top_dest_ips: 'Top destination IPs',
  interfaces: 'Sensors/interfaces',
  flow_direction: 'Flow direction',
  mitre: 'MITRE ATT&CK',
  top_artifacts: 'Top Artifacts',
  cves: 'CVE references',
  top_by_count: 'Top alerts by count',
  top_by_severity: 'Top alerts by severity',
};

// Columns that are numeric/counter — clicking them should NOT navigate to alert analysis
const NUMERIC_COLS = new Set(['alerts', 'count']);

// For each table, which columns are text-based (filterable) vs numeric
const TABLE_TEXT_COLS: Record<string, string[]> = {
  top_categories:  ['category'],
  top_protocols:   ['proto'],
  top_ports:       ['port'],
  top_src_ips:     ['src_ip'],
  top_dest_ips:    ['dest_ip'],
  interfaces:      ['in_iface'],
  flow_direction:  ['flow_direction'],
  mitre:           ['mitre'],
  cves:            ['cve'],
  top_artifacts:   ['artifact_type', 'artifact_value'],
  top_by_count:    ['category', 'severity', 'confidence', 'signature_id', 'proto', 'signature'],
  top_by_severity: ['category', 'severity', 'confidence', 'signature_id', 'proto', 'signature'],
};

// Maps Details table column → Alert Analysis filter field name
const DETAIL_COL_TO_FILTER: Record<string, string> = {
  category: 'category', proto: 'proto', port: 'dest_port', src_ip: 'src_ip', dest_ip: 'dest_ip',
  in_iface: 'in_iface', flow_direction: 'flow_direction', mitre: 'mitre', cve: 'cve',
  artifact_value: 'artifact_value', artifact_type: 'artifact_type',
  signature: 'signature', signature_id: 'signature_id', severity: 'severity', confidence: 'confidence',
};

type Tab = 'summary' | 'analysis' | 'details' | 'attack-map' | 'actions';
type AttackMapMode = 'src_ip' | 'signature' | 'severity';

export default function NetworkIdsPage() {
  const _init = idsStore.get();
  const [tab, setTab] = useState<Tab>(_init.tab as Tab);
  const [timeframe, setTimeframe] = useState(_init.timeframe);
  const [customStart, setCustomStart] = useState(_init.customStart);
  const [customEnd, setCustomEnd] = useState(_init.customEnd);
  const [q, setQ] = useState(_init.q);
  const [topN, setTopN] = useState(_init.topN);
  const [pageSize, setPageSize] = useState(30);
  const [page, setPage] = useState(0);
  const [summary, setSummary] = useState<NetworkIdsSummary | null>(null);
  const [alerts, setAlerts] = useState<NetworkIdsAlert[]>([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [config, setConfig] = useState<NetworkIdsConfig | null>(null);
  const [filters, setFilters] = useState<Record<string, string>>(_init.filters);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [moduleBusy, setModuleBusy] = useState(false);
  const [alertQueryDirty, setAlertQueryDirty] = useState(false);
  const [showOnlyNewAlerts, setShowOnlyNewAlerts] = useState(false);
  const [loadingAction, setLoadingAction] = useState('Idle');
  const [sort, setSort] = useState('timestamp');
  const [direction, setDirection] = useState<'asc' | 'desc'>('desc');
  // Details tab state
  const [detailsTable, setDetailsTable] = useState('');
  const [detailsRows, setDetailsRows] = useState<Record<string, unknown>[]>([]);
  const [detailsTotal, setDetailsTotal] = useState(0);
  const [detailsPage, setDetailsPage] = useState(0);
  const [detailsPageSize, setDetailsPageSize] = useState(100);
  const [detailsMaxRows, setDetailsMaxRows] = useState(2000);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [attackMap, setAttackMap] = useState<NetworkIdsAttackMap | null>(null);
  const [attackMapMode, setAttackMapMode] = useState<AttackMapMode>('src_ip');
  const [attackMapLoading, setAttackMapLoading] = useState(false);

  const alertRequestRef = useRef(0);
  const summaryRequestRef = useRef(0);
  const summaryAbortRef = useRef<AbortController | null>(null);
  const summaryQueryIdRef = useRef('');
  const alertAbortRef = useRef<AbortController | null>(null);
  const alertQueryIdRef = useRef('');
  const autoRunAlertsRef = useRef(false);
  const detailsRequestRef = useRef(0);
  const detailsAbortRef = useRef<AbortController | null>(null);
  const detailsQueryIdRef = useRef('');
  const attackMapAbortRef = useRef<AbortController | null>(null);
  const attackMapQueryIdRef = useRef('');
  const moduleBusyRef = useRef(false);

  // Keep a ref to current filter state so the cleanup effect can save it without stale closures
  const filterStateRef = useRef({ tab, timeframe, customStart, customEnd, q, topN, filters });
  filterStateRef.current = { tab, timeframe, customStart, customEnd, q, topN, filters };

  useEffect(() => {
    return () => {
      summaryAbortRef.current?.abort();
      alertAbortRef.current?.abort();
      detailsAbortRef.current?.abort();
      attackMapAbortRef.current?.abort();
      if (summaryQueryIdRef.current) api.cancelNetworkIdsSummary(summaryQueryIdRef.current).catch(() => undefined);
      if (alertQueryIdRef.current) api.cancelNetworkIdsAlerts(alertQueryIdRef.current).catch(() => undefined);
      if (detailsQueryIdRef.current) api.cancelNetworkIdsDetails(detailsQueryIdRef.current).catch(() => undefined);
      if (attackMapQueryIdRef.current) api.cancelNetworkIdsDetails(attackMapQueryIdRef.current).catch(() => undefined);
      idsStore.set(filterStateRef.current);
    };
  }, []);

  useEffect(() => {
    api.networkIdsConfig().then((result) => {
      setConfig(result.config);
      setTopN(result.config.default_top_n || 10);
      setPageSize(result.config.analysis_page_size || 30);
      setDetailsPageSize(result.config.details_page_size || 100);
      setDetailsMaxRows(result.config.details_max_rows || 500);
      setSummaryLoading(true);
      api.networkIdsSummary(queryParams(result.config.default_top_n || 10))
        .then(setSummary)
        .finally(() => setSummaryLoading(false));
    }).catch(() => undefined);
  }, []);
  // Timeframe, search, and Top N changes are staged; Run button applies them.
  useEffect(() => {
    if (tab === 'analysis' && autoRunAlertsRef.current) {
      autoRunAlertsRef.current = false;
      loadAlerts();
    }
  }, [tab, filters]);

  // Poll ingestion status while a refresh is running so the UI advances past
  // the in-loop 99% cap and shows "Rebuilding artifact index" → "Idle" without
  // requiring a user-triggered Refresh.
  useEffect(() => {
    if ((summary ?? config)?.refresh_status !== 'running') return;
    let cancelled = false;
    const tick = async () => {
      try {
        const state = await api.networkIdsStatus();
        if (cancelled) return;
        setConfig((prev) => prev ? { ...prev, ...state } : prev);
        setSummary((prev) => prev ? { ...prev, ...state } : prev);
        if (state.refresh_status !== 'running') {
          // Ingestion finished — refresh full summary so newly-ingested rows appear.
          loadSummary(false);
        }
      } catch { /* ignore — next tick will retry */ }
    };
    const id = window.setInterval(tick, 2000);
    return () => { cancelled = true; window.clearInterval(id); };
  }, [summary?.refresh_status, config?.refresh_status]);

  async function loadSummary(refresh = false, overrides: Record<string, string | number> = {}) {
    if (moduleBusyRef.current) return;
    moduleBusyRef.current = true;
    setModuleBusy(true);
    summaryAbortRef.current?.abort();
    const requestId = summaryRequestRef.current + 1;
    const queryId = `summary-${Date.now()}-${requestId}`;
    const controller = new AbortController();
    summaryRequestRef.current = requestId;
    summaryQueryIdRef.current = queryId;
    summaryAbortRef.current = controller;
    setSummaryLoading(true);
    setLoadingAction(refresh ? 'Requesting 5 min delta refresh' : 'Loading selected timeframe');
    try {
      const result = await api.networkIdsSummary({ ...queryParams(topN, overrides), refresh, query_id: queryId }, { signal: controller.signal });
      if (summaryRequestRef.current === requestId) setSummary(result);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) throw error;
    } finally {
      if (summaryRequestRef.current === requestId) {
        setSummaryLoading(false);
        setLoadingAction('Idle');
        summaryAbortRef.current = null;
        summaryQueryIdRef.current = '';
        moduleBusyRef.current = false;
        setModuleBusy(false);
      }
    }
  }

  function cancelSummaryLoad() {
    const queryId = summaryQueryIdRef.current;
    summaryAbortRef.current?.abort();
    if (queryId) api.cancelNetworkIdsSummary(queryId).catch(() => undefined);
    summaryRequestRef.current += 1;
    summaryAbortRef.current = null;
    summaryQueryIdRef.current = '';
    setSummaryLoading(false);
    setLoadingAction('Idle');
    moduleBusyRef.current = false;
    setModuleBusy(false);
  }

  async function loadAlerts(pageOverride = page, pageSizeOverride = pageSize, overrides: Record<string, string | number> = {}) {
    if (firstIngestionActive) return;
    if (moduleBusyRef.current) return;
    moduleBusyRef.current = true;
    setModuleBusy(true);
    alertAbortRef.current?.abort();
    const requestId = alertRequestRef.current + 1;
    const queryId = `alerts-${Date.now()}-${requestId}`;
    const controller = new AbortController();
    alertRequestRef.current = requestId;
    alertQueryIdRef.current = queryId;
    alertAbortRef.current = controller;
    setAlerts([]);
    setTotalAlerts(0);
    setAlertsLoading(true);
    setAlertQueryDirty(false);
    setLoadingAction('Loading alert analysis');
    try {
      const trackingFilter = overrides.tracking_status !== undefined ? { tracking_status: overrides.tracking_status } : (showOnlyNewAlerts ? { tracking_status: 'new' } : {});
      const result = await api.networkIdsAlerts({ ...queryParams(undefined, overrides), limit: pageSizeOverride, offset: pageOverride * pageSizeOverride, sort, direction, query_id: queryId, ...trackingFilter, ...filters }, { signal: controller.signal });
      if (alertRequestRef.current === requestId) {
        setAlerts(result.alerts);
        setTotalAlerts(result.total);
      }
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) throw error;
    } finally {
      if (alertRequestRef.current === requestId) {
        setAlertsLoading(false);
        setLoadingAction('Idle');
        alertAbortRef.current = null;
        alertQueryIdRef.current = '';
        moduleBusyRef.current = false;
        setModuleBusy(false);
      }
    }
  }

  function cancelAlertLoad() {
    const queryId = alertQueryIdRef.current;
    alertAbortRef.current?.abort();
    if (queryId) api.cancelNetworkIdsAlerts(queryId).catch(() => undefined);
    alertRequestRef.current += 1;
    alertAbortRef.current = null;
    alertQueryIdRef.current = '';
    setAlertsLoading(false);
    setLoadingAction('Idle');
    moduleBusyRef.current = false;
    setModuleBusy(false);
  }

  function openAnalysis() {
    autoRunAlertsRef.current = false;
    setFilters({});
    setAlerts([]);
    setTotalAlerts(0);
    setAlertQueryDirty(false);
    setPage(0);
    setSort('timestamp');
    setDirection('desc');
    setTab('analysis');
  }

  function applyFilter(field: string, value: string | number) {
    if (firstIngestionActive) return;
    autoRunAlertsRef.current = true;
    if (field === 'severity' && ['1', 'critical'].includes(String(value).toLowerCase()) && config?.track_critical_alerts === 'simple') {
      api.acknowledgeNetworkIdsCritical(queryParams())
        .then(() => setSummary((prev) => prev ? { ...prev, critical_new_alerts: 0 } : prev))
        .catch(() => undefined);
    }
    if (field === 'artifact_value') {
      setQ(String(value));
      setFilters({});
    } else {
      setFilters({ [field]: String(value) });
    }
    setAlerts([]);
    setTotalAlerts(0);
    setAlertQueryDirty(false);
    setPage(0);
    setSort('timestamp');
    setDirection('desc');
    setTab('analysis');
  }

  async function acknowledgeAlert(alertId: number) {
    const acknowledged = alerts.find((a) => Number(a.alert_id) === alertId);
    const wasCritical = acknowledged?.severity === '1';
    const wasNew = String(acknowledged?.tracking_status || '') === 'new';
    await api.acknowledgeNetworkIdsAlert(alertId);
    setAlerts((current) => current.map((alert) => Number(alert.alert_id) === alertId ? { ...alert, tracking_status: 'acknowledged' } : alert));
    if (wasCritical && wasNew) {
      const remaining = Math.max(0, (summary?.critical_new_alerts || 0) - 1);
      setSummary((prev) => prev && (prev.critical_new_alerts || 0) > 0
        ? { ...prev, critical_new_alerts: (prev.critical_new_alerts || 1) - 1 }
        : prev);
      if (remaining === 0) setShowOnlyNewAlerts(false);
      if (showOnlyNewAlerts) loadAlerts(page, pageSize, remaining === 0 ? { tracking_status: '' } : {}).catch(() => undefined);
    }
  }

  function filterNewAlerts() {
    if (firstIngestionActive) return;
    setShowOnlyNewAlerts(true);
    setPage(0);
    loadAlerts(0, pageSize, { tracking_status: 'new' }).catch(() => undefined);
  }

  function updateSort(field: string) {
    if (sort === field) setDirection(direction === 'asc' ? 'desc' : 'asc');
    else { setSort(field); setDirection('asc'); }
    setAlertQueryDirty(true);
  }

  async function openDetails(tableName: string) {
    if (firstIngestionActive) return;
    setDetailsTable(tableName);
    setDetailsPage(0);
    setDetailsRows([]);
    setDetailsTotal(0);
    setTab('details');
    await runDetailsQuery(tableName, detailsMaxRows);
  }

  async function reloadDetails(tableName: string, maxRows: number) {
    if (firstIngestionActive) return;
    if (!tableName) return;
    setDetailsPage(0);
    setDetailsRows([]);
    setDetailsTotal(0);
    await runDetailsQuery(tableName, maxRows);
  }

  async function runDetailsQuery(tableName: string, maxRows: number) {
    if (firstIngestionActive) return;
    if (moduleBusyRef.current) return;
    moduleBusyRef.current = true;
    setModuleBusy(true);
    detailsAbortRef.current?.abort();
    const requestId = detailsRequestRef.current + 1;
    const queryId = `details-${Date.now()}-${requestId}`;
    const controller = new AbortController();
    detailsRequestRef.current = requestId;
    detailsQueryIdRef.current = queryId;
    detailsAbortRef.current = controller;
    setDetailsLoading(true);
    try {
      const result = await api.networkIdsDetails(
        { table: tableName, ...queryParams(), top_n: maxRows, query_id: queryId },
        { signal: controller.signal },
      );
      if (detailsRequestRef.current !== requestId) return;
      setDetailsRows(result.rows);
      setDetailsTotal(result.total);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) throw error;
    } finally {
      if (detailsRequestRef.current === requestId) {
        setDetailsLoading(false);
        detailsAbortRef.current = null;
        detailsQueryIdRef.current = '';
        moduleBusyRef.current = false;
        setModuleBusy(false);
      }
    }
  }

  async function loadAttackMap(mode = attackMapMode) {
    if (firstIngestionActive || moduleBusyRef.current) return;
    moduleBusyRef.current = true;
    setModuleBusy(true);
    attackMapAbortRef.current?.abort();
    const queryId = `attack-map-${Date.now()}`;
    const controller = new AbortController();
    attackMapQueryIdRef.current = queryId;
    attackMapAbortRef.current = controller;
    setAttackMapLoading(true);
    setLoadingAction('Loading attack map');
    try {
      const result = await api.networkIdsAttackMap({ ...queryParams(topN), mode, query_id: queryId }, { signal: controller.signal });
      setAttackMap(result);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) throw error;
    } finally {
      setAttackMapLoading(false);
      setLoadingAction('Idle');
      attackMapQueryIdRef.current = '';
      attackMapAbortRef.current = null;
      moduleBusyRef.current = false;
      setModuleBusy(false);
    }
  }

  function queryParams(topNOverride?: number, overrides: Record<string, string | number> = {}) {
    const params: Record<string, string | number> = { timeframe, q, ...overrides };
    if (topNOverride !== undefined) params.top_n = topNOverride;
    if (timeframe === 'custom') {
      if (customStart) params.start_time = new Date(customStart).toISOString();
      if (customEnd) params.end_time = new Date(customEnd).toISOString();
    }
    return params;
  }

  function clearSearch() {
    setQ('');
    if (firstIngestionActive) return;
    setPage(0);
    setAlertQueryDirty(false);
    if (tab === 'analysis') loadAlerts(0, pageSize, { q: '' }).catch(() => undefined);
    else if (tab === 'attack-map') loadAttackMap().catch(() => undefined);
    else loadSummary(false, { q: '' }).catch(() => undefined);
  }

  function cancelDetailsLoad() {
    const queryId = detailsQueryIdRef.current;
    detailsAbortRef.current?.abort();
    if (queryId) api.cancelNetworkIdsDetails(queryId).catch(() => undefined);
    detailsRequestRef.current += 1;
    detailsAbortRef.current = null;
    detailsQueryIdRef.current = '';
    setDetailsLoading(false);
    moduleBusyRef.current = false;
    setModuleBusy(false);
  }

  function cancelAttackMapLoad() {
    const queryId = attackMapQueryIdRef.current;
    attackMapAbortRef.current?.abort();
    if (queryId) api.cancelNetworkIdsDetails(queryId).catch(() => undefined);
    attackMapQueryIdRef.current = '';
    attackMapAbortRef.current = null;
    setAttackMapLoading(false);
    moduleBusyRef.current = false;
    setModuleBusy(false);
  }

  const active = summary ?? config;
  const firstIngestionActive = Boolean(active?.first_ingestion_required || (active?.refresh_status === 'running' && !active?.last_updated));
  const firstIngestionReason = 'Queries will be allowed after first ingestion is complete.';

  return (
    <section className="ids-page">
      <div className="ids-tabs">
        <button className={tab === 'summary' ? 'active' : ''} onClick={() => setTab('summary')}><Activity size={17} /> Summary</button>
        <button className={tab === 'analysis' ? 'active' : ''} onClick={openAnalysis}><Database size={17} /> Alert Analysis</button>
        <button className={tab === 'details' ? 'active' : ''} onClick={() => setTab('details')}><List size={17} /> Details</button>
        <button className={tab === 'attack-map' ? 'active' : ''} onClick={() => { setTab('attack-map'); if (!attackMap && !moduleBusyRef.current) loadAttackMap().catch(() => undefined); }}><Map size={17} /> Attack Map</button>
        <button className={`actions-tab ${tab === 'actions' ? 'active' : ''}`} onClick={() => setTab('actions')}><ShieldAlert size={17} /> Actions</button>
      </div>

      <TimeframeFilterBar status={active} timeframe={timeframe} setTimeframe={(value) => { setTimeframe(value); if (tab === 'analysis') setAlertQueryDirty(true); }} customStart={customStart} setCustomStart={(value) => { setCustomStart(value); if (tab === 'analysis') setAlertQueryDirty(true); }} customEnd={customEnd} setCustomEnd={(value) => { setCustomEnd(value); if (tab === 'analysis') setAlertQueryDirty(true); }} q={q} setQ={(value) => { setQ(value); if (tab === 'analysis') setAlertQueryDirty(true); }} topN={topN} setTopN={setTopN} topNMax={500} busy={moduleBusy} queryRunning={moduleBusy} loadingAction={loadingAction} queryDisabled={firstIngestionActive} queryDisabledReason={firstIngestionReason} searchPlaceholder="Search visible alert data" onRun={() => tab === 'analysis' ? loadAlerts() : tab === 'attack-map' ? loadAttackMap() : loadSummary(false)} onClear={clearSearch} onRefresh={() => tab === 'attack-map' ? loadAttackMap() : loadSummary(true)} onCancel={attackMapLoading ? cancelAttackMapLoad : detailsLoading ? cancelDetailsLoad : alertsLoading ? cancelAlertLoad : cancelSummaryLoad} />
      {firstIngestionActive && <FirstIngestionNotice status={active} />}
      {config && !config.readable && <div className="error-box">{config.detail} Current path: {config.eve_json_path || 'not configured'}</div>}

      {tab === 'summary' && <SummaryTab summary={summary} onFilter={applyFilter} onShowDetails={openDetails} busy={summaryLoading} />}
      {tab === 'analysis' && <AnalysisTab alerts={alerts} total={totalAlerts} filters={filters} setFilters={(next) => { setFilters(next); setPage(0); setAlertQueryDirty(true); }} sort={sort} direction={direction} updateSort={updateSort} alertsLoading={alertsLoading} queryDirty={alertQueryDirty} onRunQuery={() => loadAlerts()} onCancelLoad={cancelAlertLoad} page={page} setPage={(value) => { setPage(value); setAlertQueryDirty(false); loadAlerts(value); }} pageSize={pageSize} setPageSize={(value) => { setPageSize(value); setPage(0); setAlertQueryDirty(false); loadAlerts(0, value); }} trackingMode={config?.track_critical_alerts || 'off'} newCriticalCount={summary?.critical_new_alerts || 0} onShowNewAlerts={filterNewAlerts} onAckAlert={acknowledgeAlert} />}
      {tab === 'details' && <DetailsTab detailsTable={detailsTable} setDetailsTable={(name) => { setDetailsTable(name); if (!firstIngestionActive && !moduleBusy && name) reloadDetails(name, detailsMaxRows); else { setDetailsRows([]); setDetailsTotal(0); } }} detailsRows={detailsRows} detailsTotal={detailsTotal} detailsPage={detailsPage} setDetailsPage={setDetailsPage} detailsPageSize={detailsPageSize} setDetailsPageSize={setDetailsPageSize} detailsMaxRows={detailsMaxRows} setDetailsMaxRows={(n) => { setDetailsMaxRows(n); if (!firstIngestionActive && !moduleBusy && detailsTable) reloadDetails(detailsTable, n); }} detailsLoading={detailsLoading} queryDisabled={firstIngestionActive || moduleBusy} onFilter={applyFilter} onCancelLoad={cancelDetailsLoad} />}
      {tab === 'attack-map' && <AttackMapTab data={attackMap} mode={attackMapMode} setMode={(mode) => { setAttackMapMode(mode); loadAttackMap(mode).catch(() => undefined); }} loading={attackMapLoading} disabled={firstIngestionActive || moduleBusy} onReload={() => loadAttackMap()} />}
      {tab === 'actions' && <section className="card hero-card"><p className="eyebrow">Future workflow</p><h2>Network IDS Actions</h2><p className="muted">Placeholder for export, suppressions, enrichment, escalation, and firewall response workflows.</p></section>}
    </section>
  );
}

function SummaryTab({ summary, onFilter, onShowDetails, busy }: { summary: NetworkIdsSummary | null; onFilter: (field: string, value: string | number) => void; onShowDetails: (table: string) => void; busy: boolean }) {
  if (busy && !summary) return <div className="card">Loading IDS summary...</div>;
  if (!summary) return <div className="card">No IDS summary data available.</div>;
  const severity = summary.counters.severity;
  return (
    <div className="ids-summary">
      <div className="ids-counter-grid ids-counter-grid-wide">
        <CounterCard label="Total alerts" value={summary.counters.total_alerts} highlight />
        <SeverityCounterStrip severity={severity} newCriticalCount={summary.critical_new_alerts || 0} onFilter={onFilter} />
        <CounterCard label="Categories" value={summary.counters.total_categories} />
        <CounterCard label="Signature sources" value={summary.counters.total_signature_sources} />
      </div>

      <div className="ids-chart-row">
        <TrendTable rows={summary.tables.trend || []} title="Alerts over time" />
        <SeverityTrendTable rows={summary.tables.trend_by_severity || []} />
      </div>

      <article className="card ids-compact-card"><h2>Severity Distribution</h2><div className="ids-chart-bars">{Object.entries(severity).map(([key, value]) => <button key={key} onClick={() => onFilter('severity', key)}><span>{severityLabel(key)}</span><i className={severityClass(key)} style={{ width: `${Math.max(5, (value / Math.max(...Object.values(severity), 1)) * 100)}%` }} /><strong>{value}</strong></button>)}</div></article>

      {/* Row 1: 3 columns */}
      <div className="ids-table-grid ids-table-grid-3">
        <SmallTable title="Top categories" rows={summary.tables.top_categories || []} field="category" onFilter={onFilter} onShowDetails={() => onShowDetails('top_categories')} />
        <SmallTable title="Top protocols" rows={summary.tables.top_protocols || []} field="proto" onFilter={onFilter} onShowDetails={() => onShowDetails('top_protocols')} />
        <SmallTable title="Top ports" rows={summary.tables.top_ports || []} field="port" onFilter={onFilter} onShowDetails={() => onShowDetails('top_ports')} />
      </div>

      {/* Row 2: 4 columns */}
      <div className="ids-table-grid ids-table-grid-4">
        <SmallTable title="Top source IPs" rows={summary.tables.top_src_ips || []} field="src_ip" onFilter={onFilter} onShowDetails={() => onShowDetails('top_src_ips')} />
        <SmallTable title="Top destination IPs" rows={summary.tables.top_dest_ips || []} field="dest_ip" onFilter={onFilter} onShowDetails={() => onShowDetails('top_dest_ips')} />
        <SmallTable title="Sensors/interfaces" rows={summary.tables.interfaces || []} field="in_iface" onFilter={onFilter} onShowDetails={() => onShowDetails('interfaces')} />
        <SmallTable title="Flow direction" rows={summary.tables.flow_direction || []} field="flow_direction" onFilter={onFilter} onShowDetails={() => onShowDetails('flow_direction')} />
      </div>

      {/* Row 3: 3 columns */}
      <div className="ids-table-grid ids-table-grid-3">
        <SmallTable title="MITRE ATT&CK" rows={summary.tables.mitre || []} field="mitre" onFilter={onFilter} onShowDetails={() => onShowDetails('mitre')} />
        <ArtifactTable rows={summary.tables.top_artifacts || []} onFilter={onFilter} onShowDetails={() => onShowDetails('top_artifacts')} />
        <SmallTable title="CVE references" rows={summary.tables.cves || []} field="cve" onFilter={onFilter} onShowDetails={() => onShowDetails('cves')} />
      </div>

      {/* Row 4: 2 columns */}
      <div className="ids-major-table-grid">
        <SummaryTable title="Top alerts by count" rows={summary.tables.top_by_count || []} onFilter={onFilter} filterField="signature" onShowDetails={() => onShowDetails('top_by_count')} />
        <SummaryTable title="Top alerts by severity" rows={summary.tables.top_by_severity || []} onFilter={onFilter} filterField="signature" onShowDetails={() => onShowDetails('top_by_severity')} />
      </div>
    </div>
  );
}

function AttackMapTab({ data, mode, setMode, loading, disabled, onReload }: { data: NetworkIdsAttackMap | null; mode: AttackMapMode; setMode: (mode: AttackMapMode) => void; loading: boolean; disabled: boolean; onReload: () => void }) {
  return (
    <div className="ids-attack-map">
      <article className="card attack-map-controls">
        <div>
          <h2>Attack Map</h2>
          <p className="muted">Map IDS alert source IPs with optional MaxMind GeoLite2 City geolocation.</p>
        </div>
        <div className="attack-map-mode-row">
          <button className={mode === 'src_ip' ? 'active' : ''} disabled={disabled} onClick={() => setMode('src_ip')}>SRC IPs of the attacks</button>
          <button className={mode === 'signature' ? 'active' : ''} disabled={disabled} onClick={() => setMode('signature')}>Signature</button>
          <button className={mode === 'severity' ? 'active' : ''} disabled={disabled} onClick={() => setMode('severity')}>SRC of severity</button>
          <button disabled={disabled} onClick={onReload}>{loading ? 'Loading...' : 'Reload map'}</button>
        </div>
      </article>
      {loading && !data && <article className="card ids-loading-panel"><b className="tiny-loader" /> Loading attack map...</article>}
      {data && !data.configured && <article className="card attack-map-warning"><strong>GeoIP database not configured</strong><p>{data.detail}</p><p className="muted">Download MaxMind GeoLite2 City as an MMDB file and set the local path in Settings &gt; OpenSMART Modules &gt; Network IDS.</p></article>}
      {data && <article className="card attack-map-card"><AttackMapSvg data={data} mode={mode} /><AttackMapStats data={data} /></article>}
      {data && <div className="ids-table-grid ids-table-grid-3"><AttackSmallTable title="Top source IPs" rows={data.tables.top_src_ips || []} columns={[['src_ip', 'Source IP'], ['alerts', 'Alerts'], ['country', 'Country']]} /><AttackSmallTable title="Signatures" rows={data.tables.top_signatures || []} columns={[['signature', 'Signature'], ['sources', 'Sources'], ['alerts', 'Alerts']]} /><AttackSmallTable title="Severity by source" rows={data.tables.severity_by_source || []} columns={[['severity', 'Severity'], ['sources', 'Sources'], ['alerts', 'Alerts']]} /></div>}
    </div>
  );
}

function AttackMapSvg({ data, mode }: { data: NetworkIdsAttackMap; mode: AttackMapMode }) {
  const points = data.geo_points || [];
  const max = Math.max(1, ...points.map((point) => mode === 'src_ip' ? point.src_ip_count : point.alert_count));
  return (
    <svg className="attack-map-svg" viewBox="0 0 960 480" role="img" aria-label="IDS attack map">
      <rect x="0" y="0" width="960" height="480" rx="24" />
      {[-120, -60, 0, 60, 120].map((lon) => <line key={`lon-${lon}`} x1={project(lon, 0).x} y1="34" x2={project(lon, 0).x} y2="446" />)}
      {[-60, -30, 0, 30, 60].map((lat) => <line key={`lat-${lat}`} x1="32" y1={project(0, lat).y} x2="928" y2={project(0, lat).y} />)}
      <path d="M105,155 L190,125 L280,150 L330,218 L290,300 L200,322 L125,250 Z M420,125 L555,110 L620,175 L585,250 L455,238 Z M650,165 L790,150 L865,225 L835,320 L705,305 L630,240 Z M500,285 L590,310 L625,395 L535,420 L465,365 Z" />
      {points.map((point, index) => {
        const pos = project(point.lon, point.lat);
        const value = mode === 'src_ip' ? point.src_ip_count : point.alert_count;
        const r = 5 + Math.sqrt(value / max) * 24;
        return <circle key={`${point.country}-${point.city}-${index}`} className={`attack-marker ${mode === 'severity' ? severityClass(topKey(point.severities)) : `tone-${index % 6}`}`} cx={pos.x} cy={pos.y} r={r}><title>{[point.city, point.country].filter(Boolean).join(', ')} · {point.alert_count} alerts · {point.src_ip_count} sources</title></circle>;
      })}
    </svg>
  );
}

function project(lon: number, lat: number) {
  return { x: ((lon + 180) / 360) * 900 + 30, y: ((90 - lat) / 180) * 420 + 30 };
}

function topKey(values: Record<string, number>) {
  return Object.entries(values || {}).sort((a, b) => b[1] - a[1])[0]?.[0] || 'unknown';
}

function AttackMapStats({ data }: { data: NetworkIdsAttackMap }) {
  return <div className="attack-map-stats"><span>Total alerts<strong>{data.total_alerts.toLocaleString()}</strong></span><span>Mapped<strong>{data.mapped_alerts.toLocaleString()}</strong></span><span>Unmapped<strong>{data.unmapped_alerts.toLocaleString()}</strong></span><span>Locations<strong>{data.geo_points.length.toLocaleString()}</strong></span></div>;
}

function AttackSmallTable({ title, rows, columns }: { title: string; rows: Record<string, unknown>[]; columns: [string, string][] }) {
  return <article className="card ids-table-card compact"><h2>{title}</h2><div className="table-wrap"><table className="ids-summary-table"><thead><tr>{columns.map(([, label]) => <th key={label}>{label}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={index}>{columns.map(([key]) => <td key={key}>{String(row[key] ?? '')}</td>)}</tr>)}</tbody></table></div></article>;
}

function FirstIngestionNotice({ status }: { status: NetworkIdsSummary | NetworkIdsConfig | null }) {
  return (
    <div className="ids-info-panel first-ingestion-panel">
      <Info size={16} />
      <div>
        <strong>First ingestion in progress</strong> <span className="first-ingest-size-badge">{initialIngestionLabel(status?.initial_ingestion_gb)}</span> This may take a moment depending on the size of your eve.json file. Queries will be allowed after ingestion is complete.
        <span className="ids-info-progress"> {status?.progress_percent || 0}% · {status?.last_check_alerts_read || 0} alerts read · {status?.last_check_bytes_read || 0}/{status?.last_check_bytes_total || 0} bytes</span>
      </div>
    </div>
  );
}

function initialIngestionLabel(value: string | number | undefined) {
  const size = Number(value ?? 2);
  return size > 0 ? `Max Last ${Number.isInteger(size) ? size : size.toFixed(1)} GB` : 'Full file';
}

function CounterCard({ label, value, highlight = false }: { label: string; value: number; highlight?: boolean }) {
  return (
    <article className={`card ids-table-card compact ids-summary-counter ${highlight ? 'highlight' : ''}`}>
      <h2>{label}</h2>
      <strong>{value.toLocaleString()}</strong>
      <small>Suricata eve.json</small>
    </article>
  );
}

function SeverityCounterStrip({ severity, newCriticalCount, onFilter }: { severity: Record<string, number>; newCriticalCount: number; onFilter: (field: string, value: string | number) => void }) {
  const items = ['1', '2', '3', '4', '5'];
  return (
    <article className="card ids-table-card compact ids-severity-strip">
      <h2>Severity</h2>
      <div>
        {items.map((key) => (
          <button className={severityClass(key)} key={key} onClick={() => onFilter('severity', key)}>
            <small>{severityLabel(key)}</small>
            <strong>{(severity[key] || (key === '5' ? severity.unknown : 0) || 0).toLocaleString()}{key === '1' && newCriticalCount > 0 && <span className="new-alerts-badge"><span>New</span><span>Alerts</span></span>}</strong>
          </button>
        ))}
      </div>
    </article>
  );
}

function severityLabel(value: string) {
  return ({ '1': 'Critical', '2': 'High', '3': 'Medium', '4': 'Low', '5': 'Info', unknown: 'Info' } as Record<string, string>)[value] || `Severity ${value}`;
}

function severityClass(value: string) {
  return ({ '1': 'severity-critical', '2': 'severity-high', '3': 'severity-medium', '4': 'severity-low', '5': 'severity-info', unknown: 'severity-info' } as Record<string, string>)[value] || 'severity-info';
}

function TableTitle({ title, onShowDetails }: { title: string; onShowDetails: () => void }) {
  return (
    <div className="ids-table-title-row">
      <h2>{title}</h2>
      <button className="ids-show-full-btn" type="button" onClick={onShowDetails}>Show Full List</button>
    </div>
  );
}

function SummaryTable({ title, rows, onFilter, filterField, onShowDetails }: { title: string; rows: NetworkIdsSummaryRow[]; onFilter: (field: string, value: string | number) => void; filterField: string; onShowDetails: () => void }) {
  return <article className="card ids-table-card"><TableTitle title={title} onShowDetails={onShowDetails} /><div className="table-wrap"><table className="ids-summary-table"><thead><tr><th>#</th><th>Alerts</th><th>Category</th><th>Sev.</th><th>Conf.</th><th>SID</th><th>Proto</th><th>Signature</th></tr></thead><tbody>{rows.map((row, index) => <tr key={`${row.signature}-${index}`}><td>{index + 1}</td><td>{row.alerts}</td><td>{row.category}</td><td>{row.severity}</td><td>{row.confidence}</td><td>{row.signature_id}</td><td>{row.proto}</td><td><button className="text-button" onClick={() => onFilter(filterField, row.signature)}>{row.signature}</button></td></tr>)}</tbody></table></div></article>;
}

function SmallTable({ title, rows, field, onFilter, onShowDetails }: { title: string; rows: NetworkIdsSummaryRow[]; field: string; onFilter: (field: string, value: string | number) => void; onShowDetails: () => void }) {
  return <article className="card ids-table-card compact"><TableTitle title={title} onShowDetails={onShowDetails} /><div className="table-wrap"><table className="ids-summary-table"><thead><tr><th>#</th><th>Value</th><th>Alerts</th></tr></thead><tbody>{rows.map((row, index) => <tr key={`${row[field]}-${index}`}><td>{index + 1}</td><td><button className="text-button" onClick={() => onFilter(field, row[field])}>{row[field]}</button></td><td>{row.alerts}</td></tr>)}</tbody></table></div></article>;
}

function ArtifactTable({ rows, onFilter, onShowDetails }: { rows: NetworkIdsSummaryRow[]; onFilter: (field: string, value: string | number) => void; onShowDetails: () => void }) {
  return <article className="card ids-table-card compact"><TableTitle title="Top Artifacts" onShowDetails={onShowDetails} /><div className="table-wrap"><table className="ids-summary-table"><thead><tr><th>#</th><th>Type</th><th className="artifact-value-col">Value</th><th>Alerts</th></tr></thead><tbody>{rows.map((row, index) => <tr key={`${row.artifact_type}-${row.artifact_value}-${index}`}><td>{index + 1}</td><td>{row.artifact_type}</td><td className="artifact-value-col"><button className="text-button" onClick={() => onFilter('artifact_value', row.artifact_value)}>{row.artifact_value}</button></td><td>{row.alerts}</td></tr>)}</tbody></table></div></article>;
}

function TrendTable({ rows, title = 'Alert trend' }: { rows: NetworkIdsSummaryRow[]; title?: string }) {
  const W = 400;
  const H = 170;
  const PAD_LEFT = 36;
  const PAD_BOTTOM = 22;
  const PAD_TOP = 8;
  const chartW = W - PAD_LEFT - 4;
  const chartH = H - PAD_BOTTOM - PAD_TOP;
  if (!rows.length) {
    return <article className="card ids-table-card compact"><h2>{title}</h2><p className="muted">No data.</p></article>;
  }
  const values = rows.map((r) => Number(r.alerts) || 0);
  const maxVal = Math.max(1, ...values);
  const n = rows.length;
  const toY = (v: number) => PAD_TOP + (1 - v / maxVal) * chartH;
  const toX = (i: number) => n === 1 ? PAD_LEFT + chartW / 2 : PAD_LEFT + (i / (n - 1)) * chartW;
  const linePath = values.map((v, i) => `${i === 0 ? 'M' : 'L'}${toX(i).toFixed(1)},${toY(v).toFixed(1)}`).join(' ');
  const areaPath = `${linePath} L${toX(n - 1).toFixed(1)},${toY(0).toFixed(1)} L${toX(0).toFixed(1)},${toY(0).toFixed(1)} Z`;
  const gridY = [0.25, 0.5, 0.75, 1].map((f) => ({ y: toY(f * maxVal).toFixed(1), label: Math.round(f * maxVal).toLocaleString() }));
  const labelStep = Math.max(1, Math.ceil(n / 6));
  return (
    <article className="card ids-table-card compact">
      <h2>{title}</h2>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="ids-trend-svg" style={{ width: '100%', height: 170 }}>
        {gridY.map((g) => (
          <g key={g.y}>
            <line x1={PAD_LEFT} y1={g.y} x2={W - 4} y2={g.y} stroke="rgba(255,255,255,.06)" strokeWidth="1" />
            <text x={PAD_LEFT - 4} y={g.y} dominantBaseline="middle" textAnchor="end" fontSize="7" fill="#7890a8">{g.label}</text>
          </g>
        ))}
        {rows.map((row, i) => i % labelStep === 0 ? (
          <text key={i} x={toX(i)} y={H - 4} textAnchor="middle" fontSize="7" fill="#7890a8">{String(row.bucket).slice(-5)}</text>
        ) : null)}
        <path d={areaPath} fill="rgba(88,215,255,.25)" />
        <path d={linePath} fill="none" stroke="#58d7ff" strokeWidth="1.5" strokeLinejoin="round" />
        {values.map((v, i) => (
          <circle key={i} cx={toX(i)} cy={toY(v)} r="1.6" fill="#58d7ff">
            <title>{`${rows[i].bucket}: ${v}`}</title>
          </circle>
        ))}
      </svg>
    </article>
  );
}

function SeverityTrendTable({ rows }: { rows: NetworkIdsSummaryRow[] }) {
  const keys = ['1', '2', '3', '4', '5'];
  const max = Math.max(1, ...rows.map((row) => keys.reduce((sum, key) => sum + Number(row[key] || (key === '5' ? row.unknown || 0 : 0)), 0)));
  return <article className="card ids-table-card compact"><h2>Alerts by severity over time</h2><div className="ids-severity-timechart">{rows.map((row, index) => <div key={index} title={String(row.bucket)}>{keys.map((key) => <i className={severityClass(key)} key={key} style={{ height: `${(Number(row[key] || (key === '5' ? row.unknown || 0 : 0)) / max) * 100}%` }} />)}<small>{String(row.bucket).slice(-5)}</small></div>)}</div></article>;
}

function AnalysisTab({ alerts, total, filters, setFilters, sort, direction, updateSort, alertsLoading, queryDirty, onRunQuery, onCancelLoad, page, setPage, pageSize, setPageSize, trackingMode, newCriticalCount, onShowNewAlerts, onAckAlert }: { alerts: NetworkIdsAlert[]; total: number; filters: Record<string, string>; setFilters: (filters: Record<string, string>) => void; sort: string; direction: string; updateSort: (field: string) => void; alertsLoading: boolean; queryDirty: boolean; onRunQuery: () => void; onCancelLoad: () => void; page: number; setPage: (page: number) => void; pageSize: number; setPageSize: (size: number) => void; trackingMode: string; newCriticalCount: number; onShowNewAlerts: () => void; onAckAlert: (alertId: number) => void }) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="ids-analysis">
      <article className="card ids-filter-card">
        <div className="section-actions">
          <div><h2>Extended Filters</h2><p className="muted">Filter on any normalized Suricata alert field.</p></div>
          {alertsLoading && <span className="badge warning">Generating table...</span>}
        </div>
        <div className="ids-field-grid">
          {alertFields.map((field) => <label key={field}>{field}<input disabled={alertsLoading} value={filters[field] || ''} onChange={(event) => setFilters({ ...filters, [field]: event.target.value })} /></label>)}
        </div>
      </article>

      <article className="card ids-alert-card">
        <div className="section-actions ids-alert-actions">
          <div>
            <h2>Alert Details</h2>
            <p className="muted">Showing {alerts.length} of {total.toLocaleString()} matching alerts.{newCriticalCount > 0 && <button className="show-new-alerts-btn" type="button" onClick={onShowNewAlerts}>Show only New Alerts</button>}</p>
            {alertsLoading && <div className="ids-alert-loading"><span><b className="tiny-loader" /> Loading alert analysis...</span><button type="button" onClick={onCancelLoad}>Cancel query</button></div>}
            {!alertsLoading && queryDirty && <p className="ids-query-hint">Query parameters changed. Click Run query to refresh results.</p>}
          </div>
          <div className="ids-pagination">
            <button className="ids-run-query" disabled={alertsLoading} onClick={onRunQuery}>Run query</button>
            <label>Page size<input disabled={alertsLoading} type="number" min="1" max="1000" value={pageSize} onChange={(event) => setPageSize(Number(event.target.value) || 30)} /></label>
            <button disabled={alertsLoading || page === 0} onClick={() => setPage(Math.max(0, page - 1))}>Previous</button>
            <span>{page + 1} / {pageCount}</span>
            <button disabled={alertsLoading || page + 1 >= pageCount} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        </div>
        <div className="ids-alert-scroll" role="region" aria-label="Alert details table">
          <table className="ids-alert-table">
            <thead>
              <tr>{trackingMode === 'full' && <th>Ack</th>}{visibleAlertColumns.map((column) => <th className={column.className || ''} key={column.key}><button className="text-button" disabled={alertsLoading} onClick={() => updateSort(column.key)}>{column.label}{sort === column.key ? ` ${direction}` : ''}</button></th>)}</tr>
            </thead>
            <tbody>
              {alerts.map((alert, index) => <tr key={`${alert.timestamp}-${index}`}>{trackingMode === 'full' && <td>{String(alert.tracking_status || '') === 'new' && Number(alert.alert_id) > 0 ? <button className="ack-alert-btn" onClick={() => onAckAlert(Number(alert.alert_id))}>Ack</button> : ''}</td>}{visibleAlertColumns.map((column) => <td className={column.className || ''} key={column.key}>{String(alert[column.key] ?? '')}</td>)}</tr>)}
            </tbody>
          </table>
        </div>
      </article>
    </div>
  );
}

function DetailsTab({
  detailsTable, setDetailsTable,
  detailsRows, detailsTotal,
  detailsPage, setDetailsPage,
  detailsPageSize, setDetailsPageSize,
  detailsMaxRows, setDetailsMaxRows,
  detailsLoading,
  queryDisabled,
  onFilter,
  onCancelLoad,
}: {
  detailsTable: string; setDetailsTable: (name: string) => void;
  detailsRows: Record<string, unknown>[]; detailsTotal: number;
  detailsPage: number; setDetailsPage: (p: number) => void;
  detailsPageSize: number; setDetailsPageSize: (n: number) => void;
  detailsMaxRows: number; setDetailsMaxRows: (n: number) => void;
  detailsLoading: boolean;
  queryDisabled: boolean;
  onFilter: (field: string, value: string | number) => void;
  onCancelLoad: () => void;
}) {
  const tableOptions = Object.entries(DETAIL_TABLE_LABELS);
  const textCols = detailsTable ? (TABLE_TEXT_COLS[detailsTable] || []) : [];

  // Filter state: search box + per-column dropdown selections
  const [searchText, setSearchText] = useState('');
  const [colFilters, setColFilters] = useState<Record<string, string>>({});

  // Reset filters when table changes
  useEffect(() => { setSearchText(''); setColFilters({}); setDetailsPage(0); }, [detailsTable]);

  // Apply client-side filters
  const filteredRows = detailsRows.filter((row) => {
    if (searchText) {
      const lower = searchText.toLowerCase();
      const match = Object.entries(row).some(([col, val]) => !NUMERIC_COLS.has(col) && String(val ?? '').toLowerCase().includes(lower));
      if (!match) return false;
    }
    for (const [col, filterVal] of Object.entries(colFilters)) {
      if (filterVal && String(row[col] ?? '') !== filterVal) return false;
    }
    return true;
  });

  const pageCount = Math.max(1, Math.ceil(filteredRows.length / detailsPageSize));
  const safePage = Math.min(detailsPage, pageCount - 1);
  const pageRows = filteredRows.slice(safePage * detailsPageSize, (safePage + 1) * detailsPageSize);
  const columns = detailsRows.length > 0 ? Object.keys(detailsRows[0]) : [];

  // Build unique values per text column for dropdowns
  const colValues: Record<string, string[]> = {};
  for (const col of textCols) {
    const vals = [...new Set(detailsRows.map((r) => String(r[col] ?? '')).filter(Boolean))].sort();
    if (vals.length > 1) colValues[col] = vals;
  }

  function handleColFilter(col: string, val: string) {
    setColFilters((prev) => ({ ...prev, [col]: val }));
    setDetailsPage(0);
  }

  function handleCellClick(col: string, val: unknown) {
    if (NUMERIC_COLS.has(col)) return;
    const filterField = DETAIL_COL_TO_FILTER[col];
    if (!filterField) return;
    if (!queryDisabled) onFilter(filterField, String(val));
  }

  return (
    <div className="ids-details">
      <article className="card ids-details-controls">
        <div className="ids-details-bar">
          <label>
            Table
            <select value={detailsTable} onChange={(e) => setDetailsTable(e.target.value)}>
              <option value="">— select a table —</option>
              {tableOptions.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
            </select>
          </label>
          <label>
            Max rows
            <input type="number" min="1" max="10000" value={detailsMaxRows} onChange={(e) => setDetailsMaxRows(Number(e.target.value) || 2000)} />
          </label>
          <label>
            Page size
            <input type="number" min="1" max="1000" value={detailsPageSize} onChange={(e) => { setDetailsPageSize(Number(e.target.value) || 100); setDetailsPage(0); }} />
          </label>
          {queryDisabled && <span className="badge warning">Queries allowed after first ingestion</span>}
          {detailsLoading && <span className="badge warning"><b className="tiny-loader" /> Loading IDS details...</span>}
          {detailsLoading && <button type="button" onClick={onCancelLoad}>Cancel query</button>}
          {!detailsLoading && detailsTable && <span className="muted">{detailsTotal.toLocaleString()} rows loaded</span>}
        </div>

        {/* Filter bar: search box + per-column dropdowns */}
        {detailsRows.length > 0 && (
          <div className="ids-details-filter-bar">
            <label>
              Search
              <input
                type="text"
                placeholder="Filter rows..."
                value={searchText}
                onChange={(e) => { setSearchText(e.target.value); setDetailsPage(0); }}
              />
            </label>
            {Object.entries(colValues).map(([col, vals]) => (
              <label key={col}>
                {col}
                <select value={colFilters[col] || ''} onChange={(e) => handleColFilter(col, e.target.value)}>
                  <option value="">All</option>
                  {vals.map((v) => <option key={v} value={v}>{v}</option>)}
                </select>
              </label>
            ))}
            {(searchText || Object.values(colFilters).some(Boolean)) && (
              <button type="button" onClick={() => { setSearchText(''); setColFilters({}); setDetailsPage(0); }}>Clear filters</button>
            )}
          </div>
        )}
      </article>

      {detailsTable && !detailsLoading && detailsRows.length === 0 && (
        <div className="card"><p className="muted">No data for this table.</p></div>
      )}

      {detailsRows.length > 0 && (
        <article className="card ids-details-table-card">
          <div className="ids-details-pagination">
            <button disabled={safePage === 0} onClick={() => setDetailsPage(Math.max(0, safePage - 1))}>Previous</button>
            <span>{safePage + 1} / {pageCount}</span>
            <button disabled={safePage + 1 >= pageCount} onClick={() => setDetailsPage(safePage + 1)}>Next</button>
            <span className="muted">Showing {pageRows.length} of {filteredRows.length} filtered rows ({detailsRows.length} loaded)</span>
          </div>
          <div className="ids-alert-scroll">
            <table className="ids-summary-table ids-details-table">
              <thead>
                <tr><th>#</th>{columns.map((col) => <th key={col} className={col === 'artifact_value' ? 'artifact-value-col' : undefined}>{col}</th>)}</tr>
              </thead>
              <tbody>
                {pageRows.map((row, index) => (
                  <tr key={index}>
                    <td>{safePage * detailsPageSize + index + 1}</td>
                    {columns.map((col) => {
                      const val = row[col];
                      const isClickable = !NUMERIC_COLS.has(col) && !!DETAIL_COL_TO_FILTER[col];
                      const cellClass = col === 'artifact_value' ? 'artifact-value-col' : undefined;
                      return (
                        <td key={col} className={cellClass}>
                          {isClickable
                            ? <button className="text-button" onClick={() => handleCellClick(col, val)}>{String(val ?? '')}</button>
                            : String(val ?? '')}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>
      )}
    </div>
  );
}
