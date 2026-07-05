import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import type { NetworkIdsSummary, NetworkTrafficSummary, OpenSmartModule, ResourcePoint, ResourceStatus, Settings, ToolConfig } from '../types';
import { api } from '../api';
import { toolDefinitions } from './toolDefinitions';
import { t } from '../i18n';

type Props = {
  settings: Settings;
  tools: ToolConfig[];
  modules: OpenSmartModule[];
  onNavigate: (page: string) => void;
};

type FeedItem = { title: string; category?: string; body?: string; time?: string };

export default function SummaryPage({ settings, tools, modules, onNavigate }: Props) {
  const enabledTools = tools.filter((tool) => tool.enabled);
  const enabledModules = modules.filter((module) => module.enabled);
  const disabledTools = tools.filter((tool) => !tool.enabled);
  const disabledModules = modules.filter((module) => !module.enabled);
  const warningTools = tools.filter((tool) => tool.enabled && !settings[toolDefinitions[tool.name]?.key || '']);
  const notificationWarnings = notificationWarningChips(settings);
  const warningCount = warningTools.length + notificationWarnings.length;
  const disabledItems = disabledTools.length + disabledModules.length;
  const totalItems = tools.length + modules.length || 1;
  const healthyItems = enabledTools.length + enabledModules.length - warningCount;
  const healthPercent = Math.max(0, Math.round((healthyItems / totalItems) * 100));
  const useDemo = settings.dashboard_use_demo_for_disabled === 'true';

  // Module/tool enabled helpers
  const isModuleEnabled = (name: string) => modules.find((m) => m.name === name)?.enabled ?? true;
  const isToolEnabled = (name: string) => tools.find((t) => t.name === name)?.enabled ?? true;

  const ids = {
    critical: numberSetting(settings, 'dashboard_ids_alerts_critical'),
    high: numberSetting(settings, 'dashboard_ids_alerts_high'),
    medium: numberSetting(settings, 'dashboard_ids_alerts_medium'),
    low: numberSetting(settings, 'dashboard_ids_alerts_low'),
  };
  const vulns = {
    critical: numberSetting(settings, 'dashboard_vulnerabilities_critical'),
    high: numberSetting(settings, 'dashboard_vulnerabilities_high'),
    medium: numberSetting(settings, 'dashboard_vulnerabilities_medium'),
    open: numberSetting(settings, 'dashboard_vulnerabilities_open'),
  };
  const idsNetworkDemo = {
    critical: numberSetting(settings, 'dashboard_ids_severity_critical'),
    high: numberSetting(settings, 'dashboard_ids_severity_high'),
    medium: numberSetting(settings, 'dashboard_ids_severity_medium'),
    low: numberSetting(settings, 'dashboard_ids_severity_low'),
  };
  const feed = parseFeed(settings.dashboard_feed_json);

  // Network IDS live data
  const [idsSummary, setIdsSummary] = useState<NetworkIdsSummary | null>(null);
  const [idsSummaryLoading, setIdsSummaryLoading] = useState(false);
  const idsModuleEnabled = isModuleEnabled('Network IDS');
  const trafficModuleEnabled = isModuleEnabled('Network Traffic Monitoring');
  const [trafficSummary, setTrafficSummary] = useState<NetworkTrafficSummary | null>(null);
  const [trafficSummaryLoading, setTrafficSummaryLoading] = useState(false);
  const [resources, setResources] = useState<ResourceStatus | null>(null);
  const [resourceHistory, setResourceHistory] = useState<ResourcePoint[]>([]);
  const [resourcesLoading, setResourcesLoading] = useState(true);
  useEffect(() => {
    if (!idsModuleEnabled) return;
    setIdsSummaryLoading(true);
    api.networkIdsSummary({ timeframe: '1d' }).then(setIdsSummary).catch(() => undefined).finally(() => setIdsSummaryLoading(false));
  }, [idsModuleEnabled]);
  useEffect(() => {
    if (!trafficModuleEnabled) return;
    setTrafficSummaryLoading(true);
    api.networkTrafficSummary({ timeframe: '1d', top_n: 8 }).then(setTrafficSummary).catch(() => undefined).finally(() => setTrafficSummaryLoading(false));
  }, [trafficModuleEnabled]);
  useEffect(() => {
    Promise.all([
      api.resources().then(setResources).catch(() => undefined),
      api.resourcesHistory('1h').then((result) => setResourceHistory(result.points)).catch(() => setResourceHistory([])),
    ]).finally(() => setResourcesLoading(false));
  }, []);

  // Derive IDS severity counts from live data or demo
  const idsSeverityLive = idsSummary ? {
    critical: idsSummary.counters.severity['1'] ?? idsSummary.counters.severity['critical'] ?? 0,
    high: idsSummary.counters.severity['2'] ?? idsSummary.counters.severity['high'] ?? 0,
    medium: idsSummary.counters.severity['3'] ?? idsSummary.counters.severity['medium'] ?? 0,
    low: idsSummary.counters.severity['4'] ?? idsSummary.counters.severity['low'] ?? 0,
  } : null;

  const idsSeverity = idsModuleEnabled ? (idsSeverityLive ?? idsNetworkDemo) : (useDemo ? idsNetworkDemo : { critical: 0, high: 0, medium: 0, low: 0 });
  const idsNetworkIsDemo = !idsModuleEnabled && useDemo;
  const idsNetworkDisabledNoDemo = !idsModuleEnabled && !useDemo;

  const fwAllowed = numberSetting(settings, 'dashboard_fw_allowed_packets_24h');
  const fwBlocked = numberSetting(settings, 'dashboard_fw_blocked_packets_24h');
  const fwIsDemo = !isToolEnabled('OPNsense') && useDemo;
  const fwDisabledNoDemo = !isToolEnabled('OPNsense') && !useDemo;

  const threatIsDemo = !isModuleEnabled('Threat Detection Alerts') && useDemo;
  const threatDisabledNoDemo = !isModuleEnabled('Threat Detection Alerts') && !useDemo;
  const vulnIsDemo = !isModuleEnabled('Vulnerability Management') && useDemo;
  const vulnDisabledNoDemo = !isModuleEnabled('Vulnerability Management') && !useDemo;
  const trafficIsDemo = !trafficModuleEnabled && useDemo;
  const trafficDisabledNoDemo = !trafficModuleEnabled && !useDemo;
  const trafficIsEmpty = trafficModuleEnabled && trafficSummary !== null && Number(trafficSummary.counters.total_events || 0) === 0;

  // Empty flags: live data source enabled but produces no values.
  const threatIsEmpty = isModuleEnabled('Threat Detection Alerts') && (ids.critical + ids.high + ids.medium + ids.low === 0);
  const idsNetworkIsEmpty = idsModuleEnabled && idsSeverityLive !== null && (idsSeverityLive.critical + idsSeverityLive.high + idsSeverityLive.medium + idsSeverityLive.low === 0);
  const vulnIsEmpty = isModuleEnabled('Vulnerability Management') && (vulns.critical + vulns.high + vulns.medium + vulns.open === 0);
  const fwIsEmpty = isToolEnabled('OPNsense') && (fwAllowed + fwBlocked === 0);

  // Per-service flags for Security Services panel
  const endpointsValue = numberSetting(settings, 'dashboard_endpoints_total');
  const vpnValue = numberSetting(settings, 'dashboard_vpn_users');
  const lxcValue = numberSetting(settings, 'dashboard_lxc_assets');
  const endpointDemo = !isModuleEnabled('Endpoint') && useDemo;
  const endpointDisabledNoDemo = !isModuleEnabled('Endpoint') && !useDemo;
  const endpointEmpty = isModuleEnabled('Endpoint') && endpointsValue === 0;
  const vpnDemo = !isModuleEnabled('Access VPN') && useDemo;
  const vpnDisabledNoDemo = !isModuleEnabled('Access VPN') && !useDemo;
  const vpnEmpty = isModuleEnabled('Access VPN') && vpnValue === 0;
  const lxcDemo = !isModuleEnabled('LXC Manager') && useDemo;
  const lxcDisabledNoDemo = !isModuleEnabled('LXC Manager') && !useDemo;
  const lxcEmpty = isModuleEnabled('LXC Manager') && lxcValue === 0;

  return (
    <section className="home-dashboard">
      <article className="home-hero card">
        <div>
          <p className="eyebrow">{t(settings, 'home.securityPosture', 'Security posture')}</p>
          <h2>{settings.platform_title || 'OpenSMART'} {t(settings, 'home.operationalOverview', 'operational overview')}</h2>
          <p className="muted">{t(settings, 'home.overviewText', 'A consolidated view of platform health, security telemetry, and service readiness across OpenSMART modules and integrated tools.')}</p>
        </div>
        <div className="health-ring" style={{ '--health': `${healthPercent}%` } as CSSProperties}><strong>{healthPercent}%</strong><span>{t(settings, 'home.healthy', 'healthy')}</span></div>
      </article>

      <div className="dashboard-grid overview-grid">
        <MetricCardWithChips
          label={t(settings, 'home.enabledTools', 'Enabled tools')}
          value={enabledTools.length}
          onClick={() => onNavigate('tools')}
          chips={enabledTools.map((tool) => ({ id: `tool:${tool.id}`, name: toolDefinitions[tool.name]?.title || tool.name, kind: 'enabled' as const }))}
          onChipClick={(id) => onNavigate(id)}
        />
        <MetricCardWithChips
          label={t(settings, 'home.enabledModules', 'Enabled modules')}
          value={enabledModules.length}
          onClick={() => onNavigate('opensmart-modules')}
          chips={enabledModules.map((module) => ({ id: `module:${module.id}`, name: module.name, kind: 'enabled' as const }))}
          onChipClick={(id) => onNavigate(id)}
        />
        <MetricCardWithChips
          label={t(settings, 'home.disabledServices', 'Disabled services')}
          value={disabledItems}
          tone="neutral"
          className="overview-disabled-services"
          onClick={() => onNavigate('status')}
          chips={[
            ...disabledTools.map((tool) => ({ id: `tool:${tool.id}`, name: toolDefinitions[tool.name]?.title || tool.name, kind: 'disabled' as const })),
            ...disabledModules.map((module) => ({ id: `module:${module.id}`, name: module.name, kind: 'disabled' as const })),
          ]}
          onChipClick={(id) => onNavigate(id)}
        />
        <MetricCardWithChips label={t(settings, 'home.warnings', 'Warnings')} value={warningCount} tone="warning" className="overview-warnings" onClick={() => onNavigate('webconsole-config')} chips={[...warningTools.map((tool) => ({ id: `tool:${tool.id}`, name: `${toolDefinitions[tool.name]?.title || tool.name} URL`, kind: 'warning' as const })), ...notificationWarnings]} onChipClick={(id) => { if (id.startsWith('notification_')) { const url = new URL(window.location.href); url.searchParams.set('settingsTab', 'notifications'); url.hash = 'notification-warning-details'; window.history.replaceState(null, '', url); } onNavigate('webconsole-config'); }} />
      </div>

      <div className="dashboard-second-row">
        <SensorResourcesPanel resources={resources} history={resourceHistory} loading={resourcesLoading} settings={settings} />
      </div>

      <div className="dashboard-layout">
        <article className="card posture-card">
          <PanelTitle title={t(settings, 'home.threatAlerts', 'Threat Detection Alerts')} subtitle={t(settings, 'home.threatSubtitle', 'Threat alerts by severity, last 24h.')} isDemo={threatIsDemo} isEmpty={threatIsEmpty} onDemoClick={() => onNavigate('webconsole-config')} action={<button className="panel-action-btn" onClick={() => navigateModule(modules, 'Threat Detection Alerts', onNavigate)}>{t(settings, 'home.openAlerts', 'Open alerts')}</button>} />
          {threatDisabledNoDemo ? <DisabledPanelMessage settings={settings} /> : <><SeverityBar label={t(settings, 'home.critical', 'Critical')} value={ids.critical} max={maxValue(ids)} tone="critical" /><SeverityBar label={t(settings, 'home.high', 'High')} value={ids.high} max={maxValue(ids)} tone="high" /><SeverityBar label={t(settings, 'home.medium', 'Medium')} value={ids.medium} max={maxValue(ids)} tone="medium" /><SeverityBar label={t(settings, 'home.low', 'Low')} value={ids.low} max={maxValue(ids)} tone="low" /></>}
        </article>

        <article className="card posture-card">
          <PanelTitle title={t(settings, 'home.networkIdsAlerts', 'Network IDS Alerts')} subtitle={t(settings, 'home.networkIdsSubtitle', 'IDS alerts by severity, last 24h.')} isDemo={idsNetworkIsDemo} isEmpty={idsNetworkIsEmpty} onDemoClick={() => onNavigate('webconsole-config')} action={<button className="panel-action-btn" onClick={() => navigateModule(modules, 'Network IDS', onNavigate)}>{t(settings, 'home.openIds', 'Open IDS')}</button>} />
          {idsNetworkDisabledNoDemo ? <DisabledPanelMessage settings={settings} /> : idsSummaryLoading ? <PanelLoader settings={settings} /> : <><SeverityBar label={t(settings, 'home.critical', 'Critical')} value={idsSeverity.critical} max={maxValue(idsSeverity)} tone="critical" /><SeverityBar label={t(settings, 'home.high', 'High')} value={idsSeverity.high} max={maxValue(idsSeverity)} tone="high" /><SeverityBar label={t(settings, 'home.medium', 'Medium')} value={idsSeverity.medium} max={maxValue(idsSeverity)} tone="medium" /><SeverityBar label={t(settings, 'home.low', 'Low')} value={idsSeverity.low} max={maxValue(idsSeverity)} tone="low" /></>}
        </article>

        <article className="card posture-card network-traffic-dashboard-card">
          <PanelTitle title={t(settings, 'home.networkTraffic', 'Network Traffic')} subtitle={t(settings, 'home.networkTrafficSubtitle', 'Network event and protocol distribution, last 24h.')} isDemo={trafficIsDemo} isEmpty={trafficIsEmpty} onDemoClick={() => onNavigate('webconsole-config')} action={<button className="panel-action-btn" onClick={() => navigateModule(modules, 'Network Traffic Monitoring', onNavigate)}>{t(settings, 'home.openTraffic', 'Open traffic')}</button>} />
          {trafficDisabledNoDemo ? <DisabledPanelMessage settings={settings} /> : trafficSummaryLoading ? <PanelLoader settings={settings} /> : <NetworkTrafficDashboard summary={trafficSummary} useDemo={trafficIsDemo} settings={settings} />}
        </article>

        <article className="card posture-card">
          <PanelTitle title={t(settings, 'home.firewallActivity', 'Firewall Activity')} subtitle={t(settings, 'home.firewallSubtitle', 'Allowed vs blocked packets, last 24h.')} isDemo={fwIsDemo} isEmpty={fwIsEmpty} onDemoClick={() => onNavigate('webconsole-config')} action={<button className="panel-action-btn" onClick={() => navigateTool(tools, 'OPNsense', onNavigate)}>{t(settings, 'home.openFirewall', 'Open firewall')}</button>} />
          {fwDisabledNoDemo ? <DisabledPanelMessage settings={settings} /> : <><div className="split-metrics"><MetricPill label={t(settings, 'home.blockedPackets', 'Blocked packets')} value={fwBlocked} /><MetricPill label={t(settings, 'home.allowedPackets', 'Allowed packets')} value={fwAllowed} /></div><FirewallChart blocked={fwBlocked} allowed={fwAllowed} /></>}
        </article>

        <article className="card posture-card">
          <PanelTitle title={t(settings, 'home.vulnerabilities', 'Vulnerabilities')} subtitle={t(settings, 'home.vulnSubtitle', 'Open findings by severity and remediation queue.')} isDemo={vulnIsDemo} isEmpty={vulnIsEmpty} onDemoClick={() => onNavigate('webconsole-config')} action={<button className="panel-action-btn" onClick={() => navigateModule(modules, 'Vulnerability Management', onNavigate)}>{t(settings, 'home.openModule', 'Open module')}</button>} />
          {vulnDisabledNoDemo ? <DisabledPanelMessage settings={settings} /> : <><SeverityBar label={t(settings, 'home.critical', 'Critical')} value={vulns.critical} max={maxValue(vulns)} tone="critical" /><SeverityBar label={t(settings, 'home.high', 'High')} value={vulns.high} max={maxValue(vulns)} tone="high" /><SeverityBar label={t(settings, 'home.medium', 'Medium')} value={vulns.medium} max={maxValue(vulns)} tone="medium" /><MetricPill label={t(settings, 'home.openTotal', 'Open total')} value={vulns.open} /></>}
        </article>

        <article className="card posture-card">
          <PanelTitle title={t(settings, 'home.securityServices', 'Security Services')} subtitle={t(settings, 'home.securityServicesSubtitle', 'Per-service counters across endpoint, VPN, and LXC.')} isDemo={false} isEmpty={false} onDemoClick={() => onNavigate('webconsole-config')} action={null} />
          <div className="service-list">
            <ServiceLink label={t(settings, 'home.endpoints', 'Endpoints')} value={endpointsValue} target="Endpoint" modules={modules} onNavigate={onNavigate} isDemo={endpointDemo} isEmpty={endpointEmpty} disabledNoDemo={endpointDisabledNoDemo} />
            <ServiceLink label={t(settings, 'home.vpnUsers', 'VPN users')} value={vpnValue} target="Access VPN" modules={modules} onNavigate={onNavigate} isDemo={vpnDemo} isEmpty={vpnEmpty} disabledNoDemo={vpnDisabledNoDemo} />
            <ServiceLink label={t(settings, 'home.lxcAssets', 'LXC assets')} value={lxcValue} target="LXC Manager" modules={modules} onNavigate={onNavigate} isDemo={lxcDemo} isEmpty={lxcEmpty} disabledNoDemo={lxcDisabledNoDemo} />
          </div>
        </article>
      </div>

      <article className="card feed-card emphasized-feed dashboard-bottom-feed">
        <h2>{t(settings, 'home.internalFeed', 'Internal Feed')}</h2>
        {feed.map((item, index) => <div className="feed-item" key={`${item.title}-${index}`}><small>{item.category || 'Announcement'} · {item.time || 'Now'}</small><strong>{item.title}</strong><p className="muted">{item.body}</p></div>)}
      </article>
    </section>
  );
}

function PanelTitle({ title, subtitle, isDemo, isEmpty, onDemoClick, action }: { title: string; subtitle: string; isDemo: boolean; isEmpty: boolean; onDemoClick: () => void; action: React.ReactNode }) {
  return (
    <div className="section-actions">
      <div>
        <div className="panel-title-row">
          <h2>{title}</h2>
          {isDemo && <button className="demo-badge" onClick={onDemoClick} title="Using demo data — click to configure">DEMO</button>}
          {isEmpty && <span className="empty-badge" title="Live data source enabled but no values reported">EMPTY</span>}
        </div>
        <p className="muted">{subtitle}</p>
      </div>
      {action}
    </div>
  );
}

function notificationWarningChips(settings: Settings): Chip[] {
  const items = [
    ['notification_ids_webhook_status', 'IDS webhook'],
    ['notification_network_webhook_status', 'Network webhook'],
    ['notification_platform_webhook_status', 'Platform webhook'],
  ];
  return items
    .filter(([key]) => settings[key] === 'warning')
    .map(([key, name]) => ({ id: key, name, kind: 'warning' as const }));
}

type ChipKind = 'enabled' | 'disabled' | 'warning';
type Chip = { id: string; name: string; kind: ChipKind };

const CHIP_VISIBLE_LIMIT = 8;

function MetricCardWithChips({ label, value, detail, tone = 'good', className = '', onClick, chips, onChipClick }: { label: string; value: number; detail?: string; tone?: string; className?: string; onClick: () => void; chips: Chip[]; onChipClick: (id: string) => void }) {
  const visible = chips.slice(0, CHIP_VISIBLE_LIMIT);
  const hidden = chips.length - visible.length;
  return (
    <div className={`metric-card with-chips ${tone} ${className}`.trim()}>
      <button className="metric-card-head" onClick={onClick}>
        <h2>{label}</h2>
        <strong>{value}</strong>
        {detail && <small>{detail}</small>}
      </button>
      {chips.length > 0 && (
        <div className="metric-chips">
          {visible.map((chip) => (
            <button key={chip.id} className={`chip chip-${chip.kind}`} onClick={(event) => { event.stopPropagation(); onChipClick(chip.id); }} title={chip.name}>
              {chip.name}
            </button>
          ))}
          {hidden > 0 && (
            <button className="chip chip-overflow" onClick={(event) => { event.stopPropagation(); onClick(); }} title={`${hidden} more`}>
              +{hidden} more
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function MetricPill({ label, value }: { label: string; value: number }) {
  return <div className="metric-pill"><span>{label}</span><strong>{value.toLocaleString()}</strong></div>;
}

function PanelLoader({ settings }: { settings: Settings }) {
  return <div className="dashboard-panel-loader"><b className="tiny-loader" /> {t(settings, 'home.loadingPanel', 'Loading data...')}</div>;
}

function DisabledPanelMessage({ settings }: { settings: Settings }) {
  return <div className="disabled-panel-message"><strong>{t(settings, 'home.disabled', 'Disabled')}</strong><span>{t(settings, 'home.disabledMessage', 'No live data is shown while this service is disabled. Enable Demo data in Settings to show placeholders.')}</span></div>;
}

function NetworkTrafficDashboard({ summary, useDemo, settings }: { summary: NetworkTrafficSummary | null; useDemo: boolean; settings: Settings }) {
  const eventRows = summary?.tables.event_counts || (useDemo ? demoTrafficEvents() : []);
  const protocolRows = summary?.tables.protocols || (useDemo ? demoTrafficProtocols() : []);
  if (!eventRows.length && !protocolRows.length) return <p className="muted">{t(settings, 'home.noTraffic', 'No network traffic data available.')}</p>;
  return <div className="dashboard-subsections"><TrafficBarSection title={t(settings, 'home.networkEvents', 'Network Events')} rows={eventRows} labelKey="event_type" /><TrafficBarSection title={t(settings, 'home.protocols', 'Protocols')} rows={protocolRows} labelKey="protocol" /></div>;
}

function TrafficBarSection({ title, rows, labelKey }: { title: string; rows: Record<string, string | number | undefined>[]; labelKey: string }) {
  const max = Math.max(1, ...rows.map((row) => Number(row.events || 0)));
  return <div className="dashboard-subsection"><h3>{title}</h3><div className="horizontal-stat-list">{rows.slice(0, 6).map((row, index) => <HorizontalStatBar key={`${row[labelKey] || index}`} label={String(row[labelKey] || 'unknown')} value={Number(row.events || 0)} max={max} tone={index % 4} />)}</div></div>;
}

function HorizontalStatBar({ label, value, max, tone = 0 }: { label: string; value: number; max: number; tone?: number }) {
  return <div className={`horizontal-stat-row tone-${tone}`}><span>{label}</span><div><i style={{ width: `${Math.max(4, (value / max) * 100)}%` }} /></div><strong>{value.toLocaleString()}</strong></div>;
}

function SensorResourcesPanel({ resources, history, loading, settings }: { resources: ResourceStatus | null; history: ResourcePoint[]; loading: boolean; settings: Settings }) {
  const points = history.length >= 2 ? history : demoResourcePoints(resources);
  return <article className="card sensor-resources-card compact-resources"><div className="compact-resources-head"><h2>{t(settings, 'home.sensorResources', 'Sensor Resources')}</h2><p className="muted">{t(settings, 'home.resourceSubtitle', 'Compact resource activity from the OpenSMART host.')}</p></div>{loading ? <PanelLoader settings={settings} /> : <div className="sensor-resource-grid"><MiniResourceMetric label="CPU" value={resources?.cpu_percent || 0} points={points} field="cpu" color="#58d7ff" /><MiniResourceMetric label="Memory" value={resources?.memory_percent || 0} points={points} field="memory" color="#63e6be" /><MiniResourceMetric label="Disk" value={resources?.disk_percent || 0} points={points} field="disk" color="#ffc857" /></div>}</article>;
}

function MiniResourceMetric({ label, value, points, field, color }: { label: string; value: number; points: ResourcePoint[]; field: 'cpu' | 'memory' | 'disk'; color: string }) {
  return <div className="mini-resource-metric"><div><span>{label}</span><strong>{Math.round(value)}%</strong></div><MiniAreaChart points={points} field={field} color={color} /></div>;
}

function MiniAreaChart({ points, field, color }: { points: ResourcePoint[]; field: 'cpu' | 'memory' | 'disk'; color: string }) {
  const W = 280, H = 38, pad = 4;
  const values = points.map((point) => Number(point[field] || 0));
  const max = Math.max(100, ...values);
  const x = (i: number) => points.length <= 1 ? W / 2 : pad + (i / (points.length - 1)) * (W - pad * 2);
  const y = (value: number) => pad + (1 - Math.min(max, Math.max(0, value)) / max) * (H - pad * 2);
  const line = values.map((value, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(value).toFixed(1)}`).join(' ');
  const area = values.length ? `${line} L${x(values.length - 1).toFixed(1)},${H - pad} L${x(0).toFixed(1)},${H - pad} Z` : '';
  return <svg className="mini-area-chart" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none"><path d={area} fill={color} opacity="0.18" /><path d={line} fill="none" stroke={color} strokeWidth="2" /></svg>;
}

function demoTrafficEvents() {
  return [{ event_type: 'flow', events: 42 }, { event_type: 'dns', events: 31 }, { event_type: 'http', events: 24 }, { event_type: 'tls', events: 18 }];
}

function demoTrafficProtocols() {
  return [{ protocol: 'TCP', events: 54 }, { protocol: 'DNS', events: 31 }, { protocol: 'HTTP', events: 24 }, { protocol: 'TLS', events: 18 }];
}

function demoResourcePoints(resources: ResourceStatus | null): ResourcePoint[] {
  const cpu = resources?.cpu_percent || 18, memory = resources?.memory_percent || 42, disk = resources?.disk_percent || 33;
  return Array.from({ length: 12 }, (_, index) => ({ t: String(index), cpu: Math.max(2, cpu + Math.sin(index * .9) * 6), memory: Math.max(2, memory + Math.cos(index * .6) * 4), disk: Math.max(2, disk + Math.sin(index * .35) * 2) }));
}

function SeverityBar({ label, value, max, tone }: { label: string; value: number; max: number; tone: string }) {
  return (
    <div className="severity-row">
      <span>{label}</span>
      <div><i className={tone} style={{ width: `${Math.max(4, (value / max) * 100)}%` }} /></div>
      <strong>{value.toLocaleString()}</strong>
    </div>
  );
}

function FirewallChart({ blocked, allowed }: { blocked: number; allowed: number }) {
  // Generate 12 demo buckets (2h intervals) that sum approximately to totals
  const buckets = useFirewallBuckets(blocked, allowed);
  const maxVal = Math.max(1, ...buckets.map((b) => Math.max(b.blocked, b.allowed)));
  const W = 400;
  const H = 100;
  const PAD_LEFT = 36;
  const PAD_BOTTOM = 22;
  const chartW = W - PAD_LEFT - 4;
  const chartH = H - PAD_BOTTOM - 8;
  const n = buckets.length;

  function toY(v: number) { return 8 + (1 - v / maxVal) * chartH; }
  function toX(i: number) { return PAD_LEFT + (i / (n - 1)) * chartW; }

  const allowedPath = buckets.map((b, i) => `${i === 0 ? 'M' : 'L'}${toX(i).toFixed(1)},${toY(b.allowed).toFixed(1)}`).join(' ');
  const blockedPath = buckets.map((b, i) => `${i === 0 ? 'M' : 'L'}${toX(i).toFixed(1)},${toY(b.blocked).toFixed(1)}`).join(' ');

  const hours = Array.from({ length: n }, (_, i) => {
    const h = (i * 2) % 24;
    return `${String(h).padStart(2, '0')}:00`;
  });

  const gridY = [0.25, 0.5, 0.75, 1].map((f) => ({ y: toY(f * maxVal).toFixed(1), label: Math.round(f * maxVal).toLocaleString() }));

  return (
    <div className="fw-chart-wrap">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="fw-chart-svg">
        {/* Grid lines */}
        {gridY.map((g) => (
          <g key={g.y}>
            <line x1={PAD_LEFT} y1={g.y} x2={W - 4} y2={g.y} stroke="rgba(255,255,255,.06)" strokeWidth="1" />
            <text x={PAD_LEFT - 4} y={g.y} dominantBaseline="middle" textAnchor="end" fontSize="7" fill="#4a6278">{g.label}</text>
          </g>
        ))}
        {/* X axis labels */}
        {hours.filter((_, i) => i % 3 === 0).map((label, idx) => {
          const i = idx * 3;
          return <text key={i} x={toX(i)} y={H - 4} textAnchor="middle" fontSize="7" fill="#4a6278">{label}</text>;
        })}
        {/* Lines */}
        <path d={allowedPath} fill="none" stroke="#63e6be" strokeWidth="1.5" strokeLinejoin="round" />
        <path d={blockedPath} fill="none" stroke="#ff5a5a" strokeWidth="1.5" strokeLinejoin="round" />
      </svg>
      <div className="fw-chart-legend">
        <span className="allowed">&#9632; Allowed</span>
        <span className="blocked">&#9632; Blocked</span>
      </div>
    </div>
  );
}

function useFirewallBuckets(blocked: number, allowed: number) {
  return useMemo(() => {
    const seed = blocked + allowed;
    return Array.from({ length: 12 }, (_, i) => {
      const bf = 0.6 + 0.8 * Math.abs(Math.sin((seed + i * 17) * 0.37));
      const af = 0.6 + 0.8 * Math.abs(Math.sin((seed + i * 13) * 0.41));
      return {
        blocked: Math.round((blocked / 12) * bf),
        allowed: Math.round((allowed / 12) * af),
      };
    });
  }, [blocked, allowed]);
}

function ServiceLink({ label, value, target, modules, onNavigate, isDemo = false, isEmpty = false, disabledNoDemo = false }: { label: string; value: number; target: string; modules: OpenSmartModule[]; onNavigate: (page: string) => void; isDemo?: boolean; isEmpty?: boolean; disabledNoDemo?: boolean }) {
  return (
    <button className="service-link" onClick={() => navigateModule(modules, target, onNavigate)}>
      <span>
        {label}
        {isDemo && <span className="demo-badge-inline" title="Using demo data">DEMO</span>}
        {disabledNoDemo && <span className="empty-badge" title="Disabled and demo data is off">DISABLED</span>}
        {isEmpty && <span className="empty-badge" title="Live data source enabled but no values reported">EMPTY</span>}
      </span>
      <strong>{disabledNoDemo ? '—' : value.toLocaleString()}</strong>
    </button>
  );
}

function numberSetting(settings: Settings, key: string) {
  const value = Number.parseInt(settings[key] || '0', 10);
  return Number.isFinite(value) ? value : 0;
}

function maxValue(values: Record<string, number>) {
  return Math.max(1, ...Object.values(values));
}

function parseFeed(raw = '[]'): FeedItem[] {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0) return parsed.slice(0, 5);
  } catch {
    return defaultFeed();
  }
  return defaultFeed();
}

function defaultFeed(): FeedItem[] {
  return [
    { title: 'Daily threat review ready', category: 'Operations', body: 'Review high-severity IDS events and firewall block trends from the last 24 hours.', time: 'Today' },
    { title: 'Validate endpoint coverage', category: 'Endpoint', body: 'Confirm managed endpoint counts against expected inventory.', time: 'Today' },
    { title: 'Demo feed available', category: 'Demo', body: 'Sample feed files are available in the project demo directory.', time: 'Reference' },
  ];
}

function navigateModule(modules: OpenSmartModule[], name: string, onNavigate: (page: string) => void) {
  const module = modules.find((item) => item.name === name);
  onNavigate(module ? `module:${module.id}` : 'opensmart-modules');
}

function navigateTool(tools: ToolConfig[], name: string, onNavigate: (page: string) => void) {
  const tool = tools.find((item) => item.name === name);
  onNavigate(tool ? `tool:${tool.id}` : 'tools');
}
