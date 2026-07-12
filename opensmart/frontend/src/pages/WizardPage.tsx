import { ChangeEvent, useEffect, useState } from 'react';
import { api } from '../api';
import type { HostInterface, HostResources, OpenSmartModule, ProvisionResult, Settings, ToolConfig } from '../types';
import { MODULE_BACKING, NOT_IMPLEMENTED, PROJECT_LABELS, TOOL_BACKING } from './backing';
import { toolDefinitions } from './toolDefinitions';

type StepKey = 'basics' | 'network' | 'features' | 'provision';

const steps: { key: StepKey; label: string }[] = [
  { key: 'basics', label: '1. Basics' },
  { key: 'network', label: '2. Network' },
  { key: 'features', label: '3. Modules & Tools' },
  { key: 'provision', label: '4. Provision' },
];

// Strong working defaults: Suricata+Zeek traffic monitoring, Suricata IDS,
// OpenVPN remote access, and embedded (iframe) access to Wazuh/Arkime/Proxmox.
const MODULE_DEFAULTS = new Set(['Network Traffic Monitoring', 'Network IDS', 'Access VPN']);
const TOOL_DEFAULTS = new Set(['Wazuh', 'Arkime', 'Proxmox']);

// Modules that only produce data when a given tool's containers are running.
const MODULE_REQUIRES_TOOL: Record<string, string[]> = {
  'Threat Detection Alerts': ['Wazuh'],
  Endpoint: ['Wazuh'],
  'Vulnerability Management': ['Wazuh'],
};

// Config keys merged into a module's config when it is enabled through the
// wizard and the key is not already set. Keeps eve.json ingestion pointed at
// the native Suricata container out of the box.
const MODULE_CONFIG_DEFAULTS: Record<string, Record<string, string>> = {
  'Network IDS': { eve_source: 'native' },
  'Network Traffic Monitoring': { log_source: 'eve_json' },
};

// Locally-provisioned tools get a working iframe URL prefilled (only when
// the URL setting is still empty).
// Locally-provisioned tools default to their front-door proxy alias
// (same-origin path) so they embed in the Tools iframe out of the box when
// OpenSMART is reached via the proxy. Switch a tool to a direct url:port in
// Configuration > Tools if you don't run behind the proxy.
const DEFAULT_TOOL_URLS: Record<string, (host: string) => string> = {
  Wazuh: () => '/wazuh/',
  Arkime: () => '/arkime/',
};

type RunState = 'pending' | 'running' | 'ok' | 'warning' | 'error' | 'info';

type RunItem = {
  id: string;
  phase: string;
  label: string;
  state: RunState;
  detail: string;
  containers?: { container: string; ok: boolean; detail: string }[];
};

type Props = {
  settings: Settings;
  setSettings: (settings: Settings) => void;
  modules?: OpenSmartModule[];
  onModulesUpdate?: (modules: OpenSmartModule[]) => void;
  tools?: ToolConfig[];
  onToolsUpdate?: (tools: ToolConfig[]) => void;
  onComplete?: () => void;
};

function mergeConfig(raw: string, defaults: Record<string, string>): string {
  let config: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(raw || '{}');
    if (parsed && typeof parsed === 'object') config = parsed as Record<string, unknown>;
  } catch {
    config = {};
  }
  Object.entries(defaults).forEach(([key, value]) => {
    if (config[key] === undefined || config[key] === '') config[key] = value;
  });
  return JSON.stringify(config);
}

export default function WizardPage({ settings, setSettings, modules: modulesProp, onModulesUpdate, tools: toolsProp, onToolsUpdate, onComplete }: Props) {
  const [step, setStep] = useState<StepKey>('basics');
  const [visited, setVisited] = useState<Set<StepKey>>(new Set(['basics']));
  const [appName, setAppName] = useState(settings.platform_title || 'OpenSMART');
  const [proxyHostname, setProxyHostname] = useState(settings.proxy_hostname || window.location.hostname);
  const [logoDraft, setLogoDraft] = useState(settings.logo_url || '');
  const [interfaces, setInterfaces] = useState<HostInterface[] | null>(null);
  const [ifaceError, setIfaceError] = useState('');
  const [ifacesLoading, setIfacesLoading] = useState(false);
  const [selectedIfaces, setSelectedIfaces] = useState<Set<string>>(new Set());
  const [showVirtual, setShowVirtual] = useState(false);
  const [manualIfaces, setManualIfaces] = useState('');
  const [localModules, setLocalModules] = useState<OpenSmartModule[]>(modulesProp ?? []);
  const [localTools, setLocalTools] = useState<ToolConfig[]>(toolsProp ?? []);
  const [defaultsApplied, setDefaultsApplied] = useState(false);
  const [hostResources, setHostResources] = useState<HostResources | null>(null);
  const [vpnType, setVpnType] = useState<'openvpn' | 'wireguard'>('openvpn');
  const [notices, setNotices] = useState<string[]>([]);
  const [runItems, setRunItems] = useState<RunItem[]>([]);
  const [running, setRunning] = useState(false);
  const [runDone, setRunDone] = useState(false);
  const [runError, setRunError] = useState('');

  const modules = modulesProp ?? localModules;
  const handleModulesUpdate = onModulesUpdate ?? setLocalModules;
  const tools = toolsProp ?? localTools;
  const handleToolsUpdate = onToolsUpdate ?? setLocalTools;

  useEffect(() => {
    if (modulesProp) return;
    api.openSmartModules().then((result) => setLocalModules(result.modules)).catch(() => undefined);
  }, [modulesProp]);

  useEffect(() => {
    if (toolsProp) return;
    api.tools().then((result) => setLocalTools(result.tools)).catch(() => undefined);
  }, [toolsProp]);

  // Determined once by opensmart.sh at install time (never measured live by
  // the browser) — see provisioning.py's host_resources(). Falls back to an
  // unconstrained "full" verdict if the request fails, so a broken fetch
  // never blocks setup; it just means no warning is shown.
  useEffect(() => {
    api.hostResources()
      .then(setHostResources)
      .catch(() => setHostResources({
        cpu_count: 0, memory_total_mb: 0, disk_free_gb: 0, tier: 'full',
        constrained_tools: [], constrained_modules: [],
        recommended_tiers: { core: { cpu: 2, memory_mb: 3800, disk_gb: 9 }, full: { cpu: 4, memory_mb: 7500, disk_gb: 18 } },
      }));
  }, []);

  const constrainedTools = new Set(hostResources?.constrained_tools ?? []);
  const constrainedModules = new Set(hostResources?.constrained_modules ?? []);

  // Fresh install (nothing enabled yet): pre-select the recommended defaults,
  // skipping anything this host's install-time resource check flagged.
  useEffect(() => {
    if (defaultsApplied || modules.length === 0 || tools.length === 0 || hostResources === null) return;
    if (modules.some((m) => m.enabled) || tools.some((t) => t.enabled)) {
      setDefaultsApplied(true);
      return;
    }
    const moduleDefaults = new Set([...MODULE_DEFAULTS].filter((name) => !constrainedModules.has(name)));
    const toolDefaults = new Set([...TOOL_DEFAULTS].filter((name) => !constrainedTools.has(name)));
    handleModulesUpdate(modules.map((m) => (moduleDefaults.has(m.name) ? { ...m, enabled: true } : m)));
    handleToolsUpdate(tools.map((t) => (toolDefaults.has(t.name) ? { ...t, enabled: true } : t)));
    setDefaultsApplied(true);
    const skippedTools = [...TOOL_DEFAULTS].filter((name) => constrainedTools.has(name));
    const nextNotices = ['Recommended defaults pre-selected: Suricata & Zeek traffic monitoring, Suricata IDS, OpenVPN remote access, and embedded access to ' + (toolDefaults.size ? [...toolDefaults].join(', ') : 'no local tools') + '.'];
    if (skippedTools.length) {
      nextNotices.push(`${skippedTools.join(' and ')} left disabled by default — see the resource warning below. You can still enable ${skippedTools.length > 1 ? 'them' : 'it'} manually.`);
    }
    setNotices(nextNotices);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modules, tools, defaultsApplied, hostResources]);

  function loadInterfaces() {
    setIfacesLoading(true);
    setIfaceError('');
    api.hostInterfaces()
      .then(({ interfaces: found }) => {
        setInterfaces(found);
        const saved = (settings.monitor_interfaces || '').split(',').map((s) => s.trim()).filter(Boolean);
        if (saved.length) {
          setSelectedIfaces(new Set(saved));
        } else {
          setSelectedIfaces(new Set(found.filter((i) => !i.virtual && i.up).map((i) => i.name)));
        }
      })
      .catch((error) => setIfaceError(error instanceof Error ? error.message : 'Failed to detect interfaces'))
      .finally(() => setIfacesLoading(false));
  }

  useEffect(() => {
    if (step === 'network' && interfaces === null && !ifacesLoading && !ifaceError) loadInterfaces();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  function goTo(next: StepKey) {
    setVisited((prev) => new Set(prev).add(next));
    setStep(next);
  }

  function uploadLogo(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setLogoDraft(String(reader.result || ''));
    reader.readAsDataURL(file);
  }

  function toggleIface(name: string) {
    setSelectedIfaces((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  function toggleModule(target: OpenSmartModule) {
    const enabling = !target.enabled;
    const newNotices: string[] = [];
    handleModulesUpdate(modules.map((m) => (m.id === target.id ? { ...m, enabled: enabling } : m)));
    if (enabling) {
      const required = MODULE_REQUIRES_TOOL[target.name] || [];
      const missing = required.filter((name) => !tools.find((t) => t.name === name)?.enabled);
      if (missing.length) {
        handleToolsUpdate(tools.map((t) => (missing.includes(t.name) ? { ...t, enabled: true } : t)));
        missing.forEach((name) => newNotices.push(`${name} was enabled automatically — ${target.name} requires it.`));
      }
    }
    if (newNotices.length) setNotices(newNotices);
  }

  function toggleTool(target: ToolConfig) {
    const enabling = !target.enabled;
    const newNotices: string[] = [];
    handleToolsUpdate(tools.map((t) => (t.id === target.id ? { ...t, enabled: enabling } : t)));
    if (!enabling) {
      const dependents = modules.filter((m) => m.enabled && (MODULE_REQUIRES_TOOL[m.name] || []).includes(target.name));
      if (dependents.length) {
        handleModulesUpdate(modules.map((m) => (dependents.some((d) => d.id === m.id) ? { ...m, enabled: false } : m)));
        dependents.forEach((m) => newNotices.push(`${m.name} was disabled automatically — it requires ${target.name}.`));
      }
    }
    if (newNotices.length) setNotices(newNotices);
  }

  const effectiveIfaces = interfaces === null
    ? manualIfaces.split(',').map((s) => s.trim()).filter(Boolean)
    : [...selectedIfaces];

  function updateItem(id: string, patch: Partial<RunItem>) {
    setRunItems((prev) => prev.map((item) => (item.id === id ? { ...item, ...patch } : item)));
  }

  async function runProvisioning() {
    setRunning(true);
    setRunError('');
    const host = window.location.hostname;
    const enabledModules = modules.filter((m) => m.enabled);
    const enabledTools = tools.filter((t) => t.enabled);

    const provisionModules = enabledModules.filter((m) => m.name !== 'Access VPN' && (MODULE_BACKING[m.name] || []).length > 0);
    const infoModules = enabledModules.filter((m) => m.name !== 'Access VPN' && (MODULE_BACKING[m.name] || []).length === 0);
    const provisionTools = enabledTools.filter((t) => (TOOL_BACKING[t.name] || []).length > 0);
    const infoTools = enabledTools.filter((t) => (TOOL_BACKING[t.name] || []).length === 0);
    const vpnEnabled = enabledModules.some((m) => m.name === 'Access VPN');

    const items: RunItem[] = [
      { id: 'save-settings', phase: 'Configuration', label: 'Save platform settings', state: 'pending', detail: '' },
      { id: 'save-modules', phase: 'Configuration', label: 'Save module configuration', state: 'pending', detail: '' },
      { id: 'save-tools', phase: 'Configuration', label: 'Save tool configuration', state: 'pending', detail: '' },
      ...provisionModules.map((m): RunItem => ({ id: `module:${m.name}`, phase: 'Services', label: `${m.name} (${(MODULE_BACKING[m.name] || []).map((c) => PROJECT_LABELS[c] ?? c).join(', ')})`, state: 'pending', detail: '' })),
      ...provisionTools.map((t): RunItem => ({ id: `tool:${t.name}`, phase: 'Services', label: `${t.name} (${(TOOL_BACKING[t.name] || []).map((c) => PROJECT_LABELS[c] ?? c).join(', ')})`, state: 'pending', detail: '' })),
      { id: 'container:nginx', phase: 'Services', label: `Front-door proxy (nginx, ${proxyHostname.trim() || host})`, state: 'pending', detail: '' },
      ...(vpnEnabled ? [{ id: 'info:vpn', phase: 'Services', label: 'Access VPN', state: 'info' as RunState, detail: `${vpnType === 'openvpn' ? 'OpenVPN' : 'WireGuard'} selected — create VPN instances and users from the Access VPN module after setup.` }] : []),
      ...infoModules.map((m): RunItem => ({ id: `info:module:${m.name}`, phase: 'Services', label: m.name, state: 'info', detail: NOT_IMPLEMENTED.has(m.name) ? 'Placeholder module — no services to start yet.' : 'No local services required.' })),
      ...infoTools.map((t): RunItem => ({ id: `info:tool:${t.name}`, phase: 'Services', label: t.name, state: 'info', detail: 'External tool — opens embedded once its URL is set in Configuration → Tools.' })),
      { id: 'finalize', phase: 'Finalize', label: 'Mark setup as complete', state: 'pending', detail: '' },
    ];
    setRunItems(items);

    const nextSettings: Settings = {
      ...settings,
      platform_title: appName.trim() || 'OpenSMART',
      proxy_hostname: proxyHostname.trim(),
      logo_url: logoDraft,
      monitor_interfaces: effectiveIfaces.join(','),
    };
    enabledTools.forEach((tool) => {
      const definition = toolDefinitions[tool.name];
      const makeUrl = DEFAULT_TOOL_URLS[tool.name];
      if (definition && makeUrl && !(settings[definition.key] || '').trim()) nextSettings[definition.key] = makeUrl(host);
    });

    try {
      updateItem('save-settings', { state: 'running' });
      await api.saveSettings(nextSettings);
      updateItem('save-settings', { state: 'ok', detail: 'Saved.' });

      updateItem('save-modules', { state: 'running' });
      const modulesPayload = modules.map((m) => {
        let config = m.config;
        if (m.enabled && MODULE_CONFIG_DEFAULTS[m.name]) config = mergeConfig(config, MODULE_CONFIG_DEFAULTS[m.name]);
        if (m.name === 'Access VPN' && m.enabled) config = mergeConfig(config, { vpn_type: vpnType });
        return { ...m, config };
      });
      const savedModules = await api.saveOpenSmartModules(modulesPayload);
      handleModulesUpdate(savedModules.modules);
      updateItem('save-modules', { state: 'ok', detail: 'Saved.' });

      updateItem('save-tools', { state: 'running' });
      const savedTools = await api.saveTools(tools);
      handleToolsUpdate(savedTools.tools);
      updateItem('save-tools', { state: 'ok', detail: 'Saved.' });

      for (const [kind, item] of [...provisionModules.map((m) => ['module', m] as const), ...provisionTools.map((t) => ['tool', t] as const)]) {
        const id = `${kind}:${item.name}`;
        updateItem(id, { state: 'running' });
        try {
          const result: ProvisionResult = await api.provisionStart(item.name, kind);
          const containerResults = result.containers || [];
          const okCount = containerResults.filter((c) => c.ok).length;
          const state: RunState = result.ok ? 'ok' : okCount > 0 ? 'warning' : 'error';
          updateItem(id, {
            state,
            detail: result.ok ? 'Started.' : result.detail || 'One or more services failed to start.',
            containers: containerResults,
          });
        } catch (error) {
          updateItem(id, { state: 'error', detail: error instanceof Error ? error.message : 'Provisioning request failed.' });
        }
      }

      // (Re)start the front-door proxy so it picks up the hostname just
      // saved — its init step re-issues the self-signed certificate for it.
      updateItem('container:nginx', { state: 'running' });
      try {
        const proxyResult = await api.provisionStart('nginx', 'container');
        updateItem('container:nginx', {
          state: proxyResult.ok ? 'ok' : 'warning',
          detail: proxyResult.ok
            ? `Serving https://${proxyHostname.trim() || host}/ with a self-signed certificate (accept the browser warning once).`
            : proxyResult.detail || 'Proxy failed to start — tool aliases will be unavailable; the app itself is unaffected.',
        });
      } catch (error) {
        updateItem('container:nginx', { state: 'warning', detail: error instanceof Error ? error.message : 'Proxy failed to start — tool aliases will be unavailable.' });
      }

      updateItem('finalize', { state: 'running' });
      await api.saveSettings({ ...nextSettings, wizard_completed: 'true' });
      updateItem('finalize', { state: 'ok', detail: 'Setup marked complete.' });
      setRunDone(true);
    } catch (error) {
      setRunError(error instanceof Error ? error.message : 'Setup failed.');
      setRunItems((prev) => prev.map((item) => (item.state === 'running' ? { ...item, state: 'error', detail: error instanceof Error ? error.message : 'Failed.' } : item)));
    } finally {
      setRunning(false);
    }
  }

  async function enterApp() {
    setSettings({ ...settings, wizard_completed: 'true' });
    await onComplete?.();
  }

  const doneCount = runItems.filter((item) => item.state === 'ok' || item.state === 'warning' || item.state === 'error' || item.state === 'info').length;
  const progressPct = runItems.length ? Math.round((doneCount / runItems.length) * 100) : 0;
  const errorItems = runItems.filter((item) => item.state === 'error');
  const warningItems = runItems.filter((item) => item.state === 'warning');
  const infoItems = runItems.filter((item) => item.state === 'info');
  const runStarted = runItems.length > 0;

  const physical = (interfaces || []).filter((i) => !i.virtual);
  const virtual = (interfaces || []).filter((i) => i.virtual);
  const accessVpn = modules.find((m) => m.name === 'Access VPN');

  const stateBadge: Record<RunState, { className: string; label: string }> = {
    pending: { className: 'muted', label: 'Pending' },
    running: { className: 'ok-dim', label: 'Working…' },
    ok: { className: 'ok', label: 'OK' },
    warning: { className: 'warning', label: 'Warning' },
    error: { className: 'danger', label: 'Error' },
    info: { className: 'muted', label: 'Info' },
  };

  return (
    <section className="settings-shell wizard-shell">
      <div className="settings-tabs" role="tablist" aria-label="Setup wizard steps">
        {steps.map((item) => (
          <button
            key={item.key}
            className={step === item.key ? 'active' : ''}
            onClick={() => setStep(item.key)}
            disabled={!visited.has(item.key) || runStarted}
            role="tab"
            aria-selected={step === item.key}
          >
            {item.label}
          </button>
        ))}
      </div>

      {step === 'basics' && (
        <article className="card">
          <h2>Welcome to OpenSMART</h2>
          <p className="muted">
            Version {settings.platform_version} (build {settings.platform_build}). To update later, run <code>./opensmart.sh install</code> on the host.
          </p>
          <label className="wizard-field">
            Application name
            <input type="text" value={appName} maxLength={60} onChange={(event) => setAppName(event.target.value)} placeholder="OpenSMART" />
          </label>
          <label className="wizard-field">
            Hostname (reverse-proxy access)
            <input type="text" value={proxyHostname} maxLength={253} pattern="[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?" title="letters, digits, dots and dashes" onChange={(event) => setProxyHostname(event.target.value)} placeholder={window.location.hostname} />
            <small className="muted">The name users will reach OpenSMART with (e.g. opensmart.example.local). Used as the front-door proxy&apos;s server name and its self-signed certificate&apos;s subject — the certificate is re-issued automatically when this changes.</small>
          </label>
          <div className="logo-upload-grid">
            <label>
              Logo (optional)
              <span className="logo-preview">{logoDraft ? <img src={logoDraft} alt="Logo preview" /> : 'Default branding'}</span>
              <input type="file" accept="image/*,.svg" onChange={uploadLogo} />
            </label>
          </div>
          <div className="config-save-bar">
            <button disabled={!appName.trim()} onClick={() => goTo('network')}>Next: Network</button>
          </div>
        </article>
      )}

      {step === 'network' && (
        <article className="card">
          <h2>Network interfaces to monitor</h2>
          <p className="muted">Suricata (and Zeek) will capture traffic on the selected interfaces. Physical interfaces detected on the host are listed first.</p>
          {ifacesLoading && <p className="muted">Detecting host interfaces…</p>}
          {ifaceError && (
            <>
              <p className="error-text">Interface detection failed: {ifaceError}</p>
              <label className="wizard-field">
                Enter interface names manually (comma-separated)
                <input type="text" value={manualIfaces} onChange={(event) => setManualIfaces(event.target.value)} placeholder="eth0,eth1" />
              </label>
              <button className="btn-secondary" onClick={loadInterfaces}>Retry detection</button>
            </>
          )}
          {interfaces !== null && (
            <div className="iface-list">
              {physical.map((iface) => (
                <label key={iface.name} className={`iface-row ${selectedIfaces.has(iface.name) ? 'selected' : ''}`}>
                  <input type="checkbox" checked={selectedIfaces.has(iface.name)} onChange={() => toggleIface(iface.name)} />
                  <span><strong>{iface.name}</strong><small className="muted">{iface.up ? 'up' : 'down'} · MTU {iface.mtu}</small></span>
                </label>
              ))}
              {virtual.length > 0 && (
                <button className="warning-toggle" onClick={() => setShowVirtual((v) => !v)}>
                  {showVirtual ? 'Hide' : 'Show'} {virtual.length} virtual interfaces (bridges, veth, tunnels)
                </button>
              )}
              {showVirtual && virtual.map((iface) => (
                <label key={iface.name} className={`iface-row virtual ${selectedIfaces.has(iface.name) ? 'selected' : ''}`}>
                  <input type="checkbox" checked={selectedIfaces.has(iface.name)} onChange={() => toggleIface(iface.name)} />
                  <span><strong>{iface.name}</strong><small className="muted">virtual · {iface.up ? 'up' : 'down'} · MTU {iface.mtu}</small></span>
                </label>
              ))}
            </div>
          )}
          <div className="config-save-bar">
            <button className="btn-secondary" onClick={() => setStep('basics')}>Back</button>
            <button disabled={effectiveIfaces.length === 0} onClick={() => goTo('features')}>Next: Modules &amp; Tools</button>
          </div>
        </article>
      )}

      {step === 'features' && (
        <>
          {notices.map((notice) => <p key={notice} className="wizard-notice">{notice}</p>)}
          {hostResources && hostResources.tier !== 'full' && (
            <p className="wizard-notice warning">
              ⚠ This host's resources ({hostResources.cpu_count} CPU / {hostResources.memory_total_mb}MB RAM / {hostResources.disk_free_gb}GB free disk, detected at install time) are below the recommended tier
              ({hostResources.recommended_tiers.full.cpu} CPU / {hostResources.recommended_tiers.full.memory_mb}MB RAM / {hostResources.recommended_tiers.full.disk_gb}GB disk) for the full tool set.
              {' '}{[...constrainedTools].join(' and ') || 'Some tools'} run a JVM-based OpenSearch-family indexer and are the most likely to be unstable — flagged below.
              {hostResources.tier === 'minimal' && ' This host is also below the minimal recommended tier, so even lightweight modules may be unstable under real traffic.'}
              {' '}Re-run <code>sudo ./opensmart.sh install</code> after resizing the host to refresh this check.
            </p>
          )}
          <article className="card">
            <h2>OpenSMART Modules</h2>
            <div className="wizard-feature-grid">
              {modules.map((module) => (
                <label key={module.id} className={`feature-card ${module.enabled ? 'enabled' : ''} ${constrainedModules.has(module.name) ? 'constrained' : ''}`}>
                  <input type="checkbox" checked={module.enabled} onChange={() => toggleModule(module)} />
                  <span>
                    <strong>{module.name}</strong>
                    <small className="muted">{module.description}</small>
                    {NOT_IMPLEMENTED.has(module.name) && <em className="feature-tag">placeholder</em>}
                    {(MODULE_REQUIRES_TOOL[module.name] || []).length > 0 && <em className="feature-tag">requires {(MODULE_REQUIRES_TOOL[module.name] || []).join(', ')}</em>}
                    {constrainedModules.has(module.name) && <em className="feature-tag warning">⚠ host resources limited</em>}
                  </span>
                </label>
              ))}
            </div>
            {accessVpn?.enabled && (
              <label className="wizard-field wizard-vpn-type">
                VPN type for Access VPN
                <select value={vpnType} onChange={(event) => setVpnType(event.target.value as 'openvpn' | 'wireguard')}>
                  <option value="openvpn">OpenVPN (default)</option>
                  <option value="wireguard">WireGuard</option>
                </select>
              </label>
            )}
          </article>
          <article className="card">
            <h2>Tools</h2>
            <p className="muted">Enabled tools open embedded inside OpenSMART once their URL is configured. Wazuh and Arkime run locally and get a working URL automatically.</p>
            <div className="wizard-feature-grid">
              {tools.map((tool) => (
                <label key={tool.id} className={`feature-card ${tool.enabled ? 'enabled' : ''} ${constrainedTools.has(tool.name) ? 'constrained' : ''}`}>
                  <input type="checkbox" checked={tool.enabled} onChange={() => toggleTool(tool)} />
                  <span>
                    <strong>{toolDefinitions[tool.name]?.title || tool.name}</strong>
                    <small className="muted">{tool.description}</small>
                    {NOT_IMPLEMENTED.has(tool.name) && <em className="feature-tag">placeholder</em>}
                    {(TOOL_BACKING[tool.name] || []).length > 0 && <em className="feature-tag">runs locally</em>}
                    {constrainedTools.has(tool.name) && <em className="feature-tag warning">⚠ host resources limited</em>}
                  </span>
                </label>
              ))}
            </div>
          </article>
          <div className="config-save-bar">
            <button className="btn-secondary" onClick={() => setStep('network')}>Back</button>
            <button onClick={() => goTo('provision')}>Next: Provision</button>
          </div>
        </>
      )}

      {step === 'provision' && (
        <article className="card">
          <h2>{runDone ? 'Setup complete' : runStarted ? 'Provisioning…' : 'Ready to provision'}</h2>
          {!runStarted && (
            <>
              <p>
                OpenSMART will save your configuration and start the services backing your selection:
                monitoring on <strong>{effectiveIfaces.join(', ') || 'no interfaces'}</strong>,{' '}
                {modules.filter((m) => m.enabled).length} modules and {tools.filter((t) => t.enabled).length} tools enabled.
                Everything can be changed later under Configuration.
              </p>
              <div className="config-save-bar">
                <button className="btn-secondary" onClick={() => setStep('features')}>Back</button>
                <button disabled={running} onClick={runProvisioning}>Start provisioning</button>
              </div>
            </>
          )}
          {runStarted && (
            <>
              <div className="wizard-progress"><div className="wizard-progress-fill" style={{ width: `${progressPct}%` }} /></div>
              <div className="provision-list">
                {['Configuration', 'Services', 'Finalize'].map((phase) => {
                  const phaseItems = runItems.filter((item) => item.phase === phase);
                  if (!phaseItems.length) return null;
                  return (
                    <div key={phase} className="provision-phase">
                      <h3>{phase}</h3>
                      {phaseItems.map((item) => (
                        <div key={item.id} className={`provision-row ${item.state}`}>
                          <span className={`badge ${stateBadge[item.state].className}`}>{stateBadge[item.state].label}</span>
                          <span>
                            <strong>{item.label}</strong>
                            {item.detail && <small className="muted">{item.detail}</small>}
                            {(item.containers || []).filter((c) => !c.ok).map((c) => (
                              <small key={c.container} className="error-text">{PROJECT_LABELS[c.container] ?? c.container}: {c.detail || 'failed'}</small>
                            ))}
                          </span>
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
              {runError && <p className="error-text">{runError}</p>}
              {runDone && (
                <>
                  <div className="wizard-summary">
                    {errorItems.length > 0 && <p className="error-text">{errorItems.length} item(s) failed — check the Status page after entering the app.</p>}
                    {warningItems.length > 0 && <p className="wizard-summary-warning">{warningItems.length} item(s) started partially.</p>}
                    {infoItems.length > 0 && <p className="muted">{infoItems.length} informational note(s) above.</p>}
                    {errorItems.length === 0 && warningItems.length === 0 && <p className="wizard-summary-ok">All services started successfully.</p>}
                  </div>
                  <div className="config-save-bar">
                    <button onClick={enterApp}>Enter {appName.trim() || 'OpenSMART'}</button>
                  </div>
                </>
              )}
            </>
          )}
        </article>
      )}
    </section>
  );
}
