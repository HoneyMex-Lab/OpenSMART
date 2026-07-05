import { ChangeEvent, useEffect, useState } from 'react';
import { api } from '../api';
import type { OpenSmartModule, ProvisionResult, Settings, ToolConfig } from '../types';
import OpenSmartConfigPage from './OpenSmartConfigPage';
import ToolsConfigPage from './ToolsConfigPage';

type StepKey = 'update' | 'logo' | 'modules' | 'tools' | 'finish';

const steps: { key: StepKey; label: string }[] = [
  { key: 'update', label: '1. Update' },
  { key: 'logo', label: '2. Logo' },
  { key: 'modules', label: '3. OpenSMART Modules' },
  { key: 'tools', label: '4. Tools' },
  { key: 'finish', label: '5. Finish' },
];

type Props = {
  settings: Settings;
  setSettings: (settings: Settings) => void;
  modules?: OpenSmartModule[];
  onModulesUpdate?: (modules: OpenSmartModule[]) => void;
  tools?: ToolConfig[];
  onToolsUpdate?: (tools: ToolConfig[]) => void;
  onComplete?: () => void;
};

export default function WizardPage({ settings, setSettings, modules: modulesProp, onModulesUpdate, tools: toolsProp, onToolsUpdate, onComplete }: Props) {
  const [step, setStep] = useState<StepKey>('update');
  const [updateAcknowledged, setUpdateAcknowledged] = useState(false);
  const [localModules, setLocalModules] = useState<OpenSmartModule[]>(modulesProp ?? []);
  const [localTools, setLocalTools] = useState<ToolConfig[]>(toolsProp ?? []);
  const [logoDraft, setLogoDraft] = useState(settings.logo_url || '');
  const [logoMessage, setLogoMessage] = useState('');
  const [finishing, setFinishing] = useState(false);
  const [finished, setFinished] = useState(false);
  const [provisionResults, setProvisionResults] = useState<ProvisionResult[]>([]);

  useEffect(() => {
    if (modulesProp) return;
    api.openSmartModules().then((result) => setLocalModules(result.modules)).catch(() => undefined);
  }, [modulesProp]);

  useEffect(() => {
    if (toolsProp) return;
    api.tools().then((result) => setLocalTools(result.tools)).catch(() => undefined);
  }, [toolsProp]);

  const modules = modulesProp ?? localModules;
  const handleModulesUpdate = onModulesUpdate ?? setLocalModules;
  const tools = toolsProp ?? localTools;
  const handleToolsUpdate = onToolsUpdate ?? setLocalTools;

  function uploadLogo(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setLogoDraft(String(reader.result || ''));
    reader.readAsDataURL(file);
  }

  async function saveLogo() {
    const result = await api.saveSettings({ ...settings, logo_url: logoDraft });
    setSettings(result.settings);
    setLogoMessage('Logo saved.');
  }

  async function finish() {
    setFinishing(true);
    try {
      const enabledModules = modules.filter((m) => m.enabled);
      const enabledTools = tools.filter((t) => t.enabled);
      const results = await Promise.all([
        ...enabledModules.map((m) => api.provisionStart(m.name, 'module').catch((error): ProvisionResult => ({ name: m.name, ok: false, detail: error instanceof Error ? error.message : 'Failed to provision', containers: [] }))),
        ...enabledTools.map((t) => api.provisionStart(t.name, 'tool').catch((error): ProvisionResult => ({ name: t.name, ok: false, detail: error instanceof Error ? error.message : 'Failed to provision', containers: [] }))),
      ]);
      setProvisionResults(results);
      const result = await api.saveSettings({ ...settings, wizard_completed: 'true' });
      setSettings(result.settings);
      setFinished(true);
      await onComplete?.();
    } finally {
      setFinishing(false);
    }
  }

  return (
    <section className="settings-shell wizard-shell">
      <div className="settings-tabs" role="tablist" aria-label="Setup wizard steps">
        {steps.map((item) => (
          <button
            key={item.key}
            className={step === item.key ? 'active' : ''}
            onClick={() => setStep(item.key)}
            disabled={item.key !== 'update' && !updateAcknowledged}
            role="tab"
            aria-selected={step === item.key}
          >
            {item.label}
          </button>
        ))}
      </div>

      {step === 'update' && (
        <article className="card">
          <h2>Update the Framework App</h2>
          <p className="muted">Running version: <strong>{settings.platform_version}</strong> (build {settings.platform_build})</p>
          <p>
            Before continuing, confirm OpenSMART is on its latest release. Check the project repository for newer
            releases, or run <code>./opensmart.sh install</code> / <code>--recreate</code> to rebuild against the
            latest code, then come back to this step.
          </p>
          <label className="toggle-label">
            <input type="checkbox" checked={updateAcknowledged} onChange={(event) => setUpdateAcknowledged(event.target.checked)} />
            {' '}I've updated OpenSMART, or confirmed I'm already on the latest version.
          </label>
          <div className="config-save-bar">
            <button disabled={!updateAcknowledged} onClick={() => setStep('logo')}>Next: Logo</button>
          </div>
        </article>
      )}

      {step === 'logo' && (
        <article className="card">
          <h2>Logo</h2>
          <p className="muted">Optional. If skipped, the default OpenSMART branding is used.</p>
          <div className="logo-upload-grid">
            <label>
              Main logo
              <span className="logo-preview">{logoDraft ? <img src={logoDraft} alt="Logo preview" /> : 'No image'}</span>
              <input type="file" accept="image/*,.svg" onChange={uploadLogo} />
            </label>
          </div>
          {logoMessage && <p className="save-message">{logoMessage}</p>}
          <div className="config-save-bar">
            <button className="btn-secondary" onClick={() => setStep('modules')}>Skip</button>
            <button onClick={async () => { await saveLogo(); setStep('modules'); }}>Save &amp; Continue</button>
          </div>
        </article>
      )}

      {step === 'modules' && (
        <>
          <p className="muted wizard-step-help">Enable the OpenSMART modules you want to use. Configuration options appear once a module is enabled.</p>
          <OpenSmartConfigPage modules={modules} onModulesUpdate={handleModulesUpdate} />
          <div className="config-save-bar">
            <button onClick={() => setStep('tools')}>Next: Tools</button>
          </div>
        </>
      )}

      {step === 'tools' && (
        <>
          <p className="muted wizard-step-help">Enable the Tools you want linked from OpenSMART.</p>
          <ToolsConfigPage settings={settings} setSettings={setSettings} tools={tools} onToolsUpdate={handleToolsUpdate} />
          <div className="config-save-bar">
            <button onClick={() => setStep('finish')}>Next: Finish</button>
          </div>
        </>
      )}

      {step === 'finish' && (
        <article className="card hero-card">
          <h2>{finished ? 'Setup complete' : 'Ready to finish setup'}</h2>
          <p>
            {finished
              ? 'OpenSMART is configured. Provisioning results for enabled modules/tools are below.'
              : 'Finishing setup will attempt to start the containers backing your enabled modules/tools. You can revisit these settings anytime from Configuration.'}
          </p>
          {!finished && <button disabled={finishing} onClick={finish}>{finishing ? 'Provisioning...' : 'Finish setup'}</button>}
          {finished && provisionResults.length > 0 && (
            <div className="config-field-table" style={{ marginTop: 16 }}>
              {provisionResults.map((result) => (
                <div className="checkbox-row" key={result.name}>
                  <span className={`badge ${result.ok ? 'ok-dim' : 'warning'}`}>{result.ok ? 'OK' : 'Attention'}</span>
                  <span>
                    <strong>{result.name}</strong>
                    <small className="muted">{result.detail || (result.ok ? 'Started.' : 'No detail available.')}</small>
                  </span>
                </div>
              ))}
            </div>
          )}
        </article>
      )}
    </section>
  );
}
