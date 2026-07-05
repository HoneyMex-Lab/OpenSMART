import { useEffect, useState } from 'react';
import { api } from '../api';
import type { Settings, ToolConfig } from '../types';
import { toolDefinitions } from './toolDefinitions';

type DiffEntry = { field: string; from: string; to: string };

function computeDiff(origSettings: Settings, draftSettings: Settings, origTools: ToolConfig[], draftTools: ToolConfig[]): DiffEntry[] {
  const result: DiffEntry[] = [];
  const keys = new Set([...Object.keys(origSettings), ...Object.keys(draftSettings)]);
  keys.forEach((key) => {
    const from = origSettings[key] ?? '';
    const to = draftSettings[key] ?? '';
    if (from !== to) result.push({ field: key, from: summarizeValue(key, from), to: summarizeValue(key, to) });
  });
  draftTools.forEach((tool) => {
    const orig = origTools.find((t) => t.id === tool.id);
    if (!orig) return;
    if (orig.enabled !== tool.enabled) result.push({ field: `${tool.name}: status`, from: orig.enabled ? 'Enabled' : 'Disabled', to: tool.enabled ? 'Enabled' : 'Disabled' });
    if (orig.config !== tool.config) result.push({ field: `${tool.name}: configuration`, from: 'current configuration', to: summarizeConfigChange(orig.config, tool.config) });
  });
  return result;
}

function summarizeValue(key: string, value: string): string {
  if (key.includes('logo') || key.includes('favicon') || value.startsWith('data:image/')) return value ? 'image configured' : 'empty';
  if (value.length > 80) return `${value.slice(0, 77)}...`;
  return value || 'empty';
}

function summarizeConfigChange(fromRaw: string, toRaw: string): string {
  try {
    const from = JSON.parse(fromRaw || '{}');
    const to = JSON.parse(toRaw || '{}');
    const keys = new Set([...Object.keys(from), ...Object.keys(to)]);
    const changed = [...keys].filter((key) => String(from[key] ?? '') !== String(to[key] ?? '')).length;
    return changed ? `${changed} setting${changed === 1 ? '' : 's'} updated` : 'configuration updated';
  } catch {
    return 'custom configuration';
  }
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

export default function ToolsConfigPage({ settings, setSettings, tools, onToolsUpdate }: { settings: Settings; setSettings: (settings: Settings) => void; tools: ToolConfig[]; onToolsUpdate: (tools: ToolConfig[]) => void }) {
  const [settingsDraft, setSettingsDraft] = useState<Settings>(settings);
  const [toolDraft, setToolDraft] = useState<ToolConfig[]>(tools);
  const [visibleJson, setVisibleJson] = useState<Record<number, boolean>>({});
  const [message, setMessage] = useState('');
  const [pendingDiff, setPendingDiff] = useState<DiffEntry[] | null>(null);
  const [activeId, setActiveId] = useState<number | null>(tools[0]?.id ?? null);

  useEffect(() => { setSettingsDraft(settings); }, [settings]);
  useEffect(() => {
    setToolDraft(tools);
    setActiveId((prev) => (prev === null && tools.length > 0 ? tools[0].id : prev));
  }, [tools]);

  function requestSave() {
    setPendingDiff(computeDiff(settings, settingsDraft, tools, toolDraft));
  }

  async function confirmSave() {
    setPendingDiff(null);
    const [settingsResult, toolsResult] = await Promise.all([api.saveSettings(settingsDraft), api.saveTools(toolDraft)]);
    setSettings(settingsResult.settings);
    onToolsUpdate(toolsResult.tools);
    setMessage('Tools configuration saved.');
  }

  const activeTool = toolDraft.find((t) => t.id === activeId) ?? toolDraft[0];

  return (
    <section className="config-card-list">
      {pendingDiff !== null && <ConfirmDialog diff={pendingDiff} onConfirm={confirmSave} onCancel={() => setPendingDiff(null)} />}

      <div className="config-subtabs">
        {toolDraft.map((tool) => {
          const def = toolDefinitions[tool.name];
          return (
            <button key={tool.id} className={activeId === tool.id ? 'active' : ''} onClick={() => setActiveId(tool.id)}>
              {def?.logo && <img src={def.logo} alt="" style={{ width: 18, height: 18, objectFit: 'contain', borderRadius: 4, background: 'rgba(255,255,255,.9)', padding: 2 }} />}
              {def?.title || tool.name}
            </button>
          );
        })}
      </div>

      {activeTool && (() => {
        const definition = toolDefinitions[activeTool.name] || { key: '', title: activeTool.name, logo: '/assets/tools/lxc-manager.svg' };
        const url = settingsDraft[definition.key] || '';
        return (
          <article className="card config-item">
            <div className="config-heading">
              <img src={definition.logo} alt="" />
              <div>
                <h2>{definition.title}</h2>
                <p className="muted">{activeTool.description}</p>
              </div>
            </div>
            <div className="config-toggle-row">
              <span className="toggle-label-inline">Enabled</span>
              <Toggle checked={activeTool.enabled} onChange={(checked) => setToolDraft(toolDraft.map((item) => item.id === activeTool.id ? { ...item, enabled: checked } : item))} />
            </div>
            <label>Internal URL<input type="url" placeholder="https://tool.example.local" value={url} onChange={(event) => setSettingsDraft({ ...settingsDraft, [definition.key]: event.target.value })} /></label>
            <button className="text-button" onClick={() => setVisibleJson({ ...visibleJson, [activeTool.id]: !visibleJson[activeTool.id] })}>{visibleJson[activeTool.id] ? 'Hide JSON config' : 'Show JSON config'}</button>
            {visibleJson[activeTool.id] && <label>JSON Configuration<textarea value={activeTool.config} onChange={(event) => setToolDraft(toolDraft.map((item) => item.id === activeTool.id ? { ...item, config: event.target.value } : item))} /></label>}
          </article>
        );
      })()}

      <div className="config-save-bar">
        {message && <p className="save-message">{message}</p>}
        <button onClick={requestSave}>Save tools configuration</button>
      </div>
    </section>
  );
}
