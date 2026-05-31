import { useEffect, useState } from 'react';
import { api } from '../api';
import type { Settings } from '../types';

type Props = { settings: Settings; setSettings: (settings: Settings) => void };

const groups = [
  {
    title: 'IDS Notifications',
    webhook: 'notification_ids_webhook',
    status: 'notification_ids_webhook_status',
    error: 'notification_ids_webhook_error',
    events: [
      ['notification_ids_event_critical_alerts', 'IDS Critical Alerts', 'Notify when there is a new Critical IDS alert.'],
      ['notification_ids_event_system_events', 'IDS System events', 'Platform events related with IDS module.'],
    ],
  },
  {
    title: 'Network Notifications',
    webhook: 'notification_network_webhook',
    status: 'notification_network_webhook_status',
    error: 'notification_network_webhook_error',
    events: [
      ['notification_network_event_anomalies', 'Network Anomalies', 'Placeholder for future Network anomaly notifications.'],
      ['notification_network_event_system_events', 'Network System events', 'Placeholder for platform events related with Network module.'],
    ],
  },
  {
    title: 'OpenSMART Platform',
    webhook: 'notification_platform_webhook',
    status: 'notification_platform_webhook_status',
    error: 'notification_platform_webhook_error',
    events: [
      ['notification_platform_event_health_alerts', 'Health Alerts notifications', 'Placeholder for platform health notifications.'],
      ['notification_platform_event_internal_feeds', 'Internal Feeds (HoneyMex news)', 'Placeholder for internal feed notifications.'],
    ],
  },
];

export default function NotificationsPage({ settings, setSettings }: Props) {
  const [draft, setDraft] = useState<Settings>(settings);
  const [message, setMessage] = useState('');
  const [testing, setTesting] = useState('');
  useEffect(() => setDraft(settings), [settings]);

  async function save() {
    const result = await api.saveSettings(draft);
    setSettings(result.settings);
    setDraft(result.settings);
    setMessage('Notification settings saved. Webhooks were validated when changed.');
  }

  function update(key: string, value: string) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  async function testWebhook(group: typeof groups[number]) {
    const url = (draft[group.webhook] || '').trim();
    if (!url) return;
    setTesting(group.webhook);
    try {
      const result = await api.testWebhook(url, group.title);
      const next = {
        ...draft,
        [group.status]: result.ok ? 'ok' : 'warning',
        [group.error]: result.ok ? '' : result.detail,
      };
      setDraft(next);
      setMessage(result.ok ? 'Test message sent successfully.' : `Webhook test failed: ${result.detail}`);
    } finally {
      setTesting('');
    }
  }

  const warnings = groups.filter((group) => draft[group.status] === 'warning');

  return (
    <section className="admin-stack notifications-page">
      <article className="card">
        <h2>Notifications</h2>
        <p className="muted">Configure outbound webhooks. Only IDS Critical Alerts and IDS System events emit notifications in this release.</p>
      </article>
      <div className="notification-grid">
        {groups.map((group) => (
          <article className="card notification-card" key={group.title}>
            <div className="notification-card-head">
              <h2>{group.title} {group.title === 'IDS Notifications' && draft[group.status] === 'ok' && <span className="webhook-status ok">Active</span>}</h2>
              <WebhookStatus status={draft[group.status]} error={draft[group.error]} />
            </div>
            <label>Webhook<input type="url" placeholder="https://webhook.example/path" value={draft[group.webhook] || ''} onChange={(event) => update(group.webhook, event.target.value)} /></label>
            <button type="button" className="secondary-btn" disabled={testing === group.webhook || !(draft[group.webhook] || '').trim()} onClick={() => testWebhook(group)}>{testing === group.webhook ? 'Testing...' : 'Test Webhook'}</button>
            <div className="notification-events">
              <strong>Events</strong>
              {group.events.map(([key, label, help]) => (
                <div className="checkbox-row" key={key}>
                  <Toggle checked={draft[key] === 'true'} onChange={(checked) => update(key, checked ? 'true' : 'false')} />
                  <span>{label}<small className="muted">{help}</small></span>
                </div>
              ))}
            </div>
          </article>
        ))}
      </div>
      {warnings.length > 0 && <article className="card notification-warning-details" id="notification-warning-details"><h2>Webhook Warning Details</h2>{warnings.map((group) => <p key={group.title}><strong>{group.title}</strong>: {draft[group.error] || 'Webhook validation failed.'}</p>)}</article>}
      <div className="config-save-bar">
        {message && <p className="save-message">{message}</p>}
        <button onClick={save}>Save notifications</button>
      </div>
    </section>
  );
}

function WebhookStatus({ status, error }: { status?: string; error?: string }) {
  if (status === 'ok') return <span className="webhook-status ok">OK</span>;
  if (status === 'warning') return <a className="webhook-status warning" href="#notification-warning-details" title={error || 'Webhook validation failed'}>Warning</a>;
  return <span className="webhook-status muted">Not configured</span>;
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (checked: boolean) => void }) {
  return <button role="switch" aria-checked={checked} className={`toggle-switch ${checked ? 'on' : ''}`} onClick={() => onChange(!checked)}><span className="toggle-thumb" /></button>;
}
