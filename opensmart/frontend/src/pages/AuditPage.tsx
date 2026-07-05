import { useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { api } from '../api';
import type { AuditEvent } from '../types';

type Tab = 'events' | 'log';

interface Props {
  user: { role: string };
}

export default function AuditPage({ user }: Props) {
  const [tab, setTab] = useState<Tab>('events');
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [logLines, setLogLines] = useState<string[]>([]);
  const [logPath, setLogPath] = useState('');
  const [logError, setLogError] = useState<string | null>(null);
  const [logLoading, setLogLoading] = useState(false);
  const [logN, setLogN] = useState(500);

  useEffect(() => {
    api.audit().then((result) => setEvents(result.events)).catch(() => setEvents([]));
  }, []);

  useEffect(() => {
    // Intentionally reload only on tab switch, not on every logN change —
    // the line-count dropdown is applied via the explicit Refresh button.
    if (tab === 'log') loadLog(logN);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  async function loadLog(lines: number) {
    setLogLoading(true);
    setLogError(null);
    try {
      const result = await api.auditLog(lines);
      setLogLines(result.lines);
      setLogPath(result.path);
      setLogError(result.error);
    } catch {
      setLogError('Failed to load log file.');
    } finally {
      setLogLoading(false);
    }
  }

  function onChangeLogN(value: number) {
    setLogN(value);
  }

  return (
    <section className="card">
      <div className="audit-tabs">
        <button className={tab === 'events' ? 'active' : ''} onClick={() => setTab('events')}>Audit Events</button>
        {user.role === 'admin' && (
          <button className={tab === 'log' ? 'active' : ''} onClick={() => setTab('log')}>Application Log</button>
        )}
      </div>

      {tab === 'events' && (
        <>
          <h2>Audit</h2>
          <p className="muted">Last 100 relevant activity entries.</p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Date</th><th>Event</th><th>Actor</th><th>Target</th><th>IP</th><th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event, index) => (
                  <tr key={`${event.created_at}-${index}`}>
                    <td>{event.created_at}</td>
                    <td><span className={`audit-event-pill ${auditEventClass(event.event_type)}`}>{event.event_type}</span></td>
                    <td>{event.actor_username}</td>
                    <td>{event.target}</td>
                    <td>{event.ip_address}</td>
                    <td>{event.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {tab === 'log' && (
        <>
          <div className="audit-log-toolbar">
            <h2>Application Log</h2>
            <label>
              Lines
              <input
                type="number"
                min="1"
                max="5000"
                value={logN}
                onChange={(e) => onChangeLogN(Number(e.target.value) || 500)}
              />
            </label>
            <button onClick={() => loadLog(logN)} disabled={logLoading}>
              <RefreshCw size={14} /> {logLoading ? 'Loading…' : 'Refresh'}
            </button>
          </div>
          {logPath && <p className="muted audit-log-path">{logPath}</p>}
          {logError && <p className="error-box">{logError}</p>}
          <pre className="audit-log-pre">
            {logLines.length === 0 && !logLoading ? 'No log entries found.' : logLines.join('\n')}
          </pre>
        </>
      )}
    </section>
  );
}

function auditEventClass(value: string) {
  const lower = value.toLowerCase();
  if (lower.includes('logon') || lower.includes('login') || lower.includes('logout')) return 'audit-event-auth';
  if (lower.includes('config') || lower.includes('setting') || lower.includes('update') || lower.includes('save')) return 'audit-event-config';
  if (lower.includes('reset') || lower.includes('delete') || lower.includes('failed') || lower.includes('error')) return 'audit-event-danger';
  return 'audit-event-neutral';
}
