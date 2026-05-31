import { AlertTriangle, RefreshCw } from 'lucide-react';

export type FilterStatus = {
  last_updated?: string;
  current_action?: string;
  progress_percent?: number;
  last_check_alerts_read?: number;
  last_check_network_read?: number;
  last_check_non_alerts?: number;
  last_check_bytes_read?: number;
  last_check_bytes_total?: number;
} | null;

const timeframes = ['1h', '4h', '1d', '3d', '7d', '30d', '90d', 'all', 'custom'];

export default function TimeframeFilterBar({
  status,
  timeframe,
  setTimeframe,
  customStart,
  setCustomStart,
  customEnd,
  setCustomEnd,
  q,
  setQ,
  topN,
  setTopN,
  topNMax,
  busy,
  queryRunning,
  loadingAction,
  queryDisabled = false,
  queryDisabledReason = '',
  searchPlaceholder,
  onRun,
  onClear,
  onRefresh,
  onCancel,
}: {
  status: FilterStatus;
  timeframe: string;
  setTimeframe: (value: string) => void;
  customStart: string;
  setCustomStart: (value: string) => void;
  customEnd: string;
  setCustomEnd: (value: string) => void;
  q: string;
  setQ: (value: string) => void;
  topN: number;
  setTopN: (value: number) => void;
  topNMax: number;
  busy: boolean;
  queryRunning: boolean;
  loadingAction: string;
  queryDisabled?: boolean;
  queryDisabledReason?: string;
  searchPlaceholder: string;
  onRun: () => void;
  onClear?: () => void;
  onRefresh: () => void;
  onCancel: () => void;
}) {
  const progress = status?.progress_percent || 0;
  const action = busy ? loadingAction : status?.current_action || 'Idle';
  const actionDisabled = busy || queryDisabled;
  return (
    <>
      <div className="ids-filterbar timeframe-filterbar compact">
        <div className="ids-refresh-status timeframe-status">
          <span>Last updated</span>
          <div className="ids-ts-row">
            <strong>{status?.last_updated || 'never'}</strong>
            <button className="ids-refresh-icon-btn" onClick={onRefresh} disabled={actionDisabled} title={queryDisabledReason || 'Fetch new data from eve.json'}><RefreshCw size={13} /></button>
          </div>
          <div className="ids-progress"><i style={{ width: `${progress}%` }} /></div>
          <small>{busy && <b className="tiny-loader" />} {action} · {progress}% · {status?.last_check_alerts_read || 0} alerts · {status?.last_check_network_read || 0} network · {status?.last_check_non_alerts || 0} skipped · {status?.last_check_bytes_read || 0}/{status?.last_check_bytes_total || 0} bytes</small>
        </div>

        <label className="timeframe-select-box">
          <span>Timeframe</span>
          <select disabled={busy} value={timeframe} onChange={(event) => setTimeframe(event.target.value)}>
            {timeframes.map((item) => <option key={item} value={item}>{item === 'all' ? 'All' : item === 'custom' ? 'Custom' : item}</option>)}
          </select>
        </label>

        <label className={`ids-search-box timeframe-search ${q ? 'has-value' : ''}`}>
          <span>Search</span>
          <span className="search-input-wrap">
            <input disabled={busy} value={q} placeholder={searchPlaceholder} onChange={(event) => setQ(event.target.value)} />
          </span>
        </label>

        <div className="timeframe-actions">
          <button className="search-clear-btn" type="button" onClick={() => { setQ(''); (onClear || onRun)(); }} disabled={!q || actionDisabled}>Clear</button>
          <button className="ids-run-btn" onClick={onRun} disabled={actionDisabled} title={queryDisabledReason || undefined}>Run</button>
          <button className="ids-cancel-btn" type="button" onClick={onCancel} disabled={!queryRunning}>Cancel</button>
        </div>

        <label className="timeframe-topn">Top N<input disabled={busy} type="number" min="1" max={topNMax} value={topN} onChange={(event) => setTopN(Number(event.target.value) || 10)} /></label>

        {timeframe === 'custom' && (
          <div className="custom-timeframe timeframe-custom">
            <label>Start<input disabled={busy} type="datetime-local" value={customStart} onChange={(event) => setCustomStart(event.target.value)} /></label>
            <label>End<input disabled={busy} type="datetime-local" value={customEnd} onChange={(event) => setCustomEnd(event.target.value)} /></label>
          </div>
        )}

        <div className="timeframe-messages">
          {busy && <span className="ids-search-indicator"><small><b className="tiny-loader" /> {loadingAction}</small></span>}
          {queryDisabled && queryDisabledReason && <p className="ids-query-hint">{queryDisabledReason}</p>}
          {timeframe === 'all' && <p className="ids-warning"><AlertTriangle size={15} /> All events can be expensive on large eve.json files.</p>}
        </div>
      </div>
      {q && <div className="ids-search-active-panel">Search filter active. Showing filtered events. Clear runs the query again automatically.</div>}
    </>
  );
}
