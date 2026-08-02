import { useEffect, useState } from 'react';

// A single app-wide replacement for window.confirm()/window.prompt() —
// this app's own card styling instead of the browser's native dialog.
// confirmDialog()/promptDialog() are plain async functions callable from
// anywhere (no hook, no provider wiring at each call site); <DialogHost />
// is mounted once near the app root and renders whichever request is
// currently pending via a tiny module-level pub/sub (there is only ever
// one dialog open at a time, matching how window.confirm/prompt behave).

type ConfirmOptions = { title?: string; confirmLabel?: string; cancelLabel?: string; danger?: boolean };
type PromptOptions = { title?: string; placeholder?: string };

type DialogRequest =
  | ({ kind: 'confirm'; message: string; resolve: (value: boolean) => void } & ConfirmOptions)
  | ({ kind: 'prompt'; message: string; defaultValue: string; resolve: (value: string | null) => void } & PromptOptions);

let listener: ((request: DialogRequest | null) => void) | null = null;

export function confirmDialog(message: string, options?: ConfirmOptions): Promise<boolean> {
  return new Promise((resolve) => {
    listener?.({ kind: 'confirm', message, resolve, ...options });
  });
}

export function promptDialog(message: string, defaultValue = '', options?: PromptOptions): Promise<string | null> {
  return new Promise((resolve) => {
    listener?.({ kind: 'prompt', message, defaultValue, resolve, ...options });
  });
}

export default function DialogHost() {
  const [request, setRequest] = useState<DialogRequest | null>(null);
  const [value, setValue] = useState('');

  useEffect(() => {
    listener = (next) => {
      setRequest(next);
      setValue(next?.kind === 'prompt' ? next.defaultValue : '');
    };
    return () => { listener = null; };
  }, []);

  if (!request) return null;

  function finishConfirm(result: boolean) {
    if (request?.kind === 'confirm') request.resolve(result);
    setRequest(null);
  }

  function finishPrompt(result: string | null) {
    if (request?.kind === 'prompt') request.resolve(result);
    setRequest(null);
  }

  return (
    <div className="confirm-overlay">
      <div className="confirm-dialog card" style={{ maxWidth: 480 }}>
        {request.title && <h3>{request.title}</h3>}
        <p>{request.message}</p>
        {request.kind === 'prompt' && (
          <input
            autoFocus
            value={value}
            placeholder={request.placeholder}
            onChange={(event) => setValue(event.target.value)}
            onKeyDown={(event) => { if (event.key === 'Enter') finishPrompt(value); }}
          />
        )}
        <div className="confirm-actions">
          {request.kind === 'confirm' ? (
            <>
              <button className="btn-secondary" onClick={() => finishConfirm(false)}>{request.cancelLabel || 'Cancel'}</button>
              <button className={request.danger ? 'danger-btn' : ''} onClick={() => finishConfirm(true)}>{request.confirmLabel || 'Confirm'}</button>
            </>
          ) : (
            <>
              <button className="btn-secondary" onClick={() => finishPrompt(null)}>Cancel</button>
              <button onClick={() => finishPrompt(value)}>OK</button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
