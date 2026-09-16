/**
 * CaptureControl — operational controls for starting/stopping live capture.
 * Shows real capture state from the backend.
 * Errors appear inline, near the affected control.
 */
import { useState } from 'react';
import { Play, Square } from 'lucide-react';
import type { CaptureSnapshot } from '../api/types';
import { startCapture, stopCapture } from '../api/client';
import { StatusDot } from './StatusDot';

const DEFAULT_WINDOW_MS = 120;

interface CaptureControlProps {
  snapshot: CaptureSnapshot | null;
  onUpdate: (s: CaptureSnapshot) => void;
  onRefresh: () => void;
}

export function CaptureControl({ snapshot, onUpdate, onRefresh }: CaptureControlProps) {
  const [iface, setIface] = useState('');
  const [windowMs, setWindowMs] = useState(String(DEFAULT_WINDOW_MS));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const status = snapshot?.status ?? 'idle';
  const isRunning = snapshot?.running ?? false;

  async function handleStart() {
    const ifaceTrim = iface.trim();
    if (!ifaceTrim) {
      setError('Interface name is required');
      return;
    }
    const wms = parseInt(windowMs, 10);
    if (isNaN(wms) || wms <= 0) {
      setError('Window must be a positive integer');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const s = await startCapture({ interface: ifaceTrim, window_ms: wms });
      onUpdate(s);
      if (s.status === 'error') {
        setError(s.error ?? 'Capture failed to start');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start capture');
    } finally {
      setLoading(false);
      onRefresh();
    }
  }

  async function handleStop() {
    setLoading(true);
    setError(null);
    try {
      const s = await stopCapture();
      onUpdate(s);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to stop capture');
    } finally {
      setLoading(false);
      onRefresh();
    }
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Capture Control</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <StatusDot state={status} />
          <span style={{
            fontSize: 10,
            fontWeight: 600,
            letterSpacing: '0.07em',
            textTransform: 'uppercase',
            color: status === 'running' ? 'var(--accent)'
              : status === 'error' ? 'var(--threat-critical)'
              : 'var(--text-muted)',
          }}>
            {status}
          </span>
        </div>
      </div>

      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {/* Interface field */}
        <div>
          <label className="input-label" htmlFor="capture-iface">Interface</label>
          <input
            id="capture-iface"
            className="input"
            type="text"
            value={iface}
            onChange={e => setIface(e.target.value)}
            placeholder="eth0, en0, lo..."
            disabled={isRunning || loading}
            onKeyDown={e => { if (e.key === 'Enter' && !isRunning) void handleStart(); }}
          />
        </div>

        {/* Window field */}
        <div>
          <label className="input-label" htmlFor="capture-window">Window (ms)</label>
          <input
            id="capture-window"
            className="input"
            type="number"
            value={windowMs}
            onChange={e => setWindowMs(e.target.value)}
            min={1}
            disabled={isRunning || loading}
          />
        </div>

        {/* Error */}
        {error && <div className="inline-error" role="alert">{error}</div>}

        {/* Action button */}
        {isRunning ? (
          <button
            className="btn btn-danger"
            onClick={() => void handleStop()}
            disabled={loading}
            id="btn-stop-capture"
          >
            <Square size={13} />
            Stop Capture
          </button>
        ) : (
          <button
            className="btn btn-primary"
            onClick={() => void handleStart()}
            disabled={loading}
            id="btn-start-capture"
          >
            <Play size={13} />
            Start Capture
          </button>
        )}

        {/* Runtime stats — only when running */}
        {snapshot && isRunning && (
          <div style={{
            borderTop: '1px solid var(--border-muted)',
            paddingTop: 12,
            display: 'flex',
            flexDirection: 'column',
            gap: 6,
          }}>
            {[
              ['Started', snapshot.started_at ? new Date(snapshot.started_at).toLocaleTimeString() : '—'],
              ['Windows', snapshot.windows_processed.toLocaleString()],
              ['Flows', snapshot.flows_scored.toLocaleString()],
              ['Alerts', snapshot.alerts_emitted.toLocaleString()],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{k}</span>
                <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{v}</span>
              </div>
            ))}
          </div>
        )}

        {/* Error state from backend */}
        {snapshot?.status === 'error' && snapshot.error && (
          <div style={{
            padding: '8px 10px',
            background: 'rgba(239,68,68,0.08)',
            borderRadius: 'var(--radius)',
            border: '1px solid rgba(239,68,68,0.2)',
          }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--threat-critical)', marginBottom: 3, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Capture Error
            </div>
            <div style={{ fontSize: 11, color: '#fca5a5', fontFamily: 'var(--font-mono)' }}>
              {snapshot.error}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
