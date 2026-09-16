/**
 * TelemetryStrip — compact row of key metrics from the capture status.
 * Uses typography and separators rather than giant cards.
 * Shows real data only — never invented values.
 */
import type { CaptureSnapshot } from '../api/types';

interface TelemetryStripProps {
  snapshot: CaptureSnapshot | null;
  alertCount: number;
}

interface MetricProps {
  label: string;
  value: string;
  mono?: boolean;
  color?: string;
}

function Metric({ label, value, mono = false, color }: MetricProps) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
      <span style={{
        fontSize: 10,
        fontWeight: 600,
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
        color: 'var(--text-muted)',
      }}>
        {label}
      </span>
      <span style={{
        fontSize: 22,
        fontWeight: 600,
        fontFamily: mono ? 'var(--font-mono)' : 'var(--font-ui)',
        color: color ?? 'var(--text-primary)',
        lineHeight: 1,
        letterSpacing: mono ? '-0.02em' : undefined,
      }}>
        {value}
      </span>
    </div>
  );
}

function Sep() {
  return (
    <div style={{
      width: 1,
      alignSelf: 'stretch',
      background: 'var(--border-muted)',
      flexShrink: 0,
    }} />
  );
}

function captureColor(status: string | null | undefined): string {
  switch (status) {
    case 'running':  return 'var(--accent)';
    case 'error':    return 'var(--threat-critical)';
    case 'starting': return 'var(--threat-medium)';
    default:         return 'var(--text-muted)';
  }
}

export function TelemetryStrip({ snapshot, alertCount }: TelemetryStripProps) {
  const s = snapshot;

  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-md)',
      padding: '14px 20px',
      display: 'flex',
      alignItems: 'center',
      gap: 24,
      overflow: 'auto',
    }}>
      <Metric
        label="Flows Scored"
        value={s ? s.flows_scored.toLocaleString() : '—'}
        mono
      />
      <Sep />
      <Metric
        label="Alerts Emitted"
        value={s ? s.alerts_emitted.toLocaleString() : alertCount.toLocaleString()}
        mono
        color={s && s.alerts_emitted > 0 ? 'var(--threat-critical)' : undefined}
      />
      <Sep />
      <Metric
        label="Suppressed"
        value={s ? s.alerts_suppressed.toLocaleString() : '—'}
        mono
      />
      <Sep />
      <Metric
        label="Windows"
        value={s ? s.windows_processed.toLocaleString() : '—'}
        mono
      />
      <Sep />
      <Metric
        label="Interface"
        value={s?.interface ?? '—'}
        mono
      />
      <Sep />
      <Metric
        label="Capture"
        value={(s?.status ?? 'idle').toUpperCase()}
        color={captureColor(s?.status)}
      />
      {s?.window_ms != null && (
        <>
          <Sep />
          <Metric
            label="Window"
            value={`${s.window_ms} ms`}
            mono
          />
        </>
      )}
    </div>
  );
}
