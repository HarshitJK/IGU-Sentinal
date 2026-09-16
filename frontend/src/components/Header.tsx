/**
 * Header — compact application header.
 * Shows the product name + description and three status indicators.
 * Does NOT dominate the screen — the operator should immediately see telemetry.
 */
import type { ApiState } from '../hooks/useHealth';
import type { StreamState } from '../hooks/useAlertStream';
import type { CaptureStatus } from '../api/types';
import { StatusDot } from './StatusDot';

interface HeaderProps {
  apiState: ApiState;
  streamState: StreamState;
  captureStatus: CaptureStatus | null;
}

function apiStateLabel(state: ApiState): string {
  switch (state) {
    case 'online':   return 'API ONLINE';
    case 'offline':  return 'API OFFLINE';
    case 'checking': return 'API CHECKING';
  }
}

function streamStateLabel(state: StreamState): string {
  switch (state) {
    case 'connected':    return 'STREAM CONNECTED';
    case 'connecting':   return 'STREAM CONNECTING';
    case 'disconnected': return 'STREAM DISCONNECTED';
    case 'error':        return 'STREAM ERROR';
  }
}

function captureStateLabel(status: CaptureStatus | null): string {
  if (!status) return 'CAPTURE —';
  switch (status) {
    case 'running':  return 'CAPTURE RUNNING';
    case 'starting': return 'CAPTURE STARTING';
    case 'stopped':  return 'CAPTURE STOPPED';
    case 'idle':     return 'CAPTURE IDLE';
    case 'error':    return 'CAPTURE ERROR';
  }
}

export function Header({ apiState, streamState, captureStatus }: HeaderProps) {
  return (
    <header style={{
      borderBottom: '1px solid var(--border)',
      background: 'var(--bg-surface)',
      padding: '10px 24px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: 16,
      position: 'sticky',
      top: 0,
      zIndex: 50,
    }}>
      {/* Left: Product identity */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12 }}>
        <span style={{
          fontSize: 13,
          fontWeight: 600,
          letterSpacing: '0.06em',
          color: 'var(--text-primary)',
        }}>
          IGU SENTINEL
        </span>
        <span style={{
          fontSize: 11,
          color: 'var(--text-muted)',
          borderLeft: '1px solid var(--border)',
          paddingLeft: 12,
        }}>
          Passive Network Threat Detection
        </span>
      </div>

      {/* Right: Status indicators */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 20,
      }}>
        <StatusIndicator dot={<StatusDot state={apiState} />} label={apiStateLabel(apiState)} />
        <StatusIndicator dot={<StatusDot state={streamState} />} label={streamStateLabel(streamState)} />
        <StatusIndicator dot={<StatusDot state={captureStatus ?? 'idle'} />} label={captureStateLabel(captureStatus)} />
      </div>
    </header>
  );
}

function StatusIndicator({ dot, label }: { dot: React.ReactNode; label: string }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        fontSize: 10,
        fontWeight: 600,
        letterSpacing: '0.07em',
        color: 'var(--text-muted)',
      }}
      title={label}
    >
      {dot}
      <span style={{ display: 'none' }} aria-label={label} />
      <span>{label}</span>
    </div>
  );
}
