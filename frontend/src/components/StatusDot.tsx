/**
 * StatusDot — small indicator circle for connection/service state.
 * Intentionally tiny and unobtrusive.
 */
import type { CSSProperties } from 'react';
import type { ApiState } from '../hooks/useHealth';
import type { StreamState } from '../hooks/useAlertStream';
import type { CaptureStatus } from '../api/types';

interface StatusDotProps {
  state: ApiState | StreamState | CaptureStatus | 'online' | 'offline';
  size?: number;
}

function resolveColor(state: StatusDotProps['state']): string {
  switch (state) {
    case 'online':
    case 'connected':
    case 'running':
      return 'var(--accent)';
    case 'checking':
    case 'connecting':
    case 'starting':
      return 'var(--threat-medium)';
    case 'offline':
    case 'disconnected':
    case 'error':
    case 'stopped':
    case 'idle':
      return 'var(--text-faint)';
    default:
      return 'var(--text-faint)';
  }
}

export function StatusDot({ state, size = 6 }: StatusDotProps) {
  const color = resolveColor(state);

  const style: CSSProperties = {
    display: 'inline-block',
    width: size,
    height: size,
    borderRadius: '50%',
    backgroundColor: color,
    flexShrink: 0,
  };

  return <span style={style} aria-hidden="true" />;
}
