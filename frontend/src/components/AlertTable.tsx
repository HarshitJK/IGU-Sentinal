/**
 * AlertTable — the central piece of the dashboard.
 * Displays real-time alerts from /ws/alerts.
 * Row click opens AlertDrawer with full alert detail.
 * Compact table style — not a card collection.
 */
import { useState } from 'react';
import type { AlertRecord } from '../hooks/useAlertStream';
import { THREAT_CLASS_LABELS, THREAT_CLASS_COLOR_VAR, confidenceTier } from '../api/types';
import { AlertDrawer } from './AlertDrawer';

interface AlertTableProps {
  alerts: AlertRecord[];
}

function fmtTime(isoTimestamp: string): string {
  try {
    const d = new Date(isoTimestamp);
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
  } catch {
    return '—';
  }
}

function ConfidenceBadge({ score }: { score: number }) {
  const tier = confidenceTier(score);
  const pct = Math.round(score * 100);
  return (
    <span className={`badge badge-${tier}`}>
      {pct}%
    </span>
  );
}

export function AlertTable({ alerts }: AlertTableProps) {
  const [selected, setSelected] = useState<AlertRecord | null>(null);

  return (
    <>
      <div className="panel" style={{ display: 'flex', flexDirection: 'column', minHeight: 280 }}>
        <div className="panel-header">
          <span className="panel-title">Live Alerts</span>
          <span style={{
            fontSize: 11,
            fontFamily: 'var(--font-mono)',
            color: alerts.length > 0 ? 'var(--threat-critical)' : 'var(--text-muted)',
          }}>
            {alerts.length > 0 ? `${alerts.length} recorded` : 'none'}
          </span>
        </div>

        <div style={{ flex: 1, overflow: 'auto' }}>
          {alerts.length === 0 ? (
            <div className="empty-state">
              <span className="empty-state-title">No Alerts</span>
              <span className="empty-state-desc">Monitoring for network anomalies</span>
            </div>
          ) : (
            <table style={{
              width: '100%',
              borderCollapse: 'collapse',
              fontSize: 12,
            }}>
              <thead>
                <tr style={{ background: 'var(--bg-base)' }}>
                  {['Time', 'Flow', 'Threat', 'Confidence'].map(col => (
                    <th key={col} style={{
                      padding: '8px 16px',
                      textAlign: 'left',
                      fontSize: 10,
                      fontWeight: 600,
                      letterSpacing: '0.07em',
                      textTransform: 'uppercase',
                      color: 'var(--text-muted)',
                      borderBottom: '1px solid var(--border)',
                      whiteSpace: 'nowrap',
                      position: 'sticky',
                      top: 0,
                      background: 'var(--bg-base)',
                    }}>
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.map(alert => (
                  <tr
                    key={alert._id}
                    className={alert._isNew ? 'alert-row-new' : undefined}
                    onClick={() => setSelected(alert)}
                    style={{
                      cursor: 'pointer',
                      borderBottom: '1px solid var(--border-muted)',
                      transition: 'background var(--transition)',
                    }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.background = '')}
                  >
                    <td style={{
                      padding: '9px 16px',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 11,
                      color: 'var(--text-muted)',
                      whiteSpace: 'nowrap',
                    }}>
                      {fmtTime(alert.timestamp)}
                    </td>
                    <td style={{
                      padding: '9px 16px',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 11,
                      color: 'var(--text-secondary)',
                    }}>
                      {alert.flow_id.slice(0, 8)}
                    </td>
                    <td style={{
                      padding: '9px 16px',
                      color: THREAT_CLASS_COLOR_VAR[alert.threat_class],
                      fontWeight: 500,
                    }}>
                      {THREAT_CLASS_LABELS[alert.threat_class]}
                    </td>
                    <td style={{ padding: '9px 16px' }}>
                      <ConfidenceBadge score={alert.confidence_score} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {selected && (
        <AlertDrawer alert={selected} onClose={() => setSelected(null)} />
      )}
    </>
  );
}
