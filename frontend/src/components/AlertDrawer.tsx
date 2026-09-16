/**
 * AlertDrawer — side panel showing full alert detail.
 * Opens on row click. Uses real backend evidence[].
 */
import { X } from 'lucide-react';
import type { AlertRecord } from '../hooks/useAlertStream';
import { THREAT_CLASS_LABELS, THREAT_CLASS_COLOR_VAR, confidenceTier } from '../api/types';

interface AlertDrawerProps {
  alert: AlertRecord;
  onClose: () => void;
}

function fmt(isoTimestamp: string): string {
  try {
    return new Date(isoTimestamp).toLocaleString('en-US', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return isoTimestamp;
  }
}

export function AlertDrawer({ alert, onClose }: AlertDrawerProps) {
  const tier = confidenceTier(alert.confidence_score);
  const threatColor = THREAT_CLASS_COLOR_VAR[alert.threat_class];
  const pct = Math.round(alert.confidence_score * 100);

  return (
    <>
      {/* Backdrop */}
      <div
        className="drawer-overlay"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer */}
      <aside className="drawer" role="complementary" aria-label="Alert detail">
        <div className="drawer-header">
          <div style={{ minWidth: 0 }}>
            <div style={{
              fontSize: 10,
              fontWeight: 600,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              color: 'var(--text-muted)',
              marginBottom: 6,
            }}>
              Alert
            </div>
            <div style={{
              fontSize: 16,
              fontWeight: 600,
              color: threatColor,
              lineHeight: 1.3,
            }}>
              {THREAT_CLASS_LABELS[alert.threat_class]}
            </div>
          </div>
          <button
            className="drawer-close"
            onClick={onClose}
            aria-label="Close alert detail"
          >
            <X size={16} />
          </button>
        </div>

        <div className="drawer-body">
          {/* Confidence */}
          <div>
            <div className="drawer-field-label">Confidence</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{
                fontSize: 24,
                fontWeight: 600,
                fontFamily: 'var(--font-mono)',
                color: tier === 'critical' ? 'var(--threat-critical)'
                  : tier === 'high' ? 'var(--threat-high)'
                  : tier === 'medium' ? 'var(--threat-medium)'
                  : 'var(--threat-low)',
              }}>
                {pct}%
              </span>
              <span className={`badge badge-${tier}`} style={{ textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                {tier}
              </span>
            </div>
          </div>

          {/* Flow ID */}
          <div>
            <div className="drawer-field-label">Flow ID</div>
            <code className="drawer-field-value mono" style={{ fontSize: 13 }}>
              {alert.flow_id}
            </code>
          </div>

          {/* Timestamp */}
          <div>
            <div className="drawer-field-label">Timestamp</div>
            <code className="drawer-field-value mono" style={{ fontSize: 12 }}>
              {fmt(alert.timestamp)}
            </code>
          </div>

          {/* Threat class raw */}
          <div>
            <div className="drawer-field-label">Threat Class</div>
            <code className="drawer-field-value mono" style={{ fontSize: 12, color: threatColor }}>
              {alert.threat_class}
            </code>
          </div>

          {/* Evidence */}
          <div>
            <div className="drawer-field-label" style={{ marginBottom: 8 }}>
              Evidence ({alert.evidence.length})
            </div>
            {alert.evidence.length === 0 ? (
              <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>No evidence recorded</p>
            ) : (
              <ul className="evidence-list">
                {alert.evidence.map((ev, i) => (
                  <li key={i} className="evidence-item">{ev}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </aside>
    </>
  );
}
