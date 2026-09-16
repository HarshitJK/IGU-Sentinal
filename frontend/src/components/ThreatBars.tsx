/**
 * ThreatBars — horizontal bar chart for threat class distribution.
 * Pure SVG/DOM — no chart library. Renders only when there is real data.
 */
import type { ThreatClass } from '../api/types';
import { THREAT_CLASS_LABELS, THREAT_CLASS_COLOR_VAR } from '../api/types';

interface ThreatBarsProps {
  counts: Partial<Record<ThreatClass, number>>;
}

const ALL_CLASSES: ThreatClass[] = [
  'volumetric_ddos',
  'c2_beaconing',
  'dga_dns_tunneling',
  'encrypted_malware',
  'recon_scanning',
  'data_exfiltration',
];

export function ThreatBars({ counts }: ThreatBarsProps) {
  const total = Object.values(counts).reduce((s, n) => s + (n ?? 0), 0);

  // Build rows: all six classes (even if 0), sorted by count desc
  const rows = ALL_CLASSES
    .map(tc => ({ tc, count: counts[tc] ?? 0 }))
    .sort((a, b) => b.count - a.count);

  const hasData = total > 0;

  return (
    <div className="panel" style={{ flex: 1 }}>
      <div className="panel-header">
        <span className="panel-title">Threat Distribution</span>
        {hasData && (
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            {total} total
          </span>
        )}
      </div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {!hasData ? (
          <div className="empty-state" style={{ padding: '24px 0' }}>
            <span className="empty-state-title">No Alerts</span>
            <span className="empty-state-desc">Monitoring for network anomalies</span>
          </div>
        ) : (
          rows.map(({ tc, count }) => {
            const pct = total > 0 ? (count / total) * 100 : 0;
            const color = THREAT_CLASS_COLOR_VAR[tc];
            return (
              <div key={tc} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: 8,
                }}>
                  <span style={{
                    fontSize: 12,
                    color: count > 0 ? 'var(--text-secondary)' : 'var(--text-faint)',
                  }}>
                    {THREAT_CLASS_LABELS[tc]}
                  </span>
                  <span style={{
                    fontSize: 11,
                    fontFamily: 'var(--font-mono)',
                    color: count > 0 ? 'var(--text-primary)' : 'var(--text-faint)',
                    minWidth: 24,
                    textAlign: 'right',
                  }}>
                    {count}
                  </span>
                </div>
                <div style={{
                  height: 3,
                  borderRadius: 2,
                  background: 'var(--border-muted)',
                  overflow: 'hidden',
                }}>
                  <div style={{
                    height: '100%',
                    width: `${pct}%`,
                    background: color,
                    borderRadius: 2,
                    transition: 'width 300ms ease',
                    opacity: count > 0 ? 1 : 0,
                  }} />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
