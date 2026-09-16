/**
 * AlertTimeline — per-minute bar chart of alert arrivals.
 * Pure SVG, no chart library. Shows the last 10 minute-buckets.
 * Answers only: "how many alerts arrived recently?"
 */
import type { TimelineBucket } from '../hooks/useAlertStream';

interface AlertTimelineProps {
  timeline: TimelineBucket[];
}

const BAR_W = 24;
const BAR_GAP = 6;
const CHART_H = 60;
const AXIS_H = 18;

export function AlertTimeline({ timeline }: AlertTimelineProps) {
  const hasData = timeline.length > 0 && timeline.some(b => b.count > 0);

  const maxCount = hasData ? Math.max(...timeline.map(b => b.count)) : 0;

  const svgW = timeline.length > 0
    ? timeline.length * (BAR_W + BAR_GAP) - BAR_GAP
    : 200;

  return (
    <div className="panel" style={{ flex: 1 }}>
      <div className="panel-header">
        <span className="panel-title">Alert Activity</span>
        {hasData && (
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            per minute
          </span>
        )}
      </div>
      <div className="panel-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: CHART_H + AXIS_H + 16 }}>
        {!hasData ? (
          <div className="empty-state" style={{ padding: '16px 0' }}>
            <span className="empty-state-title">No Activity</span>
            <span className="empty-state-desc">Waiting for telemetry</span>
          </div>
        ) : (
          <svg
            width={svgW}
            height={CHART_H + AXIS_H}
            style={{ overflow: 'visible', display: 'block' }}
            aria-label="Alert activity timeline"
          >
            {timeline.map((bucket, i) => {
              const barH = maxCount > 0
                ? Math.max(2, (bucket.count / maxCount) * CHART_H)
                : 0;
              const x = i * (BAR_W + BAR_GAP);
              const y = CHART_H - barH;

              return (
                <g key={bucket.label}>
                  {/* Bar */}
                  <rect
                    x={x}
                    y={y}
                    width={BAR_W}
                    height={barH}
                    fill="var(--accent)"
                    opacity={0.75}
                    rx={2}
                  />
                  {/* Count label above bar */}
                  {bucket.count > 0 && (
                    <text
                      x={x + BAR_W / 2}
                      y={y - 4}
                      textAnchor="middle"
                      fill="var(--text-muted)"
                      fontSize={9}
                      fontFamily="var(--font-mono)"
                    >
                      {bucket.count}
                    </text>
                  )}
                  {/* Time label below */}
                  <text
                    x={x + BAR_W / 2}
                    y={CHART_H + AXIS_H - 2}
                    textAnchor="middle"
                    fill="var(--text-faint)"
                    fontSize={9}
                    fontFamily="var(--font-mono)"
                  >
                    {bucket.label}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
      </div>
    </div>
  );
}
