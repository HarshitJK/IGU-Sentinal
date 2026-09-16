/**
 * App — root layout and state orchestration.
 * Composes hooks and components into the operational dashboard.
 * Deliberately not a giant component — all rendering logic lives in components.
 */
import { useState, useCallback } from 'react';
import { useHealth } from './hooks/useHealth';
import { useCaptureStatus } from './hooks/useCaptureStatus';
import { useAlertStream } from './hooks/useAlertStream';
import { Header } from './components/Header';
import { TelemetryStrip } from './components/TelemetryStrip';
import { AlertTable } from './components/AlertTable';
import { ThreatBars } from './components/ThreatBars';
import { AlertTimeline } from './components/AlertTimeline';
import { CaptureControl } from './components/CaptureControl';
import type { CaptureSnapshot } from './api/types';

export default function App() {
  const apiState = useHealth();
  const { snapshot, refresh } = useCaptureStatus();
  const { streamState, alerts, threatCounts, timeline } = useAlertStream();

  // Allow CaptureControl to immediately update snapshot on start/stop response
  const [overrideSnapshot, setOverrideSnapshot] = useState<CaptureSnapshot | null>(null);

  const handleCaptureUpdate = useCallback((s: CaptureSnapshot) => {
    setOverrideSnapshot(s);
    // Clear override after a short moment, letting polling take over
    setTimeout(() => setOverrideSnapshot(null), 3_000);
  }, []);

  const effectiveSnapshot = overrideSnapshot ?? snapshot;

  const backendOffline = apiState === 'offline';

  return (
    <div className="app-layout">
      <Header
        apiState={apiState}
        streamState={streamState}
        captureStatus={effectiveSnapshot?.status ?? null}
      />

      {/* Backend offline banner */}
      {backendOffline && (
        <div className="offline-banner" role="status">
          <span style={{
            display: 'inline-block',
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: 'var(--threat-critical)',
            flexShrink: 0,
          }} />
          Backend unavailable — retrying connection...
        </div>
      )}

      <main className="app-content">
        {/* System Overview — compact metrics strip */}
        <TelemetryStrip
          snapshot={effectiveSnapshot}
          alertCount={alerts.length}
        />

        {/* Middle row: Alert timeline + Threat distribution */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 16,
        }}>
          <AlertTimeline timeline={timeline} />
          <ThreatBars counts={threatCounts} />
        </div>

        {/* Alert table — full width */}
        <AlertTable alerts={alerts} />

        {/* Bottom row: Capture control + System info */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '320px 1fr',
          gap: 16,
          alignItems: 'start',
        }}>
          <CaptureControl
            snapshot={effectiveSnapshot}
            onUpdate={handleCaptureUpdate}
            onRefresh={refresh}
          />

          {/* System info panel */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">System</span>
            </div>
            <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {[
                ['Detection layers', 'Rules · Statistics · Isolation Forest · XGBoost'],
                ['Threat classes', '6 (DDoS · C2 · DGA/DNS · Malware · Recon · Exfil)'],
                ['Capture mode', 'Passive (diode-fed, one-way)'],
                ['Fusion gate', 'Cross-layer calibrated probability'],
                ['Alert logging', 'SHA-256 hash-chained'],
              ].map(([label, value]) => (
                <div key={label} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                  <span style={{
                    fontSize: 11,
                    color: 'var(--text-muted)',
                    flexShrink: 0,
                    width: 140,
                    paddingTop: 1,
                  }}>
                    {label}
                  </span>
                  <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                    {value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
