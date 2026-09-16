/**
 * useAlertStream — manages the WebSocket connection to /ws/alerts.
 *
 * Design decisions:
 * - Reconnects automatically with exponential backoff (max 30s).
 * - Alert history is bounded to MAX_ALERTS to prevent memory growth.
 * - Exposes stream connection state separately from API health.
 * - Does NOT use a global store — callers receive state via hook return.
 * - Each new alert is tagged with `isNew: true` briefly (cleared after 800ms)
 *   to trigger a CSS highlight on the row.
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import { wsUrl } from '../api/client';
import type { Alert, ThreatClass } from '../api/types';

export type StreamState = 'connecting' | 'connected' | 'disconnected' | 'error';

const MAX_ALERTS = 500;

export interface AlertRecord extends Alert {
  /** Client-assigned monotonic ID for React key prop */
  _id: number;
  /** Set true briefly on arrival to trigger row flash animation */
  _isNew: boolean;
}

export interface AlertStreamState {
  streamState: StreamState;
  alerts: AlertRecord[];
  threatCounts: Partial<Record<ThreatClass, number>>;
  /** Timeline: array of { minute: string, count: number } for the last 10 min */
  timeline: TimelineBucket[];
}

export interface TimelineBucket {
  label: string;   // "HH:MM"
  count: number;
}

let _idCounter = 0;

function makeId(): number {
  return ++_idCounter;
}

/** Bucket an ISO timestamp into a HH:MM string */
function bucketLabel(isoTimestamp: string): string {
  const d = new Date(isoTimestamp);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

/** Keep only the last N minute-buckets, sorted oldest→newest */
function buildTimeline(alerts: AlertRecord[]): TimelineBucket[] {
  const buckets: Map<string, number> = new Map();
  for (const a of alerts) {
    const label = bucketLabel(a.timestamp);
    buckets.set(label, (buckets.get(label) ?? 0) + 1);
  }
  // Sort and keep most recent 10
  const sorted = Array.from(buckets.entries())
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .slice(-10)
    .map(([label, count]) => ({ label, count }));
  return sorted;
}

export function useAlertStream(): AlertStreamState {
  const [streamState, setStreamState] = useState<StreamState>('connecting');
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [threatCounts, setThreatCounts] = useState<Partial<Record<ThreatClass, number>>>({});
  const [timeline, setTimeline] = useState<TimelineBucket[]>([]);

  const wsRef = useRef<WebSocket | null>(null);
  const retryDelayRef = useRef(1_000);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;
    setStreamState('connecting');

    const ws = new WebSocket(wsUrl());
    wsRef.current = ws;

    ws.onopen = () => {
      if (!mountedRef.current) { ws.close(); return; }
      setStreamState('connected');
      retryDelayRef.current = 1_000; // reset backoff on success
    };

    ws.onmessage = (ev: MessageEvent<string>) => {
      if (!mountedRef.current) return;
      let alert: Alert;
      try {
        alert = JSON.parse(ev.data) as Alert;
      } catch {
        return;
      }

      const record: AlertRecord = { ...alert, _id: makeId(), _isNew: true };

      setAlerts(prev => {
        const next = [record, ...prev].slice(0, MAX_ALERTS);
        // Clear the _isNew flag after animation completes
        setTimeout(() => {
          setAlerts(cur =>
            cur.map(a => (a._id === record._id ? { ...a, _isNew: false } : a))
          );
        }, 800);
        return next;
      });

      setThreatCounts(prev => ({
        ...prev,
        [alert.threat_class]: (prev[alert.threat_class as ThreatClass] ?? 0) + 1,
      }));

      setTimeline(prev => {
        const label = bucketLabel(alert.timestamp);
        const existing = prev.find(b => b.label === label);
        const updated = existing
          ? prev.map(b => b.label === label ? { ...b, count: b.count + 1 } : b)
          : [...prev, { label, count: 1 }];
        return updated.sort((a, b) => (a.label < b.label ? -1 : 1)).slice(-10);
      });
    };

    ws.onerror = () => {
      if (!mountedRef.current) return;
      setStreamState('error');
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      setStreamState('disconnected');
      // Exponential backoff: 1s → 2s → 4s → … → max 30s
      const delay = retryDelayRef.current;
      retryDelayRef.current = Math.min(delay * 2, 30_000);
      retryTimerRef.current = setTimeout(connect, delay);
    };
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      wsRef.current?.close();
      if (retryTimerRef.current) clearTimeout(retryTimerRef.current);
    };
  }, [connect]);

  // Rebuild timeline whenever alerts change
  useEffect(() => {
    setTimeline(buildTimeline(alerts));
  }, [alerts]);

  return { streamState, alerts, threatCounts, timeline };
}
