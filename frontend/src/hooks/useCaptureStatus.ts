/**
 * useCaptureStatus — polls GET /capture/status every 2 seconds.
 * Returns the latest snapshot plus a manual refresh function.
 */
import { useState, useEffect, useCallback } from 'react';
import { fetchCaptureStatus } from '../api/client';
import type { CaptureSnapshot } from '../api/types';

const DEFAULT_INTERVAL_MS = 2_000;

export function useCaptureStatus(intervalMs = DEFAULT_INTERVAL_MS) {
  const [snapshot, setSnapshot] = useState<CaptureSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const s = await fetchCaptureStatus();
      setSnapshot(s);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = setInterval(() => { void refresh(); }, intervalMs);
    return () => clearInterval(id);
  }, [refresh, intervalMs]);

  return { snapshot, error, refresh };
}
