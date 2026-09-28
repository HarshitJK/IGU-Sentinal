/**
 * useHealth — polls GET /health every 10 seconds.
 * Returns the health state and whether the backend is reachable.
 */
import { useState, useEffect, useCallback } from 'react';
import { fetchReadiness } from '../api/client';

export type ApiState = 'online' | 'degraded' | 'offline' | 'checking';

export function useHealth(intervalMs = 10_000) {
  const [state, setState] = useState<ApiState>('checking');

  const check = useCallback(async () => {
    try {
      setState(await fetchReadiness() ? 'online' : 'degraded');
    } catch {
      setState('offline');
    }
  }, []);

  useEffect(() => {
    void check();
    const id = setInterval(() => { void check(); }, intervalMs);
    return () => clearInterval(id);
  }, [check, intervalMs]);

  return state;
}
