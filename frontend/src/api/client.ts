/**
 * Typed API client — all backend communication goes through this module.
 * The base URL is derived from the VITE_API_BASE_URL env var; never hardcode
 * localhost throughout components.
 */

import type { CaptureSnapshot, CaptureStartRequest, HealthResponse } from './types';

// In dev, Vite proxies /health, /capture, /detect to localhost:8000.
// In production, set VITE_API_BASE_URL to the actual backend origin.
const BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '';

/** Derive WebSocket URL from the REST API base URL */
export function wsUrl(): string {
  // If BASE_URL is empty (proxy mode), use the current page's host.
  const base = BASE_URL || window.location.origin;
  const u = new URL(base);
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
  u.pathname = '/ws/alerts';
  return u.toString();
}

// ── Internal fetch helper ──────────────────────────────────────────────────

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = BASE_URL + path;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json() as { error?: string; detail?: string };
      detail = body.error ?? body.detail ?? detail;
    } catch {
      // ignore JSON parse errors
    }
    throw new Error(detail);
  }

  return res.json() as Promise<T>;
}

// ── Public API ─────────────────────────────────────────────────────────────

export async function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

export async function fetchCaptureStatus(): Promise<CaptureSnapshot> {
  return request<CaptureSnapshot>('/capture/status');
}

export async function startCapture(req: CaptureStartRequest): Promise<CaptureSnapshot> {
  return request<CaptureSnapshot>('/capture/start', {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export async function stopCapture(): Promise<CaptureSnapshot> {
  return request<CaptureSnapshot>('/capture/stop', { method: 'POST' });
}
