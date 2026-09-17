/**
 * Typed API client — all backend communication goes through this module.
 * The base URL is derived from the VITE_API_BASE_URL env var; never hardcode
 * localhost throughout components.
 */

import type { CaptureSnapshot, CaptureStartRequest, HealthResponse } from './types';

// In dev, Vite proxies /health, /capture, /detect to localhost:8000.
// In production, set VITE_API_BASE_URL to the actual backend origin.
const BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '';

// When IGU_API_TOKEN is configured on the backend, set VITE_API_TOKEN in the
// build environment to the same value.  The token lives in the browser bundle
// (acceptable for a controlled-network demo); a real deployment should use
// a login endpoint that issues short-lived session cookies instead.
const TOKEN = (import.meta.env.VITE_API_TOKEN as string | undefined) ?? '';

/** Derive WebSocket URL from the REST API base URL.
 *
 * Browsers cannot set custom headers on a WebSocket handshake, so the token
 * is passed as a query parameter instead — the backend's require_ws_token()
 * already reads websocket.query_params.get("token").
 */
export function wsUrl(): string {
  // If BASE_URL is empty (proxy mode), use the current page's host.
  const base = BASE_URL || window.location.origin;
  const u = new URL(base);
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
  u.pathname = '/ws/alerts';
  if (TOKEN) {
    u.searchParams.set('token', TOKEN);
  }
  return u.toString();
}

// ── Internal fetch helper ──────────────────────────────────────────────────

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = BASE_URL + path;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  };
  // Attach Bearer token when the backend has auth enabled.
  if (TOKEN) {
    headers['Authorization'] = `Bearer ${TOKEN}`;
  }
  const res = await fetch(url, { ...options, headers });

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
