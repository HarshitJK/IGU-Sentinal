/**
 * API types — mirrors the backend Pydantic schemas exactly.
 * Do not add fields that don't exist in the backend.
 */

// ── Alert ─────────────────────────────────────────────────────────────────

export type ThreatClass =
  | 'volumetric_ddos'
  | 'c2_beaconing'
  | 'dga_dns_tunneling'
  | 'encrypted_malware'
  | 'recon_scanning'
  | 'data_exfiltration';

export interface Alert {
  timestamp: string;      // ISO 8601
  flow_id: string;        // 16-char hex
  threat_class: ThreatClass;
  confidence_score: number; // 0.0–1.0
  evidence: string[];
}

// ── Capture status ─────────────────────────────────────────────────────────

export type CaptureStatus =
  | 'idle'
  | 'starting'
  | 'running'
  | 'stopped'
  | 'error';

export interface CaptureSnapshot {
  status: CaptureStatus;
  interface: string | null;
  window_ms: number | null;
  windows_processed: number;
  alerts_emitted: number;
  alerts_suppressed: number;
  flows_scored: number;
  error: string | null;
  started_at: string | null;
  running: boolean;
}

// ── Health ─────────────────────────────────────────────────────────────────

export interface HealthResponse {
  status: 'ok' | string;
  service: string;
}

// ── Capture start request ──────────────────────────────────────────────────

export interface CaptureStartRequest {
  interface: string;
  window_ms?: number;
}

// ── Display helpers ────────────────────────────────────────────────────────

export const THREAT_CLASS_LABELS: Record<ThreatClass, string> = {
  volumetric_ddos:   'Volumetric DDoS',
  c2_beaconing:      'C2 Beaconing',
  dga_dns_tunneling: 'DGA / DNS Tunneling',
  encrypted_malware: 'Encrypted Malware',
  recon_scanning:    'Recon Scanning',
  data_exfiltration: 'Data Exfiltration',
};

/** CSS custom property name for each threat class — defined in index.css */
export const THREAT_CLASS_COLOR_VAR: Record<ThreatClass, string> = {
  volumetric_ddos:   'var(--tc-volumetric_ddos)',
  c2_beaconing:      'var(--tc-c2_beaconing)',
  dga_dns_tunneling: 'var(--tc-dga_dns_tunneling)',
  encrypted_malware: 'var(--tc-encrypted_malware)',
  recon_scanning:    'var(--tc-recon_scanning)',
  data_exfiltration: 'var(--tc-data_exfiltration)',
};

/** Derive a confidence tier for badge styling */
export function confidenceTier(score: number): 'critical' | 'high' | 'medium' | 'low' {
  if (score >= 0.85) return 'critical';
  if (score >= 0.65) return 'high';
  if (score >= 0.40) return 'medium';
  return 'low';
}
