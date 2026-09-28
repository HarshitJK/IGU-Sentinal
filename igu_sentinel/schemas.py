"""Data contracts for IGU Sentinel pipeline.

Feature contract version: FEATURE_CONTRACT_VERSION tracks the schema so that
model artifacts trained on a different version are rejected at load time rather
than silently producing garbage scores.

v1 (original): 16-feature vector, byte_ratio = payload/frame fraction.
v2 (opt-in): 27-feature vector; v1 serving remains the default until retraining.
  * payload_frame_ratio  — payload bytes / total frame bytes (renamed from
                           byte_ratio; byte_ratio remains for compatibility).
  * outbound_bytes       — bytes observed flowing AWAY from protected_network.
                           None when directional information is unavailable
                           (e.g. single-sided one-way-transport observation).
                           Explicitly None rather than 0 so callers can tell
                           "not observed" apart from "observed to be zero".
  * inbound_bytes        — bytes observed flowing TOWARD protected_network.
                           Same None-for-missing semantics.
  * pkt_rate             — packets per second observed in this window.
  * byte_rate            — bytes per second (total frame bytes).
  * syn_count            — TCP SYN packets seen in this window.
  * syn_fraction         — SYN packets / total packets [0, 1]; 0 for non-TCP.
  * src_ip_entropy       — Shannon entropy of distinct source IPs per window.
                           High for spoofed DDoS, low for single-source flows.
  * dns_query_len        — mean DNS query label length; None for non-DNS flows.
  * dns_record_type      — most common DNS record type (A/AAAA/TXT/…);
                           None for non-DNS flows.
"""
import os
from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel, Field, field_validator

# Increment this when the feature vector layout changes.  Model artifacts embed
# this value at training time; the loaders reject any artifact whose stored
# version does not match.
FEATURE_CONTRACT_VERSION: int = int(os.environ.get("IGU_FEATURE_CONTRACT_VERSION", "1"))
if FEATURE_CONTRACT_VERSION not in (1, 2):
    raise ValueError("IGU_FEATURE_CONTRACT_VERSION must be 1 or 2")


class FlowRecord(BaseModel):
    """Network flow metadata extracted from capture (feature contract v2)."""

    flow_id: str = Field(..., description="Unique flow identifier")
    timestamp: datetime = Field(..., description="Flow start time")
    src_port: int = Field(..., description="Source port")
    dst_port: int = Field(..., description="Destination port")
    protocol: str = Field(..., description="Protocol (TCP, UDP, etc.)")
    packet_size_stats: Dict[str, float] = Field(
        ..., description="Packet size statistics {min, max, mean, std}"
    )
    inter_arrival_stats: Dict[str, float] = Field(
        ..., description="Inter-arrival time statistics {mean, std}"
    )
    entropy: float = Field(..., description="Payload entropy")

    # ── v1 field (preserved for backward compatibility) ───────────────────────
    # payload_frame_ratio is the canonical name; byte_ratio is the old alias.
    # Both refer to payload bytes / total frame bytes [0, 1].  New code should
    # read payload_frame_ratio; old JSONL fixtures continue to use byte_ratio.
    byte_ratio: float = Field(
        ...,
        description=(
            "Payload bytes / total frame bytes [0, 1].  "
            "Alias for payload_frame_ratio; kept for fixture compatibility."
        ),
    )

    ttl: int = Field(..., description="Time-to-live")
    ja4: Optional[str] = Field(None, description="JA4 TLS fingerprint")
    beacon_interval_stats: Optional[Dict[str, float]] = Field(
        None, description="Beacon interval statistics {mean, std}"
    )
    dns_ngram_entropy: Optional[float] = Field(None, description="DNS n-gram entropy")
    fanout_count: Optional[int] = Field(None, description="Connection fanout count")

    # ── v2 additions ──────────────────────────────────────────────────────────
    # Directional byte volumes.  None = not observable from this vantage point.
    # A one-way monitoring transport may have observations of both directions of
    # a production conversation, or only one — explicit None lets the feature
    # extractor distinguish "observed zero" from "not seen".
    outbound_bytes: Optional[int] = Field(
        None, ge=0,
        description=(
            "Bytes flowing away from protected_network in this window.  "
            "None when directional information is unavailable."
        ),
    )
    inbound_bytes: Optional[int] = Field(
        None, ge=0,
        description=(
            "Bytes flowing toward protected_network in this window.  "
            "None when directional information is unavailable."
        ),
    )

    # Windowed rate features — the 120ms window is fixed, so these are derived
    # from packet_count / window_duration and total frame bytes / window_duration.
    pkt_rate: float = Field(
        0.0, ge=0, allow_inf_nan=False,
        description="Packets per second observed in this capture window.",
    )
    byte_rate: float = Field(
        0.0, ge=0, allow_inf_nan=False,
        description="Total frame bytes per second in this capture window.",
    )

    # SYN statistics — distinguish TCP SYN floods from data transfers.
    syn_count: int = Field(
        0, ge=0,
        description="TCP SYN packets seen in this window (0 for non-TCP).",
    )
    syn_fraction: float = Field(
        0.0, ge=0, le=1, allow_inf_nan=False,
        description="SYN packets / total packets [0, 1]; 0 for non-TCP flows.",
    )

    # Source-IP entropy — high entropy indicates spoofed/distributed DDoS.
    src_ip_entropy: float = Field(
        0.0, ge=0, allow_inf_nan=False,
        description=(
            "Shannon entropy of distinct source IPs contributing to this window.  "
            "Near 0 for single-source flows; high for distributed or spoofed floods."
        ),
    )

    # DNS query features — separate from n-gram entropy.
    dns_query_len: Optional[float] = Field(
        None, ge=0, allow_inf_nan=False,
        description="Mean DNS query label length (characters); None for non-DNS flows.",
    )
    dns_record_type: Optional[str] = Field(
        None,
        description=(
            "Most common DNS record type seen (A, AAAA, TXT, MX, …); "
            "None for non-DNS flows.  TXT at high rate indicates tunnelling."
        ),
    )

    @property
    def payload_frame_ratio(self) -> float:
        """Canonical name for the payload/frame byte ratio (byte_ratio alias)."""
        return self.byte_ratio


class LayerScore(BaseModel):
    """Detection layer output: raw and calibrated scores."""

    flow_id: str = Field(..., description="Unique flow identifier")
    layer_name: str = Field(..., description="Detection layer name (rules, stats, isoforest, xgb)")
    raw_score: float = Field(..., description="Raw anomaly/threat score [0, 1]")
    calibrated_probability: float = Field(
        ..., description="Platt-calibrated probability [0, 1]"
    )
    threat_class_guess: Optional[str] = Field(
        None, description="Predicted threat class (if applicable)"
    )
    evidence: Optional[List[str]] = Field(
        None, description="List of evidence/reasoning strings"
    )


class Alert(BaseModel):
    """Fused alert schema (PS-mandated)."""

    timestamp: datetime = Field(..., description="Alert timestamp")
    flow_id: str = Field(..., description="Source flow identifier")
    threat_class: str = Field(
        ..., description="Threat classification (one of six mandated types)"
    )
    confidence_score: float = Field(..., description="Calibrated confidence [0, 1]")
    evidence: List[str] = Field(..., description="Fused evidence from all layers")

    @field_validator("threat_class")
    @classmethod
    def validate_threat_class(cls, v: str) -> str:
        """Ensure threat_class is one of the six mandated types."""
        valid_classes = {
            "volumetric_ddos",
            "c2_beaconing",
            "dga_dns_tunneling",
            "encrypted_malware",
            "recon_scanning",
            "data_exfiltration",
        }
        if v not in valid_classes:
            raise ValueError(
                f"threat_class must be one of {valid_classes}, got {v}"
            )
        return v
