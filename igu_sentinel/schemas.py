"""Data contracts for IGU Sentinel pipeline."""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator


class FlowRecord(BaseModel):
    """Network flow metadata extracted from capture."""

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
    byte_ratio: float = Field(..., description="Byte ratio metric")
    ttl: int = Field(..., description="Time-to-live")
    ja4: Optional[str] = Field(None, description="JA4 TLS fingerprint")
    beacon_interval_stats: Optional[Dict[str, float]] = Field(
        None, description="Beacon interval statistics {mean, std}"
    )
    dns_ngram_entropy: Optional[float] = Field(None, description="DNS n-gram entropy")
    fanout_count: Optional[int] = Field(None, description="Connection fanout count")


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
