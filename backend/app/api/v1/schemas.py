import re
import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class CaptureResponseDTO(BaseModel):
    """Metadata response for an ingested packet capture."""

    capture_id: uuid.UUID
    capture_source: str
    capture_format: str
    original_filename: str | None
    file_size_bytes: int
    sha256: str
    packet_count: int | None = None
    duration_sec: float | None = None
    first_packet_at: datetime | None = None
    last_packet_at: datetime | None = None
    link_layer_type: str | None = None
    validation_state: str
    created_at: datetime


class CreateAnalysisRequestDTO(BaseModel):
    """Request payload to initiate protocol analysis."""

    capture_id: uuid.UUID = Field(..., description="Target capture UUID to analyze")


class AnalysisRunResponseDTO(BaseModel):
    """Response payload detailing analysis run status and stage."""

    analysis_id: uuid.UUID
    capture_id: uuid.UUID
    capture_filename: str | None = None
    capture_sha256: str | None = None
    status: str
    current_stage: str
    parser_engine: str
    parser_version: str
    schema_version: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None
    parent_analysis_id: uuid.UUID | None = None
    replay_mode: str | None = None
    provenance_metadata: dict | None = None
    created_at: datetime


class ReplayExecutionResponseDTO(BaseModel):
    """Response payload returned when a forensic re-analysis run is executed."""

    child_analysis_id: uuid.UUID
    parent_analysis_id: uuid.UUID
    replay_mode: str
    status: str
    artifact_integrity: str
    comparison_status: str
    summary: str
    differences: dict | None = None
    metrics: dict | None = None
    created_at: datetime


class InterfaceMetadataDTO(BaseModel):
    """Authorized network interface for live capture."""

    interface_id: str
    display_name: str
    type: str
    capture_allowed: bool
    lab_owned: bool
    operstate: str = "UNKNOWN"


class StartLiveCaptureRequestDTO(BaseModel):
    """Request payload to initiate authorized live packet capture."""

    interface_id: str = Field(..., max_length=32, description="Target network interface (must be in allowlist)")
    duration_sec: int | None = Field(None, ge=1, le=300, description="Optional maximum capture duration in seconds (1-300)")
    capture_profile: str = Field(default="IPSEC_RELEVANT", max_length=64, description="Capture profile preset")
    bpf_filter: str | None = Field(None, max_length=256, description="Optional BPF filter expression")

    @field_validator("interface_id")
    @classmethod
    def validate_interface_id(cls, v: str) -> str:
        clean = v.strip()
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", clean):
            raise ValueError("interface_id contains invalid characters")
        return clean

    @field_validator("bpf_filter")
    @classmethod
    def validate_bpf_filter(cls, v: str | None) -> str | None:
        if v is None:
            return None
        clean = v.strip()
        if not clean:
            return None
        for forbidden in (";", "&", "|", "`", "$", "(", ")", ">", "<", "\n", "\r", "\t", "\\"):
            if forbidden in clean:
                raise ValueError(f"bpf_filter contains forbidden shell character: {forbidden!r}")
        if not re.match(r"^[a-zA-Z0-9\s_\-\.:/]+$", clean):
            raise ValueError(f"bpf_filter contains invalid characters: '{clean}'")
        return clean


class LiveCaptureSessionResponseDTO(BaseModel):
    """Response payload for a live capture session."""

    session_id: uuid.UUID
    interface_name: str
    status: str
    capture_profile: str
    packet_count: int
    byte_count: int
    duration_sec: float | None = None
    capture_id: uuid.UUID | None = None
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    created_at: datetime


class StopLiveCaptureResponseDTO(BaseModel):
    """Response payload after stopping and finalizing a live capture."""

    session_id: uuid.UUID
    capture_id: uuid.UUID
    analysis_id: uuid.UUID | None = None
    status: str
    file_size_bytes: int
    packet_count: int
    sha256: str


class AnalysisListItemDTO(BaseModel):
    """Concise item for historical and active analysis triage lists."""

    analysis_id: uuid.UUID
    capture_id: uuid.UUID
    capture_filename: str
    capture_sha256: str
    status: str
    current_stage: str
    created_at: datetime
    completed_at: datetime | None = None
    security_score: float | None = None
    critical_findings: int = 0
    high_findings: int = 0
    parent_analysis_id: uuid.UUID | None = None
    replay_mode: str | None = None
    provenance_metadata: dict | None = None
    is_synthetic_demo: bool = False


class TrafficFlowItemDTO(BaseModel):
    """Encrypted ESP flow annotated with Stage 7 ML inferences and explainability."""

    flow_id: uuid.UUID
    spi: str
    reverse_spi: str | None = None
    src_ip: str
    dst_ip: str
    duration_seconds: float
    packet_count: int
    byte_count: int
    association_state: str
    input_status: str | None = None
    supervised_hypothesis: str | None = None
    known_class: str | None = None
    final_class: str | None = None
    accepted_prediction: str | None = None
    calibrated_confidence: float | None = None
    calibration_status: str | None = None
    normalized_entropy: float | None = None
    ood_status: str | None = None
    behavioral_anomaly_status: str | None = None
    anomaly_score: float | None = None
    is_degraded: bool | None = None
    degraded_reason: str | None = None
    top_shap_features: list[dict] | None = None


class TrafficSummaryResponseDTO(BaseModel):
    """Response payload for Traffic Intelligence view."""

    analysis_id: uuid.UUID
    total_flows: int
    classified_flows: int
    classes_detected: list[str]
    ood_count: int
    anomaly_count: int
    ml_run_status: str = "NOT_CONFIGURED"
    model_version: str | None = None
    model_bundle_id: str | None = None
    flows: list[TrafficFlowItemDTO]


class AnalysisOverviewDTO(BaseModel):
    """Consolidated summary payload for Command Center overview."""

    analysis_id: uuid.UUID
    capture: dict
    analysis: dict
    security_posture: dict
    compliance_counts: dict
    findings_summary: dict
    traffic_summary: dict
    fingerprintability: dict
    protocol_summary: dict

