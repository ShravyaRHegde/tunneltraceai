"""Typed, versioned schema and validation contracts for Continuous Monitoring."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class SensorType(str, Enum):
    """Categorization of monitoring event collector."""

    GATEWAY_COLLECTOR = "GATEWAY_COLLECTOR"
    CAPTURE_SENSOR = "CAPTURE_SENSOR"


class GatewayStatus(str, Enum):
    """Administrative authorization state of a monitored VPN gateway."""

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    REVOKED = "REVOKED"


class SensorStatus(str, Enum):
    """Operational enablement of a registered telemetry sensor."""

    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    DISABLED = "DISABLED"


class EventKind(str, Enum):
    """Normalized lifecycle event types from gateway daemons and capture sensors."""

    # Gateway IKE & Child SA lifecycle
    GATEWAY_IKE_SA_INIT_STARTED = "GATEWAY_IKE_SA_INIT_STARTED"
    GATEWAY_IKE_SA_ESTABLISHED = "GATEWAY_IKE_SA_ESTABLISHED"
    GATEWAY_IKE_SA_FAILED = "GATEWAY_IKE_SA_FAILED"
    GATEWAY_CHILD_SA_ESTABLISHED = "GATEWAY_CHILD_SA_ESTABLISHED"
    GATEWAY_CHILD_SA_REKEYED = "GATEWAY_CHILD_SA_REKEYED"
    GATEWAY_CHILD_SA_EXPIRED = "GATEWAY_CHILD_SA_EXPIRED"
    GATEWAY_CHILD_SA_DELETED = "GATEWAY_CHILD_SA_DELETED"
    GATEWAY_HEARTBEAT = "GATEWAY_HEARTBEAT"

    # Capture sensor lifecycle
    CAPTURE_STARTED = "CAPTURE_STARTED"
    CAPTURE_STOPPED = "CAPTURE_STOPPED"
    CAPTURE_FAILED = "CAPTURE_FAILED"
    CAPTURE_METRICS_HEARTBEAT = "CAPTURE_METRICS_HEARTBEAT"
    CAPTURE_DROPS_RECORDED = "CAPTURE_DROPS_RECORDED"


class EvidenceGrade(str, Enum):
    """Epistemic evidence strength of a recorded observation."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    SYNTHETIC = "SYNTHETIC"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"


class SensorHealthStatus(str, Enum):
    """Continuous health classification for monitored sensors."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    STALE = "STALE"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"
    DISABLED = "DISABLED"


class SAState(str, Enum):
    """Observed state of an active IKE or Child SA."""

    INITIATING = "INITIATING"
    ESTABLISHED = "ESTABLISHED"
    REKEYED = "REKEYED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    DELETED = "DELETED"
    STALE = "STALE"


# Prohibited secret keys that must never be accepted or persisted
PROHIBITED_KEY_PATTERN = re.compile(
    r"(psk|secret|private_key|key_material|enc_key|auth_key|passwd|password)",
    re.IGNORECASE,
)


# ------------------------------------------------------------------------------
# Gateway & Sensor Registration DTOs
# ------------------------------------------------------------------------------


class RegisterGatewayRequest(BaseModel):
    """Request to register an authorized VPN gateway boundary."""

    name: str = Field(..., min_length=2, max_length=128, description="Unique human-readable gateway label")
    gateway_ip: str = Field(..., min_length=7, max_length=64, description="Primary IP address of the gateway")
    authorized_scope: str = Field(..., min_length=3, max_length=256, description="Approved CIDR boundary or scope label")
    operator_id: str = Field(..., min_length=2, max_length=128, description="Operator authorizing the gateway monitoring")
    authorization_reference: str = Field(..., min_length=3, max_length=256, description="Ticket, change order, or mandate reference")


class GatewayResponse(BaseModel):
    """Response DTO for an authorized VPN gateway."""

    id: uuid.UUID
    name: str
    gateway_ip: str
    authorized_scope: str
    operator_id: str
    authorization_reference: str
    status: GatewayStatus
    created_at: datetime
    updated_at: datetime


class RegisterSensorRequest(BaseModel):
    """Request to register a telemetry collector sensor bound to an authorized gateway."""

    sensor_name: str = Field(..., min_length=2, max_length=128, description="Unique sensor identifier")
    sensor_type: SensorType = Field(..., description="Type of sensor: GATEWAY_COLLECTOR or CAPTURE_SENSOR")
    gateway_id: uuid.UUID = Field(..., description="ID of the authorized gateway this sensor monitors")
    authorized_scope: str = Field(..., min_length=3, max_length=256, description="Explicit CIDR scope boundary")
    freshness_window_seconds: int = Field(default=60, ge=10, le=86400, description="Seconds without events before marked STALE")
    reporting_interval_seconds: int = Field(default=30, ge=5, le=3600, description="Expected reporting cadence in seconds")


class RegisterSensorResponse(BaseModel):
    """Response returned upon successful sensor registration, including raw token displayed once."""

    id: uuid.UUID
    sensor_name: str
    sensor_type: SensorType
    gateway_id: uuid.UUID
    authorized_scope: str
    token_prefix: str
    raw_token: str = Field(..., description="Secret authentication token. Displayed once; never stored in plaintext.")
    freshness_window_seconds: int
    reporting_interval_seconds: int
    status: SensorStatus
    created_at: datetime


class SensorResponse(BaseModel):
    """Public details of a registered telemetry sensor (secret token omitted)."""

    id: uuid.UUID
    sensor_name: str
    sensor_type: SensorType
    gateway_id: uuid.UUID
    authorized_scope: str
    token_prefix: str
    freshness_window_seconds: int
    reporting_interval_seconds: int
    status: SensorStatus
    created_at: datetime
    revoked_at: datetime | None
    last_heartbeat_at: datetime | None


# ------------------------------------------------------------------------------
# Monitoring Event Contracts & Validation
# ------------------------------------------------------------------------------


class MonitoringEventDTO(BaseModel):
    """Typed, versioned event contract ingested from an authorized telemetry sensor."""

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique event identifier")
    schema_version: str = Field(default="v1.0.0", description="Event contract schema semver")
    sensor_id: uuid.UUID = Field(..., description="Registered sensor identifier")
    gateway_id: uuid.UUID = Field(..., description="Authorized gateway identifier")
    authorized_scope: str = Field(..., min_length=3, max_length=256, description="Approved scope boundary")
    event_kind: EventKind = Field(..., description="Normalized lifecycle or telemetry event kind")
    source_timestamp: datetime = Field(..., description="UTC timestamp observed by source sensor")
    sequence_number: int | None = Field(default=None, ge=0, description="Monotonic sequence number from sensor")
    source_boot_id: str | None = Field(default=None, max_length=64, description="Boot/restart identifier of sensor host")
    source_session_id: str | None = Field(default=None, max_length=64, description="Daemon run/process identifier")
    evidence_grade: EvidenceGrade = Field(default=EvidenceGrade.OBSERVED)
    raw_source_status: str | None = Field(default=None, description="Raw status or log string from daemon")

    # Normalized IKE / SA fields
    ike_version: str | None = Field(default=None, max_length=16)
    local_endpoint: str | None = Field(default=None, max_length=64)
    remote_endpoint: str | None = Field(default=None, max_length=64)
    initiator_spi: str | None = Field(default=None, max_length=32)
    responder_spi: str | None = Field(default=None, max_length=32)
    child_spi_in: str | None = Field(default=None, max_length=32)
    child_spi_out: str | None = Field(default=None, max_length=32)
    cipher_suite: str | None = Field(default=None, max_length=128)
    failure_reason: str | None = Field(default=None)
    failure_code: str | None = Field(default=None, max_length=64)

    # Normalized capture fields
    interface_name: str | None = Field(default=None, max_length=64)
    packet_count: int | None = Field(default=None, ge=0)
    drop_count: int | None = Field(default=None, ge=0)
    byte_count: int | None = Field(default=None, ge=0)
    artifact_hash: str | None = Field(default=None, max_length=64)

    # Provenance and metadata
    collector_version: str | None = Field(default=None, max_length=64)
    payload: dict[str, Any] | None = Field(default=None, description="Sanitized payload strictly free of secrets")

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, v: str) -> str:
        if not v.startswith("v1"):
            raise ValueError(f"Unsupported schema_version '{v}'. Expected v1.x.x.")
        return v

    @field_validator("source_timestamp")
    @classmethod
    def validate_timestamp_not_unreasonable_future(cls, v: datetime) -> datetime:
        now_utc = datetime.now(timezone.utc)
        ts = v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        diff = (ts - now_utc).total_seconds()
        if diff > 60.0:
            raise ValueError(
                f"source_timestamp '{ts.isoformat()}' is {diff:.1f}s in the future. "
                "Unreasonable clock skew or invalid timestamp."
            )
        return ts

    @model_validator(mode="before")
    @classmethod
    def scrub_secrets_from_payload(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Check top-level keys for secrets
            for k in list(data.keys()):
                if PROHIBITED_KEY_PATTERN.search(str(k)):
                    del data[k]

            # Check nested payload
            payload = data.get("payload")
            if isinstance(payload, dict):
                cleaned_payload = {}
                for pk, pv in payload.items():
                    if not PROHIBITED_KEY_PATTERN.search(str(pk)):
                        cleaned_payload[pk] = pv
                data["payload"] = cleaned_payload
        return data


class MonitoringEventBatchRequest(BaseModel):
    """Batch ingestion request containing up to 100 typed monitoring events."""

    events: list[MonitoringEventDTO] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of monitoring events to ingest (max 100 per batch)",
    )


class MonitoringEventBatchResponse(BaseModel):
    """Deterministic outcome of a batch ingestion request."""

    batch_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    total_received: int
    accepted_count: int
    duplicate_count: int
    rejected_count: int
    sequence_gaps_detected: int
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ------------------------------------------------------------------------------
# Projections & Health Query DTOs
# ------------------------------------------------------------------------------


class SensorHealthDTO(BaseModel):
    """Comprehensive health and freshness state for a registered sensor."""

    sensor_id: uuid.UUID
    sensor_name: str
    sensor_type: SensorType
    gateway_id: uuid.UUID
    gateway_name: str
    authorized_scope: str
    current_health: SensorHealthStatus
    health_reason: str
    last_source_timestamp: datetime | None
    last_received_at: datetime | None
    freshness_window_seconds: int
    reporting_interval_seconds: int
    total_events_received: int
    total_drops_reported: int
    sequence_gaps_count: int
    clock_skew_seconds: float
    active_quality_warnings: list[str]
    is_stale: bool


class MonitoredSAStateDTO(BaseModel):
    """Rebuildable state projection of an active or recent IKE/Child SA."""

    id: uuid.UUID
    gateway_id: uuid.UUID
    gateway_name: str
    sensor_id: uuid.UUID
    sa_type: str
    initiator_spi: str
    responder_spi: str | None
    child_spi_in: str | None
    child_spi_out: str | None
    state: SAState
    local_endpoint: str | None
    remote_endpoint: str | None
    cipher_suite: str | None
    established_at: datetime | None
    last_event_at: datetime
    is_stale: bool
    staleness_reason: str | None
    evidence_grade: EvidenceGrade


class MonitoringTimelineFilter(BaseModel):
    """Query filters for the immutable event timeline."""

    gateway_id: uuid.UUID | None = None
    sensor_id: uuid.UUID | None = None
    event_kind: EventKind | None = None
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
