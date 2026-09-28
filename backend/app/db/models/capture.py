"""SQLAlchemy declarative models for Captures, Analysis Runs, and Protocol Observations."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.reconstruction import (
        ChildSecurityAssociation,
        ESPFlow,
        IKESession,
    )


class Capture(Base):
    """Represents an ingested packet capture artifact (PCAP/PCAPNG), offline or live."""

    __tablename__ = "captures"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    capture_source: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # OFFLINE_UPLOAD, LIVE_CAPTURE, TESTBED_GENERATED
    capture_format: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # PCAP, PCAPNG
    original_filename: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # Sanitized display metadata only
    storage_path: Mapped[str] = mapped_column(
        String(512), nullable=False
    )  # Relative safe path in storage
    file_size_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False
    )
    sha256_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    packet_count: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    first_packet_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_packet_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_sec: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    link_layer_type: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    interface_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    validation_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="VALIDATED"
    )  # VALIDATED, REJECTED, PENDING
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    analyses: Mapped[list[AnalysisRun]] = relationship(
        "AnalysisRun", back_populates="capture", cascade="all, delete-orphan"
    )


class AnalysisRun(Base):
    """Represents an asynchronous execution of protocol analysis on an immutable capture."""

    __tablename__ = "analysis_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    capture_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("captures.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="QUEUED", index=True
    )  # QUEUED, RUNNING, COMPLETED, PARTIAL, FAILED, CANCELLED
    current_stage: Mapped[str] = mapped_column(
        String(64), nullable=False, default="INGESTING"
    )  # INGESTING, PROTOCOL_ANALYSIS, COMPLETED
    parser_engine: Mapped[str] = mapped_column(
        String(32), nullable=False, default="tshark"
    )
    parser_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0.0"
    )
    pipeline_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="2.0.0"
    )
    policy_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0"
    )
    is_archived: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_code: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    parent_analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    replay_mode: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )  # FORENSIC_REANALYSIS, SCENARIO_REPLAY
    provenance_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    capture: Mapped[Capture] = relationship(
        "Capture", back_populates="analyses"
    )
    parent_analysis: Mapped[AnalysisRun | None] = relationship(
        "AnalysisRun",
        remote_side=[id],
        foreign_keys=[parent_analysis_id],
        backref="child_analyses",
    )
    observations: Mapped[list[ProtocolObservation]] = relationship(
        "ProtocolObservation", back_populates="analysis", cascade="all, delete-orphan"
    )
    ike_sessions: Mapped[list[IKESession]] = relationship(
        "IKESession", back_populates="analysis", cascade="all, delete-orphan"
    )
    child_sas: Mapped[list[ChildSecurityAssociation]] = relationship(
        "ChildSecurityAssociation", back_populates="analysis", cascade="all, delete-orphan"
    )
    flows: Mapped[list[ESPFlow]] = relationship(
        "ESPFlow", back_populates="analysis", cascade="all, delete-orphan"
    )


class ProtocolObservation(Base):
    """Persisted, normalized, deterministic IPsec protocol fact extracted from packet dissection."""

    __tablename__ = "protocol_observations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    frame_number: Mapped[int] = mapped_column(
        Integer, nullable=False, index=True
    )
    frame_offset: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    packet_time: Mapped[float] = mapped_column(
        Float, nullable=False
    )
    protocol: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # IKEv1, IKEv2, ESP, AH, NAT-T, IPv4, IPv6, UDP
    category: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # IKE_HEADER, IKE_EXCHANGE, IKE_SA_PROPOSAL, IKE_TRANSFORM, IKE_NOTIFY, IKE_TRAFFIC_SELECTOR, ESP_HEADER, AH_HEADER, NAT_T
    field_name: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    normalized_value: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    raw_value: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    raw_numeric_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    source_field: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    source_tool: Mapped[str] = mapped_column(
        String(32), nullable=False, default="tshark"
    )
    source_tool_version: Mapped[str] = mapped_column(
        String(32), nullable=False
    )
    evidence_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="VERIFIED", index=True
    )  # VERIFIED, INFERRED, UNKNOWN, MISCONFIGURATION_OBSERVED
    src_ip: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    dst_ip: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    src_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    dst_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    extra_attributes: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # Relationships
    analysis: Mapped[AnalysisRun] = relationship(
        "AnalysisRun", back_populates="observations"
    )


class LiveCaptureSession(Base):
    """Represents an authorized live network interface packet capture session."""

    __tablename__ = "live_capture_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    interface_name: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="CREATED", index=True
    )  # CREATED, CAPTURING, STOPPING, COMPLETED, FAILED, CANCELLED
    capture_profile: Mapped[str] = mapped_column(
        String(64), nullable=False, default="IPSEC_RELEVANT"
    )
    bpf_filter: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    max_duration_sec: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    max_bytes: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    packet_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    byte_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    storage_path: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )
    capture_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("captures.id", ondelete="SET NULL"),
        nullable=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    stopped_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
