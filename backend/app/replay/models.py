"""Data transfer objects and domain exceptions for Replay and Evidence Chain."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CaptureIntegrityError(Exception):
    """Raised when on-disk capture bytes fail SHA-256 integrity check against recorded hash."""

    def __init__(self, message: str, expected_hash: str = "", actual_hash: str = "") -> None:
        super().__init__(message)
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash


class EnvironmentMismatchError(Exception):
    """Raised when an environment cannot satisfy the required scenario replay tools/kernel."""

    def __init__(self, message: str, missing_tools: list[str] | None = None) -> None:
        super().__init__(message)
        self.missing_tools = missing_tools or []


class ForensicReanalysisRequestDTO(BaseModel):
    """Optional version pins requested for deterministic re-analysis."""

    pinned_parser_engine: str = Field(default="tshark", description="Dissection engine")
    pinned_parser_version: str | None = Field(default=None, description="Exact parser version required")
    pinned_policy_bundle_version: str | None = Field(default=None, description="Security policy bundle version")
    pinned_model_bundle_id: str | None = Field(default=None, description="Traffic ML model bundle ID")


class ReplayComparisonDTO(BaseModel):
    """Structured result of deterministic or semantic comparison."""

    comparison_id: uuid.UUID
    replay_mode: str
    parent_run_id: str
    child_run_id: str
    comparison_status: str
    artifact_integrity: str
    differences: dict[str, Any] | None = None
    summary: str
    metrics: dict[str, Any] | None = None
    created_at: datetime


class ReplayLineageDTO(BaseModel):
    """Complete provenance lineage, version pins, and replay history for an analysis run."""

    analysis_id: uuid.UUID
    parent_analysis_id: uuid.UUID | None
    replay_mode: str | None
    capture_id: uuid.UUID
    capture_filename: str
    capture_sha256: str
    capture_integrity_verified: bool
    capture_integrity_status: str = "NOT_CHECKED"
    actual_capture_sha256: str | None = None
    child_runs: list[dict[str, Any]] = Field(default_factory=list)
    version_pins: dict[str, Any] = Field(default_factory=dict)
    latest_comparison: ReplayComparisonDTO | None = None
