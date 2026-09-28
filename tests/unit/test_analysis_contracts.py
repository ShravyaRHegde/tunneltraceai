"""Unit tests for Phase 1 contract integrity and Phase 3 synthetic pulse quarantine."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from app.api.v1.schemas import AnalysisListItemDTO
from app.monitoring.schema import (
    EventKind,
    EvidenceGrade,
    MonitoringEventBatchRequest,
    MonitoringEventDTO,
    SensorHealthStatus,
)
from app.remediation.parser import ForensicFactsSnapshotBuilder
from app.security.facts.models import DerivationType, EvidenceState, SecurityFact, SubjectType


class TestAnalysisContractIntegrity:
    """Verifies DTO serialization and consistency of analysis summary metrics."""

    def test_analysis_list_item_dto_optional_fields_defaults(self):
        """Ensures missing/legacy API fields have safe, truthful defaults."""
        aid = uuid.uuid4()
        cid = uuid.uuid4()
        now = datetime.now(timezone.utc)
        item = AnalysisListItemDTO(
            analysis_id=aid,
            capture_id=cid,
            capture_filename="test_capture.pcap",
            capture_sha256="a" * 64,
            status="COMPLETED",
            current_stage="COMPLETED",
            created_at=now,
        )
        assert item.analysis_id == aid
        assert item.packet_count is None
        assert item.flows_count is None
        assert item.ike_sessions_count is None
        assert item.model_artifact_state == "EXPERIMENTAL"
        assert item.is_synthetic_demo is False
        assert item.security_score is None

    def test_forensic_facts_snapshot_builder_maps_wire_facts(self):
        """Verifies that observable wire facts (IKEv2, AES-GCM, child mode) are extracted as KNOWN."""
        aid = str(uuid.uuid4())
        sha = "b" * 64
        facts = [
            SecurityFact(
                key="ike_session.ike_version",
                value="IKEv2",
                data_type="string",
                subject_type=SubjectType.IKE_SESSION,
                subject_id="sess_1",
                evidence_state=EvidenceState.VERIFIED,
                analysis_id=aid,
                capture_sha256=sha,
                derivation_type=DerivationType.DIRECT,
            ),
            SecurityFact(
                key="ike_sa.encryption_algorithm",
                value="AES-GCM-16-256",
                data_type="string",
                subject_type=SubjectType.IKE_SA,
                subject_id="sa_1",
                evidence_state=EvidenceState.VERIFIED,
                analysis_id=aid,
                capture_sha256=sha,
                derivation_type=DerivationType.DIRECT,
            ),
            SecurityFact(
                key="child_sa.mode",
                value="TUNNEL",
                data_type="string",
                subject_type=SubjectType.CHILD_SA,
                subject_id="csa_1",
                evidence_state=EvidenceState.VERIFIED,
                analysis_id=aid,
                capture_sha256=sha,
                derivation_type=DerivationType.DIRECT,
            ),
        ]

        snapshot = ForensicFactsSnapshotBuilder.build_snapshot(aid, sha, facts)
        assert snapshot.ike_version.value == "IKEv2"
        assert snapshot.ike_version.state.value == "KNOWN"
        assert snapshot.ike_encryption.value == "AES-GCM-16-256"
        assert snapshot.ike_encryption.state.value == "KNOWN"
        assert snapshot.child_mode.value == "TUNNEL"
        assert snapshot.child_mode.state.value == "KNOWN"

    def test_forensic_facts_snapshot_builder_handles_unobserved_mode(self):
        """Verifies unobserved facts correctly return UNKNOWN without raising errors."""
        aid = str(uuid.uuid4())
        sha = "c" * 64
        facts = []
        snapshot = ForensicFactsSnapshotBuilder.build_snapshot(aid, sha, facts)
        assert snapshot.child_mode.value is None
        assert snapshot.child_mode.state.value == "UNKNOWN"
        assert snapshot.ike_version.state.value == "UNKNOWN"


class TestSyntheticPulseQuarantineContract:
    """Verifies that synthetic monitoring pulses are tagged with SYNTHETIC evidence grade."""

    def test_synthetic_event_dto_tags(self):
        sid = uuid.uuid4()
        gid = uuid.uuid4()
        now = datetime.now(timezone.utc)
        event = MonitoringEventDTO(
            event_id=uuid.uuid4(),
            sensor_id=sid,
            gateway_id=gid,
            authorized_scope="198.51.100.0/24",
            event_kind=EventKind.GATEWAY_HEARTBEAT,
            evidence_grade=EvidenceGrade.SYNTHETIC,
            sequence_number=1,
            source_timestamp=now,
            payload={"is_synthetic_test": True},
        )
        assert event.evidence_grade == EvidenceGrade.SYNTHETIC
        assert event.payload["is_synthetic_test"] is True
