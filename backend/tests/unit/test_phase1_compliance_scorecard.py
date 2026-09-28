"""Unit tests for Phase 1: Compliance Scorecard Data Bug & Severity Matrix.

Verifies:
1. Explicit severity matrix for FAIL/UNKNOWN/PASS across rules.
2. Compliance summary API returns non-empty title, category, standard, and severity.
3. Analysis snapshot builds enriched compliance evaluations with real titles and citations.
"""

import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.db.base import Base
from app.db.session import get_db_session
from app.main import create_app
from app.db.models.capture import AnalysisRun, Capture
from app.db.models.security import ComplianceEvaluationModel, ScoreAssessmentModel
from app.api.v1.security.router import resolve_compliance_severity
from app.reporting.snapshot import AnalysisSnapshotBuilder


def test_severity_matrix_mappings():
    """Verify explicit severity matrix mapping requirements from Phase 1 rebuild plan."""
    # 1. Cipher / Key Length (3DES, <128-bit)
    assert resolve_compliance_severity("POL-NIST-001", "CRYPTOGRAPHY", "FAIL") == "CRITICAL"
    assert resolve_compliance_severity("POL-RFC-8221-01", "CIPHER_SUITE", "FAIL") == "CRITICAL"
    assert resolve_compliance_severity("POL-NIST-001", "CRYPTOGRAPHY", "UNKNOWN") == "MEDIUM"

    # 2. Key exchange / DH group strength
    assert resolve_compliance_severity("POL-NIST-004", "KEY_EXCHANGE", "FAIL") == "HIGH"
    assert resolve_compliance_severity("POL-NIST-004", "KEY_EXCHANGE", "UNKNOWN") == "MEDIUM"

    # 3. Perfect Forward Secrecy
    assert resolve_compliance_severity("POL-PFS-001", "PFS", "FAIL") == "MEDIUM"
    assert resolve_compliance_severity("POL-PFS-001", "PFS", "UNKNOWN") == "LOW"

    # 4. Replay protection / anti-replay window
    assert resolve_compliance_severity("POL-REPLAY-001", "REPLAY_EVIDENCE", "FAIL") == "HIGH"
    assert resolve_compliance_severity("POL-REPLAY-001", "REPLAY_EVIDENCE", "UNKNOWN") == "MEDIUM"

    # 5. PASS state preserves standard severity
    assert resolve_compliance_severity("POL-NIST-001", "CRYPTOGRAPHY", "PASS", "CRITICAL") == "CRITICAL"
    assert resolve_compliance_severity("POL-PFS-001", "PFS", "PASS", "MEDIUM") == "MEDIUM"


@pytest.mark.asyncio
async def test_compliance_summary_endpoint_enrichment():
    """Test that GET /api/v1/analyses/{id}/compliance enriches evaluations with real titles, categories, standards, and severities."""
    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    settings = Settings(
        DATABASE_URL=test_db_url,
        ENVIRONMENT="test",
        DEBUG=True,
    )
    app = create_app(settings=settings)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db_session] = override_get_db

    # Seed test capture and analysis run with compliance evaluation
    analysis_id = uuid.uuid4()
    capture_id = uuid.uuid4()

    async with session_factory() as session:
        cap = Capture(
            id=capture_id,
            capture_source="UPLOAD",
            capture_format="PCAP",
            original_filename="sample_test.pcap",
            file_size_bytes=1024,
            sha256_hash="a" * 64,
            packet_count=10,
            storage_path="/tmp/sample_test.pcap",
            validation_state="VALID",
        )
        run = AnalysisRun(
            id=analysis_id,
            capture_id=capture_id,
            status="COMPLETED",
            current_stage="COMPLETED",
            pipeline_version="2.0.0",
            policy_version="1.0.0",
        )
        eval1 = ComplianceEvaluationModel(
            analysis_id=analysis_id,
            bundle_id="bundle-nist-sp800-77",
            rule_id="POL-NIST-001",
            rule_version="1.0.0",
            subject_type="IPSEC_ENTITY",
            subject_id="GLOBAL",
            compliance_state="PASS",
            evidence_state="VERIFIED",
            rationale="AES-256 negotiated; 3DES not observed.",
        )
        eval2 = ComplianceEvaluationModel(
            analysis_id=analysis_id,
            bundle_id="bundle-nist-sp800-77",
            rule_id="POL-NIST-004",
            rule_version="1.0.0",
            subject_type="IPSEC_ENTITY",
            subject_id="GLOBAL",
            compliance_state="UNKNOWN",
            evidence_state="UNOBSERVED",
            rationale="IKE_SA_INIT unobserved in partial capture.",
        )
        score = ScoreAssessmentModel(
            analysis_id=analysis_id,
            overall_score=85.0,
            raw_score=85.0,
            score_policy_id="policy_default_v1",
            score_policy_version="1.0.0",
            score_policy_hash="0123456789abcdef",
            status="VALIDATED",
            coverage_percentage=75.0,
            category_scores={},
            deduction_audit={},
            evidence_coverage={},
        )
        session.add_all([cap, run, eval1, eval2, score])
        await session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/analyses/{analysis_id}/compliance")
        assert resp.status_code == 200, resp.text
        data = resp.json()

        assert data["profile_name"] == "NIST SP 800-77 Rev. 1 Federal Security Profile"
        assert len(data["evaluations"]) == 2

        # Check POL-NIST-001 enrichment
        e1 = next(e for e in data["evaluations"] if e["rule_id"] == "POL-NIST-001")
        assert e1["rule_title"] == "Prohibition of DES and Triple-DES (3DES)"
        assert e1["category"] == "CRYPTOGRAPHY"
        assert "NIST SP 800-77 Rev. 1" in e1["standard"]
        assert e1["severity"] == "CRITICAL"
        assert e1["compliance_state"] == "PASS"

        # Check POL-NIST-004 enrichment (UNKNOWN -> MEDIUM severity per matrix)
        e2 = next(e for e in data["evaluations"] if e["rule_id"] == "POL-NIST-004")
        assert "Mandatory Diffie-Hellman Group Strength" in e2["rule_title"]
        assert e2["category"] == "KEY_EXCHANGE"
        assert "NIST SP 800-77 Rev. 1" in e2["standard"]
        assert e2["severity"] == "MEDIUM"
        assert e2["compliance_state"] == "UNKNOWN"

    await engine.dispose()


@pytest.mark.asyncio
async def test_snapshot_builder_compliance_and_version_enrichment():
    """Test that AnalysisSnapshotBuilder produces enriched evaluations and analysis version fields."""
    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    analysis_id = uuid.uuid4()
    capture_id = uuid.uuid4()

    async with session_factory() as session:
        cap = Capture(
            id=capture_id,
            capture_source="UPLOAD",
            capture_format="PCAP",
            original_filename="golden.pcapng",
            file_size_bytes=2048,
            sha256_hash="b" * 64,
            packet_count=50,
            storage_path="/tmp/golden.pcapng",
            validation_state="VALID",
        )
        run = AnalysisRun(
            id=analysis_id,
            capture_id=capture_id,
            status="COMPLETED",
            current_stage="COMPLETED",
            pipeline_version="2.0.0",
            policy_version="1.0.0",
            is_archived=False,
        )
        eval1 = ComplianceEvaluationModel(
            analysis_id=analysis_id,
            bundle_id="bundle-nist-sp800-77",
            rule_id="POL-PFS-001",
            rule_version="1.0.0",
            subject_type="IPSEC_ENTITY",
            subject_id="GLOBAL",
            compliance_state="FAIL",
            evidence_state="VERIFIED",
            rationale="PFS not enabled for Child SA.",
        )
        session.add_all([cap, run, eval1])
        await session.commit()

    async with session_factory() as session:
        builder = AnalysisSnapshotBuilder(session)
        snap = await builder.build_snapshot(analysis_id)

        # 1. Verify analysis version fields
        assert snap["analysis"]["pipeline_version"] == "2.0.0"
        assert snap["analysis"]["is_outdated_version"] is False
        assert snap["analysis"]["is_archived"] is False

        # 2. Verify compliance enrichment
        evals = snap["compliance"]["evaluations"]
        assert len(evals) == 1
        e = evals[0]
        assert e["rule_id"] == "POL-PFS-001"
        assert e["rule_title"] == "Child SA Perfect Forward Secrecy (PFS) Enforcement"
        assert e["category"] == "PFS"
        assert e["severity"] == "MEDIUM"  # FAIL on PFS = MEDIUM
        assert "NIST SP 800-77" in e["standard"]

    await engine.dispose()
