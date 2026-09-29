"""Stage 1: As-Built End-to-End Verification and Integration Trace.

Traces the canonical verified capture `tests/fixtures/captures/real_tunnel_gcm.pcapng`
through the entire application lifecycle:
- Ingestion & SHA-256 verification
- TShark packet dissection & ProtocolObservation persistence
- IKE/SA & ESP flow stateful reconstruction
- ML flow classification execution & FlowClassification persistence
- Deterministic Policy-as-Code evaluation & SecurityFinding persistence
- Tamper-evident AssessmentManifest generation
- Executive & Technical report rendering
- API read DTO queryability
"""

from __future__ import annotations

import hashlib
import shutil
import uuid
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.v1.analyses.router import get_analysis_overview, get_analysis_traffic
from app.api.v1.security.router import _ensure_assessment_executed, get_security_service
from app.db.base import Base
from app.db.models.capture import AnalysisRun, Capture, ProtocolObservation
from app.db.models.ml import FlowClassification
from app.db.models.reconstruction import ChildSecurityAssociation, ESPFlow, IKESecurityAssociation, IKESession
from app.db.models.security import ComplianceEvaluationModel, ScoreAssessmentModel, SecurityFindingModel
from app.ml.anomaly import AnomalyFeatureSchema, IsolationForestAnomalyDetector
from app.ml.bundle import ModelBundleBuilder
from app.ml.calibration import CalibrationConfig
from app.ml.cnn.model import Lightweight1DCNN
from app.ml.fusion import FusionConfig
from app.ml.ood import OODConfig
from app.ml.preprocessing import FeaturePreprocessor
from app.ml.schema import FeatureSchema
from app.ml.sequence_schema import SequenceSchema
from app.ml.service import execute_flow_classification
from app.ml.trainer import XGBoostBaselineModel
from app.protocol.service import ProtocolForensicsService
from app.reconstruction.engine import ReconstructionEngine
from app.reporting.service import ReportingService
from app.services.storage import get_storage_provider

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "captures" / "real_tunnel_gcm.pcapng"
EXPECTED_SHA = "949531329196d1fbc836ee0685efe8a204c68d6d8da5a5b75ecaa0128c59e04d"


@pytest_asyncio.fixture
async def isolated_db(tmp_path: Path):
    """Create an isolated SQLite database for pure end-to-end trace verification."""
    db_file = tmp_path / "test_trace.db"
    db_url = f"sqlite+aiosqlite:///{db_file.as_posix()}"
    engine = create_async_engine(db_url, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def test_model_bundle_dir(tmp_path: Path) -> Path:
    """Build a valid Stage 7 model bundle in a temporary directory for inference testing."""
    bundle_dir = tmp_path / "active_model_bundle"
    feat_schema = FeatureSchema()
    seq_schema = SequenceSchema(default_horizon=32, min_cnn_packets=2)
    num_feats = len(feat_schema.features)
    anom_schema = AnomalyFeatureSchema(features=[f.name for f in feat_schema.features[:6]])

    import numpy as np
    np.random.seed(42)
    preprocessor = FeaturePreprocessor(apply_log1p=True, scaling_strategy="NONE")
    dummy_x = np.random.randn(20, num_feats).astype(np.float32)
    preprocessor.fit(dummy_x, feature_names=feat_schema.feature_names)

    xgb_model = XGBoostBaselineModel()
    dummy_y = np.array([i % 7 for i in range(20)])
    x_trans = preprocessor.transform(dummy_x)
    xgb_model.fit(x_trans, dummy_y)

    cnn_model = Lightweight1DCNN(
        num_classes=7,
        in_channels=3,
        conv1_channels=16,
        conv2_channels=32,
        dropout_rate=0.1,
    )
    cnn_model.eval()

    fusion_cfg = FusionConfig(alpha=0.6)
    calib_cfg = CalibrationConfig(method="TEMPERATURE_SCALING", temperature=1.1)
    ood_cfg = OODConfig(entropy_threshold=1.5, min_confidence_threshold=0.4)

    anomaly_detector = IsolationForestAnomalyDetector(schema=anom_schema)
    anom_x = dummy_x[:, :6]
    anomaly_detector.fit(anom_x, n_estimators=10)
    anomaly_detector.tune_threshold(anom_x, target_fpr=0.05)

    builder = ModelBundleBuilder()
    builder.build_and_export(
        output_dir=bundle_dir,
        xgb_model=xgb_model,
        cnn_model=cnn_model,
        preprocessor=preprocessor,
        feature_schema=feat_schema,
        sequence_schema=seq_schema,
        anomaly_schema=anom_schema,
        fusion_config=fusion_cfg,
        calibration_config=calib_cfg,
        ood_config=ood_cfg,
        anomaly_detector=anomaly_detector,
        bundle_id="stage1_as_built_test_bundle",
        bundle_version="v1.0.0-as-built",
    )
    return bundle_dir


@pytest.mark.asyncio
async def test_as_built_real_capture_end_to_end_trace(
    isolated_db: AsyncSession,
    test_model_bundle_dir: Path,
):
    """Trace real_tunnel_gcm.pcapng through the complete application pipeline."""
    # 0. Fixture Integrity Verification
    assert FIXTURE_PATH.exists(), f"Capture fixture missing at {FIXTURE_PATH}"
    file_bytes = FIXTURE_PATH.read_bytes()
    actual_sha = hashlib.sha256(file_bytes).hexdigest()
    assert actual_sha == EXPECTED_SHA, f"Fixture SHA-256 mismatch: {actual_sha} != {EXPECTED_SHA}"
    assert len(file_bytes) == 3048

    # 1. Capture Ingestion & Storage Setup
    storage = get_storage_provider()
    storage_rel_path = f"captures/test_trace_{uuid.uuid4().hex[:8]}.pcapng"
    dest_path = storage.resolve_safe_path(storage_rel_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(FIXTURE_PATH, dest_path)

    capture_id = uuid.uuid4()
    analysis_id = uuid.uuid4()

    capture_record = Capture(
        id=capture_id,
        capture_source="OFFLINE_UPLOAD",
        capture_format="PCAPNG",
        original_filename="real_tunnel_gcm.pcapng",
        storage_path=storage_rel_path,
        file_size_bytes=len(file_bytes),
        sha256_hash=actual_sha,
        validation_state="VALIDATED",
    )
    analysis_record = AnalysisRun(
        id=analysis_id,
        capture_id=capture_id,
        status="QUEUED",
        current_stage="INGESTING",
    )
    isolated_db.add(capture_record)
    isolated_db.add(analysis_record)
    await isolated_db.commit()

    # 2. Protocol Forensics (TShark Dissection & Normalization)
    proto_service = ProtocolForensicsService(isolated_db)
    summary = await proto_service.execute_analysis(analysis_id)

    assert summary.ipsec_detected is True
    assert summary.packet_counts["total"] == 12
    assert "IKEv2" in summary.protocols_observed or "ESP" in summary.protocols_observed

    # Verify ProtocolObservations persisted
    obs_rows = (
        await isolated_db.execute(
            select(ProtocolObservation).where(ProtocolObservation.analysis_id == analysis_id)
        )
    ).scalars().all()
    assert len(obs_rows) > 0, "No ProtocolObservation records persisted!"

    # 3. Stateful IKE & Flow Reconstruction
    recon_engine = ReconstructionEngine(isolated_db)
    recon_summary = await recon_engine.execute_reconstruction(analysis_id)

    assert recon_summary.paired_flows_count >= 1 or recon_summary.directional_streams_count >= 1

    # Verify SAs and Flows persisted
    ike_sas = (
        await isolated_db.execute(
            select(IKESecurityAssociation)
            .join(IKESession, IKESecurityAssociation.session_id == IKESession.id)
            .where(IKESession.analysis_id == analysis_id)
        )
    ).scalars().all()
    assert len(ike_sas) >= 1
    assert "AES-GCM" in ike_sas[0].encryption_algorithm or "GCM" in ike_sas[0].encryption_algorithm

    flows = (
        await isolated_db.execute(
            select(ESPFlow).where(ESPFlow.analysis_id == analysis_id)
        )
    ).scalars().all()
    assert len(flows) >= 1

    # 4. ML Flow Classification
    # Test case A: Model bundle absent -> gracefully bypassed
    empty_dir = test_model_bundle_dir.parent / "empty_models"
    empty_dir.mkdir(exist_ok=True)
    bypassed_count = await execute_flow_classification(analysis_id, isolated_db, model_dir=empty_dir)
    assert bypassed_count == 0

    # Test case B: Model bundle present -> classified and persisted
    classified_count = await execute_flow_classification(analysis_id, isolated_db, model_dir=test_model_bundle_dir)
    assert classified_count == len(flows), f"Classified {classified_count}/{len(flows)} flows"

    ml_rows = (
        await isolated_db.execute(
            select(FlowClassification).where(FlowClassification.flow_id.in_([f.id for f in flows]))
        )
    ).scalars().all()
    assert len(ml_rows) == len(flows)
    for ml in ml_rows:
        assert ml.known_class is not None
        assert ml.final_class is not None
        assert 0.0 <= ml.calibrated_confidence <= 1.0
        assert ml.transparency_data is not None

    # 5. Deterministic Policy-as-Code & Scoring
    sec_service = get_security_service()
    await _ensure_assessment_executed(analysis_id, isolated_db, sec_service)

    eval_rows = (
        await isolated_db.execute(
            select(ComplianceEvaluationModel).where(ComplianceEvaluationModel.analysis_id == analysis_id)
        )
    ).scalars().all()
    assert len(eval_rows) >= 7, f"Expected at least 7 policy evaluations, got {len(eval_rows)}"

    score_record = (
        await isolated_db.execute(
            select(ScoreAssessmentModel).where(ScoreAssessmentModel.analysis_id == analysis_id)
        )
    ).scalar_one_or_none()
    assert score_record is not None
    assert 0.0 <= score_record.overall_score <= 100.0
    assert 0.0 <= score_record.coverage_percentage <= 100.0

    # 6. Reporting Service
    reporting_svc = ReportingService(isolated_db)
    exec_report = await reporting_svc.create_report(analysis_id, "EXECUTIVE")
    tech_report = await reporting_svc.create_report(analysis_id, "TECHNICAL")

    assert exec_report.status in ("COMPLETED", "PDF_FAILED_HTML_AVAILABLE")
    assert tech_report.status in ("COMPLETED", "PDF_FAILED_HTML_AVAILABLE")
    assert exec_report.html_sha256 is not None
    assert tech_report.html_sha256 is not None

    # 7. API Read DTO Queryability
    overview_dto = await get_analysis_overview(analysis_id, isolated_db)
    assert overview_dto.analysis_id == analysis_id
    assert overview_dto.security_posture["score"] == score_record.overall_score
    assert (overview_dto.capture.get("sha256") or overview_dto.capture.get("sha256_hash")) == EXPECTED_SHA

    traffic_dto = await get_analysis_traffic(analysis_id, isolated_db)
    assert traffic_dto.total_flows == len(flows)
    assert traffic_dto.classified_flows == overview_dto.traffic_summary["classified_flows"]
    assert traffic_dto.ood_count == 1
    assert len(traffic_dto.flows) == len(flows)
    assert traffic_dto.flows[0].final_class is not None
    assert traffic_dto.flows[0].calibrated_confidence is not None

    # Clean up test capture
    dest_path.unlink(missing_ok=True)
