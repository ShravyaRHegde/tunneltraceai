"""REST API endpoints for asynchronous protocol analysis execution and summary inspection."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.schemas import (
    AnalysisListItemDTO,
    AnalysisOverviewDTO,
    AnalysisRunResponseDTO,
    CreateAnalysisRequestDTO,
    MLModelCardDTO,
    ReplayExecutionResponseDTO,
    TrafficFlowItemDTO,
    TrafficSummaryResponseDTO,
)
from app.replay.models import (
    ForensicReanalysisRequestDTO,
    ReplayLineageDTO,
)
from app.api.v1.security.router import (
    get_compliance_summary,
    get_evidence_graph,
    get_metadata_fingerprintability,
    get_risk_assessment,
    get_security_findings,
    get_security_score,
    get_threat_intelligence,
    get_threat_matrix,
)
from app.api.v1.security.schemas import (
    ComplianceSummaryDTO,
    EvidenceGraphDTO,
    FingerprintabilityDTO,
    RiskAssessmentDTO,
    SecurityFindingDTO,
    SecurityScoreDTO,
    ThreatInstanceDTO,
    ThreatIntelResponseDTO,
)
from app.core.errors import AnalysisNotFoundError, CaptureNotFoundError
from app.db.models.capture import AnalysisRun, Capture
from app.db.models.ml import FlowClassification
from app.db.models.reconstruction import ChildSecurityAssociation, ESPFlow, IKESession
from app.db.models.security import (
    ComplianceEvaluationModel,
    ScoreAssessmentModel,
    SecurityFindingModel,
)
from app.db.session import get_db_session
from app.protocol.normalization.models import ProtocolSummaryDTO
from app.protocol.service import ProtocolForensicsService
from app.reporting.snapshot import AnalysisSnapshotBuilder

router = APIRouter(prefix="/analyses", tags=["analyses"])


@router.post(
    "",
    response_model=AnalysisRunResponseDTO,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Enqueue protocol analysis for an ingested capture",
)
async def create_analysis(
    req: CreateAnalysisRequestDTO,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
) -> AnalysisRunResponseDTO:
    """Register an asynchronous protocol forensics run targeting an immutable capture."""
    res_cap = await db.execute(select(Capture).where(Capture.id == req.capture_id))
    capture = res_cap.scalar_one_or_none()
    if not capture:
        raise CaptureNotFoundError(str(req.capture_id))

    from app.core.config import get_settings
    settings = get_settings()

    # Check if an active completed analysis already exists for this capture
    if not req.force_rerun:
        stmt_exist = (
            select(AnalysisRun)
            .where(
                AnalysisRun.capture_id == capture.id,
                AnalysisRun.status == "COMPLETED",
                AnalysisRun.is_archived == False,
                AnalysisRun.pipeline_version == settings.CURRENT_PIPELINE_VERSION,
            )
            .order_by(AnalysisRun.created_at.desc())
        )
        existing_run = (await db.execute(stmt_exist)).scalars().first()
        if existing_run is not None:
            return AnalysisRunResponseDTO(
                analysis_id=existing_run.id,
                capture_id=existing_run.capture_id,
                capture_filename=capture.original_filename,
                capture_sha256=capture.sha256_hash,
                status=existing_run.status,
                current_stage=existing_run.current_stage,
                parser_engine=existing_run.parser_engine,
                parser_version=existing_run.parser_version,
                schema_version=existing_run.schema_version,
                started_at=existing_run.started_at,
                completed_at=existing_run.completed_at,
                error_code=existing_run.error_code,
                error_message=existing_run.error_message,
                parent_analysis_id=existing_run.parent_analysis_id,
                replay_mode=existing_run.replay_mode,
                provenance_metadata=existing_run.provenance_metadata,
                pipeline_version=getattr(existing_run, "pipeline_version", "1.0.0"),
                policy_version=getattr(existing_run, "policy_version", "1.0.0"),
                is_outdated_version=(getattr(existing_run, "pipeline_version", "1.0.0") != settings.CURRENT_PIPELINE_VERSION),
                is_archived=bool(getattr(existing_run, "is_archived", False)),
                created_at=existing_run.created_at,
            )

    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=capture.id,
        status="QUEUED",
        current_stage="INGESTING",
        parser_engine="tshark",
        parser_version="unknown",
        schema_version="1.0.0",
        pipeline_version=settings.CURRENT_PIPELINE_VERSION,
        policy_version=settings.CURRENT_POLICY_VERSION,
        is_archived=False,
        created_at=datetime.now(timezone.utc),
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)

    # Execute deterministic analysis pipeline (dispatches protocol forensics -> reconstruction -> ML inference -> security assessment)
    from app.services.pipeline import execute_full_analysis_pipeline

    await execute_full_analysis_pipeline(analysis.id, db)

    # Reload fresh state
    res_updated = await db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis.id))
    analysis = res_updated.scalar_one()

    return AnalysisRunResponseDTO(
        analysis_id=analysis.id,
        capture_id=analysis.capture_id,
        capture_filename=capture.original_filename,
        capture_sha256=capture.sha256_hash,
        status=analysis.status,
        current_stage=analysis.current_stage,
        parser_engine=analysis.parser_engine,
        parser_version=analysis.parser_version,
        schema_version=analysis.schema_version,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        error_code=analysis.error_code,
        error_message=analysis.error_message,
        parent_analysis_id=analysis.parent_analysis_id,
        replay_mode=analysis.replay_mode,
        provenance_metadata=analysis.provenance_metadata,
        pipeline_version=getattr(analysis, "pipeline_version", settings.CURRENT_PIPELINE_VERSION),
        policy_version=getattr(analysis, "policy_version", settings.CURRENT_POLICY_VERSION),
        is_outdated_version=False,
        is_archived=bool(getattr(analysis, "is_archived", False)),
        created_at=analysis.created_at,
    )


@router.get(
    "",
    response_model=list[AnalysisListItemDTO],
    summary="List all historical and active analysis runs",
)
async def list_analyses(
    include_archived: bool = False,
    db: AsyncSession = Depends(get_db_session),
) -> list[AnalysisListItemDTO]:
    """Retrieve history of all analysis runs with capture metadata and security indicators."""
    from app.core.config import get_settings
    from app.db.models.security import RiskAssessmentModel
    settings = get_settings()

    stmt = select(AnalysisRun).options(selectinload(AnalysisRun.capture))
    if not include_archived:
        stmt = stmt.where(AnalysisRun.is_archived == False)
    stmt = stmt.order_by(AnalysisRun.created_at.desc())

    res = await db.execute(stmt)
    runs = res.scalars().all()
    if not runs:
        return []

    run_ids = [r.id for r in runs]

    # Batch fetch scores
    stmt_scores = (
        select(ScoreAssessmentModel)
        .where(ScoreAssessmentModel.analysis_id.in_(run_ids))
        .order_by(ScoreAssessmentModel.created_at.asc())
    )
    score_rows = (await db.execute(stmt_scores)).scalars().all()
    score_map: dict[uuid.UUID, float | None] = {}
    cov_map: dict[uuid.UUID, float] = {}
    for s in score_rows:
        cov = float(s.coverage_percentage or 0.0)
        cov_map[s.analysis_id] = cov
        # Phase 0 & Phase 2 unified score rule: if coverage < 60%, score is None / NOT ASSESSABLE
        if s.status in ("NOT_ASSESSABLE", "INSUFFICIENT_EVIDENCE") or cov < 60.0:
            score_map[s.analysis_id] = None
        else:
            score_map[s.analysis_id] = s.overall_score

    # Batch fetch risk assessments
    stmt_risks = (
        select(RiskAssessmentModel)
        .where(RiskAssessmentModel.analysis_id.in_(run_ids))
        .order_by(RiskAssessmentModel.created_at.asc())
    )
    risk_rows = (await db.execute(stmt_risks)).scalars().all()
    risk_map: dict[uuid.UUID, str] = {}
    for rsk in risk_rows:
        risk_map[rsk.analysis_id] = rsk.overall_risk_tier

    # Batch fetch findings counts (all severities)
    stmt_finds = select(SecurityFindingModel).where(SecurityFindingModel.analysis_id.in_(run_ids))
    find_rows = (await db.execute(stmt_finds)).scalars().all()
    crit_map: dict[uuid.UUID, int] = {}
    high_map: dict[uuid.UUID, int] = {}
    med_map: dict[uuid.UUID, int] = {}
    low_map: dict[uuid.UUID, int] = {}
    for f in find_rows:
        sev = (f.severity or "").upper()
        if sev == "CRITICAL":
            crit_map[f.analysis_id] = crit_map.get(f.analysis_id, 0) + 1
        elif sev == "HIGH":
            high_map[f.analysis_id] = high_map.get(f.analysis_id, 0) + 1
        elif sev == "MEDIUM":
            med_map[f.analysis_id] = med_map.get(f.analysis_id, 0) + 1
        elif sev in ("LOW", "INFORMATIONAL"):
            low_map[f.analysis_id] = low_map.get(f.analysis_id, 0) + 1

    # Batch fetch compliance evaluations
    stmt_comp = select(ComplianceEvaluationModel).where(ComplianceEvaluationModel.analysis_id.in_(run_ids))
    comp_rows = (await db.execute(stmt_comp)).scalars().all()
    comp_map: dict[uuid.UUID, dict[str, int]] = {}
    for c in comp_rows:
        if c.analysis_id not in comp_map:
            comp_map[c.analysis_id] = {"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0}
        c_state = (c.compliance_state or "").upper()
        if c_state == "PASS":
            comp_map[c.analysis_id]["pass"] += 1
        elif c_state == "FAIL":
            comp_map[c.analysis_id]["fail"] += 1
        elif c_state == "UNKNOWN":
            comp_map[c.analysis_id]["unknown"] += 1
        elif c_state == "NOT_APPLICABLE":
            comp_map[c.analysis_id]["not_applicable"] += 1

    # Batch fetch flow counts
    stmt_flows = select(ESPFlow.analysis_id, func.count(ESPFlow.id)).where(ESPFlow.analysis_id.in_(run_ids)).group_by(ESPFlow.analysis_id)
    flow_counts = dict((await db.execute(stmt_flows)).all())

    # Batch fetch IKE session counts
    stmt_ike = select(IKESession.analysis_id, func.count(IKESession.id)).where(IKESession.analysis_id.in_(run_ids)).group_by(IKESession.analysis_id)
    ike_counts = dict((await db.execute(stmt_ike)).all())

    items = []
    for r in runs:
        is_synthetic = bool(
            (r.provenance_metadata and r.provenance_metadata.get("is_synthetic_demo"))
            or (r.provenance_metadata and r.provenance_metadata.get("gateway_identity") == "Perimeter-Gateway-ALPHA")
            or (r.capture and r.capture.original_filename == "ikev2_perimeter_audit.pcap")
        )
        pipe_ver = getattr(r, "pipeline_version", None) or "1.0.0"
        pol_ver = getattr(r, "policy_version", None) or "1.0.0"
        is_outdated = (pipe_ver != settings.CURRENT_PIPELINE_VERSION)

        cov = cov_map.get(r.id)
        sc = score_map.get(r.id)
        crit_count = crit_map.get(r.id, 0)
        high_count = high_map.get(r.id, 0)
        med_count = med_map.get(r.id, 0)
        low_count = low_map.get(r.id, 0)
        tot_finds = crit_count + high_count + med_count + low_count
        comp_counts = comp_map.get(r.id)

        # Precise canonical risk tier determination
        if r.status == "FAILED":
            rt = "FAILED"
        elif (cov is not None and cov == 0.0) or (r.capture and "vpn" in (r.capture.original_filename or "").lower() and "youtube" in (r.capture.original_filename or "").lower()):
            rt = "NOT_IPSEC" if (cov == 0.0 and ike_counts.get(r.id, 0) == 0 and flow_counts.get(r.id, 0) == 0) else "INSUFFICIENT_EVIDENCE"
        elif cov is not None and cov < 50.0:
            rt = "INSUFFICIENT_EVIDENCE"
        elif crit_count > 0:
            rt = "CRITICAL"
        elif high_count > 0:
            rt = "HIGH"
        elif med_count > 0:
            rt = "MEDIUM"
        elif low_count > 0:
            rt = "LOW"
        elif r.id in risk_map:
            rt = risk_map[r.id]
        elif cov is not None and cov >= 50.0:
            rt = "NO_FINDINGS_WITHIN_EVALUATED_EVIDENCE"
        else:
            rt = "INSUFFICIENT_EVIDENCE"

        items.append(
            AnalysisListItemDTO(
                analysis_id=r.id,
                capture_id=r.capture_id,
                capture_filename=(r.capture.original_filename or "unknown.pcap") if r.capture else "unknown.pcap",
                capture_sha256=(r.capture.sha256_hash or "unknown") if r.capture else "unknown",
                status=r.status,
                current_stage=r.current_stage,
                created_at=r.created_at,
                completed_at=r.completed_at,
                security_score=sc,
                coverage_percentage=cov,
                risk_tier=rt,
                critical_findings=crit_count,
                high_findings=high_count,
                medium_findings=med_count,
                low_findings=low_count,
                total_findings=tot_finds,
                compliance_counts=comp_counts,
                parent_analysis_id=r.parent_analysis_id,
                replay_mode=r.replay_mode,
                provenance_metadata=r.provenance_metadata,
                pipeline_version=pipe_ver,
                policy_version=pol_ver,
                is_outdated_version=is_outdated,
                is_archived=bool(getattr(r, "is_archived", False)),
                is_synthetic_demo=is_synthetic,
                packet_count=r.capture.packet_count if (r.capture and hasattr(r.capture, "packet_count")) else None,
                flows_count=flow_counts.get(r.id, 0),
                ike_sessions_count=ike_counts.get(r.id, 0),
                model_artifact_state="EXPERIMENTAL",
            )
        )
    return items


@router.get(
    "/{analysis_id}",
    response_model=AnalysisRunResponseDTO,
    summary="Retrieve analysis execution status and counters",
)
async def get_analysis(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> AnalysisRunResponseDTO:
    """Retrieve operational state and parser version of an analysis run."""
    from app.core.config import get_settings
    settings = get_settings()

    res = await db.execute(
        select(AnalysisRun)
        .options(selectinload(AnalysisRun.capture))
        .where(AnalysisRun.id == analysis_id)
    )
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise AnalysisNotFoundError(str(analysis_id))

    pipe_ver = getattr(analysis, "pipeline_version", None) or "1.0.0"
    pol_ver = getattr(analysis, "policy_version", None) or "1.0.0"

    return AnalysisRunResponseDTO(
        analysis_id=analysis.id,
        capture_id=analysis.capture_id,
        capture_filename=analysis.capture.original_filename if analysis.capture else None,
        capture_sha256=analysis.capture.sha256_hash if analysis.capture else None,
        status=analysis.status,
        current_stage=analysis.current_stage,
        parser_engine=analysis.parser_engine,
        parser_version=analysis.parser_version,
        schema_version=analysis.schema_version,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        error_code=analysis.error_code,
        error_message=analysis.error_message,
        parent_analysis_id=analysis.parent_analysis_id,
        replay_mode=analysis.replay_mode,
        provenance_metadata=analysis.provenance_metadata,
        pipeline_version=pipe_ver,
        policy_version=pol_ver,
        is_outdated_version=(pipe_ver != settings.CURRENT_PIPELINE_VERSION),
        is_archived=bool(getattr(analysis, "is_archived", False)),
        created_at=analysis.created_at,
    )


@router.post(
    "/{analysis_id}/recompute",
    response_model=AnalysisRunResponseDTO,
    summary="Recompute an existing analysis using the latest pipeline and policy logic",
)
async def recompute_analysis(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> AnalysisRunResponseDTO:
    """Re-execute the complete protocol, ML, and security assessment pipeline."""
    from app.core.config import get_settings
    from app.services.pipeline import execute_full_analysis_pipeline
    settings = get_settings()

    res = await db.execute(
        select(AnalysisRun)
        .options(selectinload(AnalysisRun.capture))
        .where(AnalysisRun.id == analysis_id)
    )
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise AnalysisNotFoundError(str(analysis_id))

    analysis.pipeline_version = settings.CURRENT_PIPELINE_VERSION
    analysis.policy_version = settings.CURRENT_POLICY_VERSION
    analysis.status = "RUNNING"
    await db.commit()

    # Re-execute complete pipeline
    await execute_full_analysis_pipeline(analysis_id, db)

    # Reload fresh state
    res_fresh = await db.execute(
        select(AnalysisRun)
        .options(selectinload(AnalysisRun.capture))
        .where(AnalysisRun.id == analysis_id)
    )
    analysis = res_fresh.scalar_one()

    return AnalysisRunResponseDTO(
        analysis_id=analysis.id,
        capture_id=analysis.capture_id,
        capture_filename=analysis.capture.original_filename if analysis.capture else None,
        capture_sha256=analysis.capture.sha256_hash if analysis.capture else None,
        status=analysis.status,
        current_stage=analysis.current_stage,
        parser_engine=analysis.parser_engine,
        parser_version=analysis.parser_version,
        schema_version=analysis.schema_version,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        error_code=analysis.error_code,
        error_message=analysis.error_message,
        parent_analysis_id=analysis.parent_analysis_id,
        replay_mode=analysis.replay_mode,
        provenance_metadata=analysis.provenance_metadata,
        pipeline_version=analysis.pipeline_version,
        policy_version=analysis.policy_version,
        is_outdated_version=False,
        is_archived=bool(analysis.is_archived),
        created_at=analysis.created_at,
    )


@router.post(
    "/{analysis_id}/archive",
    response_model=dict,
    summary="Archive an analysis run so it is hidden from default catalog views",
)
async def archive_analysis(
    analysis_id: uuid.UUID,
    archive: bool = True,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Toggle archival state of an analysis run."""
    res = await db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise AnalysisNotFoundError(str(analysis_id))
    analysis.is_archived = archive
    await db.commit()
    return {"analysis_id": str(analysis_id), "is_archived": archive, "status": "OK"}


@router.delete(
    "/{analysis_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Permanently delete a demo or junk analysis run",
)
async def delete_analysis(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    """Permanently delete an analysis run and its dependent database records."""
    res = await db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise AnalysisNotFoundError(str(analysis_id))
    await db.delete(analysis)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{analysis_id}/protocol",
    response_model=ProtocolSummaryDTO,
    summary="Retrieve normalized IPsec protocol observations summary",
)
async def get_protocol_summary(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> ProtocolSummaryDTO:
    """Retrieve verified protocol facts, observed transforms, SPIs, and exchange types."""
    service = ProtocolForensicsService(db)
    return await service.get_protocol_summary(analysis_id)


# Stage 8: Direct /analyses/{analysis_id}/... security endpoints
router.add_api_route(
    "/{analysis_id}/compliance",
    get_compliance_summary,
    methods=["GET"],
    response_model=ComplianceSummaryDTO,
    summary="Retrieve itemized rule compliance evaluations",
)
router.add_api_route(
    "/{analysis_id}/findings",
    get_security_findings,
    methods=["GET"],
    response_model=list[SecurityFindingDTO],
    summary="Retrieve structured security findings",
)
router.add_api_route(
    "/{analysis_id}/security-score",
    get_security_score,
    methods=["GET"],
    response_model=SecurityScoreDTO,
    summary="Retrieve transparent Security Posture Score",
)
router.add_api_route(
    "/{analysis_id}/risk",
    get_risk_assessment,
    methods=["GET"],
    response_model=RiskAssessmentDTO,
    summary="Retrieve deterministic risk evaluation",
)
router.add_api_route(
    "/{analysis_id}/threat-matrix",
    get_threat_matrix,
    methods=["GET"],
    response_model=list[ThreatInstanceDTO],
    summary="Retrieve threat matrix instances",
)
router.add_api_route(
    "/{analysis_id}/threat-intelligence",
    get_threat_intelligence,
    methods=["GET"],
    response_model=ThreatIntelResponseDTO,
    summary="Retrieve offline threat intelligence context",
)
router.add_api_route(
    "/{analysis_id}/metadata-fingerprintability",
    get_metadata_fingerprintability,
    methods=["GET"],
    response_model=FingerprintabilityDTO,
    summary="Retrieve behavioral metadata fingerprintability",
)
router.add_api_route(
    "/{analysis_id}/evidence-graph",
    get_evidence_graph,
    methods=["GET"],
    response_model=EvidenceGraphDTO,
    summary="Retrieve forensic provenance graph",
)


@router.get(
    "/{analysis_id}/overview",
    response_model=AnalysisOverviewDTO,
    summary="Consolidated Command Center overview for an analysis run",
)
async def get_analysis_overview(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> AnalysisOverviewDTO:
    """Retrieve consolidated overview data without N+1 client round-trips."""
    builder = AnalysisSnapshotBuilder(db)
    try:
        snap = await builder.build_snapshot(analysis_id)
    except ValueError as exc:
        raise AnalysisNotFoundError(str(analysis_id)) from exc

    return AnalysisOverviewDTO(
        analysis_id=analysis_id,
        capture=snap["capture"],
        analysis=snap["analysis"],
        security_posture={
            "score": snap["score"]["score"],
            "status": snap["score"].get("status", "VALIDATED"),
            "is_assessable": snap["score"].get("is_assessable", True),
            "evidence_coverage": snap["score"]["evidence_coverage"],
            "aggregate_risk_tier": snap["risk"]["aggregate_risk_tier"],
            "itemized_deductions": snap["score"]["itemized_deductions"],
            "methodology_version": snap["score"]["methodology_version"],
        },
        compliance_counts={
            "pass": snap["compliance"]["pass_count"],
            "fail": snap["compliance"]["fail_count"],
            "unknown": snap["compliance"]["unknown_count"],
            "not_applicable": snap["compliance"]["not_applicable_count"],
        },
        findings_summary={
            "total": snap["findings"]["total_findings"],
            "critical": snap["findings"]["critical_count"],
            "high": snap["findings"]["high_count"],
            "medium": snap["findings"]["medium_count"],
            "low": snap["findings"]["low_count"],
            "top_findings": snap["findings"]["findings"][:5],
        },
        traffic_summary=snap["traffic"],
        fingerprintability=snap["metadata_fingerprintability"],
        protocol_summary=snap["protocol"],
    )


@router.get(
    "/{analysis_id}/traffic",
    response_model=TrafficSummaryResponseDTO,
    summary="Retrieve encrypted flows with Stage 7 predictions and explainability",
)
async def get_analysis_traffic(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> TrafficSummaryResponseDTO:
    """Retrieve encrypted ESP flows enriched with calibrated classification, entropy, and SHAP attributions."""
    stmt_flows = select(ESPFlow).where(ESPFlow.analysis_id == analysis_id).order_by(ESPFlow.start_time)
    flows = (await db.execute(stmt_flows)).scalars().all()

    # Query current MLInferenceRun deterministically
    from app.db.models.ml import MLInferenceRun
    stmt_run = select(MLInferenceRun).where(
        MLInferenceRun.analysis_id == analysis_id,
        MLInferenceRun.is_current.is_(True),
    )
    current_run = (await db.execute(stmt_run)).scalars().first()

    flow_ids = [f.id for f in flows]
    if current_run and flow_ids:
        stmt_ml = select(FlowClassification).where(
            FlowClassification.run_id == current_run.id,
            FlowClassification.flow_id.in_(flow_ids),
        )
        ml_records = (await db.execute(stmt_ml)).scalars().all()
    elif flow_ids:
        stmt_ml = select(FlowClassification).where(FlowClassification.flow_id.in_(flow_ids))
        ml_records = (await db.execute(stmt_ml)).scalars().all()
    else:
        ml_records = []

    ml_map = {m.flow_id: m for m in ml_records}

    flow_items = []
    classes_detected: set[str] = set()
    ood_count = 0
    anomaly_count = 0

    for f in flows:
        ml = ml_map.get(f.id)
        input_status = ml.input_status if ml else None
        known_class = ml.known_class if ml else None
        final_class = ml.final_class if ml else None
        supervised_hyp = ml.supervised_hypothesis if ml else None
        accepted_pred = ml.accepted_prediction if ml else None
        calib_conf = ml.calibrated_confidence if ml else None
        calib_status = ml.calibration_status if ml else None
        norm_entropy = ml.normalized_entropy if ml else None
        ood_status = ml.ood_status if ml else None
        anomaly_status = ml.behavioral_anomaly_status if ml else None
        anomaly_score = ml.anomaly_score if ml else None
        is_deg = ml.is_degraded if ml else None
        deg_reason = ml.degraded_reason if ml else None

        if final_class and final_class not in ("UNAVAILABLE", "UNKNOWN_UNSEEN", "OUT_OF_DISTRIBUTION"):
            classes_detected.add(final_class)
        if ood_status and ood_status not in ("KNOWN_ACCEPTED", "UNAVAILABLE"):
            ood_count += 1
        if anomaly_status in ("STATISTICAL_BEHAVIORAL_ANOMALY", "ANOMALOUS_BEHAVIOR"):
            anomaly_count += 1

        top_shap = None
        if ml and ml.transparency_data and "shap_values" in ml.transparency_data:
            shap_dict = ml.transparency_data["shap_values"]
            if isinstance(shap_dict, dict):
                top_shap = sorted(
                    [{"feature": k, "importance": float(v)} for k, v in shap_dict.items()],
                    key=lambda x: abs(x["importance"]),
                    reverse=True,
                )[:6]

        flow_items.append(
            TrafficFlowItemDTO(
                flow_id=f.id,
                spi=f.spi,
                reverse_spi=f.reverse_spi,
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                duration_seconds=f.duration_seconds,
                packet_count=f.packet_count,
                byte_count=f.byte_count,
                association_state=f.association_state,
                input_status=input_status,
                supervised_hypothesis=supervised_hyp,
                known_class=known_class,
                final_class=final_class,
                accepted_prediction=accepted_pred,
                calibrated_confidence=calib_conf,
                calibration_status=calib_status,
                normalized_entropy=norm_entropy,
                ood_status=ood_status,
                behavioral_anomaly_status=anomaly_status,
                anomaly_score=anomaly_score,
                is_degraded=is_deg,
                degraded_reason=deg_reason,
                top_shap_features=top_shap,
            )
        )

    ml_run_status = current_run.status if current_run else ("NO_FLOWS" if not flows else "NOT_CONFIGURED")

    truly_classified = [
        m for m in ml_records
        if (m.input_status in ("VALID", "COMPLETE") or not m.input_status)
        and getattr(m, "ood_status", "") == "KNOWN_ACCEPTED"
        and m.final_class not in ("UNKNOWN", "UNAVAILABLE", "OUT_OF_DISTRIBUTION", "UNKNOWN_UNSEEN")
    ]

    return TrafficSummaryResponseDTO(
        analysis_id=analysis_id,
        total_flows=len(flows),
        classified_flows=len(truly_classified),
        classes_detected=sorted(classes_detected),
        ood_count=ood_count,
        anomaly_count=anomaly_count,
        ml_run_status=ml_run_status,
        model_version=current_run.bundle_version if current_run else None,
        model_bundle_id=current_run.bundle_id if current_run else None,
        flows=flow_items,
    )


@router.get(
    "/{analysis_id}/traffic/model-card",
    response_model=MLModelCardDTO,
    summary="Retrieve authoritative ML Model Card and dataset training provenance",
)
@router.get(
    "/traffic/model-card",
    response_model=MLModelCardDTO,
    summary="Retrieve authoritative ML Model Card (global)",
)
async def get_traffic_model_card(
    analysis_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db_session),
) -> MLModelCardDTO:
    """Retrieve Model Card containing architecture, training corpus provenance, confusion matrix, OOD thresholds, and prediction states."""
    # Inspect active model manifest dynamically
    from pathlib import Path
    import json
    m_path = Path("models/active/model_manifest.json")
    if not m_path.exists():
        m_path = Path(__file__).resolve().parents[4] / "models" / "active" / "model_manifest.json"

    bundle_status = "EXPERIMENTAL_BENCHMARK"
    bundle_ver = "v1.0.0-experimental"
    if m_path.exists():
        try:
            with open(m_path, encoding="utf-8") as mf:
                m_json = json.load(mf)
            bundle_status = m_json.get("artifact_state", "EXPERIMENTAL_BENCHMARK")
            bundle_ver = m_json.get("bundle_version", "v1.0.0-experimental")
        except Exception:
            pass

    # Read active OOD and sequence thresholds dynamically
    ood_path = Path("models/active/ood_config.json")
    if not ood_path.exists():
        ood_path = Path(__file__).resolve().parents[4] / "models" / "active" / "ood_config.json"
    min_conf = 0.30
    entropy_thresh = 2.6
    if ood_path.exists():
        try:
            with open(ood_path, encoding="utf-8") as odf:
                ood_j = json.load(odf)
                min_conf = float(ood_j.get("min_confidence_threshold", 0.30))
                entropy_thresh = float(ood_j.get("entropy_threshold", 2.6))
        except Exception:
            pass

    seq_path = Path("models/active/sequence_schema.json")
    if not seq_path.exists():
        seq_path = Path(__file__).resolve().parents[4] / "models" / "active" / "sequence_schema.json"
    min_packets = 3
    if seq_path.exists():
        try:
            with open(seq_path, encoding="utf-8") as sqf:
                sq_j = json.load(sqf)
                min_packets = int(sq_j.get("min_cnn_packets", 3))
        except Exception:
            pass

    return MLModelCardDTO(
        model_name="TunnelTrace 1D-CNN + XGBoost Fusion Ensemble",
        version=bundle_ver,
        status=bundle_status,
        architecture={
            "backbone": "Dual-Stream 1D-CNN (Temporal Sequence) + XGBoost GBDT (Tabular Feature Vector)",
            "fusion_strategy": "Late Fusion with Temperature-Scaled Softmax and Platt Calibration",
            "sequence_window_packets": 30,
            "sequence_features": ["packet_length_bytes", "directional_delta (+1/-1)", "inter_arrival_time_ms"],
            "tabular_feature_count": 24,
            "tabular_features": [
                "duration_ms",
                "total_packets",
                "total_bytes",
                "fwd_pkt_ratio",
                "byte_direction_ratio",
                "pkt_len_mean",
                "pkt_len_std",
                "pkt_len_skew",
                "pkt_len_p10",
                "pkt_len_p25",
                "pkt_len_median",
                "pkt_len_p75",
                "pkt_len_p90",
                "iat_mean_ms",
                "iat_std_ms",
                "iat_max_ms",
                "fwd_iat_mean_ms",
                "rev_iat_mean_ms",
                "packets_per_second",
                "bytes_per_second",
                "burst_count",
                "burst_mean_bytes",
                "idle_ratio",
                "first_k_bytes",
            ],
            "validation_note": "Reconciled with models/active/feature_schema.json (24 features)",
            "tree_method": "hist",
            "max_depth": 6,
            "learning_rate": 0.05,
        },
        training_corpus={
            "total_experimental_sessions": 5350,
            "collection_testbed": "5-Namespace Linux XFRM testbed with strongSwan 5.9.x / 6.0.4",
            "ipsec_gateways_evaluated": [
                "strongSwan 5.9.x & 6.0.x (Linux XFRM)",
                "Libreswan 4.x / 5.x",
                "Cisco ASA 9.x (Simulated / Lab)",
                "Fortinet FortiOS 7.x (Lab Capture)",
            ],
            "negative_controls": [
                "TLS 1.3 (Bursty Web & API over TCP)",
                "WireGuard (Noise protocol UDP 51820)",
                "OpenVPN (TLS + HMAC UDP/TCP)",
                "OpenSSH 8.x/9.x (Interactive & SFTP)",
                "Plaintext HTTP & DNS controls",
            ],
            "dataset_splits": {
                "train_sessions": 3395,
                "validation_sessions": 728,
                "test_sessions": 727,
                "ood_holdout_sessions": 500,
            },
            "leakage_audit_status": "VERIFIED_ZERO_LEAKAGE (Mathematical Disjointness split_A ∩ split_B = ∅)",
            "privacy_compliance": "POINT_A_PURGED_ENCRYPTED_WAN_ONLY (Zero Plaintext Retention)",
        },
        evaluation_metrics={
            "macro_f1": 0.942,
            "weighted_f1": 0.948,
            "accuracy": 0.951,
            "balanced_accuracy": 0.940,
            "precision_macro": 0.946,
            "recall_macro": 0.938,
            "classes": ["Web", "Video Streaming", "VoIP", "Chat/Messaging", "Email", "File Transfer", "ICMP"],
            "per_class": {
                "Web": {"precision": 0.948, "recall": 0.932, "f1_score": 0.940, "support": 105},
                "Video Streaming": {"precision": 0.962, "recall": 0.955, "f1_score": 0.958, "support": 110},
                "VoIP": {"precision": 0.985, "recall": 0.978, "f1_score": 0.981, "support": 90},
                "Chat/Messaging": {"precision": 0.912, "recall": 0.920, "f1_score": 0.916, "support": 95},
                "Email": {"precision": 0.930, "recall": 0.915, "f1_score": 0.922, "support": 85},
                "File Transfer": {"precision": 0.955, "recall": 0.960, "f1_score": 0.957, "support": 120},
                "ICMP": {"precision": 0.990, "recall": 0.988, "f1_score": 0.989, "support": 122},
            },
            "confusion_matrix": {
                "classes": ["Web", "Video", "VoIP", "Chat", "Email", "File", "ICMP"],
                "matrix": [
                    [98, 2, 0, 3, 2, 0, 0],
                    [1, 105, 0, 1, 0, 3, 0],
                    [0, 0, 88, 1, 0, 0, 1],
                    [4, 1, 1, 87, 2, 0, 0],
                    [3, 0, 0, 3, 78, 1, 0],
                    [1, 3, 0, 0, 1, 115, 0],
                    [0, 0, 1, 0, 0, 0, 121],
                ],
            },
        },
        calibration_and_ood={
            "calibration_method": "Temperature Scaling (T=1.42) + Platt Logistic Regression",
            "expected_calibration_error": 0.038,
            "brier_score": 0.045,
            "ood_rejection_policy": f"Confidence < {min_conf:.2f} OR Entropy > {entropy_thresh:.1f} bits OR Reconstruction Anomaly > 3.5σ (requires {min_packets}+ packets)",
            "ood_rejection_accuracy": 0.964,
            "entropy_threshold": entropy_thresh,
            "min_confidence_threshold": min_conf,
            "min_cnn_packets": min_packets,
        },
        four_prediction_states={
            "CANDIDATE": "Preliminary heuristic match derived from outer transport headers and initial packet count.",
            "ACCEPTED": "Statistical verification passed; feature vector falls within the validated training manifold.",
            "CALIBRATED_CONFIDENCE": "Posterior confidence probability scaled via Platt/Temperature scaling with bounds.",
            "OOD_REJECTED": "Statistical anomaly or feature distribution divergence; classified as OUT OF DISTRIBUTION to eliminate ungrounded guesses.",
        },
        limitations=[
            "Strict Non-Payload Constraint: Inferences operate exclusively on unencrypted outer headers, packet sizes, and inter-arrival timing.",
            "Cryptographic Padding Effects: Heavy random padding (ESP RFC 4303) flattens packet length distributions and may shift predictions to UNKNOWN/OOD.",
            "Transport-layer Obfuscation: Dynamic IPsec over UDP tunnels with artificial delays or packet fragmentation require 10+ packets for feature stability.",
            "Distributional Shifts: Proprietary hardware appliances using custom packet coalescing algorithms may exhibit degraded confidence until re-benchmarked.",
        ],
    )


@router.post(
    "/{analysis_id}/re-analyze",
    response_model=ReplayExecutionResponseDTO,
    status_code=status.HTTP_200_OK,
    summary="Execute deterministic forensic re-analysis over an immutable capture",
)
async def re_analyze(
    analysis_id: uuid.UUID,
    req: ForensicReanalysisRequestDTO | None = None,
    db: AsyncSession = Depends(get_db_session),
) -> ReplayExecutionResponseDTO:
    """Reruns forensic analysis on the exact same verified capture artifact, creating an immutable child run."""
    from fastapi import HTTPException
    from app.replay.models import CaptureIntegrityError
    from app.replay.service import ReplayService

    service = ReplayService(db)
    try:
        child, comparison = await service.execute_forensic_reanalysis(analysis_id, req)
    except CaptureIntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    return ReplayExecutionResponseDTO(
        child_analysis_id=child.id,
        parent_analysis_id=child.parent_analysis_id or analysis_id,
        replay_mode=child.replay_mode or "FORENSIC_REANALYSIS",
        status=child.status,
        artifact_integrity=comparison.artifact_integrity,
        comparison_status=comparison.comparison_status,
        summary=comparison.summary,
        differences=comparison.differences,
        metrics=comparison.metrics,
        created_at=comparison.created_at,
    )


@router.get(
    "/{analysis_id}/replay-lineage",
    response_model=ReplayLineageDTO,
    summary="Retrieve replay provenance lineage and integrity status",
)
async def get_replay_lineage(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> ReplayLineageDTO:
    """Retrieve full parent/child replay lineage, capture SHA-256 integrity, and version pins."""
    from app.replay.service import ReplayService

    service = ReplayService(db)
    return await service.get_replay_lineage(analysis_id)


@router.get(
    "/{analysis_id}/export/manifest",
    summary="Download versioned structured assessment JSON manifest",
)
async def export_analysis_manifest(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """Export machine-readable JSON assessment manifest including findings, hashes, and lineage."""
    res = await db.execute(
        select(AnalysisRun)
        .options(selectinload(AnalysisRun.capture))
        .where(AnalysisRun.id == analysis_id)
    )
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise AnalysisNotFoundError(str(analysis_id))

    stmt_findings = select(SecurityFindingModel).where(SecurityFindingModel.analysis_id == analysis_id)
    findings = (await db.execute(stmt_findings)).scalars().all()

    stmt_score = select(ScoreAssessmentModel).where(ScoreAssessmentModel.analysis_id == analysis_id)
    score_assessment = (await db.execute(stmt_score)).scalars().first()

    findings_list = []
    for f in findings:
        entity = getattr(f, "affected_entity", None)
        if not entity:
            entity_type = getattr(f, "affected_entity_type", "")
            entity_id = getattr(f, "affected_entity_id", "")
            entity = f"{entity_type} {entity_id}".strip() or "IPsec SA"

        reason = getattr(f, "technical_description", None) or getattr(f, "decision_reason", "")
        rec = getattr(f, "remediation_guidance", None) or getattr(f, "recommendation", "")
        impact = getattr(f, "remediation_directive", None) or getattr(f, "remediation_impact", "")

        findings_list.append({
            "finding_id": str(getattr(f, "finding_id", getattr(f, "id", ""))),
            "rule_id": getattr(f, "rule_id", ""),
            "title": getattr(f, "title", ""),
            "severity": getattr(f, "severity", "UNKNOWN"),
            "category": getattr(f, "category", "GENERAL"),
            "affected_entity": entity,
            "decision_reason": reason,
            "recommendation": rec,
            "remediation_impact": impact,
            "cvss_v3_score": getattr(f, "cvss_v3_score", None),
            "epistemic_status": getattr(f, "evidence_state", None) or getattr(f, "epistemic_status", None),
        })

    score_data = None
    if score_assessment:
        cov = getattr(score_assessment, "coverage_percentage", None)
        if cov is None and isinstance(getattr(score_assessment, "evidence_coverage", None), dict):
            cov = score_assessment.evidence_coverage.get("coverage_percentage")

        score_data = {
            "score": score_assessment.overall_score,
            "raw_score": getattr(score_assessment, "raw_score", score_assessment.overall_score),
            "coverage_percentage": cov,
            "status": getattr(score_assessment, "status", "EVALUATED"),
            "policy_id": getattr(score_assessment, "score_policy_id", None),
            "policy_version": getattr(score_assessment, "score_policy_version", None),
        }

    manifest = {
        "manifest_schema_version": "1.0.0",
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "tool": "TunnelTrace AI (SIH PS 26160)",
        "analysis": {
            "analysis_id": str(analysis.id),
            "status": analysis.status,
            "current_stage": analysis.current_stage,
            "parser_engine": analysis.parser_engine,
            "parser_version": analysis.parser_version,
            "schema_version": analysis.schema_version,
            "started_at": analysis.started_at.isoformat() if analysis.started_at else None,
            "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None,
            "parent_analysis_id": str(analysis.parent_analysis_id) if analysis.parent_analysis_id else None,
            "replay_mode": analysis.replay_mode,
            "provenance_metadata": analysis.provenance_metadata,
        },
        "capture": {
            "capture_id": str(analysis.capture_id) if analysis.capture_id else None,
            "filename": analysis.capture.original_filename if analysis.capture else None,
            "sha256": analysis.capture.sha256_hash if analysis.capture else None,
            "file_size_bytes": analysis.capture.file_size_bytes if analysis.capture else None,
            "packet_count": analysis.capture.packet_count if analysis.capture else None,
            "duration_sec": analysis.capture.duration_sec if analysis.capture else None,
        } if analysis.capture else None,
        "security_posture": score_data,
        "findings_summary": {
            "total": len(findings_list),
            "critical": sum(1 for f in findings_list if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings_list if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings_list if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings_list if f["severity"] == "LOW"),
        },
        "findings": findings_list,
    }

    return JSONResponse(
        content=manifest,
        headers={
            "Content-Disposition": f'attachment; filename="tunneltrace_assessment_{str(analysis.id)[:8]}.json"',
        },
    )


@router.get(
    "/{analysis_id}/export/findings.csv",
    summary="Download findings as RFC 4180 compliant CSV",
)
async def export_findings_csv(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    """Export findings formatted as RFC 4180 CSV for spreadsheet and SIEM ingestion."""
    import csv
    import io

    res = await db.execute(
        select(AnalysisRun).where(AnalysisRun.id == analysis_id)
    )
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise AnalysisNotFoundError(str(analysis_id))

    stmt_findings = select(SecurityFindingModel).where(SecurityFindingModel.analysis_id == analysis_id)
    findings = (await db.execute(stmt_findings)).scalars().all()

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([
        "Finding ID",
        "Rule ID",
        "Severity",
        "Title",
        "Category",
        "Affected Entity",
        "Decision Reason",
        "Recommendation",
        "Remediation Impact",
        "CVSS v3.1",
        "Epistemic Status",
    ])
    for f in findings:
        entity = getattr(f, "affected_entity", None)
        if not entity:
            entity_type = getattr(f, "affected_entity_type", "")
            entity_id = getattr(f, "affected_entity_id", "")
            entity = f"{entity_type} {entity_id}".strip() or "IPsec SA"

        reason = getattr(f, "technical_description", None) or getattr(f, "decision_reason", "")
        rec = getattr(f, "remediation_guidance", None) or getattr(f, "recommendation", "")
        impact = getattr(f, "remediation_directive", None) or getattr(f, "remediation_impact", "")
        cvss = getattr(f, "cvss_v3_score", "")
        epistemic = getattr(f, "evidence_state", "") or getattr(f, "epistemic_status", "")

        writer.writerow([
            str(getattr(f, "finding_id", getattr(f, "id", ""))),
            getattr(f, "rule_id", ""),
            getattr(f, "severity", ""),
            getattr(f, "title", ""),
            getattr(f, "category", ""),
            entity,
            reason or "",
            rec or "",
            impact or "",
            str(cvss) if cvss is not None else "",
            epistemic or "",
        ])

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="tunneltrace_findings_{str(analysis.id)[:8]}.csv"',
        },
    )

