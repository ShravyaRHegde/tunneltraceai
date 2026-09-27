"""REST API endpoints for asynchronous protocol analysis execution and summary inspection."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.schemas import (
    AnalysisListItemDTO,
    AnalysisOverviewDTO,
    AnalysisRunResponseDTO,
    CreateAnalysisRequestDTO,
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
from app.db.models.reconstruction import ESPFlow
from app.db.models.security import ScoreAssessmentModel, SecurityFindingModel
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

    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=capture.id,
        status="QUEUED",
        current_stage="INGESTING",
        parser_engine="tshark",
        parser_version="unknown",
        schema_version="1.0.0",
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
        created_at=analysis.created_at,
    )


@router.get(
    "",
    response_model=list[AnalysisListItemDTO],
    summary="List all historical and active analysis runs",
)
async def list_analyses(
    db: AsyncSession = Depends(get_db_session),
) -> list[AnalysisListItemDTO]:
    """Retrieve history of all analysis runs with capture metadata and security indicators."""
    stmt = (
        select(AnalysisRun)
        .options(selectinload(AnalysisRun.capture))
        .order_by(AnalysisRun.created_at.desc())
    )
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
    for s in score_rows:
        if s.status == "NOT_ASSESSABLE" or s.coverage_percentage == 0.0:
            score_map[s.analysis_id] = None
        else:
            score_map[s.analysis_id] = s.overall_score

    # Batch fetch findings counts
    stmt_finds = select(SecurityFindingModel).where(SecurityFindingModel.analysis_id.in_(run_ids))
    find_rows = (await db.execute(stmt_finds)).scalars().all()
    crit_map: dict[uuid.UUID, int] = {}
    high_map: dict[uuid.UUID, int] = {}
    for f in find_rows:
        if f.severity == "CRITICAL":
            crit_map[f.analysis_id] = crit_map.get(f.analysis_id, 0) + 1
        elif f.severity == "HIGH":
            high_map[f.analysis_id] = high_map.get(f.analysis_id, 0) + 1

    items = []
    for r in runs:
        is_synthetic = bool(
            (r.provenance_metadata and r.provenance_metadata.get("is_synthetic_demo"))
            or (r.provenance_metadata and r.provenance_metadata.get("gateway_identity") == "Perimeter-Gateway-ALPHA")
            or (r.capture and r.capture.original_filename == "ikev2_perimeter_audit.pcap")
        )
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
                security_score=score_map.get(r.id),
                critical_findings=crit_map.get(r.id, 0),
                high_findings=high_map.get(r.id, 0),
                parent_analysis_id=r.parent_analysis_id,
                replay_mode=r.replay_mode,
                provenance_metadata=r.provenance_metadata,
                is_synthetic_demo=is_synthetic,
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
    res = await db.execute(
        select(AnalysisRun)
        .options(selectinload(AnalysisRun.capture))
        .where(AnalysisRun.id == analysis_id)
    )
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise AnalysisNotFoundError(str(analysis_id))

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
        created_at=analysis.created_at,
    )


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

    return TrafficSummaryResponseDTO(
        analysis_id=analysis_id,
        total_flows=len(flows),
        classified_flows=current_run.classified_count if current_run else len(ml_records),
        classes_detected=sorted(classes_detected),
        ood_count=ood_count,
        anomaly_count=anomaly_count,
        ml_run_status=ml_run_status,
        model_version=current_run.bundle_version if current_run else None,
        model_bundle_id=current_run.bundle_id if current_run else None,
        flows=flow_items,
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

