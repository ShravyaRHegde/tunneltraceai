"""Replay and Evidence Chain Service.

Orchestrates:
1. Fail-closed capture SHA-256 integrity verification before re-analysis.
2. Parent-child immutable lineage tracking without overwriting historical runs.
3. Deterministic pipeline execution with pinned tool/policy versions.
4. Forensic comparison and comparison record persistence.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.errors import AnalysisNotFoundError
from app.db.models.capture import AnalysisRun, Capture, ProtocolObservation
from app.db.models.reconstruction import ChildSecurityAssociation, ESPFlow, IKESession
from app.db.models.replay import ReplayComparisonModel
from app.db.models.security import (
    ComplianceEvaluationModel,
    EvidenceGraphModel,
    ScoreAssessmentModel,
    SecurityFindingModel,
)
from app.replay.comparator import ForensicReplayComparator
from app.replay.models import (
    CaptureIntegrityError,
    ForensicReanalysisRequestDTO,
    ReplayComparisonDTO,
    ReplayLineageDTO,
)
from app.services.pipeline import execute_full_analysis_pipeline

logger = logging.getLogger(__name__)


class ReplayService:
    """Service implementing the Replay and Evidence Chain capability."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.settings = get_settings()

    def resolve_capture_file_path(self, capture: Capture) -> Path | None:
        """Resolves the physical on-disk location of a capture artifact."""
        try:
            from app.services.storage import get_storage_provider
            storage = get_storage_provider()
            candidate = storage.resolve_safe_path(capture.storage_path)
            if candidate.is_file():
                return candidate
        except Exception:
            pass

        candidate_paths = [
            Path(capture.storage_path),
            Path("./storage") / capture.storage_path,
            Path("./backend/storage") / capture.storage_path,
            Path(__file__).resolve().parent.parent.parent.parent / "storage" / capture.storage_path,
            Path(__file__).resolve().parent.parent.parent.parent / "backend" / "storage" / capture.storage_path,
            Path(__file__).resolve().parent.parent.parent.parent / capture.storage_path,
            Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "captures" / Path(capture.storage_path).name,
        ]
        for p in candidate_paths:
            if p.is_file():
                return p
        return None

    def verify_capture_integrity(self, capture: Capture) -> tuple[bool, str, str]:
        """Calculates SHA-256 over capture artifact bytes and compares with recorded hash.

        Returns:
            tuple[bool, str, str]: (is_valid, computed_hash, recorded_hash)
        """
        file_path = self.resolve_capture_file_path(capture)
        if not file_path or not file_path.is_file():
            return False, "FILE_NOT_FOUND", capture.sha256_hash

        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        computed_hash = hasher.hexdigest()

        is_valid = (computed_hash.lower() == capture.sha256_hash.lower())
        return is_valid, computed_hash, capture.sha256_hash

    async def execute_forensic_reanalysis(
        self,
        analysis_id: uuid.UUID,
        req: ForensicReanalysisRequestDTO | None = None,
    ) -> tuple[AnalysisRun, ReplayComparisonModel]:
        """Executes deterministic forensic re-analysis over an existing analysis run.

        Enforces:
        - Fail-closed SHA-256 integrity check: rejects corrupted or tampered capture artifacts.
        - Immutable child record: creates new AnalysisRun linked to parent without overwriting historical data.
        - Provenance binding: records parent ID, capture digest, tool versions, and comparison outcome.
        """
        # 1. Fetch parent AnalysisRun and Capture
        stmt = (
            select(AnalysisRun)
            .options(selectinload(AnalysisRun.capture))
            .where(AnalysisRun.id == analysis_id)
        )
        res = await self.db.execute(stmt)
        parent = res.scalar_one_or_none()
        if not parent:
            raise AnalysisNotFoundError(str(analysis_id))

        capture = parent.capture
        if not capture:
            raise AnalysisNotFoundError(f"Capture for analysis {analysis_id} not found")

        # 2. Fail-Closed Artifact Integrity Check
        is_valid, computed_hash, recorded_hash = self.verify_capture_integrity(capture)
        if not is_valid:
            logger.error(
                "Capture integrity mismatch for '%s': recorded=%s, computed=%s. Failing closed.",
                capture.id,
                recorded_hash,
                computed_hash,
            )
            raise CaptureIntegrityError(
                f"Capture artifact failed SHA-256 integrity verification: recorded '{recorded_hash}' "
                f"vs computed '{computed_hash}'. Forensic re-analysis strictly aborted.",
                expected_hash=recorded_hash,
                actual_hash=computed_hash,
            )

        # 3. Create Child AnalysisRun with Lineage Link
        child_id = uuid.uuid4()
        pinned_engine = req.pinned_parser_engine if req else parent.parser_engine
        pinned_version = (req.pinned_parser_version if req and req.pinned_parser_version else parent.parser_version)

        provenance_meta = {
            "parent_analysis_id": str(parent.id),
            "parent_created_at": parent.created_at.isoformat() if parent.created_at else None,
            "capture_sha256": capture.sha256_hash,
            "integrity_verified_at": datetime.now(timezone.utc).isoformat(),
            "pinned_parser_engine": pinned_engine,
            "pinned_parser_version": pinned_version,
            "pinned_policy_bundle_version": req.pinned_policy_bundle_version if req else None,
            "pinned_model_bundle_id": req.pinned_model_bundle_id if req else None,
        }

        child = AnalysisRun(
            id=child_id,
            capture_id=parent.capture_id,
            parent_analysis_id=parent.id,
            replay_mode="FORENSIC_REANALYSIS",
            status="QUEUED",
            current_stage="INGESTING",
            parser_engine=pinned_engine,
            parser_version=pinned_version,
            schema_version=parent.schema_version,
            provenance_metadata=provenance_meta,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(child)
        await self.db.commit()
        await self.db.refresh(child)

        # 4. Execute Full Pipeline Deterministically on Child Run
        await execute_full_analysis_pipeline(child.id, self.db)

        # 5. Extract Parent and Child Entities for Deterministic Comparison
        parent_data = await self._extract_run_entities(parent.id)
        child_data = await self._extract_run_entities(child.id)

        # 6. Run Forensic Replay Comparator
        comparison_res = ForensicReplayComparator.compare_runs(parent_data, child_data)

        # 7. Persist ReplayComparisonModel Record
        comparison_record = ReplayComparisonModel(
            id=uuid.uuid4(),
            replay_mode="FORENSIC_REANALYSIS",
            parent_run_id=str(parent.id),
            child_run_id=str(child.id),
            comparison_status=comparison_res["comparison_status"],
            artifact_integrity="VERIFIED",
            differences=comparison_res["differences"],
            summary=comparison_res["summary"],
            metrics=comparison_res["metrics"],
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(comparison_record)

        # Update child provenance with comparison reference
        child.provenance_metadata["comparison_status"] = comparison_res["comparison_status"]
        child.provenance_metadata["comparison_id"] = str(comparison_record.id)
        await self.db.commit()
        await self.db.refresh(child)
        await self.db.refresh(comparison_record)

        return child, comparison_record

    async def _extract_run_entities(self, analysis_id: uuid.UUID) -> dict[str, Any]:
        """Extracts normalized facts, SAs, findings, evaluations, and scores for comparison."""
        # Protocol Observations
        res_obs = await self.db.execute(
            select(ProtocolObservation)
            .where(ProtocolObservation.analysis_id == analysis_id)
            .order_by(ProtocolObservation.frame_number, ProtocolObservation.field_name)
        )
        obs_rows = res_obs.scalars().all()
        obs_list = [
            {
                "frame_number": o.frame_number,
                "protocol": o.protocol,
                "category": o.category,
                "field_name": o.field_name,
                "normalized_value": o.normalized_value,
                "evidence_state": o.evidence_state,
            }
            for o in obs_rows
        ]

        # IKE Sessions
        res_ike = await self.db.execute(
            select(IKESession).where(IKESession.analysis_id == analysis_id)
        )
        ike_rows = res_ike.scalars().all()
        ike_list = [
            {
                "initiator_spi": s.initiator_spi,
                "responder_spi": s.responder_spi,
                "version": s.version,
                "chosen_encryption": s.chosen_encryption,
                "chosen_integrity": s.chosen_integrity,
                "chosen_dh_group": s.chosen_dh_group,
                "chosen_prf": s.chosen_prf,
            }
            for s in ike_rows
        ]

        # Child SAs
        res_sa = await self.db.execute(
            select(ChildSecurityAssociation).where(ChildSecurityAssociation.analysis_id == analysis_id)
        )
        sa_rows = res_sa.scalars().all()
        sa_list = [
            {
                "inbound_spi": a.inbound_spi,
                "outbound_spi": a.outbound_spi,
                "mode": a.mode,
                "protocol": a.protocol,
                "encryption_algorithm": a.encryption_algorithm,
                "integrity_algorithm": a.integrity_algorithm,
            }
            for a in sa_rows
        ]

        # ESP Flows
        res_flows = await self.db.execute(
            select(ESPFlow).where(ESPFlow.analysis_id == analysis_id)
        )
        flow_rows = res_flows.scalars().all()
        flow_list = [
            {
                "spi": f.spi,
                "reverse_spi": f.reverse_spi,
                "packet_count": f.packet_count,
                "byte_count": f.byte_count,
            }
            for f in flow_rows
        ]

        # Compliance Evaluations
        res_eval = await self.db.execute(
            select(ComplianceEvaluationModel).where(ComplianceEvaluationModel.analysis_id == analysis_id)
        )
        eval_rows = res_eval.scalars().all()
        eval_list = [
            {
                "rule_id": e.rule_id,
                "subject_id": e.subject_id,
                "compliance_state": e.compliance_state,
            }
            for e in eval_rows
        ]

        # Findings
        res_find = await self.db.execute(
            select(SecurityFindingModel).where(SecurityFindingModel.analysis_id == analysis_id)
        )
        find_rows = res_find.scalars().all()
        find_list = [
            {
                "finding_id": f.finding_id,
                "rule_id": f.rule_id,
                "category": f.category,
                "severity": f.severity,
                "root_cause_key": f.root_cause_key,
                "record_hash": f.record_hash,
            }
            for f in find_rows
        ]

        # Score Assessment
        res_score = await self.db.execute(
            select(ScoreAssessmentModel).where(ScoreAssessmentModel.analysis_id == analysis_id)
        )
        score_row = res_score.scalars().first()
        score_dict = {
            "overall_score": score_row.overall_score if score_row else None,
            "raw_score": score_row.raw_score if score_row else None,
        }

        return {
            "observations": obs_list,
            "ike_sessions": ike_list,
            "child_sas": sa_list,
            "flows": flow_list,
            "evaluations": eval_list,
            "findings": find_list,
            "score": score_dict,
        }

    async def get_replay_lineage(self, analysis_id: uuid.UUID) -> ReplayLineageDTO:
        """Retrieves complete replay provenance lineage, version pins, and latest comparison."""
        stmt = (
            select(AnalysisRun)
            .options(selectinload(AnalysisRun.capture))
            .where(AnalysisRun.id == analysis_id)
        )
        res = await self.db.execute(stmt)
        analysis = res.scalar_one_or_none()
        if not analysis:
            raise AnalysisNotFoundError(str(analysis_id))

        capture = analysis.capture
        if not capture:
            is_valid = False
            integrity_status = "UNAVAILABLE"
            actual_sha = None
        else:
            is_valid, computed_hash, recorded_hash = self.verify_capture_integrity(capture)
            if is_valid:
                integrity_status = "VERIFIED"
                actual_sha = computed_hash
            elif computed_hash == "FILE_NOT_FOUND":
                integrity_status = "FILE_NOT_FOUND"
                actual_sha = None
            else:
                integrity_status = "HASH_MISMATCH"
                actual_sha = computed_hash

        # Fetch child runs
        stmt_children = select(AnalysisRun).where(AnalysisRun.parent_analysis_id == analysis_id)
        res_children = await self.db.execute(stmt_children)
        child_runs = [
            {
                "analysis_id": c.id,
                "replay_mode": c.replay_mode,
                "status": c.status,
                "created_at": c.created_at,
                "completed_at": c.completed_at,
            }
            for c in res_children.scalars().all()
        ]

        # Fetch latest comparison
        stmt_comp = (
            select(ReplayComparisonModel)
            .where(
                (ReplayComparisonModel.parent_run_id == str(analysis_id)) |
                (ReplayComparisonModel.child_run_id == str(analysis_id))
            )
            .order_by(ReplayComparisonModel.created_at.desc())
        )
        res_comp = await self.db.execute(stmt_comp)
        comp_row = res_comp.scalars().first()

        latest_comp_dto = None
        if comp_row:
            comp_status = comp_row.comparison_status
            comp_summary = comp_row.summary
            if comp_row.parent_run_id == comp_row.child_run_id:
                comp_status = "INVALID_SELF_COMPARISON"
                comp_summary = f"[NOTICE: Invalid self-comparison - parent and child run are identical ({comp_row.parent_run_id})]"

            latest_comp_dto = ReplayComparisonDTO(
                comparison_id=comp_row.id,
                replay_mode=comp_row.replay_mode,
                parent_run_id=comp_row.parent_run_id,
                child_run_id=comp_row.child_run_id,
                comparison_status=comp_status,
                artifact_integrity=comp_row.artifact_integrity,
                differences=comp_row.differences,
                summary=comp_summary,
                metrics=comp_row.metrics,
                created_at=comp_row.created_at,
            )

        version_pins = {
            "parser_engine": analysis.parser_engine,
            "parser_version": analysis.parser_version,
            "schema_version": analysis.schema_version,
            **(analysis.provenance_metadata or {}),
        }

        return ReplayLineageDTO(
            analysis_id=analysis.id,
            parent_analysis_id=analysis.parent_analysis_id,
            replay_mode=analysis.replay_mode,
            capture_id=analysis.capture_id,
            capture_filename=(capture.original_filename if capture and capture.original_filename else "capture.pcap"),
            capture_sha256=capture.sha256_hash if capture else "unknown",
            capture_integrity_verified=is_valid,
            capture_integrity_status=integrity_status,
            actual_capture_sha256=actual_sha,
            child_runs=child_runs,
            version_pins=version_pins,
            latest_comparison=latest_comp_dto,
        )

