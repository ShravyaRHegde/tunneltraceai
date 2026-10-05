"""Canonical Analysis Pipeline Execution Service.

Coordinates end-to-end execution of protocol forensics, stateful reconstruction,
ML flow classification, and deterministic Policy-as-Code security evaluation.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.protocol.normalization.models import ProtocolSummaryDTO
from app.protocol.service import ProtocolForensicsService

logger = logging.getLogger(__name__)


async def execute_full_analysis_pipeline(
    analysis_id: uuid.UUID,
    db: AsyncSession,
) -> ProtocolSummaryDTO:
    """Execute consolidated product analysis pipeline in strict deterministic order.

    Order of operations:
    1. Protocol Forensics (TShark dissection, normalization, ProtocolObservation persistence)
    2. Stateful Reconstruction (IKE SA, Child SA, ESPFlow pairing and stream aggregation)
    3. ML Flow Classification (authentic frame packet extraction, CPU inference, MLInferenceRun persistence)
    4. Deterministic Security Posture (Policy-as-Code, CVE/ATT&CK mapping, scoring invariants)

    Status isolation guarantee:
    - Protocol analysis success/failure is persisted independently from ML inference status.
    - If active model bundle is not configured, MLInferenceRun records NOT_CONFIGURED
      without failing protocol forensics or inventing mock predictions.
    """
    # 1. Deterministic Protocol Forensics
    service = ProtocolForensicsService(db)
    summary = await service.execute_analysis(analysis_id)

    # 2. Stateful Reconstruction & Dependent Stages across all capture profiles
    from app.reconstruction.engine import ReconstructionEngine

    engine = ReconstructionEngine(db)
    await engine.execute_reconstruction(analysis_id)

    # 3. Stage 7 & 17: ML Flow Classification with auditable lifecycle
    try:
        from app.ml.service import execute_flow_classification

        await execute_flow_classification(analysis_id, db)
    except Exception as ml_err:
        logger.warning(
            "ML classification encountered non-fatal error for '%s' (protocol forensics preserved): %s",
            analysis_id,
            ml_err,
        )

    # 4. Stage 8 & 16: Deterministic Policy-as-Code, Evidence Graph, Scoring
    try:
        from app.api.v1.security.router import (
            _ensure_assessment_executed,
            get_security_service,
        )

        sec_service = get_security_service()
        await _ensure_assessment_executed(analysis_id, db, sec_service, force=True)
    except Exception as sec_err:
        logger.warning(
            "Security assessment encountered error for '%s': %s",
            analysis_id,
            sec_err,
        )

    return summary
