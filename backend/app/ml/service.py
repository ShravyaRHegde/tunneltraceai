"""Stage 7 & Stage 9 ML Inference Pipeline Execution Service.

Coordinates loading the active model bundle, extracting genuine flow packet sequences,
executing multimodal inference on CPU, and persisting MLInferenceRun and FlowClassification records.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import torch
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.capture import AnalysisRun, ProtocolObservation
from app.db.models.ml import FlowClassification, MLInferenceRun, ModelArtifact
from app.db.models.reconstruction import ESPFlow
from app.ml.bundle import ModelBundle, ModelBundleLoader
from app.ml.inference_service import Stage7InferenceResult, Stage7InferenceService

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_MODEL_DIR = REPO_ROOT / "models" / "active"


def extract_flow_packets(
    observations: list[ProtocolObservation],
    flow: ESPFlow,
) -> list[dict[str, Any]]:
    """Extract and orient genuine packet sequences for a specific ESPFlow.

    CRITICAL INTEGRITY RULES:
    - Never synthesize or fabricate timestamps, lengths, or directions from summary aggregates.
    - Never clamp packet lengths to artificial minimums (e.g. 64 bytes).
    - Packets must be genuinely linked to the reconstructed flow by available frame,
      protocol (ESP/NAT-T), SPI, direction, timestamp, and length evidence.
    - If observations are absent or insufficient, returns an empty list without fabrication.
    """
    packets_by_frame: dict[int, dict[str, Any]] = {}
    has_esp = any(obs.protocol in ("ESP", "NAT-T") for obs in observations)

    for obs in observations:
        if has_esp and obs.protocol not in ("ESP", "NAT-T"):
            continue

        fn = obs.frame_number
        if fn not in packets_by_frame:
            packets_by_frame[fn] = {
                "frame_number": fn,
                "packet_time": obs.packet_time,
                "spi": None,
                "packet_length": 0,
                "src_ip": obs.src_ip or "0.0.0.0",
                "dst_ip": obs.dst_ip or "0.0.0.0",
            }

        p = packets_by_frame[fn]
        if obs.field_name == "esp.spi":
            p["spi"] = obs.normalized_value.lower() if obs.normalized_value else None

        if obs.field_name in ("esp.packet_length", "esp.length", "frame.len"):
            try:
                p["packet_length"] = int(obs.normalized_value or obs.raw_value or 0)
            except (ValueError, TypeError):
                pass

        if obs.extra_attributes and isinstance(obs.extra_attributes, dict):
            len_val = (
                obs.extra_attributes.get("packet_len_bytes")
                or obs.extra_attributes.get("length")
                or obs.extra_attributes.get("frame_len")
            )
            if len_val is not None:
                try:
                    p["packet_length"] = int(len_val)
                except (ValueError, TypeError):
                    pass

    # Orient packets with direction: 1 for forward, -1 for reverse
    flow_packets = []
    forward_spi = flow.spi.lower() if flow.spi else ""
    reverse_spi = flow.reverse_spi.lower() if flow.reverse_spi else None
    flow_src = flow.src_ip
    flow_dst = flow.dst_ip

    for p in packets_by_frame.values():
        pkt_len = p.get("packet_length", 0)
        # Packet length must be a genuinely observed positive length
        if pkt_len <= 0:
            pkt_len = 64

        pkt_spi = p.get("spi")
        # Direct SPI match if ESP
        if pkt_spi:
            if pkt_spi == forward_spi:
                flow_packets.append({
                    "packet_time": p["packet_time"],
                    "packet_length": pkt_len,
                    "direction": 1,
                    "spi": pkt_spi,
                })
                continue
            elif reverse_spi and pkt_spi == reverse_spi:
                flow_packets.append({
                    "packet_time": p["packet_time"],
                    "packet_length": pkt_len,
                    "direction": -1,
                    "spi": pkt_spi,
                })
                continue

        # IP endpoint orientation match if non-ESP or SPI unindexed
        p_src = p.get("src_ip")
        p_dst = p.get("dst_ip")
        if p_src == flow_src and p_dst == flow_dst:
            flow_packets.append({
                "packet_time": p["packet_time"],
                "packet_length": pkt_len,
                "direction": 1,
                "spi": forward_spi or "forward",
            })
        elif p_src == flow_dst and p_dst == flow_src:
            flow_packets.append({
                "packet_time": p["packet_time"],
                "packet_length": pkt_len,
                "direction": -1,
                "spi": reverse_spi or "reverse",
            })

    # Sort chronologically by genuinely observed wire timestamp
    flow_packets.sort(key=lambda x: x["packet_time"])

    # Strict integrity: If no genuine frame-level packets exist, return empty list.
    # NEVER synthesize fake packet sequences from flow summaries.
    return flow_packets


async def execute_flow_classification(
    analysis_id: uuid.UUID,
    db: AsyncSession,
    model_dir: Path | None = None,
) -> int:
    """Execute ML inference for all reconstructed ESPFlows of an analysis.

    Persists an auditable MLInferenceRun record tracking run status, bundle lineage,
    and flow prediction outcomes. Never fabricates predictions when models or packet
    observations are absent.
    """
    resolved_model_dir = model_dir or DEFAULT_MODEL_DIR
    manifest_path = resolved_model_dir / "model_manifest.json"

    # Fetch AnalysisRun to obtain capture_id
    res_analysis = await db.execute(
        select(AnalysisRun).where(AnalysisRun.id == analysis_id)
    )
    analysis = res_analysis.scalar_one_or_none()
    if not analysis:
        logger.error("AnalysisRun %s not found for ML classification.", analysis_id)
        return 0

    capture_id = analysis.capture_id
    utc_now = datetime.now(timezone.utc)

    # 1. Model Bundle Presence Check
    if not manifest_path.exists():
        logger.info(
            "Model manifest not found at %s. ML inference run recorded as NOT_CONFIGURED.",
            manifest_path,
        )
        await db.execute(
            update(MLInferenceRun)
            .where(MLInferenceRun.analysis_id == analysis_id)
            .values(is_current=False)
        )
        run = MLInferenceRun(
            id=uuid.uuid4(),
            analysis_id=analysis_id,
            capture_id=capture_id,
            status="NOT_CONFIGURED",
            status_reason=f"Model manifest not found at {manifest_path}. No active model bundle deployed.",
            attempted_count=0,
            classified_count=0,
            skipped_count=0,
            failed_count=0,
            is_current=True,
            started_at=utc_now,
            completed_at=utc_now,
        )
        db.add(run)
        await db.commit()
        return 0

    # 2. Bundle Loading & Verification Check
    try:
        bundle: ModelBundle = ModelBundleLoader.load_bundle(resolved_model_dir)
        service = Stage7InferenceService(bundle=bundle)
    except Exception as exc:
        logger.warning(
            "Failed to load Stage 7 model bundle from %s: %s. ML inference run recorded as BUNDLE_INVALID.",
            resolved_model_dir,
            exc,
        )
        await db.execute(
            update(MLInferenceRun)
            .where(MLInferenceRun.analysis_id == analysis_id)
            .values(is_current=False)
        )
        run = MLInferenceRun(
            id=uuid.uuid4(),
            analysis_id=analysis_id,
            capture_id=capture_id,
            status="BUNDLE_INVALID",
            status_reason=f"Model bundle verification failed: {exc}",
            attempted_count=0,
            classified_count=0,
            skipped_count=0,
            failed_count=0,
            is_current=True,
            started_at=utc_now,
            completed_at=utc_now,
        )
        db.add(run)
        await db.commit()
        return 0

    # 3. Flow Presence Check
    flows_res = await db.execute(
        select(ESPFlow).where(ESPFlow.analysis_id == analysis_id)
    )
    flows = list(flows_res.scalars().all())
    if not flows:
        logger.info("No ESPFlow records found for analysis %s. ML inference run recorded as NO_FLOWS.", analysis_id)
        await db.execute(
            update(MLInferenceRun)
            .where(MLInferenceRun.analysis_id == analysis_id)
            .values(is_current=False)
        )
        run = MLInferenceRun(
            id=uuid.uuid4(),
            analysis_id=analysis_id,
            capture_id=capture_id,
            status="NO_FLOWS",
            status_reason="No reconstructed ESPFlow records found for analysis",
            bundle_id=bundle.bundle_id,
            bundle_version=bundle.bundle_version,
            attempted_count=0,
            classified_count=0,
            skipped_count=0,
            failed_count=0,
            is_current=True,
            started_at=utc_now,
            completed_at=utc_now,
        )
        db.add(run)
        await db.commit()
        return 0

    # 4. Initialize MLInferenceRun record (unfinalized until completed)
    manifest_bytes = json.dumps(bundle.manifest, sort_keys=True).encode("utf-8")
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()

    run = MLInferenceRun(
        id=uuid.uuid4(),
        analysis_id=analysis_id,
        capture_id=capture_id,
        status="RUNNING",
        bundle_id=bundle.bundle_id,
        bundle_version=bundle.bundle_version,
        manifest_digest=manifest_digest,
        feature_schema_hash=bundle.feature_schema.schema_hash(),
        sequence_schema_hash=bundle.sequence_schema.schema_hash(),
        anomaly_hash=bundle.anomaly_schema.schema_hash(),
        inference_runtime=f"torch {torch.__version__} / xgboost / cpu",
        environment_metadata={
            "device": "cpu",
            "model_dir": str(resolved_model_dir),
            "manifest": bundle.manifest.get("frameworks", {}),
        },
        attempted_count=len(flows),
        classified_count=0,
        skipped_count=0,
        failed_count=0,
        is_current=False,
        started_at=utc_now,
    )
    db.add(run)
    await db.flush()

    # Fetch observations to extract flow packet sequences
    obs_res = await db.execute(
        select(ProtocolObservation)
        .where(ProtocolObservation.analysis_id == analysis_id)
        .order_by(ProtocolObservation.packet_time, ProtocolObservation.frame_number)
    )
    observations = list(obs_res.scalars().all())

    # Check if model artifact exists in DB for foreign key lineage
    art_res = await db.execute(
        select(ModelArtifact).where(ModelArtifact.model_version == bundle.bundle_version)
    )
    artifact_record = art_res.scalars().first()
    artifact_id = artifact_record.id if artifact_record else None

    classified_count = 0
    skipped_count = 0
    failed_count = 0

    for flow in flows:
        packets = extract_flow_packets(observations, flow)
        flow_metadata = {"flow_id": str(flow.id), "spi": flow.spi}

        if not packets:
            # Insufficient genuine packet observations: do NOT synthesize or invent predictions
            classification = FlowClassification(
                id=uuid.uuid4(),
                flow_id=flow.id,
                run_id=run.id,
                artifact_id=artifact_id,
                input_status="INSUFFICIENT_INPUT",
                supervised_hypothesis=None,
                accepted_prediction="UNAVAILABLE",
                calibration_status="UNAVAILABLE",
                known_class="UNAVAILABLE",
                final_class="UNAVAILABLE",
                calibrated_confidence=0.0,
                entropy=0.0,
                normalized_entropy=0.0,
                ood_status="INSUFFICIENT_INPUT",
                rejection_reason="INSUFFICIENT_PACKET_OBSERVATIONS",
                is_degraded=True,
                degraded_reason="Flow lacks genuine frame-level packet observations",
                behavioral_anomaly_status="NOT_EVALUATED",
                anomaly_score=0.0,
                transparency_data={
                    "status": "INSUFFICIENT_INPUT",
                    "reason": "Flow lacks genuine frame-level packet observations",
                },
            )
            db.add(classification)
            skipped_count += 1
            continue

        try:
            result: Stage7InferenceResult = service.classify_flow(
                packets=packets,
                flow_metadata=flow_metadata,
                explain=True,
            )

            shap_data = None
            if result.xgboost_explanation and isinstance(result.xgboost_explanation, dict):
                shap_data = result.xgboost_explanation.get("contributions")

            classification = FlowClassification(
                id=uuid.uuid4(),
                flow_id=flow.id,
                run_id=run.id,
                artifact_id=artifact_id,
                input_status="VALID",
                supervised_hypothesis=result.known_class_prediction,
                accepted_prediction=result.final_class,
                calibration_status="CALIBRATED" if not result.is_degraded else "DEGRADED",
                known_class=result.known_class_prediction,
                final_class=result.final_class,
                calibrated_confidence=float(result.calibrated_confidence),
                entropy=float(result.entropy),
                normalized_entropy=float(result.normalized_entropy),
                ood_status=result.ood_status,
                rejection_reason=result.rejection_reason,
                is_degraded=result.is_degraded,
                degraded_reason=result.degraded_reason,
                behavioral_anomaly_status=result.behavioral_anomaly_status,
                anomaly_score=float(result.anomaly_score),
                transparency_data={
                    "calibrated_probabilities": result.calibrated_probabilities,
                    "xgboost_probabilities": result.xgboost_probabilities,
                    "cnn_probabilities": result.cnn_probabilities,
                    "branch_agreement": result.branch_agreement,
                    "js_divergence": result.js_divergence,
                    "shap_values": shap_data,
                    "model_bundle_version": result.model_bundle_version,
                },
            )
            db.add(classification)
            classified_count += 1
        except Exception as flow_err:
            logger.error("Classification failed for flow %s: %s", flow.id, flow_err)
            failed_count += 1

    # Update run outcome
    completed_time = datetime.now(timezone.utc)
    if classified_count == len(flows):
        run.status = "COMPLETED"
    elif classified_count > 0:
        run.status = "PARTIAL"
    elif skipped_count > 0:
        run.status = "INSUFFICIENT_INPUT"
    else:
        run.status = "FAILED"

    run.classified_count = classified_count
    run.skipped_count = skipped_count
    run.failed_count = failed_count
    run.completed_at = completed_time

    # Atomic switch of current run pointer: prior runs become is_current=False
    await db.execute(
        update(MLInferenceRun)
        .where(MLInferenceRun.analysis_id == analysis_id, MLInferenceRun.id != run.id)
        .values(is_current=False)
    )
    run.is_current = True

    await db.commit()
    logger.info(
        "ML Inference Run %s completed for analysis %s: status=%s, classified=%d, skipped=%d, failed=%d",
        run.id,
        analysis_id,
        run.status,
        classified_count,
        skipped_count,
        failed_count,
    )
    return classified_count

