"""Deterministic database auto-initialization and seeding for fresh container environments.
Ensures that empty databases (e.g. fresh Render deployments) are immediately populated
with baseline assets, captures, analysis runs, security findings, and monitoring telemetry.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine

from app.db.base import Base
import app.db.models  # register all models

logger = logging.getLogger(__name__)


async def ensure_db_initialized(engine: AsyncEngine, session_factory) -> None:
    """Ensure database schema tables exist and populate initial baseline data if empty."""
    # 1. Ensure all 56 tables exist
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database schema verified / created successfully.")
    except Exception as exc:
        logger.error(f"Error during Base.metadata.create_all: {exc}", exc_info=True)
        return

    # 2. Check if analyses table has data
    from app.db.models.capture import AnalysisRun

    async with session_factory() as session:
        try:
            res = await session.execute(select(func.count(AnalysisRun.id)))
            count = res.scalar() or 0
            if count > 0:
                logger.info(f"Database already contains {count} analysis runs. Auto-seed skipped.")
                return

            logger.info("Database is empty. Initiating automatic seeding of baseline SOC data...")
            await _run_auto_seed(session)
            logger.info("Automatic database seeding completed successfully.")
        except Exception as exc:
            logger.error(f"Error during auto-seeding: {exc}", exc_info=True)
            await session.rollback()


async def _run_auto_seed(session: AsyncSession) -> None:
    from app.monitoring.service import MonitoringService
    from app.monitoring.schema import (
        RegisterGatewayRequest,
        RegisterSensorRequest,
        SensorType,
        EventKind,
        MonitoringEventDTO,
        MonitoringEventBatchRequest,
    )
    from app.db.models.monitoring import SensorHealthState
    from app.db.models.inventory import (
        GatewayConfigurationSnapshot,
        GatewayCertificate,
    )
    from app.db.models.capture import Capture, AnalysisRun
    from app.db.models.security import (
        SecurityFindingModel,
        ScoreAssessmentModel,
        EvidenceGraphModel,
    )
    from app.db.models.replay import ReplayComparisonModel
    from app.db.models.report import ReportModel

    now = datetime.now(timezone.utc)

    # 1. Register Gateway
    gw = await MonitoringService.register_gateway(
        session,
        RegisterGatewayRequest(
            name="Perimeter-Gateway-ALPHA",
            gateway_ip="198.51.100.1",
            authorized_scope="198.51.100.0/24",
            operator_id="sec-ops-admin",
            authorization_reference="AUTH-REF-2026-0925-01",
        ),
    )

    # 2. Register Sensors
    s1, _ = await MonitoringService.register_sensor(
        session,
        RegisterSensorRequest(
            sensor_name="gw-collector-eth0",
            sensor_type=SensorType.GATEWAY_COLLECTOR,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
            freshness_window_seconds=60,
            reporting_interval_seconds=30,
        ),
    )

    s2, _ = await MonitoringService.register_sensor(
        session,
        RegisterSensorRequest(
            sensor_name="pcap-sensor-dmz",
            sensor_type=SensorType.CAPTURE_SENSOR,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
            freshness_window_seconds=60,
            reporting_interval_seconds=30,
        ),
    )

    # 3. Ingest Events
    evt1 = MonitoringEventDTO(
        sensor_id=s1.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_HEARTBEAT,
        source_timestamp=now - timedelta(seconds=15),
        sequence_number=1,
        payload={"daemon": "strongswan-6.0.4", "uptime_sec": 864000},
    )
    evt2 = MonitoringEventDTO(
        sensor_id=s1.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_IKE_SA_ESTABLISHED,
        source_timestamp=now - timedelta(seconds=10),
        sequence_number=2,
        ike_version="2",
        local_endpoint="198.51.100.1:500",
        remote_endpoint="203.0.113.50:500",
        initiator_spi="c0a8000100000001",
        responder_spi="c0a8000200000002",
        cipher_suite="AES_GCM_16_256/PRF_HMAC_SHA2_256/MODP_3072",
        payload={"connection_name": "corp-branch-link"},
    )
    evt3 = MonitoringEventDTO(
        sensor_id=s1.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_CHILD_SA_ESTABLISHED,
        source_timestamp=now - timedelta(seconds=8),
        sequence_number=3,
        child_spi_in="0x1a2b3c4d",
        child_spi_out="0x5e6f7a8b",
        cipher_suite="AES_GCM_16_256",
        payload={"mode": "TUNNEL"},
    )
    evt4 = MonitoringEventDTO(
        sensor_id=s2.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.CAPTURE_DROPS_RECORDED,
        source_timestamp=now - timedelta(seconds=300),
        sequence_number=1,
        interface_name="eth0",
        packet_count=10420,
        drop_count=12,
        payload={"drop_rate_ppm": 1151},
    )

    await MonitoringService.ingest_event_batch(session, s1, MonitoringEventBatchRequest(events=[evt1, evt2, evt3]))
    await MonitoringService.ingest_event_batch(session, s2, MonitoringEventBatchRequest(events=[evt4]))

    h2 = await session.get(SensorHealthState, s2.id)
    if h2:
        h2.current_health = "STALE"
        h2.health_reason = "Last observation 300s ago exceeds documented 60s freshness threshold"
        h2.active_quality_warnings = ["CAPTURE_DROPS_RECORDED", "FRESHNESS_WINDOW_EXCEEDED"]

    # 4. Configuration Snapshot
    snap_id = uuid.uuid4()
    session.add(
        GatewayConfigurationSnapshot(
            id=snap_id,
            gateway_id=gw.id,
            gateway_identity="Perimeter-Gateway-ALPHA",
            authorized_scope="198.51.100.0/24",
            source_type="CONFIGURED_FILE",
            collection_method="OFFLINE_IMPORT",
            collector_version="1.0.0",
            parser_version="swanctl-6.0.4",
            schema_version="1.0.0",
            canonical_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            normalized_ir={
                "connections": {
                    "corp-branch-link": {
                        "version": "2",
                        "local_addrs": ["198.51.100.1"],
                        "remote_addrs": ["203.0.113.50"],
                        "proposals": ["aes256gcm16-prfsha256-modp3072", "3des-sha1-modp1024"],
                    }
                }
            },
            unsupported_directives=[],
            is_baseline=True,
            baseline_version=1,
            approved_by="sec-ops-admin",
        )
    )

    # 5. Gateway Certificate
    cert_id = uuid.uuid4()
    session.add(
        GatewayCertificate(
            id=cert_id,
            gateway_id=gw.id,
            gateway_identity="Perimeter-Gateway-ALPHA",
            sha256_fingerprint="a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            serial_number="482019482019284",
            subject_dn="CN=vpn-gw-alpha.corp.internal, O=Enterprise Defense",
            issuer_dn="CN=Corp Root CA 2024, O=Enterprise Defense",
            subject_alt_names={"dns": ["vpn-gw-alpha.corp.internal"]},
            not_valid_before=now - timedelta(days=30),
            not_valid_after=now + timedelta(days=335),
            validity_status="VALID",
            days_until_expiry=335,
            public_key_algorithm="RSA",
            public_key_bits=4096,
            signature_algorithm="sha256WithRSAEncryption",
            is_ca=False,
            key_usages=["digitalSignature", "keyEncipherment"],
            extended_key_usages=["serverAuth", "clientAuth"],
            identity_association_status="MATCHED",
            chain_validation_status="VALIDATED",
        )
    )

    # 6. Capture Artifact
    cap_id = uuid.uuid4()
    cap = Capture(
        id=cap_id,
        capture_source="OFFLINE_UPLOAD",
        capture_format="PCAP",
        original_filename="ikev2_perimeter_audit.pcap",
        storage_path="captures/ikev2_perimeter_audit.pcap",
        file_size_bytes=524288,
        sha256_hash="8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
        packet_count=128,
        validation_state="VALIDATED",
    )
    session.add(cap)
    await session.flush()

    # 7. Analysis Run
    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=cap.id,
        status="COMPLETED",
        current_stage="COMPLETED",
        parser_engine="tshark",
        parser_version="4.2.2",
        schema_version="1.0.0",
        started_at=now - timedelta(minutes=15),
        completed_at=now - timedelta(minutes=14, seconds=45),
        replay_mode="ORIGINAL_INGESTION",
        provenance_metadata={
            "gateway_identity": "Perimeter-Gateway-ALPHA",
            "authorized_scope": "198.51.100.0/24",
        },
    )
    session.add(analysis)
    await session.flush()

    # 8. Score Assessment
    session.add(
        ScoreAssessmentModel(
            id=uuid.uuid4(),
            analysis_id=analysis.id,
            overall_score=74.0,
            raw_score=74.0,
            score_policy_id="NIST-SP-800-77-REV1",
            score_policy_version="1.0.0",
            score_policy_hash="a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            status="COMPUTED",
            coverage_percentage=92.0,
        )
    )

    # 9. Findings
    session.add(
        SecurityFindingModel(
            id=uuid.uuid4(),
            finding_id="FND-001",
            analysis_id=analysis.id,
            rule_id="RFC8221-3DES-DEPRECATION",
            rule_version="1.0.0",
            profile_id="NIST-SP-800-77-REV1",
            category="CRYPTOGRAPHIC_POSTURE",
            severity="CRITICAL",
            title="Deprecated 3DES-CBC Encryption Proposal in IKE SA Offer",
            technical_description="IKEv2 SA_INIT proposal contains 3DES-CBC (RFC 8221 non-compliant; SWEET32 vulnerable).",
            root_cause_key="CIPHER_3DES_OFFERED",
            affected_entity_type="IKE_PROPOSAL",
            affected_entity_id="ike-prop-01",
            evidence_state="VERIFIED",
            remediation_guidance="Remove 3des proposal from swanctl.conf and enforce aes256gcm16 exclusively.",
            record_hash="f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        )
    )
    session.add(
        SecurityFindingModel(
            id=uuid.uuid4(),
            finding_id="FND-002",
            analysis_id=analysis.id,
            rule_id="SCANNER-SUPPLEMENTAL-CVE-2023-35945",
            rule_version="1.0.0",
            profile_id="OPENVAS-FEED-V2",
            category="VULNERABILITY",
            severity="HIGH",
            title="Greenbone Scanner Correlation: strongSwan 5.9.10 Denial of Service (CVE-2023-35945)",
            technical_description="Supplemental external vulnerability report matched running daemon banner version.",
            root_cause_key="CVE_2023_35945",
            affected_entity_type="GATEWAY_HOST",
            affected_entity_id="198.51.100.1",
            evidence_state="INFERRED",
            remediation_guidance="Upgrade strongSwan daemon to 5.9.11+.",
            record_hash="f2a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        )
    )
    session.add(
        SecurityFindingModel(
            id=uuid.uuid4(),
            finding_id="FND-003",
            analysis_id=analysis.id,
            rule_id="DRIFT-CONFIG-MODP1024-ALLOW",
            rule_version="1.0.0",
            profile_id="CONFIG_BASELINE_V1",
            category="CONFIGURATION_INVENTORY",
            severity="MEDIUM",
            title="Configuration Baseline Drift: Diffie-Hellman Group 2 (MODP 1024) Permitted",
            technical_description="Active configuration diverges from authorized security baseline (unauthorized DH group enabled).",
            root_cause_key="DH_GROUP_2_UNAUTHORIZED",
            affected_entity_type="GATEWAY_CONFIG",
            affected_entity_id="Perimeter-Gateway-ALPHA",
            evidence_state="VERIFIED",
            remediation_guidance="Restore baseline swanctl configuration approved under CHG-0001.",
            record_hash="f3a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        )
    )
    session.add(
        SecurityFindingModel(
            id=uuid.uuid4(),
            finding_id="FND-004",
            analysis_id=analysis.id,
            rule_id="THREAT-MITRE-T1040-SNIFF",
            rule_version="1.0.0",
            profile_id="TACTICAL-THREAT-MATRIX",
            category="THREAT_INTELLIGENCE",
            severity="LOW",
            title="Adversary TTP Mapping: Network Sniffing / Metadata Distinguishability (MITRE ATT&CK T1040)",
            technical_description="Flow packet length distributions exhibit distinguishing entropy (side-channel signature).",
            root_cause_key="SIDE_CHANNEL_ENTROPY",
            affected_entity_type="ESP_FLOW",
            affected_entity_id="flow-esp-01",
            evidence_state="INFERRED",
            remediation_guidance="Enable ESP traffic padding to constant burst profile.",
            record_hash="f4a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        )
    )

    # 10. Evidence DAG
    nodes = [
        {"id": "node-finding-1", "node_type": "finding", "entity_id": "FND-001", "label": "3DES Proposal Violation", "properties": {"severity": "CRITICAL", "rfc": "8221", "byte_offset": 84}},
        {"id": "node-rule-1", "node_type": "rule", "entity_id": "RFC8221-3DES-DEPRECATION", "label": "RFC 8221 Policy Rule", "properties": {"standard": "NIST SP 800-77"}},
        {"id": "node-fact-1", "node_type": "fact", "entity_id": "FACT-CIPHER-3DES", "label": "Observed 3DES Cipher Transform", "properties": {"transform_type": "ENCR", "value": "3DES_CBC"}},
        {"id": "node-packet-1", "node_type": "packet", "entity_id": "FRAME-001", "label": "IKE_SA_INIT Request Frame #1", "properties": {"frame_number": 1, "byte_offset": 84}},
        {"id": "node-capture-1", "node_type": "capture", "entity_id": str(cap.id), "label": "ikev2_perimeter_audit.pcap", "properties": {"sha256": cap.sha256_hash}},
    ]
    edges = [
        {"source_id": "node-finding-1", "target_id": "node-rule-1", "relation_type": "EVALUATED_AGAINST"},
        {"source_id": "node-finding-1", "target_id": "node-fact-1", "relation_type": "SUPPORTED_BY"},
        {"source_id": "node-fact-1", "target_id": "node-packet-1", "relation_type": "EXTRACTED_FROM"},
        {"source_id": "node-packet-1", "target_id": "node-capture-1", "relation_type": "CONTAINED_IN"},
    ]
    session.add(
        EvidenceGraphModel(
            id=uuid.uuid4(),
            analysis_id=analysis.id,
            capture_sha256=cap.sha256_hash,
            nodes_count=len(nodes),
            edges_count=len(edges),
            graph_data={"nodes": nodes, "edges": edges},
            manifest_data={"evidence_grade": "VERIFIED", "tamper_seal": "VALID"},
        )
    )

    # 11. Replay Lineage
    session.add(
        ReplayComparisonModel(
            id=uuid.uuid4(),
            replay_mode="FORENSIC_REANALYSIS",
            parent_run_id=str(analysis.id),
            child_run_id=str(analysis.id),
            comparison_status="EXACT_MATCH",
            artifact_integrity="VERIFIED",
            summary="Deterministic forensic re-analysis verified exact cryptographic agreement across all 4 findings, transform tables, and SPI allocations with zero variance.",
            differences={},
            metrics={"finding_count": 4, "exact_matches": 4, "variance": 0.0},
        )
    )

    # 12. Report Model
    session.add(
        ReportModel(
            id=uuid.uuid4(),
            analysis_id=analysis.id,
            report_type="TECHNICAL",
            status="COMPLETED",
            format="HTML",
            template_version="1.0.0",
            engine_version="1.0.0",
            html_artifact_path="reports/technical_report.html",
            html_sha256="7c89a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
            metadata_json={
                "generated_at": now.isoformat(),
                "scope": "198.51.100.0/24",
                "policy_bundle": "NIST-SP-800-77-REV1",
            },
        )
    )

    await session.commit()
