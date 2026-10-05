"""Reconstruction Engine: Coordinates IKE, SA, and Flow reconstruction with idempotent persistence."""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.capture import AnalysisRun, ProtocolObservation
from app.db.models.reconstruction import (
    ChildSecurityAssociation,
    ESPFlow,
    IKESecurityAssociation,
    IKESession,
    TrafficSelector,
)
from app.reconstruction.flow.aggregator import (
    DEFAULT_FLOW_IDLE_TIMEOUT_SEC,
    DEFAULT_FLOW_MAX_DURATION_SEC,
    ESPFlowAggregator,
)
from app.reconstruction.ike.correlator import IKEEventCorrelator
from app.reconstruction.models import (
    EvidenceState,
    FlowAssociationState,
    LifecycleState,
    Mode,
    PFSStatus,
    ReconstructedChildSA,
    ReconstructionSummary,
)
from app.reconstruction.sa.builder import SABuilder

logger = logging.getLogger(__name__)


class ReconstructionEngine:
    """Orchestrates end-to-end Stage 4 stateful protocol and flow reconstruction."""

    def __init__(
        self,
        db: AsyncSession,
        idle_timeout_sec: float = DEFAULT_FLOW_IDLE_TIMEOUT_SEC,
        max_duration_sec: float = DEFAULT_FLOW_MAX_DURATION_SEC,
    ) -> None:
        self.db = db
        self.idle_timeout_sec = idle_timeout_sec
        self.max_duration_sec = max_duration_sec

    async def execute_reconstruction(
        self, analysis_id: uuid.UUID
    ) -> ReconstructionSummary:
        """Execute deterministic reconstruction against stored Stage-3 observations."""
        logger.info("Starting Stage 4 reconstruction for analysis %s", analysis_id)

        # 1. Update analysis stage to SA_RECONSTRUCTION
        analysis_res = await self.db.execute(
            select(AnalysisRun).where(AnalysisRun.id == analysis_id)
        )
        analysis = analysis_res.scalar_one_or_none()
        if not analysis:
            raise ValueError(f"AnalysisRun {analysis_id} not found")

        analysis.current_stage = "SA_RECONSTRUCTION"
        await self.db.flush()

        # 2. Fetch all protocol observations for this analysis
        obs_res = await self.db.execute(
            select(ProtocolObservation)
            .where(ProtocolObservation.analysis_id == analysis_id)
            .order_by(ProtocolObservation.packet_time, ProtocolObservation.frame_number)
        )
        observations = list(obs_res.scalars().all())

        if not observations:
            logger.info("Zero observations found for analysis %s. Finishing cleanly.", analysis_id)
            analysis.current_stage = "COMPLETED"
            await self.db.commit()
            return ReconstructionSummary(
                analysis_id=analysis_id,
                ike_sessions_count=0,
                ike_sas_count=0,
                child_sas_count=0,
                orphan_child_sas_count=0,
                directional_streams_count=0,
                paired_flows_count=0,
                unpaired_flows_count=0,
                mode_verified_count=0,
                mode_inferred_count=0,
                mode_unknown_count=0,
                pfs_known_count=0,
                pfs_unknown_count=0,
                retransmissions_detected=0,
            )

        # 3. Correlate IKE events and sessions
        correlator = IKEEventCorrelator(analysis_id)
        ike_events = correlator.extract_events_from_observations(observations)
        ike_sessions = correlator.correlate_sessions(ike_events)

        # 4. Build Parent IKE SAs and Child SAs
        sa_builder = SABuilder(analysis_id)
        esp_obs = [o for o in observations if o.protocol in ("ESP", "NAT-T")]

        all_child_sas = []
        if ike_sessions:
            for session in ike_sessions:
                parent_sa = sa_builder.build_parent_ike_sa(session, ike_events)
                session.parent_sa = parent_sa
                child_sas = sa_builder.build_child_sas(session, parent_sa, ike_events, esp_obs)
                session.child_sas = child_sas
                all_child_sas.extend(child_sas)
        else:
            # Orphan capture: ESP packets without IKE handshake
            if esp_obs:
                orphan_child_sas = sa_builder.build_child_sas(None, None, [], esp_obs)
                all_child_sas.extend(orphan_child_sas)

        # 5. Flow Reconstruction Stage
        analysis.current_stage = "FLOW_RECONSTRUCTION"
        await self.db.flush()

        flow_aggregator = ESPFlowAggregator(
            analysis_id=analysis_id,
            idle_timeout_sec=self.idle_timeout_sec,
            max_duration_sec=self.max_duration_sec,
        )
        flow_packets = flow_aggregator.extract_packets(esp_obs if esp_obs else observations)
        directional_streams = flow_aggregator.build_directional_streams(flow_packets)
        flows = flow_aggregator.pair_flows(directional_streams, all_child_sas)

        # Generate representative Child SAs for non-IPsec / alternate flows if no SAs exist
        if not all_child_sas and flows:
            for fl in flows:
                csa_id = uuid.uuid4()
                fl.child_sa_id = csa_id
                spi_str = (fl.spi or "").lower()
                proto = "ESP"
                mode = Mode.UNKNOWN
                mode_ev = EvidenceState.UNKNOWN
                if "wg" in spi_str:
                    proto = "WIREGUARD"
                    mode = Mode.TUNNEL
                    mode_ev = EvidenceState.INFERRED
                elif "ovpn" in spi_str:
                    proto = "OPENVPN"
                    mode = Mode.TUNNEL
                    mode_ev = EvidenceState.INFERRED
                elif "icmp" in spi_str:
                    proto = "ICMP"
                else:
                    proto = "NON_IPSEC"

                csa = ReconstructedChildSA(
                    id=csa_id,
                    analysis_id=analysis_id,
                    ike_sa_id=None,
                    protocol=proto,
                    inbound_spi=fl.spi,
                    outbound_spi=fl.reverse_spi,
                    src_ip=fl.src_ip,
                    dst_ip=fl.dst_ip,
                    mode=mode,
                    mode_evidence_state=mode_ev,
                    encryption_algorithm=None,
                    integrity_algorithm=None,
                    pfs_status=PFSStatus.UNKNOWN,
                    pfs_dh_group=None,
                    pfs_evidence_state=EvidenceState.UNKNOWN,
                    first_observed_at=fl.start_time,
                    last_observed_at=fl.end_time,
                    lifecycle_state=LifecycleState.ORPHAN,
                    evidence_state=EvidenceState.VERIFIED,
                )
                all_child_sas.append(csa)

        # 6. Idempotent Transactional Persistence: Clear prior reconstruction state
        await self.db.execute(delete(ESPFlow).where(ESPFlow.analysis_id == analysis_id))
        # Cascades handle traffic selectors, child_sas, ike_sas when sessions deleted
        await self.db.execute(delete(ChildSecurityAssociation).where(ChildSecurityAssociation.analysis_id == analysis_id))
        await self.db.execute(delete(IKESession).where(IKESession.analysis_id == analysis_id))
        await self.db.flush()

        # 7. Insert reconstructed models
        for sess in ike_sessions:
            db_sess = IKESession(
                id=sess.id,
                analysis_id=analysis_id,
                initiator_spi=sess.initiator_spi,
                responder_spi=sess.responder_spi,
                ike_version=sess.ike_version,
                initiator_ip=sess.initiator_ip,
                responder_ip=sess.responder_ip,
                initiator_port=sess.initiator_port,
                responder_port=sess.responder_port,
                first_observed_at=sess.first_observed_at,
                last_observed_at=sess.last_observed_at,
                lifecycle_state=sess.lifecycle_state.value,
                is_nat_detected=sess.is_nat_detected,
                retransmission_count=sess.retransmission_count,
                packet_count=sess.packet_count,
                evidence_state=sess.evidence_state.value,
                frame_numbers=sess.frame_numbers,
            )
            self.db.add(db_sess)

            if sess.parent_sa:
                psa = sess.parent_sa
                db_psa = IKESecurityAssociation(
                    id=psa.id,
                    session_id=sess.id,
                    encryption_algorithm=psa.encryption_algorithm,
                    key_length_bits=psa.key_length_bits,
                    prf_algorithm=psa.prf_algorithm,
                    integrity_algorithm=psa.integrity_algorithm,
                    dh_group=psa.dh_group,
                    selection_evidence_state=psa.selection_evidence_state.value,
                    established_at=psa.established_at,
                    evidence_state=psa.evidence_state.value,
                )
                self.db.add(db_psa)

        # Insert Child SAs and Traffic Selectors
        for csa in all_child_sas:
            db_csa = ChildSecurityAssociation(
                id=csa.id,
                analysis_id=analysis_id,
                ike_sa_id=csa.ike_sa_id,
                protocol=csa.protocol,
                inbound_spi=csa.inbound_spi,
                outbound_spi=csa.outbound_spi,
                src_ip=csa.src_ip,
                dst_ip=csa.dst_ip,
                mode=csa.mode.value,
                mode_evidence_state=csa.mode_evidence_state.value,
                encryption_algorithm=csa.encryption_algorithm,
                integrity_algorithm=csa.integrity_algorithm,
                pfs_status=csa.pfs_status.value,
                pfs_dh_group=csa.pfs_dh_group,
                pfs_evidence_state=csa.pfs_evidence_state.value,
                first_observed_at=csa.first_observed_at,
                last_observed_at=csa.last_observed_at,
                lifecycle_state=csa.lifecycle_state.value,
                evidence_state=csa.evidence_state.value,
            )
            self.db.add(db_csa)

            for ts in csa.traffic_selectors:
                db_ts = TrafficSelector(
                    id=ts.id,
                    child_sa_id=csa.id,
                    direction=ts.direction,
                    ip_subnet=ts.ip_subnet,
                    start_ip=ts.start_ip,
                    end_ip=ts.end_ip,
                    ip_protocol=ts.ip_protocol,
                    start_port=ts.start_port,
                    end_port=ts.end_port,
                    evidence_state=ts.evidence_state.value,
                )
                self.db.add(db_ts)

        # Insert ESP Flows
        for fl in flows:
            db_flow = ESPFlow(
                id=fl.id,
                analysis_id=analysis_id,
                child_sa_id=fl.child_sa_id,
                spi=fl.spi,
                reverse_spi=fl.reverse_spi,
                src_ip=fl.src_ip,
                dst_ip=fl.dst_ip,
                ip_version=fl.ip_version,
                is_nat_t=fl.is_nat_t,
                orientation_basis=fl.orientation_basis.value,
                start_time=fl.start_time,
                end_time=fl.end_time,
                duration_seconds=fl.duration_seconds,
                packet_count=fl.packet_count,
                byte_count=fl.byte_count,
                forward_packets=fl.forward_packets,
                forward_bytes=fl.forward_bytes,
                reverse_packets=fl.reverse_packets,
                reverse_bytes=fl.reverse_bytes,
                association_state=fl.association_state.value,
                end_reason=fl.end_reason.value,
            )
            self.db.add(db_flow)

        # 8. Mark analysis completed
        analysis.current_stage = "COMPLETED"
        await self.db.commit()

        # 9. Compute summary metrics
        paired_count = sum(1 for f in flows if f.association_state == FlowAssociationState.PAIRED_BIDIRECTIONAL)
        unpaired_count = len(flows) - paired_count
        retrans_count = sum(s.retransmission_count for s in ike_sessions)
        orphan_csa_count = sum(1 for c in all_child_sas if c.ike_sa_id is None)

        mode_verified = sum(1 for c in all_child_sas if c.mode == Mode.TRANSPORT)
        mode_unknown = sum(1 for c in all_child_sas if c.mode == Mode.UNKNOWN)
        pfs_known = sum(1 for c in all_child_sas if c.pfs_status != PFSStatus.UNKNOWN)
        pfs_unknown = sum(1 for c in all_child_sas if c.pfs_status == PFSStatus.UNKNOWN)

        summary = ReconstructionSummary(
            analysis_id=analysis_id,
            ike_sessions_count=len(ike_sessions),
            ike_sas_count=sum(1 for s in ike_sessions if s.parent_sa is not None),
            child_sas_count=len(all_child_sas),
            orphan_child_sas_count=orphan_csa_count,
            directional_streams_count=len(directional_streams),
            paired_flows_count=paired_count,
            unpaired_flows_count=unpaired_count,
            mode_verified_count=mode_verified,
            mode_inferred_count=0,
            mode_unknown_count=mode_unknown,
            pfs_known_count=pfs_known,
            pfs_unknown_count=pfs_unknown,
            retransmissions_detected=retrans_count,
        )

        logger.info(
            "Stage 4 reconstruction completed for %s: %d sessions, %d child SAs, %d flows",
            analysis_id,
            len(ike_sessions),
            len(all_child_sas),
            len(flows),
        )
        return summary
