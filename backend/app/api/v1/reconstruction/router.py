"""REST API endpoints for Stage 4: IKE Sessions, Security Associations, SA Graph, and Encrypted Flows."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.reconstruction.schemas import (
    ChildSecurityAssociationDTO,
    FlowListResponseDTO,
    FlowResponseDTO,
    IKESecurityAssociationDTO,
    IKESessionDetailDTO,
    IKESessionResponseDTO,
    SAGraphEdgeDTO,
    SAGraphNodeDTO,
    SAGraphResponseDTO,
    TrafficSelectorDTO,
)
from app.db.models.capture import AnalysisRun
from app.db.models.reconstruction import (
    ChildSecurityAssociation,
    ESPFlow,
    IKESecurityAssociation,
    IKESession,
)
from app.db.session import get_db_session

router = APIRouter(prefix="/analyses/{analysis_id}", tags=["Reconstruction"])


async def _verify_analysis_exists(analysis_id: uuid.UUID, db: AsyncSession) -> AnalysisRun:
    """Helper to verify AnalysisRun existence."""
    res = await db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found",
        )
    return analysis


@router.get(
    "/ike-sessions",
    response_model=list[IKESessionResponseDTO],
    summary="List reconstructed IKE sessions",
)
async def list_ike_sessions(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[IKESessionResponseDTO]:
    """Retrieve all reconstructed IKE sessions discovered for an analysis run."""
    await _verify_analysis_exists(analysis_id, db)

    res = await db.execute(
        select(IKESession)
        .where(IKESession.analysis_id == analysis_id)
        .order_by(IKESession.first_observed_at)
    )
    sessions = res.scalars().all()

    return [
        IKESessionResponseDTO(
            id=s.id,
            analysis_id=s.analysis_id,
            initiator_spi=s.initiator_spi,
            responder_spi=s.responder_spi,
            ike_version=s.ike_version,
            initiator_ip=s.initiator_ip,
            responder_ip=s.responder_ip,
            initiator_port=s.initiator_port,
            responder_port=s.responder_port,
            first_observed_at=s.first_observed_at,
            last_observed_at=s.last_observed_at,
            lifecycle_state=s.lifecycle_state,
            is_nat_detected=s.is_nat_detected,
            retransmission_count=s.retransmission_count,
            packet_count=s.packet_count,
            evidence_state=s.evidence_state,
            frame_numbers=s.frame_numbers,
        )
        for s in sessions
    ]


@router.get(
    "/ike-sessions/{session_id}",
    response_model=IKESessionDetailDTO,
    summary="Get detailed IKE session with parent and child SAs",
)
async def get_ike_session_detail(
    analysis_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> IKESessionDetailDTO:
    """Retrieve detailed view of an IKE session including parent SA and negotiated child SAs."""
    await _verify_analysis_exists(analysis_id, db)

    res = await db.execute(
        select(IKESession)
        .options(
            selectinload(IKESession.ike_sas).selectinload(IKESecurityAssociation.child_sas).selectinload(ChildSecurityAssociation.traffic_selectors)
        )
        .where(IKESession.analysis_id == analysis_id)
        .where(IKESession.id == session_id)
    )
    s = res.scalar_one_or_none()
    if not s:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IKE session {session_id} not found in analysis {analysis_id}",
        )

    parent_sa_dto = None
    child_sa_dtos = []
    if s.ike_sas:
        psa = s.ike_sas[0]
        parent_sa_dto = IKESecurityAssociationDTO(
            id=psa.id,
            session_id=psa.session_id,
            encryption_algorithm=psa.encryption_algorithm,
            key_length_bits=psa.key_length_bits,
            prf_algorithm=psa.prf_algorithm,
            integrity_algorithm=psa.integrity_algorithm,
            dh_group=psa.dh_group,
            selection_evidence_state=psa.selection_evidence_state,
            established_at=psa.established_at,
            evidence_state=psa.evidence_state,
        )

        for c in psa.child_sas:
            child_sa_dtos.append(
                ChildSecurityAssociationDTO(
                    id=c.id,
                    analysis_id=c.analysis_id,
                    ike_sa_id=c.ike_sa_id,
                    protocol=c.protocol,
                    inbound_spi=c.inbound_spi,
                    outbound_spi=c.outbound_spi,
                    src_ip=c.src_ip,
                    dst_ip=c.dst_ip,
                    mode=c.mode,
                    mode_evidence_state=c.mode_evidence_state,
                    encryption_algorithm=c.encryption_algorithm,
                    integrity_algorithm=c.integrity_algorithm,
                    pfs_status=c.pfs_status,
                    pfs_dh_group=c.pfs_dh_group,
                    pfs_evidence_state=c.pfs_evidence_state,
                    first_observed_at=c.first_observed_at,
                    last_observed_at=c.last_observed_at,
                    lifecycle_state=c.lifecycle_state,
                    evidence_state=c.evidence_state,
                    traffic_selectors=[
                        TrafficSelectorDTO(
                            id=ts.id,
                            direction=ts.direction,
                            ip_subnet=ts.ip_subnet,
                            start_ip=ts.start_ip,
                            end_ip=ts.end_ip,
                            ip_protocol=ts.ip_protocol,
                            start_port=ts.start_port,
                            end_port=ts.end_port,
                            evidence_state=ts.evidence_state,
                        )
                        for ts in c.traffic_selectors
                    ],
                )
            )

    return IKESessionDetailDTO(
        id=s.id,
        analysis_id=s.analysis_id,
        initiator_spi=s.initiator_spi,
        responder_spi=s.responder_spi,
        ike_version=s.ike_version,
        initiator_ip=s.initiator_ip,
        responder_ip=s.responder_ip,
        initiator_port=s.initiator_port,
        responder_port=s.responder_port,
        first_observed_at=s.first_observed_at,
        last_observed_at=s.last_observed_at,
        lifecycle_state=s.lifecycle_state,
        is_nat_detected=s.is_nat_detected,
        retransmission_count=s.retransmission_count,
        packet_count=s.packet_count,
        evidence_state=s.evidence_state,
        frame_numbers=s.frame_numbers,
        parent_sa=parent_sa_dto,
        child_sas=child_sa_dtos,
    )


@router.get(
    "/security-associations",
    response_model=list[ChildSecurityAssociationDTO],
    summary="List reconstructed Security Associations",
)
@router.get(
    "/child-sas",
    response_model=list[ChildSecurityAssociationDTO],
    summary="List reconstructed Child Security Associations (alias)",
)
async def list_security_associations(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[ChildSecurityAssociationDTO]:
    """Retrieve all Child Security Associations (both paired and orphan SAs) for an analysis run."""
    await _verify_analysis_exists(analysis_id, db)

    res = await db.execute(
        select(ChildSecurityAssociation)
        .options(selectinload(ChildSecurityAssociation.traffic_selectors))
        .where(ChildSecurityAssociation.analysis_id == analysis_id)
        .order_by(ChildSecurityAssociation.first_observed_at)
    )
    csas = res.scalars().all()

    return [
        ChildSecurityAssociationDTO(
            id=c.id,
            analysis_id=c.analysis_id,
            ike_sa_id=c.ike_sa_id,
            protocol=c.protocol,
            inbound_spi=c.inbound_spi,
            outbound_spi=c.outbound_spi,
            src_ip=c.src_ip,
            dst_ip=c.dst_ip,
            mode=c.mode,
            mode_evidence_state=c.mode_evidence_state,
            encryption_algorithm=c.encryption_algorithm,
            integrity_algorithm=c.integrity_algorithm,
            pfs_status=c.pfs_status,
            pfs_dh_group=c.pfs_dh_group,
            pfs_evidence_state=c.pfs_evidence_state,
            first_observed_at=c.first_observed_at,
            last_observed_at=c.last_observed_at,
            lifecycle_state=c.lifecycle_state,
            evidence_state=c.evidence_state,
            traffic_selectors=[
                TrafficSelectorDTO(
                    id=ts.id,
                    direction=ts.direction,
                    ip_subnet=ts.ip_subnet,
                    start_ip=ts.start_ip,
                    end_ip=ts.end_ip,
                    ip_protocol=ts.ip_protocol,
                    start_port=ts.start_port,
                    end_port=ts.end_port,
                    evidence_state=ts.evidence_state,
                )
                for ts in c.traffic_selectors
            ],
        )
        for c in csas
    ]


@router.get(
    "/security-associations/graph",
    response_model=SAGraphResponseDTO,
    summary="Get Security Association topology graph for visualization",
)
@router.get(
    "/sa-graph",
    response_model=SAGraphResponseDTO,
    summary="Get Security Association topology graph (alias)",
)
async def get_sa_graph(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> SAGraphResponseDTO:
    """Generate React Flow-compatible topology graph data for IKE sessions, SAs, and Flows."""
    await _verify_analysis_exists(analysis_id, db)

    # 1. Fetch sessions
    sess_res = await db.execute(
        select(IKESession)
        .options(selectinload(IKESession.ike_sas))
        .where(IKESession.analysis_id == analysis_id)
    )
    sessions = sess_res.scalars().all()

    # 2. Fetch child SAs
    csa_res = await db.execute(
        select(ChildSecurityAssociation)
        .where(ChildSecurityAssociation.analysis_id == analysis_id)
    )
    child_sas = csa_res.scalars().all()

    # 3. Fetch flows
    flow_res = await db.execute(
        select(ESPFlow).where(ESPFlow.analysis_id == analysis_id)
    )
    flows = flow_res.scalars().all()

    nodes: list[SAGraphNodeDTO] = []
    edges: list[SAGraphEdgeDTO] = []
    peers_seen: set[str] = set()

    for s in sessions:
        # Peer nodes
        if s.initiator_ip and s.initiator_ip not in peers_seen:
            nodes.append(
                SAGraphNodeDTO(
                    id=f"peer-{s.initiator_ip}",
                    type="peer",
                    label=f"Peer: {s.initiator_ip}",
                    data={"ip": s.initiator_ip, "role": "initiator"},
                )
            )
            peers_seen.add(s.initiator_ip)

        if s.responder_ip and s.responder_ip not in peers_seen:
            nodes.append(
                SAGraphNodeDTO(
                    id=f"peer-{s.responder_ip}",
                    type="peer",
                    label=f"Peer: {s.responder_ip}",
                    data={"ip": s.responder_ip, "role": "responder"},
                )
            )
            peers_seen.add(s.responder_ip)

        # Session node
        sess_node_id = f"sess-{s.id}"
        nodes.append(
            SAGraphNodeDTO(
                id=sess_node_id,
                type="session",
                label=f"IKE Session ({s.ike_version})",
                data={
                    "initiator_spi": s.initiator_spi,
                    "responder_spi": s.responder_spi,
                    "lifecycle": s.lifecycle_state,
                    "nat_t": s.is_nat_detected,
                },
            )
        )

        if s.initiator_ip:
            edges.append(
                SAGraphEdgeDTO(
                    id=f"e-peer-init-{s.id}",
                    source=f"peer-{s.initiator_ip}",
                    target=sess_node_id,
                    label="PARTICIPATES_IN",
                )
            )
        if s.responder_ip:
            edges.append(
                SAGraphEdgeDTO(
                    id=f"e-peer-resp-{s.id}",
                    source=f"peer-{s.responder_ip}",
                    target=sess_node_id,
                    label="PARTICIPATES_IN",
                )
            )

        # Parent IKE SA
        for psa in s.ike_sas:
            psa_node_id = f"ike-sa-{psa.id}"
            nodes.append(
                SAGraphNodeDTO(
                    id=psa_node_id,
                    type="ike_sa",
                    label=f"IKE SA: {psa.encryption_algorithm or 'UNKNOWN'}",
                    data={
                        "cipher": psa.encryption_algorithm,
                        "prf": psa.prf_algorithm,
                        "dh_group": psa.dh_group,
                        "evidence_state": psa.selection_evidence_state,
                    },
                )
            )
            edges.append(
                SAGraphEdgeDTO(
                    id=f"e-sess-sa-{psa.id}",
                    source=sess_node_id,
                    target=psa_node_id,
                    label="NEGOTIATES",
                )
            )

    # Child SAs
    for c in child_sas:
        csa_node_id = f"child-sa-{c.id}"
        is_orphan = c.ike_sa_id is None
        nodes.append(
            SAGraphNodeDTO(
                id=csa_node_id,
                type="unmapped_sa" if is_orphan else "child_sa",
                label=f"Child SA ({c.protocol}) [{c.inbound_spi[:8]}]",
                data={
                    "inbound_spi": c.inbound_spi,
                    "outbound_spi": c.outbound_spi,
                    "mode": c.mode,
                    "pfs": c.pfs_status,
                    "lifecycle": c.lifecycle_state,
                },
            )
        )
        if c.ike_sa_id:
            edges.append(
                SAGraphEdgeDTO(
                    id=f"e-sa-csa-{c.id}",
                    source=f"ike-sa-{c.ike_sa_id}",
                    target=csa_node_id,
                    label="PARENT_OF",
                )
            )

    # Flows
    for fl in flows:
        flow_node_id = f"flow-{fl.id}"
        nodes.append(
            SAGraphNodeDTO(
                id=flow_node_id,
                type="flow",
                label=f"ESP Flow ({fl.packet_count} pkts, {fl.byte_count} B)",
                data={
                    "spi": fl.spi,
                    "reverse_spi": fl.reverse_spi,
                    "src_ip": fl.src_ip,
                    "dst_ip": fl.dst_ip,
                    "nat_t": fl.is_nat_t,
                    "duration": fl.duration_seconds,
                    "association": fl.association_state,
                },
            )
        )
        if fl.child_sa_id:
            edges.append(
                SAGraphEdgeDTO(
                    id=f"e-csa-flow-{fl.id}",
                    source=f"child-sa-{fl.child_sa_id}",
                    target=flow_node_id,
                    label="PROTECTS",
                )
            )

    return SAGraphResponseDTO(
        analysis_id=analysis_id,
        nodes=nodes,
        edges=edges,
    )


@router.get(
    "/flows",
    response_model=FlowListResponseDTO,
    summary="List paginated encrypted ESP flows",
)
async def list_flows(
    analysis_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db_session),
) -> FlowListResponseDTO:
    """Retrieve paginated encrypted ESP flows without raw payload."""
    await _verify_analysis_exists(analysis_id, db)

    total_res = await db.execute(
        select(func.count(ESPFlow.id)).where(ESPFlow.analysis_id == analysis_id)
    )
    total_count = total_res.scalar_one()

    res = await db.execute(
        select(ESPFlow)
        .where(ESPFlow.analysis_id == analysis_id)
        .order_by(ESPFlow.start_time)
        .offset(offset)
        .limit(limit)
    )
    flows = res.scalars().all()

    return FlowListResponseDTO(
        analysis_id=analysis_id,
        total_flows=total_count,
        items=[
            FlowResponseDTO(
                id=f.id,
                analysis_id=f.analysis_id,
                child_sa_id=f.child_sa_id,
                spi=f.spi,
                reverse_spi=f.reverse_spi,
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                ip_version=f.ip_version,
                is_nat_t=f.is_nat_t,
                orientation_basis=f.orientation_basis,
                start_time=f.start_time,
                end_time=f.end_time,
                duration_seconds=f.duration_seconds,
                packet_count=f.packet_count,
                byte_count=f.byte_count,
                forward_packets=f.forward_packets,
                forward_bytes=f.forward_bytes,
                reverse_packets=f.reverse_packets,
                reverse_bytes=f.reverse_bytes,
                association_state=f.association_state,
                end_reason=f.end_reason,
            )
            for f in flows
        ],
    )
