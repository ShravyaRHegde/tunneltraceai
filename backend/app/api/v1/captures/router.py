import io
from pathlib import Path
from typing import Any
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.schemas import CaptureResponseDTO
from app.capture.ingestion import CaptureIngestionService
from app.core.errors import CaptureNotFoundError
from app.db.models.capture import Capture
from app.db.session import get_db_session

router = APIRouter(prefix="/captures", tags=["captures"])


class SampleCaptureDTO(BaseModel):
    sample_id: str
    filename: str
    title: str
    description: str
    packet_count: int
    format: str
    sha256: str
    provenance: str


def _find_repo_root() -> Path:
    current = Path(__file__).resolve()
    for p in current.parents:
        if (p / "tests" / "fixtures").exists() or (p / "pytest.ini").exists():
            return p
    return Path(".")


SAMPLE_FIXTURES: dict[str, dict[str, Any]] = {
    "real_tunnel_gcm": {
        "sample_id": "real_tunnel_gcm",
        "filename": "real_tunnel_gcm.pcapng",
        "rel_path": "tests/fixtures/captures/real_tunnel_gcm.pcapng",
        "title": "IKEv2 Site-to-Site Tunnel (AES-256-GCM / ECP-256 / PFS)",
        "description": "Full RFC 7296 cryptographic handshake with IKE_SA_INIT, IKE_AUTH, and 8 bidirectional ESP data plane frames.",
        "packet_count": 12,
        "format": "PCAPNG",
        "sha256": "949531329196d1fbc836ee0685efe8a204c68d6d8da5a5b75ecaa0128c59e04d",
        "provenance": "Authentic dual-strongSwan Linux namespace benchmark capture",
    },
    "real_esp_only": {
        "sample_id": "real_esp_only",
        "filename": "real_esp_only.pcap",
        "rel_path": "tests/fixtures/captures/real_esp_only.pcap",
        "title": "ESP-Only Mid-Stream Flow (No Handshake Observed)",
        "description": "Mid-stream ESP packets illustrating passive visibility limitations when IKE exchange packets are missing from capture.",
        "packet_count": 8,
        "format": "PCAP",
        "sha256": "76b74be5fc6e60d931c1bcf959360c84b59d7f70bada30b46af8938bff339bdd",
        "provenance": "Subset of frames 5-12 isolating encrypted data plane encapsulation",
    },
    "sample_cbc_nopfs": {
        "sample_id": "sample_cbc_nopfs",
        "filename": "sample_cbc_nopfs.pcap",
        "rel_path": "tests/fixtures/captures/sample_cbc_nopfs.pcap",
        "title": "IKEv2 Tunnel Mode (AES-256-CBC / DH14 / No PFS)",
        "description": "Authentic strongSwan tunnel with Perfect Forward Secrecy disabled. Triggers policy audit evaluation for non-PFS rekeying exposure.",
        "packet_count": 12,
        "format": "PCAP",
        "sha256": "14782b9996945e3f5c82b48d2ea4596dd730ede00cae7f791bdb053daca804b2",
        "provenance": "dual-strongSwan namespace benchmark capture from scn-02-tunnel-v4-cbc-nopfs",
    },
    "strongswan_natt_udp4500": {
        "sample_id": "strongswan_natt_udp4500",
        "filename": "03_strongswan_natt_udp4500.pcap",
        "rel_path": "tests/fixtures/verification_captures/03_strongswan_natt_udp4500.pcap",
        "title": "NAT-Traversal UDP Port 4500 Tunnel",
        "description": "RFC 3948 UDP-encapsulated ESP tunnel passing through NAT boundary with Non-ESP marker detection.",
        "packet_count": 12,
        "format": "PCAP",
        "sha256": "7b63a0fd455202ac286de8d5c1dd8e499fc988680b9bdcb6c8afe6567f7f21fa",
        "provenance": "dual-strongSwan namespace test with iptables NAT-T port 4500 mapping",
    },
    "edge_esp_seq_jump_replay": {
        "sample_id": "edge_esp_seq_jump_replay",
        "filename": "10_edge_esp_seq_jump_replay.pcap",
        "rel_path": "tests/fixtures/verification_captures/10_edge_esp_seq_jump_replay.pcap",
        "title": "Anti-Replay Anomaly & Sequence Number Jump",
        "description": "Synthesized sequence number regression testing RFC 4303 anti-replay window protection and replay attack alerting.",
        "packet_count": 12,
        "format": "PCAP",
        "sha256": "f0cb561a3be595b59b21aac8f67b746251370faa105d91e0c5b31886ea879790",
        "provenance": "Mutated ESP sequence number sequence testing anti-replay integrity checks",
    },
    "plaintext_icmp_control": {
        "sample_id": "plaintext_icmp_control",
        "filename": "04_plaintext_icmp_non_ipsec.pcap",
        "rel_path": "tests/fixtures/verification_captures/04_plaintext_icmp_non_ipsec.pcap",
        "title": "Plaintext ICMP Traffic (Negative Control)",
        "description": "Non-IPsec network traffic used to verify negative control validation and automatic capture rejection.",
        "packet_count": 10,
        "format": "PCAP",
        "sha256": "b37aa527dd51c80a1b003cc305f56bc77f53ba44da0ec3d4144fc29efb1ad61c",
        "provenance": "Baseline client plaintext echo request/reply capture without IPsec transforms",
    },
}


@router.get(
    "/samples",
    response_model=list[SampleCaptureDTO],
    summary="List available repository sample captures for immediate evaluation",
)
async def list_sample_captures() -> list[SampleCaptureDTO]:
    """Retrieve safe repository benchmark fixtures ready for one-click ingestion."""
    return [
        SampleCaptureDTO(
            sample_id=item["sample_id"],
            filename=item["filename"],
            title=item["title"],
            description=item["description"],
            packet_count=item["packet_count"],
            format=item["format"],
            sha256=item["sha256"],
            provenance=item["provenance"],
        )
        for item in SAMPLE_FIXTURES.values()
    ]


@router.post(
    "/samples/{sample_id}/ingest",
    response_model=CaptureResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a verified safe repository fixture without external file upload",
)
async def ingest_sample_capture(
    sample_id: str,
    force_rerun: bool = Query(False, description="Force new analysis run even if already analyzed"),
    db: AsyncSession = Depends(get_db_session),
) -> CaptureResponseDTO:
    """Read a verified repository test fixture and ingest it immutably into the analysis pipeline."""
    if sample_id not in SAMPLE_FIXTURES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample fixture '{sample_id}' not found. Available: {list(SAMPLE_FIXTURES.keys())}",
        )
    fix_meta = SAMPLE_FIXTURES[sample_id]
    repo_root = _find_repo_root()
    file_path = repo_root / fix_meta["rel_path"]
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Fixture file missing on server disk at {file_path}",
        )

    with open(file_path, "rb") as f:
        content = f.read()

    upload_file = UploadFile(
        file=io.BytesIO(content),
        filename=fix_meta["filename"],
        size=len(content),
    )
    service = CaptureIngestionService(db)
    capture = await service.ingest_upload(upload_file, capture_source="SAMPLE_FIXTURE")

    # Check if a completed analysis already exists for this capture
    from app.db.models.capture import AnalysisRun

    stmt_run = (
        select(AnalysisRun)
        .where(
            AnalysisRun.capture_id == capture.id,
            AnalysisRun.status == "COMPLETED",
            AnalysisRun.is_archived == False,
        )
        .order_by(AnalysisRun.created_at.desc())
    )
    existing_run = (await db.execute(stmt_run)).scalars().first()
    already_analyzed = (existing_run is not None and not force_rerun)

    return CaptureResponseDTO(
        capture_id=capture.id,
        capture_source=capture.capture_source,
        capture_format=capture.capture_format,
        original_filename=capture.original_filename,
        file_size_bytes=capture.file_size_bytes,
        sha256=capture.sha256_hash,
        packet_count=capture.packet_count,
        duration_sec=capture.duration_sec,
        first_packet_at=capture.first_packet_at,
        last_packet_at=capture.last_packet_at,
        link_layer_type=capture.link_layer_type,
        validation_state=capture.validation_state,
        already_analyzed=already_analyzed,
        existing_analysis_id=existing_run.id if existing_run else None,
        existing_run_status=existing_run.status if existing_run else None,
        existing_pipeline_version=getattr(existing_run, "pipeline_version", None) if existing_run else None,
        created_at=capture.created_at,
    )


@router.post(
    "",
    response_model=CaptureResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and ingest a packet capture file (PCAP/PCAPNG)",
)
@router.post(
    "/",
    response_model=CaptureResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and ingest a packet capture file (PCAP/PCAPNG) [trailing slash]",
)
@router.post(
    "/upload",
    response_model=CaptureResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and ingest a packet capture file (PCAP/PCAPNG) [alias]",
)
async def upload_capture(
    file: UploadFile = File(..., description="Binary packet capture file (PCAP or PCAPNG)"),
    force_rerun: bool = Query(False, description="Force new analysis run even if already analyzed"),
    db: AsyncSession = Depends(get_db_session),
) -> CaptureResponseDTO:
    """Safely stream, validate, hash, and persist an offline packet capture file."""
    service = CaptureIngestionService(db)
    capture = await service.ingest_upload(file, capture_source="OFFLINE_UPLOAD")

    # Check if a completed analysis already exists for this capture
    from app.db.models.capture import AnalysisRun

    stmt_run = (
        select(AnalysisRun)
        .where(
            AnalysisRun.capture_id == capture.id,
            AnalysisRun.status == "COMPLETED",
            AnalysisRun.is_archived == False,
        )
        .order_by(AnalysisRun.created_at.desc())
    )
    existing_run = (await db.execute(stmt_run)).scalars().first()
    already_analyzed = (existing_run is not None and not force_rerun)

    return CaptureResponseDTO(
        capture_id=capture.id,
        capture_source=capture.capture_source,
        capture_format=capture.capture_format,
        original_filename=capture.original_filename,
        file_size_bytes=capture.file_size_bytes,
        sha256=capture.sha256_hash,
        packet_count=capture.packet_count,
        duration_sec=capture.duration_sec,
        first_packet_at=capture.first_packet_at,
        last_packet_at=capture.last_packet_at,
        link_layer_type=capture.link_layer_type,
        validation_state=capture.validation_state,
        already_analyzed=already_analyzed,
        existing_analysis_id=existing_run.id if existing_run else None,
        existing_run_status=existing_run.status if existing_run else None,
        existing_pipeline_version=getattr(existing_run, "pipeline_version", None) if existing_run else None,
        created_at=capture.created_at,
    )


@router.get(
    "",
    response_model=list[CaptureResponseDTO],
    summary="List recently ingested capture records",
)
@router.get(
    "/",
    response_model=list[CaptureResponseDTO],
    summary="List recently ingested capture records [trailing slash]",
)
async def list_captures(
    db: AsyncSession = Depends(get_db_session),
) -> list[CaptureResponseDTO]:
    """Retrieve catalog of ingested packet captures ordered newest first."""
    res = await db.execute(select(Capture).order_by(Capture.created_at.desc()).limit(50))
    captures = res.scalars().all()
    return [
        CaptureResponseDTO(
            capture_id=c.id,
            capture_source=c.capture_source,
            capture_format=c.capture_format,
            original_filename=c.original_filename,
            file_size_bytes=c.file_size_bytes,
            sha256=c.sha256_hash,
            packet_count=c.packet_count,
            duration_sec=c.duration_sec,
            first_packet_at=c.first_packet_at,
            last_packet_at=c.last_packet_at,
            link_layer_type=c.link_layer_type,
            validation_state=c.validation_state,
            created_at=c.created_at,
        )
        for c in captures
    ]


@router.get(
    "/{capture_id}",
    response_model=CaptureResponseDTO,
    summary="Retrieve capture metadata by UUID",
)
async def get_capture(
    capture_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> CaptureResponseDTO:
    """Retrieve verified metadata and provenance for an ingested capture."""
    res = await db.execute(select(Capture).where(Capture.id == capture_id))
    capture = res.scalar_one_or_none()
    if not capture:
        raise CaptureNotFoundError(str(capture_id))

    return CaptureResponseDTO(
        capture_id=capture.id,
        capture_source=capture.capture_source,
        capture_format=capture.capture_format,
        original_filename=capture.original_filename,
        file_size_bytes=capture.file_size_bytes,
        sha256=capture.sha256_hash,
        packet_count=capture.packet_count,
        duration_sec=capture.duration_sec,
        first_packet_at=capture.first_packet_at,
        last_packet_at=capture.last_packet_at,
        link_layer_type=capture.link_layer_type,
        validation_state=capture.validation_state,
        created_at=capture.created_at,
    )
