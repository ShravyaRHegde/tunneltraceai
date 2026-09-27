import io
from pathlib import Path
from typing import Any
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
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
    db: AsyncSession = Depends(get_db_session),
) -> CaptureResponseDTO:
    """Read a verified repository test fixture and ingest it immutably into the analysis pipeline."""
    if sample_id not in SAMPLE_FIXTURES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample fixture '{sample_id}' not found. Available: {list(SAMPLE_FIXTURES.keys())}",
        )
    fix_meta = SAMPLE_FIXTURES[sample_id]
    repo_root = Path(__file__).resolve().parents[5]
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


@router.post(
    "",
    response_model=CaptureResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and ingest a packet capture file (PCAP/PCAPNG)",
)
async def upload_capture(
    file: UploadFile = File(..., description="Binary packet capture file (PCAP or PCAPNG)"),
    db: AsyncSession = Depends(get_db_session),
) -> CaptureResponseDTO:
    """Safely stream, validate, hash, and persist an offline packet capture file."""
    service = CaptureIngestionService(db)
    capture = await service.ingest_upload(file, capture_source="OFFLINE_UPLOAD")

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
