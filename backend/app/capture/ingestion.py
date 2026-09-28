"""Secure streaming packet capture ingestion, hashing, and storage management."""

import hashlib
import logging
import os
import re
import uuid
from datetime import datetime, timezone

from fastapi import UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.capture.metadata import extract_capture_metadata
from app.capture.validation import (
    PCAP_GLOBAL_HEADER_LEN,
    CaptureFormat,
    validate_capture_header,
)
from app.core.config import get_settings
from app.core.errors import CaptureValidationError
from app.db.models.capture import Capture
from app.services.storage import get_storage_provider

logger = logging.getLogger(__name__)

# Sanitization regex for display filename (strips directory traversal, null bytes, dangerous chars)
SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9_\-\.]")


def sanitize_filename(filename: str | None) -> str:
    """Sanitize user-provided filename strictly for display/audit metadata.

    Never used for internal storage paths.
    """
    if not filename or not filename.strip():
        return "unnamed_capture.pcap"
    base = os.path.basename(filename.replace("\\", "/"))
    clean = SAFE_FILENAME_RE.sub("_", base).strip("._")
    if not clean:
        return "unnamed_capture.pcap"
    return clean[:200]


class CaptureIngestionService:
    """Handles secure streaming upload, validation, hashing, and registration of packet captures."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.settings = get_settings()
        self.storage = get_storage_provider()

    async def ingest_upload(
        self,
        upload_file: UploadFile,
        capture_source: str = "OFFLINE_UPLOAD",
    ) -> Capture:
        """Stream an uploaded capture file into temporary storage, validate, hash, and persist immutably.

        Args:
            upload_file: FastAPI multipart UploadFile.
            capture_source: Source descriptor (e.g. OFFLINE_UPLOAD, TESTBED_GENERATED).

        Returns:
            Durable registered Capture database model instance.

        Raises:
            CaptureValidationError: If file violates format, header, or size boundaries.
            StorageError: If storage operations fail.
        """
        capture_id = uuid.uuid4()
        temp_dir = self.storage.root_path / "tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_path = temp_dir / f"upload_{capture_id.hex}.tmp"

        sha256 = hashlib.sha256()
        total_bytes = 0
        header_buffer = bytearray()
        max_bytes = self.settings.CAPTURE_MAX_UPLOAD_BYTES
        chunk_size = 64 * 1024  # 64 KB chunks for memory-bounded streaming

        sanitized_name = sanitize_filename(upload_file.filename)

        try:
            with open(temp_path, "wb") as f_out:
                while True:
                    chunk = await upload_file.read(chunk_size)
                    if not chunk:
                        break

                    total_bytes += len(chunk)
                    if total_bytes > max_bytes:
                        raise CaptureValidationError(
                            f"Capture file exceeds maximum allowed safety limit ({max_bytes} bytes).",
                            code="CAPTURE_TOO_LARGE",
                            details={"size_bytes": total_bytes, "limit_bytes": max_bytes},
                        )

                    sha256.update(chunk)
                    f_out.write(chunk)

                    # Collect leading bytes for header validation
                    if len(header_buffer) < PCAP_GLOBAL_HEADER_LEN:
                        needed = PCAP_GLOBAL_HEADER_LEN - len(header_buffer)
                        header_buffer.extend(chunk[:needed])

            # Validation 1: Check empty file
            if total_bytes == 0:
                raise CaptureValidationError(
                    "Uploaded capture file is empty (0 bytes).", code="CAPTURE_EMPTY"
                )

            # Validation 2: Check magic header and format
            fmt, _ = validate_capture_header(bytes(header_buffer))

            # Validation 3: Structural metadata extraction via Capinfos
            metadata = extract_capture_metadata(temp_path)

            # Prepare canonical immutable destination path
            # Hierarchy: storage/captures/<capture_id>/raw.pcap[ng]
            ext = ".pcapng" if fmt == CaptureFormat.PCAPNG else ".pcap"
            rel_dir = f"captures/{capture_id}"
            rel_path = f"{rel_dir}/raw{ext}"
            final_path = self.storage.resolve_safe_path(rel_path)
            final_path.parent.mkdir(parents=True, exist_ok=True)

            sha256_digest = sha256.hexdigest().lower()

            # Check for existing capture with identical SHA-256
            from sqlalchemy import select
            stmt_exist = select(Capture).where(Capture.sha256_hash == sha256_digest).order_by(Capture.created_at.asc())
            res_exist = await self.db.execute(stmt_exist)
            existing_cap = res_exist.scalars().first()

            if existing_cap is not None:
                if temp_path.exists():
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
                logger.info(
                    f"Capture with SHA-256 '{sha256_digest[:16]}...' already registered as '{existing_cap.id}'"
                )
                return existing_cap

            # Atomic promotion from temp to immutable storage
            os.replace(temp_path, final_path)

            # Create and persist database record
            capture_record = Capture(
                id=capture_id,
                capture_source=capture_source,
                capture_format=fmt.value,
                original_filename=sanitized_name,
                storage_path=rel_path,
                file_size_bytes=total_bytes,
                sha256_hash=sha256_digest,
                packet_count=metadata.packet_count,
                first_packet_at=metadata.first_packet_at,
                last_packet_at=metadata.last_packet_at,
                duration_sec=metadata.duration_sec,
                link_layer_type=metadata.link_layer_type,
                interface_metadata=metadata.interface_metadata,
                validation_state="VALIDATED",
                created_at=datetime.now(timezone.utc),
            )

            self.db.add(capture_record)
            await self.db.commit()
            await self.db.refresh(capture_record)

            logger.info(
                f"Successfully ingested capture '{capture_id}' ({fmt.value}, {total_bytes} bytes, "
                f"SHA-256: {sha256_digest[:16]}...)"
            )
            return capture_record

        except Exception:
            # Clean up temp file on failure to prevent disk leakage
            if temp_path.exists():
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise
