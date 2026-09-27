"""Reporting orchestration service managing report lifecycle, storage, and persistence."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.capture import AnalysisRun
from app.db.models.report import ReportModel
from app.reporting.engine import ReportGeneratorEngine
from app.reporting.snapshot import AnalysisSnapshotBuilder
from app.services.storage import get_storage_provider
from app.services.storage.base import StorageProvider

logger = logging.getLogger(__name__)


class ReportingService:
    """Orchestrates report generation, database records, and artifact streaming."""

    def __init__(
        self,
        db: AsyncSession,
        storage: StorageProvider | None = None,
        engine: ReportGeneratorEngine | None = None,
    ) -> None:
        self.db = db
        self.storage = storage or get_storage_provider()
        self.engine = engine or ReportGeneratorEngine()
        self.snapshot_builder = AnalysisSnapshotBuilder(db)

    async def create_report(
        self, analysis_id: uuid.UUID, report_type: str = "EXECUTIVE"
    ) -> ReportModel:
        """Build snapshot, render artifacts, persist record, and return populated ReportModel."""
        # 1. Verify AnalysisRun existence
        stmt_run = select(AnalysisRun).where(AnalysisRun.id == analysis_id)
        res_run = await self.db.execute(stmt_run)
        run = res_run.scalar_one_or_none()
        if not run:
            raise ValueError(f"Analysis '{analysis_id}' not found")

        # 2. Build immutable snapshot
        snapshot = await self.snapshot_builder.build_snapshot(analysis_id)

        # 3. Generate artifacts
        res = self.engine.generate_report_artifacts(
            analysis_id=analysis_id,
            report_type=report_type,
            snapshot=snapshot,
            storage=self.storage,
        )

        # 4. Persist in database
        report = ReportModel(
            id=res["report_id"],
            analysis_id=analysis_id,
            report_type=res["report_type"],
            status=res["status"],
            format=res["format"],
            template_version=res["template_version"],
            engine_version=res["engine_version"],
            html_artifact_path=res["html_artifact_path"],
            html_sha256=res["html_sha256"],
            pdf_artifact_path=res["pdf_artifact_path"],
            pdf_sha256=res["pdf_sha256"],
            snapshot_manifest_sha256=res["snapshot_manifest_sha256"],
            error_message=res["error_message"],
            generation_duration_ms=res["generation_duration_ms"],
            metadata_json={"capture_sha256": snapshot["capture"]["sha256"]},
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        self.db.add(report)
        await self.db.commit()
        await self.db.refresh(report)

        logger.info(
            f"Successfully generated {report.report_type} report '{report.id}' for analysis '{analysis_id}' in {report.generation_duration_ms}ms"
        )
        return report

    async def get_report(self, report_id: uuid.UUID) -> ReportModel | None:
        """Fetch report record by ID."""
        stmt = select(ReportModel).where(ReportModel.id == report_id)
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    def _read_artifact_bytes(self, rel_path: str) -> bytes | None:
        """Safely read artifact bytes from configured storage provider or candidate workspace storage roots."""
        if not rel_path:
            return None
        if self.storage.exists(rel_path):
            try:
                return self.storage.read_file(rel_path)
            except Exception:
                pass
        import os
        from pathlib import Path
        clean_rel = rel_path.replace("\\", "/").lstrip("/")
        candidate_roots = [
            Path("storage"),
            Path("backend/storage"),
            Path(__file__).resolve().parent.parent.parent.parent / "storage",
            Path(__file__).resolve().parent.parent.parent / "storage",
        ]
        for root in candidate_roots:
            candidate = root / clean_rel
            if candidate.is_file():
                try:
                    return candidate.read_bytes()
                except Exception:
                    pass
        return None

    def check_report_integrity(self, report: ReportModel) -> tuple[str, str | None]:
        """Verify on-disk report artifact SHA-256 against recorded database digest.

        Returns:
            tuple[str, str | None]: (integrity_status, actual_sha256)
            integrity_status: "VERIFIED" | "HASH_MISMATCH" | "FILE_NOT_FOUND" | "UNAVAILABLE"
        """
        if not report.html_artifact_path:
            return "UNAVAILABLE", None
        content = self._read_artifact_bytes(report.html_artifact_path)
        if content is None:
            return "FILE_NOT_FOUND", None
        try:
            actual_sha = hashlib.sha256(content).hexdigest()
            if report.html_sha256 and actual_sha.lower() == report.html_sha256.lower():
                return "VERIFIED", actual_sha
            return "HASH_MISMATCH", actual_sha
        except Exception:
            return "UNAVAILABLE", None

    async def list_reports(self, analysis_id: uuid.UUID) -> list[ReportModel]:
        """List all generated reports for an analysis run, ordered newest first."""
        stmt = (
            select(ReportModel)
            .where(ReportModel.analysis_id == analysis_id)
            .order_by(ReportModel.created_at.desc())
        )
        res = await self.db.execute(stmt)
        return list(res.scalars().all())

    async def get_report_html(self, report_id: uuid.UUID) -> str:
        """Retrieve the raw HTML string of a generated report artifact."""
        report = await self.get_report(report_id)
        if not report or not report.html_artifact_path:
            raise ValueError(f"Report '{report_id}' HTML artifact not found")

        raw_bytes = self._read_artifact_bytes(report.html_artifact_path)
        if raw_bytes is None:
            raise ValueError(f"Report '{report_id}' file not found on disk")
        return raw_bytes.decode("utf-8")

    async def get_report_bytes(
        self, report_id: uuid.UUID, requested_format: str = "pdf"
    ) -> tuple[bytes, str, str]:
        """Retrieve binary bytes, media type, and suggested filename for download."""
        report = await self.get_report(report_id)
        if not report:
            raise ValueError(f"Report '{report_id}' not found")

        clean_format = requested_format.lower()
        if clean_format == "pdf":
            if report.pdf_artifact_path:
                data = self._read_artifact_bytes(report.pdf_artifact_path)
                if data:
                    media_type = "application/pdf"
                    filename = f"TunnelTrace_Report_{report.report_type.lower()}_{str(report.id)[:8]}.pdf"
                    return data, media_type, filename

            # On-the-fly generation if PDF artifact was not rendered at creation time
            try:
                from app.reporting.pdf import build_report_pdf
                snapshot = await self.snapshot_builder.build_snapshot(report.analysis_id)
                pdf_bytes = build_report_pdf(report.report_type, snapshot)
                rel_pdf_path = f"reports/{report.analysis_id}/{report.id}_{report.report_type.lower()}.pdf"
                self.storage.save_file(rel_pdf_path, pdf_bytes)
                report.pdf_artifact_path = rel_pdf_path
                report.pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
                if report.status == "PDF_FAILED_HTML_AVAILABLE":
                    report.status = "COMPLETED"
                    report.format = "BOTH"
                await self.db.commit()
                return pdf_bytes, "application/pdf", f"TunnelTrace_Report_{report.report_type.lower()}_{str(report.id)[:8]}.pdf"
            except Exception as e:
                logger.warning(f"On-the-fly PDF generation fallback failed: {e}")

        if report.html_artifact_path:
            data = self._read_artifact_bytes(report.html_artifact_path)
            if data:
                media_type = "text/html; charset=utf-8"
                filename = f"TunnelTrace_Report_{report.report_type.lower()}_{str(report.id)[:8]}.html"
                return data, media_type, filename

        raise FileNotFoundError(f"Requested artifact format '{requested_format}' unavailable for report '{report_id}'")
