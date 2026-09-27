"""REST API router for Stage 9 report generation, status, preview, and download."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.reporting.schemas import (
    CreateReportRequestDTO,
    ReportListResponseDTO,
    ReportResponseDTO,
)
from app.db.session import get_db_session
from app.reporting.service import ReportingService

router = APIRouter(prefix="/analyses/{analysis_id}/reports", tags=["Reporting"])


def get_reporting_service(db: AsyncSession = Depends(get_db_session)) -> ReportingService:
    """Dependency provider for ReportingService."""
    return ReportingService(db=db)


@router.post(
    "",
    response_model=ReportResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a publication-grade Executive or Technical report",
)
@router.post(
    "/generate",
    response_model=ReportResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a publication-grade Executive or Technical report (alias)",
)
async def generate_report(
    analysis_id: uuid.UUID,
    req: CreateReportRequestDTO,
    service: ReportingService = Depends(get_reporting_service),
) -> ReportResponseDTO:
    """Generate an immutable, deterministic report from the current analysis evidence snapshot."""
    try:
        report = await service.create_report(analysis_id, req.report_type)
        return ReportResponseDTO(
            id=report.id,
            analysis_id=report.analysis_id,
            report_type=report.report_type,
            status=report.status,
            format=report.format,
            template_version=report.template_version,
            engine_version=report.engine_version,
            html_sha256=report.html_sha256,
            pdf_sha256=report.pdf_sha256,
            snapshot_manifest_sha256=report.snapshot_manifest_sha256,
            generation_duration_ms=report.generation_duration_ms,
            created_at=report.created_at,
            completed_at=report.completed_at,
            error_message=report.error_message,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {exc}",
        ) from exc


def _safe_check_integrity(service: Any, report: Any) -> tuple[str, str | None]:
    if hasattr(service, "check_report_integrity"):
        try:
            res = service.check_report_integrity(report)
            if isinstance(res, (tuple, list)) and len(res) == 2:
                return str(res[0]), res[1]
        except Exception:
            pass
    return "UNKNOWN", None


@router.get(
    "",
    response_model=ReportListResponseDTO,
    summary="List all generated reports for an analysis run",
)
async def list_reports(
    analysis_id: uuid.UUID,
    service: ReportingService = Depends(get_reporting_service),
) -> ReportListResponseDTO:
    """Retrieve history of all generated report artifacts for the specified analysis run."""
    reports = await service.list_reports(analysis_id)
    items = []
    for r in reports:
        integ_status, actual_sha = _safe_check_integrity(service, r)
        items.append(
            ReportResponseDTO(
                id=r.id,
                analysis_id=r.analysis_id,
                report_type=r.report_type,
                status=r.status,
                format=r.format,
                template_version=r.template_version,
                engine_version=r.engine_version,
                html_sha256=r.html_sha256,
                pdf_sha256=r.pdf_sha256,
                snapshot_manifest_sha256=r.snapshot_manifest_sha256,
                generation_duration_ms=r.generation_duration_ms,
                created_at=r.created_at,
                completed_at=r.completed_at,
                error_message=r.error_message,
                artifact_integrity_status=integ_status,
                actual_html_sha256=actual_sha,
            )
        )
    return ReportListResponseDTO(
        analysis_id=analysis_id,
        total_reports=len(items),
        items=items,
    )


@router.get(
    "/{report_id}",
    response_model=ReportResponseDTO,
    summary="Get report metadata and artifact status",
)
async def get_report_metadata(
    analysis_id: uuid.UUID,
    report_id: uuid.UUID,
    service: ReportingService = Depends(get_reporting_service),
) -> ReportResponseDTO:
    """Retrieve metadata, SHA-256 digests, and generation status for a specific report."""
    report = await service.get_report(report_id)
    if not report or report.analysis_id != analysis_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found for analysis '{analysis_id}'",
        )
    integ_status, actual_sha = _safe_check_integrity(service, report)
    return ReportResponseDTO(
        id=report.id,
        analysis_id=report.analysis_id,
        report_type=report.report_type,
        status=report.status,
        format=report.format,
        template_version=report.template_version,
        engine_version=report.engine_version,
        html_sha256=report.html_sha256,
        pdf_sha256=report.pdf_sha256,
        snapshot_manifest_sha256=report.snapshot_manifest_sha256,
        generation_duration_ms=report.generation_duration_ms,
        created_at=report.created_at,
        completed_at=report.completed_at,
        error_message=report.error_message,
        artifact_integrity_status=integ_status,
        actual_html_sha256=actual_sha,
    )


@router.get(
    "/{report_id}/html",
    response_class=HTMLResponse,
    summary="Preview raw generated HTML report in browser",
)
async def preview_report_html(
    analysis_id: uuid.UUID,
    report_id: uuid.UUID,
    service: ReportingService = Depends(get_reporting_service),
) -> HTMLResponse:
    """Preview the standalone, sealed HTML report artifact."""
    report = await service.get_report(report_id)
    if not report or report.analysis_id != analysis_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found",
        )
    try:
        html = await service.get_report_html(report_id)
        return HTMLResponse(
            content=html,
            headers={
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline';",
                "X-Content-Type-Options": "nosniff",
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get(
    "/{report_id}/download",
    summary="Download report artifact (PDF or HTML)",
)
async def download_report_artifact(
    analysis_id: uuid.UUID,
    report_id: uuid.UUID,
    format: str = Query("pdf", description="Requested format: 'pdf' or 'html'"),
    service: ReportingService = Depends(get_reporting_service),
) -> Response:
    """Download the requested report artifact with safe filename and headers."""
    report = await service.get_report(report_id)
    if not report or report.analysis_id != analysis_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found",
        )
    try:
        data, media_type, filename = await service.get_report_bytes(report_id, format)
        return Response(
            content=data,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Artifact download error: {exc}",
        ) from exc
