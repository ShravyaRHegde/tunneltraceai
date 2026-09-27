"""Unit & integration tests for Stage 9 reporting REST API endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.v1.reporting.router import get_reporting_service
from app.db.models.report import ReportModel
from app.main import app


class TestReportingAPIEndpoints:
    """Verifies report creation, listing, HTML preview, and download REST endpoints."""

    @pytest.fixture
    def mock_service(self):
        service = MagicMock()
        service.create_report = AsyncMock()
        service.get_report = AsyncMock()
        service.list_reports = AsyncMock()
        service.get_report_html = AsyncMock()
        service.get_report_bytes = AsyncMock()
        service.check_report_integrity = MagicMock(return_value=("VERIFIED", "a" * 64))
        return service

    @pytest.mark.asyncio
    async def test_generate_report_endpoint(self, mock_service) -> None:
        analysis_id = uuid.uuid4()
        report_id = uuid.uuid4()

        mock_report = ReportModel(
            id=report_id,
            analysis_id=analysis_id,
            report_type="EXECUTIVE",
            status="COMPLETED",
            format="HTML",
            template_version="1.0.0",
            engine_version="1.0.0",
            html_artifact_path=f"reports/{analysis_id}/{report_id}_executive.html",
            html_sha256="a" * 64,
            pdf_artifact_path=None,
            pdf_sha256=None,
            snapshot_manifest_sha256="b" * 64,
            generation_duration_ms=45.2,
            error_message=None,
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        mock_service.create_report.return_value = mock_report

        app.dependency_overrides[get_reporting_service] = lambda: mock_service
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as ac:
                res = await ac.post(
                    f"/api/v1/analyses/{analysis_id}/reports",
                    json={"report_type": "EXECUTIVE"},
                )
                assert res.status_code == 201
                data = res.json()
                assert data["id"] == str(report_id)
                assert data["analysis_id"] == str(analysis_id)
                assert data["report_type"] == "EXECUTIVE"
                assert data["status"] == "COMPLETED"
                assert data["html_sha256"] == "a" * 64
        finally:
            app.dependency_overrides.pop(get_reporting_service, None)

    @pytest.mark.asyncio
    async def test_list_reports_endpoint(self, mock_service) -> None:
        analysis_id = uuid.uuid4()
        report_id = uuid.uuid4()

        mock_report = ReportModel(
            id=report_id,
            analysis_id=analysis_id,
            report_type="TECHNICAL",
            status="COMPLETED",
            format="HTML",
            template_version="1.0.0",
            engine_version="1.0.0",
            html_sha256="c" * 64,
            created_at=datetime.now(timezone.utc),
        )
        mock_service.list_reports.return_value = [mock_report]

        app.dependency_overrides[get_reporting_service] = lambda: mock_service
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as ac:
                res = await ac.get(f"/api/v1/analyses/{analysis_id}/reports")
                assert res.status_code == 200
                data = res.json()
                assert data["total_reports"] == 1
                assert data["items"][0]["id"] == str(report_id)
                assert data["items"][0]["report_type"] == "TECHNICAL"
        finally:
            app.dependency_overrides.pop(get_reporting_service, None)

    @pytest.mark.asyncio
    async def test_preview_report_html_endpoint(self, mock_service) -> None:
        analysis_id = uuid.uuid4()
        report_id = uuid.uuid4()

        mock_report = ReportModel(
            id=report_id,
            analysis_id=analysis_id,
            report_type="EXECUTIVE",
            status="COMPLETED",
            format="HTML",
            template_version="1.0.0",
            engine_version="1.0.0",
            html_artifact_path=f"reports/{analysis_id}/{report_id}_executive.html",
            created_at=datetime.now(timezone.utc),
        )
        mock_service.get_report.return_value = mock_report
        mock_service.get_report_html.return_value = "<html><body><h1>Executive Report</h1></body></html>"

        app.dependency_overrides[get_reporting_service] = lambda: mock_service
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as ac:
                res = await ac.get(f"/api/v1/analyses/{analysis_id}/reports/{report_id}/html")
                assert res.status_code == 200
                assert "text/html" in res.headers["content-type"]
                assert "Executive Report" in res.text
                assert "Content-Security-Policy" in res.headers
        finally:
            app.dependency_overrides.pop(get_reporting_service, None)

    @pytest.mark.asyncio
    async def test_download_report_endpoint(self, mock_service) -> None:
        analysis_id = uuid.uuid4()
        report_id = uuid.uuid4()

        mock_report = ReportModel(
            id=report_id,
            analysis_id=analysis_id,
            report_type="EXECUTIVE",
            status="COMPLETED",
            format="HTML",
            template_version="1.0.0",
            engine_version="1.0.0",
            created_at=datetime.now(timezone.utc),
        )
        mock_service.get_report.return_value = mock_report
        mock_service.get_report_bytes.return_value = (
            b"<html>Report Content</html>",
            "text/html; charset=utf-8",
            "TunnelTrace_Report_executive.html",
        )

        app.dependency_overrides[get_reporting_service] = lambda: mock_service
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as ac:
                res = await ac.get(
                    f"/api/v1/analyses/{analysis_id}/reports/{report_id}/download?format=html"
                )
                assert res.status_code == 200
                assert "attachment" in res.headers["content-disposition"]
                assert res.content == b"<html>Report Content</html>"
        finally:
            app.dependency_overrides.pop(get_reporting_service, None)
