"""Deterministic server-side report generator engine using Jinja2 and WeasyPrint."""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from pathlib import Path
from typing import Any

import jinja2

from app.services.storage.base import StorageProvider

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


class ReportGeneratorEngine:
    """Renders deterministic Executive and Technical reports from immutable analysis snapshots."""

    def __init__(self, templates_dir: Path | None = None) -> None:
        self.templates_dir = templates_dir or TEMPLATES_DIR
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.templates_dir)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
            undefined=jinja2.StrictUndefined,
        )
        self._css_cache: str | None = None

    def _get_css_content(self) -> str:
        """Read and cache report.css stylesheet."""
        if self._css_cache is None:
            css_path = self.templates_dir / "report.css"
            if css_path.exists():
                self._css_cache = css_path.read_text(encoding="utf-8")
            else:
                self._css_cache = ""
        return self._css_cache

    def render_html(self, report_type: str, snapshot: dict[str, Any]) -> str:
        """Render standalone, self-contained HTML document for the specified report type."""
        template_name = "executive.html" if report_type.upper() == "EXECUTIVE" else "technical.html"
        template = self.jinja_env.get_template(template_name)
        css_content = self._get_css_content()

        return template.render(
            snapshot=snapshot,
            css_content=css_content,
        )

    def render_pdf(
        self,
        report_type: str,
        snapshot: dict[str, Any],
        html_content: str | None = None,
    ) -> tuple[bytes | None, str | None]:
        """Render deterministic server-side PDF report via ReportLab with WeasyPrint fallback."""
        try:
            from app.reporting.pdf import build_report_pdf

            pdf_bytes = build_report_pdf(report_type, snapshot)
            return pdf_bytes, None
        except Exception as exc:
            logger.warning(f"ReportLab PDF generation failed: {exc}. Attempting WeasyPrint fallback...")
            try:
                import weasyprint

                if html_content:
                    pdf_bytes = weasyprint.HTML(string=html_content).write_pdf()
                    return pdf_bytes, None
            except ImportError:
                pass
            except Exception as w_exc:
                logger.warning(f"WeasyPrint fallback also failed: {w_exc}")

            msg = f"PDF rendering error: {exc}"
            return None, msg

    def generate_report_artifacts(
        self,
        analysis_id: uuid.UUID,
        report_type: str,
        snapshot: dict[str, Any],
        storage: StorageProvider,
    ) -> dict[str, Any]:
        """Generate and persist report artifacts (HTML + optional PDF) into the storage provider."""
        start_time = time.perf_counter()
        report_id = uuid.uuid4()
        sanitized_type = report_type.lower()

        # 1. Render Canonical HTML
        html_content = self.render_html(report_type, snapshot)
        html_bytes = html_content.encode("utf-8")
        html_sha256 = hashlib.sha256(html_bytes).hexdigest()

        rel_html_path = f"reports/{analysis_id}/{report_id}_{sanitized_type}.html"
        storage.save_file(rel_html_path, html_bytes)

        # 2. Render PDF with Graceful Fallback
        pdf_bytes, pdf_err = self.render_pdf(report_type, snapshot, html_content=html_content)
        rel_pdf_path = None
        pdf_sha256 = None
        status = "COMPLETED"

        if pdf_bytes:
            rel_pdf_path = f"reports/{analysis_id}/{report_id}_{sanitized_type}.pdf"
            storage.save_file(rel_pdf_path, pdf_bytes)
            pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
        else:
            status = "PDF_FAILED_HTML_AVAILABLE" if pdf_err else "COMPLETED"

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "report_id": report_id,
            "analysis_id": analysis_id,
            "report_type": report_type.upper(),
            "status": status,
            "format": "BOTH" if pdf_bytes else "HTML",
            "template_version": "1.0.0",
            "engine_version": "1.0.0",
            "html_artifact_path": rel_html_path,
            "html_sha256": html_sha256,
            "pdf_artifact_path": rel_pdf_path,
            "pdf_sha256": pdf_sha256,
            "snapshot_manifest_sha256": snapshot.get("snapshot_sha256"),
            "generation_duration_ms": duration_ms,
            "error_message": pdf_err,
        }
