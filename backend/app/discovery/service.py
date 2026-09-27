"""Discovery service orchestrating validation, execution, XML parsing, and persistence with AsyncSession."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.db.models.discovery import DiscoveredHost, DiscoveredService, DiscoveryJob
from app.discovery.parser import NmapParseError, parse_nmap_xml
from app.discovery.profiles import DiscoveryProfile
from app.discovery.runner import run_discovery_scan
from app.discovery.validator import (
    AuthorizationError,
    ScopeValidationError,
    validate_scope_request,
)


class DiscoveryService:
    @staticmethod
    async def create_and_execute_job(
        db: AsyncSession,
        *,
        job_name: str,
        operator_id: str,
        authorization_reference: str,
        authorization_attestation: str,
        profile: str,
        requested_targets: list[str],
        exclusions: list[str] | None = None,
        permitted_ports: list[int] | None = None,
        mock_runner: Any = None,
        simulate_demo: bool = False,
    ) -> DiscoveryJob:
        """Validate request scope, persist initial job, execute bounded scan, and record evidence."""
        # 1. Scope validation
        validated_scope = validate_scope_request(
            operator_id=operator_id,
            authorization_reference=authorization_reference,
            authorization_attestation=authorization_attestation,
            profile_name=profile,
            requested_targets=requested_targets,
            exclusions=exclusions,
            permitted_ports=permitted_ports,
        )

        # 2. Persist job in RUNNING state
        job = DiscoveryJob(
            id=uuid.uuid4(),
            job_name=job_name.strip() or f"Scan-{validated_scope.profile.value}",
            operator_id=validated_scope.operator_id,
            authorization_reference=validated_scope.authorization_reference,
            authorization_attestation=validated_scope.authorization_attestation,
            authorized_at=validated_scope.authorized_at,
            profile=validated_scope.profile.value,
            requested_targets=validated_scope.requested_targets,
            canonical_targets=validated_scope.canonical_targets,
            exclusions=validated_scope.exclusions,
            permitted_ports=validated_scope.permitted_ports,
            status="RUNNING",
            target_count=validated_scope.target_count,
            started_at=datetime.now(timezone.utc),
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)

        # 3. Subprocess execution in worker thread to prevent blocking event loop
        if mock_runner is None and simulate_demo:
            target_ip = validated_scope.canonical_targets[0] if validated_scope.canonical_targets else "127.0.0.1"
            from app.discovery.runner import DemoSimulatedRunner
            mock_runner = DemoSimulatedRunner(target_ip=target_ip)

        exec_result = await asyncio.to_thread(
            run_discovery_scan,
            job_id=job.id,
            scope=validated_scope,
            mock_runner=mock_runner,
        )

        job.tool_version = exec_result.tool_version
        job.output_bytes_count = exec_result.output_bytes_count
        job.raw_output_sha256 = exec_result.output_sha256
        job.completed_at = datetime.now(timezone.utc)

        if exec_result.status == "TOOL_UNAVAILABLE":
            job.status = "TOOL_UNAVAILABLE"
            job.failure_reason = exec_result.diagnostic_message
            await db.commit()
            await db.refresh(job)
            return job

        if exec_result.status in ("FAILED", "CANCELLED"):
            job.status = exec_result.status
            job.failure_reason = exec_result.diagnostic_message
            await db.commit()
            await db.refresh(job)
            return job

        # 4. Parse Nmap machine-readable XML
        if not exec_result.raw_xml_content:
            job.status = "FAILED"
            job.failure_reason = "Nmap completed with zero XML output content."
            await db.commit()
            await db.refresh(job)
            return job

        try:
            parsed_result = parse_nmap_xml(exec_result.raw_xml_content)
        except NmapParseError as e:
            job.status = "FAILED"
            job.failure_reason = f"XML Parsing Error: {e}"
            await db.commit()
            await db.refresh(job)
            return job

        # 5. Persist host and service evidence
        job.hosts_up_count = parsed_result.hosts_up_count
        job.services_discovered_count = parsed_result.services_discovered_count
        job.status = "COMPLETED_WITH_AMBIGUITY" if parsed_result.has_ambiguity else "COMPLETED"

        for h in parsed_result.hosts:
            host_row = DiscoveredHost(
                id=uuid.uuid4(),
                job_id=job.id,
                ip_address=h.ip_address,
                ip_version=h.ip_version,
                state=h.state,
                hostnames=h.hostnames,
            )
            db.add(host_row)
            await db.flush()

            for s in h.services:
                svc_row = DiscoveredService(
                    id=uuid.uuid4(),
                    job_id=job.id,
                    host_id=host_row.id,
                    protocol=s.protocol,
                    port=s.port,
                    state=s.state,
                    state_reason=s.state_reason,
                    service_name=s.service_name,
                    product=s.product,
                    version=s.version,
                    extra_info=s.extra_info,
                    confidence=s.confidence,
                    fingerprint=s.fingerprint,
                )
                db.add(svc_row)

        await db.commit()
        await db.refresh(job)
        return job

    @staticmethod
    async def get_job(db: AsyncSession, job_id: uuid.UUID) -> DiscoveryJob | None:
        """Fetch discovery job with nested hosts and services."""
        stmt = (
            select(DiscoveryJob)
            .where(DiscoveryJob.id == job_id)
            .options(
                selectinload(DiscoveryJob.hosts).selectinload(DiscoveredHost.services),
                selectinload(DiscoveryJob.services),
            )
        )
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @staticmethod
    async def list_jobs(db: AsyncSession, operator_id: str | None = None, limit: int = 50) -> list[DiscoveryJob]:
        """List discovery jobs, optionally filtered by operator."""
        stmt = (
            select(DiscoveryJob)
            .order_by(DiscoveryJob.created_at.desc())
            .options(
                selectinload(DiscoveryJob.hosts).selectinload(DiscoveredHost.services),
                selectinload(DiscoveryJob.services),
            )
            .limit(limit)
        )
        if operator_id:
            stmt = stmt.where(DiscoveryJob.operator_id == operator_id)
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @staticmethod
    async def cancel_job(db: AsyncSession, job_id: uuid.UUID) -> DiscoveryJob | None:
        """Mark an in-flight job as cancelled."""
        job = await db.get(DiscoveryJob, job_id)
        if not job:
            return None
        if job.status in ("QUEUED", "VALIDATING", "RUNNING"):
            job.status = "CANCELLED"
            job.failure_reason = "Cancelled by operator request."
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(job)
        return job
