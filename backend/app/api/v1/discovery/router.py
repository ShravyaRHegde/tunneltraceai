"""FastAPI Router for Stage 2 Authorized Asset Discovery."""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.discovery.schemas import (
    DiscoveryJobCreateRequest,
    DiscoveryJobResponse,
    DiscoveryStatusResponse,
)
from app.core.config import settings
from app.db.session import get_db_session
from app.discovery.profiles import SCAN_PROFILES
from app.discovery.runner import detect_nmap_binary
from app.discovery.service import DiscoveryService
from app.discovery.validator import AuthorizationError, ScopeValidationError

router = APIRouter(prefix="/discovery", tags=["Authorized Asset Discovery"])


@router.get(
    "/status",
    response_model=DiscoveryStatusResponse,
    summary="Check discovery subsystem status and limits",
)
async def get_discovery_status() -> DiscoveryStatusResponse:
    """Retrieve operational status, limits, and tool availability for discovery subsystem."""
    binary_info = detect_nmap_binary()
    profiles_meta = [
        {"name": p.name.value, "description": p.description, "protocol": p.default_protocol}
        for p in SCAN_PROFILES.values()
    ]

    return DiscoveryStatusResponse(
        enabled=settings.DISCOVERY_ENABLED,
        nmap_available=binary_info.is_available,
        nmap_version=binary_info.version,
        nmap_path=binary_info.path,
        max_targets=settings.DISCOVERY_MAX_TARGETS,
        max_ports=settings.DISCOVERY_MAX_PORTS,
        timeout_sec=settings.DISCOVERY_TIMEOUT_SEC,
        rate_limit_pps=settings.DISCOVERY_RATE_LIMIT_PPS,
        available_profiles=profiles_meta,
    )


@router.post(
    "/jobs",
    response_model=DiscoveryJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create and execute an authorized asset discovery scan",
)
async def create_discovery_job(
    request: DiscoveryJobCreateRequest,
    db: AsyncSession = Depends(get_db_session),
) -> DiscoveryJobResponse:
    """Submit an authorized, strictly bounded target scope for discovery.

    Requires:
    - Explicit operator ID and authorization reference
    - Explicit attestation statement
    - Strictly bounded targets and ports within hard caps
    """
    try:
        job = await DiscoveryService.create_and_execute_job(
            db,
            job_name=request.job_name,
            operator_id=request.operator_id,
            authorization_reference=request.authorization_reference,
            authorization_attestation=request.authorization_attestation,
            profile=request.profile,
            requested_targets=request.requested_targets,
            exclusions=request.exclusions,
            permitted_ports=request.permitted_ports,
            simulate_demo=request.simulate_demo,
        )
        job_full = await DiscoveryService.get_job(db, job.id)
        return DiscoveryJobResponse.model_validate(job_full or job)
    except AuthorizationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Authorization Rejected: {str(e)}",
        )
    except ScopeValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Target Scope Validation Failed: {str(e)}",
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Discovery job execution failure: {str(e)}",
        )


@router.get(
    "/jobs",
    response_model=list[DiscoveryJobResponse],
    summary="List discovery jobs",
)
async def list_discovery_jobs(
    operator_id: str | None = Query(default=None, description="Filter by operator ID"),
    limit: int = Query(default=50, ge=1, le=100),
    db: AsyncSession = Depends(get_db_session),
) -> list[DiscoveryJobResponse]:
    """Retrieve history of discovery scans."""
    jobs = await DiscoveryService.list_jobs(db, operator_id=operator_id, limit=limit)
    return [DiscoveryJobResponse.model_validate(j) for j in jobs]


@router.get(
    "/jobs/{job_id}",
    response_model=DiscoveryJobResponse,
    summary="Get discovery job details and normalized evidence",
)
async def get_discovery_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> DiscoveryJobResponse:
    """Retrieve full details, host observations, and service evidence for a discovery scan."""
    job = await DiscoveryService.get_job(db, job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Discovery job {job_id} not found",
        )
    return DiscoveryJobResponse.model_validate(job)


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=DiscoveryJobResponse,
    summary="Cancel an active discovery job",
)
async def cancel_discovery_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> DiscoveryJobResponse:
    """Request immediate cancellation of a running or queued discovery job."""
    job = await DiscoveryService.cancel_job(db, job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Discovery job {job_id} not found",
        )
    job_full = await DiscoveryService.get_job(db, job.id)
    return DiscoveryJobResponse.model_validate(job_full or job)
