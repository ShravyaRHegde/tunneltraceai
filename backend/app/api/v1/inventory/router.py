"""REST API router for Configuration and Certificate Inventory."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.inventory.certificate_parser import CertificateParseError, CertificateSecurityViolation
from app.inventory.schemas import (
    BaselineDesignateRequest,
    CertificateImportRequest,
    CertificateResponse,
    ConfigurationDriftResponse,
    ConfigurationImportRequest,
    ConfigurationSnapshotResponse,
    DriftCompareRequest,
    GatewayInventorySummaryResponse,
)
from app.inventory.service import InventoryService
from app.inventory.strongswan_parser import ConfigurationParseError

router = APIRouter(prefix="", tags=["Configuration & Certificate Inventory"])


@router.post(
    "/configurations/import",
    response_model=ConfigurationSnapshotResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Import strongSwan Configuration Snapshot",
    description="Parses, bounds-checks, scrubs secrets, and registers a gateway configuration snapshot.",
)
async def import_configuration(
    request: ConfigurationImportRequest,
    db: AsyncSession = Depends(get_db_session),
) -> ConfigurationSnapshotResponse:
    try:
        snapshot = await InventoryService.import_configuration_snapshot(db, request)
        return ConfigurationSnapshotResponse.model_validate(snapshot, from_attributes=True)
    except ConfigurationParseError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.post(
    "/configurations/{snapshot_id}/baseline",
    response_model=ConfigurationSnapshotResponse,
    summary="Designate Snapshot as Baseline",
    description="Promotes a configuration snapshot to the active baseline for its gateway, demoting previous baselines.",
)
async def designate_baseline(
    snapshot_id: uuid.UUID,
    request: BaselineDesignateRequest,
    db: AsyncSession = Depends(get_db_session),
) -> ConfigurationSnapshotResponse:
    try:
        snapshot = await InventoryService.designate_baseline(db, snapshot_id, request)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    if not snapshot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration snapshot {snapshot_id} not found",
        )
    return ConfigurationSnapshotResponse.model_validate(snapshot, from_attributes=True)


@router.get(
    "/configurations/snapshots",
    response_model=list[ConfigurationSnapshotResponse],
    summary="List Configuration Snapshots",
)
async def list_snapshots(
    gateway_identity: str | None = Query(None, description="Filter by gateway identity"),
    is_baseline: bool | None = Query(None, description="Filter by baseline flag"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db_session),
) -> list[ConfigurationSnapshotResponse]:
    snapshots = await InventoryService.list_snapshots(
        db, gateway_identity=gateway_identity, is_baseline=is_baseline, limit=limit
    )
    return [ConfigurationSnapshotResponse.model_validate(s, from_attributes=True) for s in snapshots]


@router.get(
    "/configurations/snapshots/{snapshot_id}",
    response_model=ConfigurationSnapshotResponse,
    summary="Get Configuration Snapshot by ID",
)
async def get_snapshot(
    snapshot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> ConfigurationSnapshotResponse:
    snapshot = await InventoryService.get_snapshot(db, snapshot_id)
    if not snapshot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration snapshot {snapshot_id} not found",
        )
    return ConfigurationSnapshotResponse.model_validate(snapshot, from_attributes=True)


@router.post(
    "/configurations/drift",
    response_model=ConfigurationDriftResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Evaluate Configuration Drift",
    description="Performs an evidence-based diff between baseline and observed snapshots.",
)
@router.post(
    "/configurations/drift/compare",
    response_model=ConfigurationDriftResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def compute_drift(
    request: DriftCompareRequest,
    db: AsyncSession = Depends(get_db_session),
) -> ConfigurationDriftResponse:
    drift = await InventoryService.compute_drift(db, request)
    if not drift:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or both configuration snapshots could not be found",
        )
    return ConfigurationDriftResponse.model_validate(drift, from_attributes=True)


@router.get(
    "/configurations/drifts",
    response_model=list[ConfigurationDriftResponse],
    summary="List Drift Reports",
)
@router.get(
    "/configurations/drift/history",
    response_model=list[ConfigurationDriftResponse],
    include_in_schema=False,
)
async def list_drifts(
    gateway_identity: str | None = Query(None, description="Filter by gateway identity"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db_session),
) -> list[ConfigurationDriftResponse]:
    drifts = await InventoryService.list_drifts(db, gateway_identity=gateway_identity, limit=limit)
    return [ConfigurationDriftResponse.model_validate(d, from_attributes=True) for d in drifts]


@router.post(
    "/certificates/import",
    response_model=list[CertificateResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Import X.509 Public Certificates",
    description="Parses PEM certificate bundle, evaluates validity, associates IKE identity, and checks chain.",
)
async def import_certificates(
    request: CertificateImportRequest,
    db: AsyncSession = Depends(get_db_session),
) -> list[CertificateResponse]:
    try:
        certs = await InventoryService.import_certificates(db, request)
        return [CertificateResponse.model_validate(c, from_attributes=True) for c in certs]
    except CertificateSecurityViolation as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        ) from e
    except CertificateParseError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e


@router.get(
    "/certificates",
    response_model=list[CertificateResponse],
    summary="List Public Certificates",
)
async def list_certificates(
    gateway_identity: str | None = Query(None),
    validity_status: str | None = Query(None),
    associated_connection: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db_session),
) -> list[CertificateResponse]:
    certs = await InventoryService.list_certificates(
        db,
        gateway_identity=gateway_identity,
        validity_status=validity_status,
        associated_connection=associated_connection,
        limit=limit,
    )
    return [CertificateResponse.model_validate(c, from_attributes=True) for c in certs]


@router.get(
    "/certificates/{certificate_id}",
    response_model=CertificateResponse,
    summary="Get Certificate by ID",
)
async def get_certificate(
    certificate_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> CertificateResponse:
    cert = await InventoryService.get_certificate(db, certificate_id)
    if not cert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Certificate {certificate_id} not found",
        )
    return CertificateResponse.model_validate(cert, from_attributes=True)


@router.get(
    "/gateways/summary",
    response_model=list[GatewayInventorySummaryResponse],
    summary="List Gateway Inventory Summaries",
)
async def get_gateway_summaries(
    db: AsyncSession = Depends(get_db_session),
) -> list[GatewayInventorySummaryResponse]:
    return await InventoryService.get_gateway_summaries(db)
