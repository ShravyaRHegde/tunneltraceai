"""REST and WebSocket API endpoints for Continuous Monitoring."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db_session
from app.monitoring.auth import verify_sensor_credential
from app.monitoring.schema import (
    EventKind,
    GatewayResponse,
    MonitoredSAStateDTO,
    MonitoringEventBatchRequest,
    MonitoringEventBatchResponse,
    MonitoringTimelineFilter,
    RegisterGatewayRequest,
    RegisterSensorRequest,
    RegisterSensorResponse,
    SensorHealthDTO,
    SensorResponse,
)
from app.monitoring.service import MonitoringService
from app.monitoring.websocket import monitoring_ws_manager

logger = logging.getLogger("tunneltrace.api.monitoring")

router = APIRouter(prefix="/monitoring", tags=["Continuous Monitoring"])


# ------------------------------------------------------------------------------
# Gateway Endpoints
# ------------------------------------------------------------------------------


@router.post(
    "/gateways",
    response_model=GatewayResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register an authorized VPN gateway boundary",
)
async def register_gateway(
    req: RegisterGatewayRequest,
    db: AsyncSession = Depends(get_db_session),
) -> GatewayResponse:
    """Registers an authorized gateway boundary monitored by TunnelTrace AI."""
    if not settings.MONITORING_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Continuous Monitoring subsystem is disabled in configuration.",
        )
    try:
        gw = await MonitoringService.register_gateway(db, req)
        return GatewayResponse(
            id=gw.id,
            name=gw.name,
            gateway_ip=gw.gateway_ip,
            authorized_scope=gw.authorized_scope,
            operator_id=gw.operator_id,
            authorization_reference=gw.authorization_reference,
            status=gw.status,
            created_at=gw.created_at,
            updated_at=gw.updated_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/gateways",
    response_model=list[GatewayResponse],
    summary="List all registered monitored gateways",
)
async def list_gateways(
    db: AsyncSession = Depends(get_db_session),
) -> list[GatewayResponse]:
    """Retrieves all authorized gateways."""
    gateways = await MonitoringService.list_gateways(db)
    return [
        GatewayResponse(
            id=g.id,
            name=g.name,
            gateway_ip=g.gateway_ip,
            authorized_scope=g.authorized_scope,
            operator_id=g.operator_id,
            authorization_reference=g.authorization_reference,
            status=g.status,
            created_at=g.created_at,
            updated_at=g.updated_at,
        )
        for g in gateways
    ]


# ------------------------------------------------------------------------------
# Sensor Registration & Management Endpoints
# ------------------------------------------------------------------------------


@router.post(
    "/sensors",
    response_model=RegisterSensorResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a telemetry sensor and issue credential token",
)
async def register_sensor(
    req: RegisterSensorRequest,
    db: AsyncSession = Depends(get_db_session),
) -> RegisterSensorResponse:
    """Registers a telemetry sensor bound to an authorized gateway and returns its secret token once."""
    if not settings.MONITORING_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Continuous Monitoring subsystem is disabled in configuration.",
        )
    try:
        sensor, raw_token = await MonitoringService.register_sensor(db, req)
        return RegisterSensorResponse(
            id=sensor.id,
            sensor_name=sensor.sensor_name,
            sensor_type=sensor.sensor_type,
            gateway_id=sensor.gateway_id,
            authorized_scope=sensor.authorized_scope,
            token_prefix=sensor.token_prefix,
            raw_token=raw_token,
            freshness_window_seconds=sensor.freshness_window_seconds,
            reporting_interval_seconds=sensor.reporting_interval_seconds,
            status=sensor.status,
            created_at=sensor.created_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/sensors",
    response_model=list[SensorResponse],
    summary="List all registered telemetry sensors",
)
async def list_sensors(
    gateway_id: uuid.UUID | None = Query(None, description="Optional gateway filter"),
    db: AsyncSession = Depends(get_db_session),
) -> list[SensorResponse]:
    """Retrieves all registered sensors (secret tokens strictly omitted)."""
    sensors = await MonitoringService.list_sensors(db, gateway_id=gateway_id)
    return [
        SensorResponse(
            id=s.id,
            sensor_name=s.sensor_name,
            sensor_type=s.sensor_type,
            gateway_id=s.gateway_id,
            authorized_scope=s.authorized_scope,
            token_prefix=s.token_prefix,
            freshness_window_seconds=s.freshness_window_seconds,
            reporting_interval_seconds=s.reporting_interval_seconds,
            status=s.status,
            created_at=s.created_at,
            revoked_at=s.revoked_at,
            last_heartbeat_at=s.last_heartbeat_at,
        )
        for s in sensors
    ]


@router.post(
    "/sensors/{sensor_id}/revoke",
    response_model=SensorResponse,
    summary="Revoke a sensor token immediately",
)
async def revoke_sensor(
    sensor_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> SensorResponse:
    """Revokes a sensor's authentication token, immediately rejecting subsequent telemetry."""
    try:
        s = await MonitoringService.revoke_sensor(db, sensor_id)
        return SensorResponse(
            id=s.id,
            sensor_name=s.sensor_name,
            sensor_type=s.sensor_type,
            gateway_id=s.gateway_id,
            authorized_scope=s.authorized_scope,
            token_prefix=s.token_prefix,
            freshness_window_seconds=s.freshness_window_seconds,
            reporting_interval_seconds=s.reporting_interval_seconds,
            status=s.status,
            created_at=s.created_at,
            revoked_at=s.revoked_at,
            last_heartbeat_at=s.last_heartbeat_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


# ------------------------------------------------------------------------------
# Event Ingestion Endpoint
# ------------------------------------------------------------------------------


@router.post(
    "/events",
    response_model=MonitoringEventBatchResponse,
    summary="Ingest a batch of typed monitoring telemetry events",
)
async def ingest_events(
    batch_req: MonitoringEventBatchRequest,
    request: Request,
    x_sensor_token: str | None = Header(None, alias="X-Sensor-Token"),
    db: AsyncSession = Depends(get_db_session),
) -> MonitoringEventBatchResponse:
    """Ingests, validates, and idempotently commits telemetry events from authorized sensors."""
    if not settings.MONITORING_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Continuous Monitoring subsystem is disabled in configuration.",
        )

    # Authenticate sensor credential
    client_host = request.client.host if request.client else None
    sensor = await verify_sensor_credential(db, x_sensor_token, client_host=client_host)

    # Ingest event batch
    res = await MonitoringService.ingest_event_batch(db, sensor, batch_req)
    return res


# ------------------------------------------------------------------------------
# Health & Status Queries
# ------------------------------------------------------------------------------


@router.get(
    "/health",
    response_model=list[SensorHealthDTO],
    summary="Query fleet sensor health, freshness, drops, and sequence gaps",
)
async def get_sensor_health(
    db: AsyncSession = Depends(get_db_session),
) -> list[SensorHealthDTO]:
    """Retrieves real-time sensor health with dynamic freshness evaluation."""
    return await MonitoringService.get_sensor_health_summary(db)


@router.get(
    "/sa-states",
    response_model=list[MonitoredSAStateDTO],
    summary="Query active and recent monitored Security Associations (SAs)",
)
async def get_sa_states(
    gateway_id: uuid.UUID | None = Query(None, description="Optional gateway filter"),
    db: AsyncSession = Depends(get_db_session),
) -> list[MonitoredSAStateDTO]:
    """Queries rebuildable projections of active IKE and Child SAs."""
    return await MonitoringService.get_active_sa_states(db, gateway_id=gateway_id)


@router.get(
    "/timeline",
    summary="Query immutable event timeline with filters and pagination",
)
async def get_timeline(
    gateway_id: uuid.UUID | None = Query(None),
    sensor_id: uuid.UUID | None = Query(None),
    event_kind: EventKind | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Retrieves immutable append-only event evidence."""
    flt = MonitoringTimelineFilter(
        gateway_id=gateway_id,
        sensor_id=sensor_id,
        event_kind=event_kind,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
    items, total_count = await MonitoringService.get_timeline(db, flt)
    return {
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "id": str(i.id),
                "event_id": str(i.event_id),
                "schema_version": i.schema_version,
                "sensor_id": str(i.sensor_id),
                "gateway_id": str(i.gateway_id),
                "authorized_scope": i.authorized_scope,
                "event_kind": i.event_kind,
                "source_timestamp": i.source_timestamp.isoformat(),
                "received_at": i.received_at.isoformat(),
                "clock_skew_seconds": i.clock_skew_seconds,
                "sequence_number": i.sequence_number,
                "evidence_grade": i.evidence_grade,
                "raw_source_status": i.raw_source_status,
                "ike_version": i.ike_version,
                "local_endpoint": i.local_endpoint,
                "remote_endpoint": i.remote_endpoint,
                "initiator_spi": i.initiator_spi,
                "responder_spi": i.responder_spi,
                "child_spi_in": i.child_spi_in,
                "child_spi_out": i.child_spi_out,
                "cipher_suite": i.cipher_suite,
                "failure_reason": i.failure_reason,
                "interface_name": i.interface_name,
                "packet_count": i.packet_count,
                "drop_count": i.drop_count,
                "byte_count": i.byte_count,
                "artifact_hash": i.artifact_hash,
            }
            for i in items
        ],
    }


@router.post(
    "/pulse",
    summary="Trigger a demo telemetry heartbeat pulse",
    status_code=status.HTTP_200_OK,
)
async def trigger_telemetry_pulse(db: AsyncSession = Depends(get_db_session)) -> dict[str, Any]:
    """Emit a live heartbeat and established IKE SA telemetry event for testing and evaluation."""
    from datetime import timezone
    from app.db.models.monitoring import MonitoredSensor
    from app.monitoring.schema import (
        EvidenceGrade,
        MonitoringEventDTO,
        SAState,
        SensorType,
    )

    sensors = await MonitoringService.list_sensors(db)
    active_sensor = next((s for s in sensors if s.status == "ACTIVE"), None)
    if not active_sensor:
        gateways = await MonitoringService.list_gateways(db)
        if not gateways:
            gw = await MonitoringService.register_gateway(
                db,
                RegisterGatewayRequest(
                    name="Perimeter-Gateway-ALPHA",
                    gateway_ip="198.51.100.1",
                    authorized_scope="198.51.100.0/24",
                    operator_id="operator-admin",
                    authorization_reference="DEMO-PULSE-01",
                ),
            )
            gw_id = gw.id
        else:
            gw_id = gateways[0].id

        reg = await MonitoringService.register_sensor(
            db,
            RegisterSensorRequest(
                sensor_name="perimeter-strongswan-collector",
                sensor_type=SensorType.GATEWAY_COLLECTOR,
                gateway_id=gw_id,
                authorized_scope="198.51.100.0/24",
                freshness_window_seconds=120,
            ),
        )
        active_sensor = await db.get(MonitoredSensor, reg.sensor.id)

    now = datetime.now(timezone.utc)
    batch = MonitoringEventBatchRequest(
        events=[
            MonitoringEventDTO(
                event_id=uuid.uuid4(),
                sensor_id=active_sensor.id,
                gateway_id=active_sensor.gateway_id,
                authorized_scope=active_sensor.authorized_scope,
                event_kind=EventKind.GATEWAY_HEARTBEAT,
                evidence_grade=EvidenceGrade.SYNTHETIC,
                sequence_number=int(now.timestamp()),
                source_timestamp=now,
                payload={"status": "HEALTHY", "active_tunnels": 1, "cpu_usage_pct": 12.4, "memory_usage_pct": 28.5, "is_synthetic_test": True},
            ),
            MonitoringEventDTO(
                event_id=uuid.uuid4(),
                sensor_id=active_sensor.id,
                gateway_id=active_sensor.gateway_id,
                authorized_scope=active_sensor.authorized_scope,
                event_kind=EventKind.GATEWAY_IKE_SA_ESTABLISHED,
                evidence_grade=EvidenceGrade.SYNTHETIC,
                sequence_number=int(now.timestamp()) + 1,
                source_timestamp=now,
                ike_version="IKEv2",
                initiator_spi=uuid.uuid4().hex[:16],
                responder_spi=uuid.uuid4().hex[:16],
                local_endpoint="198.51.100.1",
                remote_endpoint="203.0.113.50",
                cipher_suite="AES-256-GCM-16",
                payload={"proposal": "aes256gcm16-prfsha256-ecp256", "rekey_time": 28800, "is_synthetic_test": True},
            ),
        ]
    )
    res = await MonitoringService.ingest_event_batch(db, active_sensor, batch)
    return {
        "status": "ISOLATED_SYNTHETIC_DEMO_COMPLETED",
        "sensor_id": str(active_sensor.id),
        "gateway_id": str(active_sensor.gateway_id),
        "accepted_count": res.accepted_count,
        "timestamp": now.isoformat(),
        "is_synthetic": True,
        "operational_impact": "QUARANTINED — zero modification to operational sensor freshness or active SA projections",
        "disclaimer": "Demonstration synthetic test pulse. Not an observed gateway event or live packet capture.",
    }


# ------------------------------------------------------------------------------
# WebSocket Real-Time Telemetry Feed
# ------------------------------------------------------------------------------


@router.websocket("/ws")
async def monitoring_websocket_endpoint(websocket: WebSocket) -> None:
    """Real-time streaming WebSocket endpoint for continuous monitoring events."""
    await monitoring_ws_manager.connect(websocket)
    try:
        # Initial greeting with timestamp
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "message": "Connected to TunnelTrace AI Continuous Monitoring WebSocket feed",
            "connected_at": datetime.now().isoformat(),
        })

        while True:
            data = await websocket.receive_text()
            if data == "PING" or '"PING"' in data:
                await websocket.send_text("PONG")
    except WebSocketDisconnect:
        await monitoring_ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.debug(f"Monitoring WebSocket connection closed: {exc}")
        await monitoring_ws_manager.disconnect(websocket)
