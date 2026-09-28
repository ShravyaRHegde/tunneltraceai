"""Service engine for Continuous Monitoring: event ingestion, health evaluation, gap detection, and SA state projections."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.db.models.monitoring import (
    MonitoredGateway,
    MonitoredSAState,
    MonitoredSensor,
    MonitoringEvent,
    SensorHealthState,
)
from app.monitoring.auth import generate_sensor_token, validate_sensor_event_scope
from app.monitoring.schema import (
    EventKind,
    EvidenceGrade,
    GatewayStatus,
    MonitoredSAStateDTO,
    MonitoringEventBatchRequest,
    MonitoringEventBatchResponse,
    MonitoringEventDTO,
    MonitoringTimelineFilter,
    RegisterGatewayRequest,
    RegisterSensorRequest,
    SAState,
    SensorHealthDTO,
    SensorHealthStatus,
    SensorStatus,
    SensorType,
)
from app.monitoring.websocket import monitoring_ws_manager

logger = logging.getLogger("tunneltrace.monitoring.service")


class MonitoringService:
    """Core domain service for Continuous Monitoring."""

    # --------------------------------------------------------------------------
    # Gateway Management
    # --------------------------------------------------------------------------

    @staticmethod
    async def register_gateway(db: AsyncSession, req: RegisterGatewayRequest) -> MonitoredGateway:
        """Register a new authorized VPN gateway boundary."""
        # Check uniqueness of name
        existing = await db.scalar(
            select(MonitoredGateway).where(MonitoredGateway.name == req.name)
        )
        if existing:
            raise ValueError(f"A monitored gateway named '{req.name}' already exists.")

        gw = MonitoredGateway(
            id=uuid.uuid4(),
            name=req.name.strip(),
            gateway_ip=req.gateway_ip.strip(),
            authorized_scope=req.authorized_scope.strip(),
            operator_id=req.operator_id.strip(),
            authorization_reference=req.authorization_reference.strip(),
            status=GatewayStatus.ACTIVE.value,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(gw)
        await db.commit()
        await db.refresh(gw)
        logger.info(f"Registered monitored gateway '{gw.name}' ({gw.gateway_ip}) bound to {gw.authorized_scope}")
        return gw

    @staticmethod
    async def list_gateways(db: AsyncSession) -> list[MonitoredGateway]:
        """List all registered monitored gateways."""
        res = await db.execute(select(MonitoredGateway).order_by(MonitoredGateway.created_at.desc()))
        return list(res.scalars().all())

    # --------------------------------------------------------------------------
    # Sensor Management
    # --------------------------------------------------------------------------

    @staticmethod
    async def register_sensor(
        db: AsyncSession, req: RegisterSensorRequest
    ) -> tuple[MonitoredSensor, str]:
        """Register a telemetry sensor, generating a secure secret token displayed once."""
        # Check gateway exists and is active
        gw = await db.get(MonitoredGateway, req.gateway_id)
        if not gw:
            raise ValueError(f"Target gateway '{req.gateway_id}' does not exist.")
        if gw.status != GatewayStatus.ACTIVE.value:
            raise ValueError(f"Target gateway '{gw.name}' is {gw.status}; cannot attach new sensor.")

        # Check sensor name uniqueness
        existing = await db.scalar(
            select(MonitoredSensor).where(MonitoredSensor.sensor_name == req.sensor_name)
        )
        if existing:
            raise ValueError(f"A sensor named '{req.sensor_name}' already exists.")

        raw_token, token_hash, token_prefix = generate_sensor_token()
        sensor_id = uuid.uuid4()

        sensor = MonitoredSensor(
            id=sensor_id,
            sensor_name=req.sensor_name.strip(),
            sensor_type=req.sensor_type.value,
            gateway_id=req.gateway_id,
            authorized_scope=req.authorized_scope.strip(),
            auth_token_hash=token_hash,
            token_prefix=token_prefix,
            freshness_window_seconds=req.freshness_window_seconds,
            reporting_interval_seconds=req.reporting_interval_seconds,
            status=SensorStatus.ACTIVE.value,
            created_at=datetime.now(timezone.utc),
        )
        db.add(sensor)

        # Initial rebuildable health state projection
        initial_health = SensorHealthState(
            sensor_id=sensor_id,
            current_health=SensorHealthStatus.UNKNOWN.value,
            health_reason="Sensor registered; awaiting initial telemetry heartbeat",
            total_events_received=0,
            total_drops_reported=0,
            sequence_gaps_count=0,
            clock_skew_seconds=0.0,
            active_quality_warnings=[],
            updated_at=datetime.now(timezone.utc),
        )
        db.add(initial_health)

        await db.commit()
        await db.refresh(sensor)
        logger.info(f"Registered sensor '{sensor.sensor_name}' ({sensor.sensor_type}) for gateway '{gw.name}'")
        return sensor, raw_token

    @staticmethod
    async def list_sensors(
        db: AsyncSession, gateway_id: uuid.UUID | None = None
    ) -> list[MonitoredSensor]:
        """List registered sensors, optionally filtered by gateway."""
        query = select(MonitoredSensor).options(selectinload(MonitoredSensor.gateway))
        if gateway_id:
            query = query.where(MonitoredSensor.gateway_id == gateway_id)
        query = query.order_by(MonitoredSensor.created_at.desc())
        res = await db.execute(query)
        return list(res.scalars().all())

    @staticmethod
    async def revoke_sensor(db: AsyncSession, sensor_id: uuid.UUID) -> MonitoredSensor:
        """Revoke a sensor token immediately."""
        sensor = await db.get(MonitoredSensor, sensor_id)
        if not sensor:
            raise ValueError(f"Sensor '{sensor_id}' not found.")

        sensor.status = SensorStatus.REVOKED.value
        sensor.revoked_at = datetime.now(timezone.utc)

        health = await db.get(SensorHealthState, sensor_id)
        if health:
            health.current_health = SensorHealthStatus.DISABLED.value
            health.health_reason = "Sensor revoked by administrator"
            health.updated_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(sensor)
        logger.warning(f"Sensor '{sensor.sensor_name}' ({sensor.id}) has been REVOKED.")
        return sensor

    # --------------------------------------------------------------------------
    # Event Ingestion Engine (Append-Only Evidence + Rebuildable Projections)
    # --------------------------------------------------------------------------

    @staticmethod
    async def ingest_event_batch(
        db: AsyncSession,
        sensor: MonitoredSensor | None,
        batch_req: MonitoringEventBatchRequest,
    ) -> MonitoringEventBatchResponse:
        """Idempotently ingest an event batch, update health projections, and project SA state."""
        accepted_count = 0
        duplicate_count = 0
        rejected_count = 0
        gaps_detected_in_batch = 0
        warnings: list[str] = []
        errors: list[str] = []

        now_utc = datetime.now(timezone.utc)

        for event_dto in batch_req.events:
            try:
                # 1. Scope & Gateway Authorization Check
                validate_sensor_event_scope(sensor, event_dto.gateway_id, event_dto.authorized_scope)

                # 2. Idempotency Check: (sensor_id, event_id)
                existing_evt = await db.scalar(
                    select(MonitoringEvent.id).where(
                        MonitoringEvent.sensor_id == event_dto.sensor_id,
                        MonitoringEvent.event_id == event_dto.event_id,
                    )
                )
                if existing_evt:
                    duplicate_count += 1
                    continue

                # 3. Clock Skew Calculation
                src_time = (
                    event_dto.source_timestamp
                    if event_dto.source_timestamp.tzinfo
                    else event_dto.source_timestamp.replace(tzinfo=timezone.utc)
                )
                clock_skew = (now_utc - src_time).total_seconds()

                # 4. Fetch or create SensorHealthState projection
                health_state = await db.get(SensorHealthState, event_dto.sensor_id)
                if not health_state:
                    health_state = SensorHealthState(
                        sensor_id=event_dto.sensor_id,
                        current_health=SensorHealthStatus.UNKNOWN.value,
                        health_reason="Processing initial event",
                        total_events_received=0,
                        total_drops_reported=0,
                        sequence_gaps_count=0,
                        clock_skew_seconds=clock_skew,
                        active_quality_warnings=[],
                        updated_at=now_utc,
                    )
                    db.add(health_state)

                quality_warnings: list[str] = list(health_state.active_quality_warnings or [])

                # 5. Sequence Gap & Reset Detection
                if event_dto.sequence_number is not None:
                    if health_state.last_sequence_number is not None:
                        if event_dto.sequence_number > health_state.last_sequence_number + 1:
                            gap_size = event_dto.sequence_number - health_state.last_sequence_number - 1
                            health_state.sequence_gaps_count += 1
                            gaps_detected_in_batch += 1
                            warn_msg = f"Sequence gap: skipped {gap_size} events ({health_state.last_sequence_number} -> {event_dto.sequence_number})"
                            warnings.append(warn_msg)
                            if "SEQUENCE_GAP_DETECTED" not in quality_warnings:
                                quality_warnings.append("SEQUENCE_GAP_DETECTED")
                        elif event_dto.sequence_number < health_state.last_sequence_number:
                            # Sequence reset (e.g. collector reboot)
                            warn_msg = f"Sequence reset: counter dropped from {health_state.last_sequence_number} to {event_dto.sequence_number} (source reboot)"
                            warnings.append(warn_msg)
                            if "SEQUENCE_RESET_OBSERVED" not in quality_warnings:
                                quality_warnings.append("SEQUENCE_RESET_OBSERVED")
                    health_state.last_sequence_number = event_dto.sequence_number

                # 6. Capture Drops Accounting
                if event_dto.drop_count and event_dto.drop_count > 0:
                    health_state.total_drops_reported += event_dto.drop_count
                    warn_msg = f"Capture drops reported: {event_dto.drop_count} packet(s) dropped on {event_dto.interface_name or 'interface'}"
                    warnings.append(warn_msg)
                    if "CAPTURE_DROPS_RECORDED" not in quality_warnings:
                        quality_warnings.append("CAPTURE_DROPS_RECORDED")

                # 7. Clock Skew Warning
                if abs(clock_skew) > settings.MONITORING_CLOCK_SKEW_TOLERANCE_SECONDS:
                    if "CLOCK_SKEW_EXCEEDED" not in quality_warnings:
                        quality_warnings.append("CLOCK_SKEW_EXCEEDED")
                    warnings.append(f"Clock skew exceeded: {clock_skew:.2f}s difference between source and server clock")

                # 8. Record Append-Only Event
                event_record = MonitoringEvent(
                    id=uuid.uuid4(),
                    event_id=event_dto.event_id,
                    schema_version=event_dto.schema_version,
                    sensor_id=event_dto.sensor_id,
                    gateway_id=event_dto.gateway_id,
                    authorized_scope=event_dto.authorized_scope,
                    event_kind=event_dto.event_kind.value,
                    source_timestamp=src_time,
                    received_at=now_utc,
                    clock_skew_seconds=clock_skew,
                    sequence_number=event_dto.sequence_number,
                    source_boot_id=event_dto.source_boot_id,
                    source_session_id=event_dto.source_session_id,
                    evidence_grade=event_dto.evidence_grade.value,
                    raw_source_status=event_dto.raw_source_status,
                    ike_version=event_dto.ike_version,
                    local_endpoint=event_dto.local_endpoint,
                    remote_endpoint=event_dto.remote_endpoint,
                    initiator_spi=event_dto.initiator_spi,
                    responder_spi=event_dto.responder_spi,
                    child_spi_in=event_dto.child_spi_in,
                    child_spi_out=event_dto.child_spi_out,
                    cipher_suite=event_dto.cipher_suite,
                    failure_reason=event_dto.failure_reason,
                    failure_code=event_dto.failure_code,
                    interface_name=event_dto.interface_name,
                    packet_count=event_dto.packet_count,
                    drop_count=event_dto.drop_count,
                    byte_count=event_dto.byte_count,
                    artifact_hash=event_dto.artifact_hash,
                    collector_version=event_dto.collector_version,
                    payload=event_dto.payload,
                )
                db.add(event_record)

                # 9. Update Sensor Health Projection ONLY for non-synthetic events
                is_synthetic = (
                    event_dto.evidence_grade == EvidenceGrade.SYNTHETIC
                    or bool(event_dto.payload and event_dto.payload.get("is_synthetic_test"))
                )

                if not is_synthetic:
                    health_state.total_events_received += 1
                    health_state.last_source_timestamp = src_time
                    health_state.last_received_at = now_utc
                    health_state.clock_skew_seconds = clock_skew
                    health_state.active_quality_warnings = quality_warnings

                    # Health state transition
                    if event_dto.event_kind == EventKind.CAPTURE_FAILED:
                        health_state.current_health = SensorHealthStatus.UNAVAILABLE.value
                        health_state.health_reason = f"Capture sensor fatal error: {event_dto.failure_reason or 'Capture process failure'}"
                    elif quality_warnings:
                        health_state.current_health = SensorHealthStatus.DEGRADED.value
                        health_state.health_reason = f"Degraded telemetry: {', '.join(quality_warnings)}"
                    else:
                        health_state.current_health = SensorHealthStatus.HEALTHY.value
                        health_state.health_reason = "Telemetry streaming normally; 0 drops, 0 sequence gaps"

                    health_state.updated_at = now_utc

                    # 10. Update Monitored SA State Projection
                    await MonitoringService._project_sa_state(db, event_dto, src_time)

                accepted_count += 1

                # Broadcast live event to WebSockets
                await monitoring_ws_manager.broadcast({
                    "type": "MONITORING_EVENT",
                    "event_kind": event_dto.event_kind.value,
                    "sensor_id": str(event_dto.sensor_id),
                    "gateway_id": str(event_dto.gateway_id),
                    "source_timestamp": src_time.isoformat(),
                    "initiator_spi": event_dto.initiator_spi,
                    "child_spi_in": event_dto.child_spi_in,
                    "raw_source_status": event_dto.raw_source_status,
                    "is_synthetic": is_synthetic,
                    "label": "DEMO / SYNTHETIC TEST PULSE — NOT OBSERVED TELEMETRY" if is_synthetic else "OBSERVED GATEWAY TELEMETRY",
                })

            except Exception as exc:
                logger.error(f"Error processing monitoring event '{event_dto.event_id}': {exc}", exc_info=True)
                rejected_count += 1
                errors.append(f"Event {event_dto.event_id}: {str(exc)}")

        # Commit all accepted events and projection updates
        await db.commit()

        return MonitoringEventBatchResponse(
            batch_id=uuid.uuid4(),
            total_received=len(batch_req.events),
            accepted_count=accepted_count,
            duplicate_count=duplicate_count,
            rejected_count=rejected_count,
            sequence_gaps_detected=gaps_detected_in_batch,
            warnings=warnings,
            errors=errors,
        )

    @staticmethod
    async def _project_sa_state(db: AsyncSession, event: MonitoringEventDTO, src_time: datetime) -> None:
        """Projects explicit IKE and Child SA lifecycle events into the rebuildable MonitoredSAState table."""
        # Only process IKE/Child SA related events
        is_ike_event = event.event_kind in (
            EventKind.GATEWAY_IKE_SA_INIT_STARTED,
            EventKind.GATEWAY_IKE_SA_ESTABLISHED,
            EventKind.GATEWAY_IKE_SA_FAILED,
        )
        is_child_event = event.event_kind in (
            EventKind.GATEWAY_CHILD_SA_ESTABLISHED,
            EventKind.GATEWAY_CHILD_SA_REKEYED,
            EventKind.GATEWAY_CHILD_SA_EXPIRED,
            EventKind.GATEWAY_CHILD_SA_DELETED,
        )

        if not (is_ike_event or is_child_event):
            return

        sa_type = "IKE_SA" if is_ike_event else "CHILD_SA"
        initiator_spi = (event.initiator_spi or "0000000000000000").strip()
        child_spi_in = (event.child_spi_in or "00000000").strip() if is_child_event else None

        # Determine target SA State
        state_map = {
            EventKind.GATEWAY_IKE_SA_INIT_STARTED: SAState.INITIATING.value,
            EventKind.GATEWAY_IKE_SA_ESTABLISHED: SAState.ESTABLISHED.value,
            EventKind.GATEWAY_IKE_SA_FAILED: SAState.FAILED.value,
            EventKind.GATEWAY_CHILD_SA_ESTABLISHED: SAState.ESTABLISHED.value,
            EventKind.GATEWAY_CHILD_SA_REKEYED: SAState.REKEYED.value,
            EventKind.GATEWAY_CHILD_SA_EXPIRED: SAState.EXPIRED.value,
            EventKind.GATEWAY_CHILD_SA_DELETED: SAState.DELETED.value,
        }
        new_state = state_map.get(event.event_kind, SAState.ESTABLISHED.value)

        # Query existing SA state record
        query = select(MonitoredSAState).where(
            MonitoredSAState.gateway_id == event.gateway_id,
            MonitoredSAState.initiator_spi == initiator_spi,
            MonitoredSAState.child_spi_in == child_spi_in,
        )
        existing_sa = await db.scalar(query)

        now_utc = datetime.now(timezone.utc)

        if existing_sa:
            existing_sa.state = new_state
            existing_sa.last_event_at = src_time
            existing_sa.last_event_id = event.event_id
            existing_sa.updated_at = now_utc
            if event.responder_spi:
                existing_sa.responder_spi = event.responder_spi
            if event.child_spi_out:
                existing_sa.child_spi_out = event.child_spi_out
            if event.local_endpoint:
                existing_sa.local_endpoint = event.local_endpoint
            if event.remote_endpoint:
                existing_sa.remote_endpoint = event.remote_endpoint
            if event.cipher_suite:
                existing_sa.cipher_suite = event.cipher_suite
            if new_state == SAState.ESTABLISHED.value and not existing_sa.established_at:
                existing_sa.established_at = src_time
        else:
            new_sa = MonitoredSAState(
                id=uuid.uuid4(),
                gateway_id=event.gateway_id,
                sensor_id=event.sensor_id,
                sa_type=sa_type,
                initiator_spi=initiator_spi,
                responder_spi=event.responder_spi,
                child_spi_in=child_spi_in,
                child_spi_out=event.child_spi_out,
                state=new_state,
                local_endpoint=event.local_endpoint,
                remote_endpoint=event.remote_endpoint,
                cipher_suite=event.cipher_suite,
                established_at=src_time if new_state == SAState.ESTABLISHED.value else None,
                last_event_at=src_time,
                last_event_id=event.event_id,
                is_stale=False,
                staleness_reason=None,
                evidence_grade=event.evidence_grade.value,
                updated_at=now_utc,
            )
            db.add(new_sa)

    # --------------------------------------------------------------------------
    # Health & Freshness Query Engine
    # --------------------------------------------------------------------------

    @staticmethod
    async def get_sensor_health_summary(db: AsyncSession) -> list[SensorHealthDTO]:
        """Calculates dynamic freshness and health state across all registered sensors.
        
        Dynamically transitions sensors exceeding their freshness window to STALE.
        Does NOT invent 'healthy' status for sensors with zero received events.
        """
        now_utc = datetime.now(timezone.utc)

        query = (
            select(MonitoredSensor)
            .options(
                selectinload(MonitoredSensor.gateway),
                selectinload(MonitoredSensor.health_state),
            )
            .order_by(MonitoredSensor.created_at.desc())
        )
        res = await db.execute(query)
        sensors = list(res.scalars().all())

        health_summaries: list[SensorHealthDTO] = []

        for s in sensors:
            h = s.health_state
            gateway_name = s.gateway.name if s.gateway else "Unknown Gateway"

            # 1. Administratively disabled or revoked
            if s.status in (SensorStatus.REVOKED.value, SensorStatus.DISABLED.value):
                health_summaries.append(
                    SensorHealthDTO(
                        sensor_id=s.id,
                        sensor_name=s.sensor_name,
                        sensor_type=SensorType(s.sensor_type),
                        gateway_id=s.gateway_id,
                        gateway_name=gateway_name,
                        authorized_scope=s.authorized_scope,
                        current_health=SensorHealthStatus.DISABLED,
                        health_reason=f"Sensor is {s.status}",
                        last_source_timestamp=h.last_source_timestamp if h else None,
                        last_received_at=h.last_received_at if h else None,
                        freshness_window_seconds=s.freshness_window_seconds,
                        reporting_interval_seconds=s.reporting_interval_seconds,
                        total_events_received=h.total_events_received if h else 0,
                        total_drops_reported=h.total_drops_reported if h else 0,
                        sequence_gaps_count=h.sequence_gaps_count if h else 0,
                        clock_skew_seconds=h.clock_skew_seconds if h else 0.0,
                        active_quality_warnings=h.active_quality_warnings if h else [],
                        is_stale=False,
                    )
                )
                continue

            # 2. No events ever received -> strictly UNKNOWN, never healthy
            if not h or h.total_events_received == 0 or not h.last_received_at:
                health_summaries.append(
                    SensorHealthDTO(
                        sensor_id=s.id,
                        sensor_name=s.sensor_name,
                        sensor_type=SensorType(s.sensor_type),
                        gateway_id=s.gateway_id,
                        gateway_name=gateway_name,
                        authorized_scope=s.authorized_scope,
                        current_health=SensorHealthStatus.UNKNOWN,
                        health_reason="No events received yet from sensor",
                        last_source_timestamp=None,
                        last_received_at=None,
                        freshness_window_seconds=s.freshness_window_seconds,
                        reporting_interval_seconds=s.reporting_interval_seconds,
                        total_events_received=0,
                        total_drops_reported=0,
                        sequence_gaps_count=0,
                        clock_skew_seconds=0.0,
                        active_quality_warnings=[],
                        is_stale=False,
                    )
                )
                continue

            # 3. Dynamic Freshness Evaluation
            recv_time = h.last_received_at if h.last_received_at.tzinfo else h.last_received_at.replace(tzinfo=timezone.utc)
            elapsed_seconds = (now_utc - recv_time).total_seconds()
            is_stale = elapsed_seconds > s.freshness_window_seconds

            current_health = SensorHealthStatus(h.current_health)
            health_reason = h.health_reason

            if is_stale:
                # Elapsed > freshness window -> STALE
                current_health = SensorHealthStatus.STALE
                health_reason = (
                    f"Stale telemetry: last event received {int(elapsed_seconds)}s ago "
                    f"(freshness threshold is {s.freshness_window_seconds}s)"
                )
                # Mark associated SA states as stale (NOT deleted!)
                await MonitoringService._mark_sensor_sas_stale(db, s.id, health_reason)
            elif elapsed_seconds > 3 * s.freshness_window_seconds:
                current_health = SensorHealthStatus.UNAVAILABLE
                health_reason = f"Sensor communication lost for {int(elapsed_seconds)}s"

            health_summaries.append(
                SensorHealthDTO(
                    sensor_id=s.id,
                    sensor_name=s.sensor_name,
                    sensor_type=SensorType(s.sensor_type),
                    gateway_id=s.gateway_id,
                    gateway_name=gateway_name,
                    authorized_scope=s.authorized_scope,
                    current_health=current_health,
                    health_reason=health_reason,
                    last_source_timestamp=h.last_source_timestamp,
                    last_received_at=h.last_received_at,
                    freshness_window_seconds=s.freshness_window_seconds,
                    reporting_interval_seconds=s.reporting_interval_seconds,
                    total_events_received=h.total_events_received,
                    total_drops_reported=h.total_drops_reported,
                    sequence_gaps_count=h.sequence_gaps_count,
                    clock_skew_seconds=h.clock_skew_seconds,
                    active_quality_warnings=h.active_quality_warnings or [],
                    is_stale=is_stale,
                )
            )

        return health_summaries

    @staticmethod
    async def _mark_sensor_sas_stale(db: AsyncSession, sensor_id: uuid.UUID, reason: str) -> None:
        """Marks SA states associated with a stale sensor as stale WITHOUT deleting them."""
        query = select(MonitoredSAState).where(
            MonitoredSAState.sensor_id == sensor_id,
            MonitoredSAState.state.in_([SAState.ESTABLISHED.value, SAState.REKEYED.value]),
            MonitoredSAState.is_stale.is_(False),
        )
        res = await db.execute(query)
        for sa in res.scalars().all():
            sa.is_stale = True
            sa.staleness_reason = reason
            sa.updated_at = datetime.now(timezone.utc)
        await db.commit()

    # --------------------------------------------------------------------------
    # SA State Query Engine
    # --------------------------------------------------------------------------

    @staticmethod
    async def get_active_sa_states(
        db: AsyncSession, gateway_id: uuid.UUID | None = None
    ) -> list[MonitoredSAStateDTO]:
        """Query rebuildable projection of active or recent Security Associations."""
        query = (
            select(MonitoredSAState)
            .options(selectinload(MonitoredSAState.gateway))
            .order_by(MonitoredSAState.last_event_at.desc())
        )
        if gateway_id:
            query = query.where(MonitoredSAState.gateway_id == gateway_id)

        res = await db.execute(query)
        sa_records = list(res.scalars().all())

        dtos: list[MonitoredSAStateDTO] = []
        for r in sa_records:
            gateway_name = r.gateway.name if r.gateway else "Unknown Gateway"
            dtos.append(
                MonitoredSAStateDTO(
                    id=r.id,
                    gateway_id=r.gateway_id,
                    gateway_name=gateway_name,
                    sensor_id=r.sensor_id,
                    sa_type=r.sa_type,
                    initiator_spi=r.initiator_spi,
                    responder_spi=r.responder_spi,
                    child_spi_in=r.child_spi_in,
                    child_spi_out=r.child_spi_out,
                    state=SAState(r.state),
                    local_endpoint=r.local_endpoint,
                    remote_endpoint=r.remote_endpoint,
                    cipher_suite=r.cipher_suite,
                    established_at=r.established_at,
                    last_event_at=r.last_event_at,
                    is_stale=r.is_stale,
                    staleness_reason=r.staleness_reason,
                    evidence_grade=EvidenceGrade(r.evidence_grade),
                )
            )
        return dtos

    # --------------------------------------------------------------------------
    # Immutable Timeline Query Engine
    # --------------------------------------------------------------------------

    @staticmethod
    async def get_timeline(
        db: AsyncSession, flt: MonitoringTimelineFilter
    ) -> tuple[list[MonitoringEvent], int]:
        """Query time-ordered immutable event timeline with filtering and pagination."""
        query = select(MonitoringEvent)

        if flt.gateway_id:
            query = query.where(MonitoringEvent.gateway_id == flt.gateway_id)
        if flt.sensor_id:
            query = query.where(MonitoringEvent.sensor_id == flt.sensor_id)
        if flt.event_kind:
            query = query.where(MonitoringEvent.event_kind == flt.event_kind.value)
        if flt.since:
            query = query.where(MonitoringEvent.source_timestamp >= flt.since)
        if flt.until:
            query = query.where(MonitoringEvent.source_timestamp <= flt.until)

        # Count total matching
        count_query = select(func.count()).select_from(query.subquery())
        total_count = await db.scalar(count_query) or 0

        # Paginate
        query = query.order_by(MonitoringEvent.source_timestamp.desc())
        query = query.offset(flt.offset).limit(flt.limit)

        res = await db.execute(query)
        items = list(res.scalars().all())
        return items, total_count
