"""Business logic service for Configuration and Certificate Inventory."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.inventory import (
    GatewayCertificate,
    GatewayConfigurationDrift,
    GatewayConfigurationSnapshot,
)
from app.inventory.certificate_parser import SafeCertificateParser
from app.inventory.drift_engine import ConfigurationDriftEngine
from app.inventory.schemas import (
    BaselineDesignateRequest,
    CertificateImportRequest,
    ComparisonStatus,
    ConfigurationImportRequest,
    DriftCompareRequest,
    FieldDriftItem,
    GatewayInventorySummaryResponse,
    ValidityStatus,
)
from app.inventory.strongswan_parser import SafeSwanctlParser


class InventoryService:
    """Service orchestrating snapshot ingestion, baseline management, drift evaluation, and certificate tracking."""

    @classmethod
    async def import_configuration_snapshot(
        cls,
        db: AsyncSession,
        request: ConfigurationImportRequest,
    ) -> GatewayConfigurationSnapshot:
        """Parse, scrub, and persist a strongSwan configuration snapshot."""
        if not request.config_text or not request.config_text.strip():
            raise ConfigurationParseError("Configuration content cannot be empty. Please provide valid swanctl.conf syntax.")

        # In-memory parse and secret scrubbing
        parse_result = SafeSwanctlParser.parse(request.config_text)
        normalized_ir = parse_result["normalized_ir"]
        unsupported = parse_result["unsupported_directives"]
        canonical_digest = parse_result["canonical_digest"]

        # Check for idempotent existing snapshot with same identity and digest
        query = select(GatewayConfigurationSnapshot).where(
            GatewayConfigurationSnapshot.gateway_identity == request.gateway_identity,
            GatewayConfigurationSnapshot.canonical_digest == canonical_digest,
        )
        existing = (await db.execute(query)).scalar_one_or_none()
        if existing is not None:
            return existing

        provenance = {
            "operator_id": request.operator_id,
            "authorization_reference": request.authorization_reference,
            "collection_method": request.collection_method,
            "imported_at": datetime.now(timezone.utc).isoformat(),
        }

        snapshot = GatewayConfigurationSnapshot(
            id=uuid.uuid4(),
            gateway_identity=request.gateway_identity,
            authorized_scope=request.authorized_scope,
            source_type=request.source_type.value,
            collection_method=request.collection_method,
            collector_version="1.0.0",
            parser_version="swanctl-6.0.4",
            schema_version="1.0.0",
            canonical_digest=canonical_digest,
            normalized_ir=normalized_ir,
            unsupported_directives=unsupported,
            is_baseline=False,
            source_observed_at=request.source_observed_at,
            provenance=provenance,
        )

        db.add(snapshot)
        await db.commit()
        await db.refresh(snapshot)
        return snapshot

    @classmethod
    async def designate_baseline(
        cls,
        db: AsyncSession,
        snapshot_id: uuid.UUID,
        request: BaselineDesignateRequest,
    ) -> GatewayConfigurationSnapshot | None:
        """Designate a snapshot as the authoritative baseline for its gateway."""
        query = select(GatewayConfigurationSnapshot).where(GatewayConfigurationSnapshot.id == snapshot_id)
        snapshot = (await db.execute(query)).scalar_one_or_none()
        if not snapshot:
            return None

        # Guard: Prohibit empty-content snapshots from being designated as verified baselines
        if snapshot.canonical_digest and snapshot.canonical_digest.startswith("e3b0c442"):
            raise ValueError(
                "Cannot designate unverified configuration snapshot with empty-content digest (e3b0c442...) as an authoritative baseline."
            )

        # Demote existing baselines for this gateway
        demote_stmt = (
            update(GatewayConfigurationSnapshot)
            .where(
                GatewayConfigurationSnapshot.gateway_identity == snapshot.gateway_identity,
                GatewayConfigurationSnapshot.is_baseline == True,  # noqa: E712
            )
            .values(is_baseline=False)
        )
        await db.execute(demote_stmt)

        # Set new baseline
        snapshot.is_baseline = True
        snapshot.baseline_version = request.baseline_version
        snapshot.approved_by = request.operator_id
        snapshot.approval_reference = request.approval_reference

        await db.commit()
        await db.refresh(snapshot)
        return snapshot

    @classmethod
    async def get_snapshot(
        cls,
        db: AsyncSession,
        snapshot_id: uuid.UUID,
    ) -> GatewayConfigurationSnapshot | None:
        """Retrieve single configuration snapshot."""
        query = select(GatewayConfigurationSnapshot).where(GatewayConfigurationSnapshot.id == snapshot_id)
        return (await db.execute(query)).scalar_one_or_none()

    @classmethod
    async def list_snapshots(
        cls,
        db: AsyncSession,
        gateway_identity: str | None = None,
        is_baseline: bool | None = None,
        limit: int = 50,
    ) -> list[GatewayConfigurationSnapshot]:
        """List snapshots matching criteria."""
        query = select(GatewayConfigurationSnapshot).order_by(desc(GatewayConfigurationSnapshot.created_at)).limit(limit)
        if gateway_identity:
            query = query.where(GatewayConfigurationSnapshot.gateway_identity == gateway_identity)
        if is_baseline is not None:
            query = query.where(GatewayConfigurationSnapshot.is_baseline == is_baseline)
        result = await db.execute(query)
        return list(result.scalars().all())

    @classmethod
    async def compute_drift(
        cls,
        db: AsyncSession,
        request: DriftCompareRequest,
    ) -> GatewayConfigurationDrift | None:
        """Compare baseline and observed snapshots and persist drift record."""
        base_query = select(GatewayConfigurationSnapshot).where(
            GatewayConfigurationSnapshot.id == request.baseline_snapshot_id
        )
        base = (await db.execute(base_query)).scalar_one_or_none()
        if not base:
            return None

        obs_query = select(GatewayConfigurationSnapshot).where(
            GatewayConfigurationSnapshot.id == request.observed_snapshot_id
        )
        obs = (await db.execute(obs_query)).scalar_one_or_none()
        if not obs:
            return None

        comparison_status, drift_summary, field_drifts = ConfigurationDriftEngine.compare_snapshots(
            baseline_ir=base.normalized_ir,
            observed_ir=obs.normalized_ir,
            baseline_identity=base.gateway_identity,
            observed_identity=obs.gateway_identity,
        )

        drift_record = GatewayConfigurationDrift(
            id=uuid.uuid4(),
            gateway_identity=base.gateway_identity,
            baseline_snapshot_id=base.id,
            observed_snapshot_id=obs.id,
            comparison_status=comparison_status.value,
            drift_summary=drift_summary,
            field_drifts=[item.model_dump() for item in field_drifts],
        )

        db.add(drift_record)
        await db.commit()
        await db.refresh(drift_record)
        return drift_record

    @classmethod
    async def list_drifts(
        cls,
        db: AsyncSession,
        gateway_identity: str | None = None,
        limit: int = 50,
    ) -> list[GatewayConfigurationDrift]:
        """List drift evaluations."""
        query = select(GatewayConfigurationDrift).order_by(desc(GatewayConfigurationDrift.created_at)).limit(limit)
        if gateway_identity:
            query = query.where(GatewayConfigurationDrift.gateway_identity == gateway_identity)
        result = await db.execute(query)
        return list(result.scalars().all())

    @classmethod
    async def import_certificates(
        cls,
        db: AsyncSession,
        request: CertificateImportRequest,
    ) -> list[GatewayCertificate]:
        """Parse, validate, and store X.509 public certificates."""
        connections_ir: dict[str, Any] | None = None
        if request.snapshot_id:
            snap = await cls.get_snapshot(db, request.snapshot_id)
            if snap and snap.normalized_ir:
                connections_ir = snap.normalized_ir.get("connections")

        parsed_certs = SafeCertificateParser.parse_pem_bundle(
            pem_text=request.certificate_pem,
            trust_store_pem=request.trust_store_pem,
            connections_ir=connections_ir,
            source_alias=request.source_alias,
        )

        created: list[GatewayCertificate] = []
        for cert_dict in parsed_certs:
            cert_row = GatewayCertificate(
                id=uuid.uuid4(),
                gateway_identity=request.gateway_identity,
                snapshot_id=request.snapshot_id,
                sha256_fingerprint=cert_dict["sha256_fingerprint"],
                serial_number=cert_dict["serial_number"],
                subject_dn=cert_dict["subject_dn"],
                issuer_dn=cert_dict["issuer_dn"],
                subject_alt_names=cert_dict["subject_alt_names"],
                not_valid_before=cert_dict["not_valid_before"],
                not_valid_after=cert_dict["not_valid_after"],
                validity_status=cert_dict["validity_status"],
                days_until_expiry=cert_dict["days_until_expiry"],
                public_key_algorithm=cert_dict["public_key_algorithm"],
                public_key_bits=cert_dict["public_key_bits"],
                signature_algorithm=cert_dict["signature_algorithm"],
                is_ca=cert_dict["is_ca"],
                key_usages=cert_dict["key_usages"],
                extended_key_usages=cert_dict["extended_key_usages"],
                associated_connection=cert_dict["associated_connection"],
                identity_association_status=cert_dict["identity_association_status"],
                chain_validation_status=cert_dict["chain_validation_status"],
                trust_store_identifier=cert_dict["trust_store_identifier"],
                trust_store_digest=cert_dict["trust_store_digest"],
                revocation_status=cert_dict["revocation_status"],
                source_alias=cert_dict["source_alias"],
                epistemic_status=request.epistemic_status,
            )
            db.add(cert_row)
            created.append(cert_row)

        await db.commit()
        for c in created:
            await db.refresh(c)
        return created

    @classmethod
    async def list_certificates(
        cls,
        db: AsyncSession,
        gateway_identity: str | None = None,
        validity_status: str | None = None,
        associated_connection: str | None = None,
        limit: int = 100,
    ) -> list[GatewayCertificate]:
        """List public certificates."""
        query = select(GatewayCertificate).order_by(GatewayCertificate.not_valid_after.asc()).limit(limit)
        if gateway_identity:
            query = query.where(GatewayCertificate.gateway_identity == gateway_identity)
        if validity_status:
            query = query.where(GatewayCertificate.validity_status == validity_status)
        if associated_connection:
            query = query.where(GatewayCertificate.associated_connection == associated_connection)
        result = await db.execute(query)
        return list(result.scalars().all())

    @classmethod
    async def get_certificate(
        cls,
        db: AsyncSession,
        certificate_id: uuid.UUID,
    ) -> GatewayCertificate | None:
        """Get certificate by primary key."""
        query = select(GatewayCertificate).where(GatewayCertificate.id == certificate_id)
        return (await db.execute(query)).scalar_one_or_none()

    @classmethod
    async def get_gateway_summaries(
        cls,
        db: AsyncSession,
    ) -> list[GatewayInventorySummaryResponse]:
        """Aggregate summary of gateway inventory states."""
        # Find distinct gateway identities
        stmt = select(
            GatewayConfigurationSnapshot.gateway_identity,
            GatewayConfigurationSnapshot.authorized_scope,
        ).distinct()
        rows = (await db.execute(stmt)).all()

        summaries: list[GatewayInventorySummaryResponse] = []
        for identity, scope in rows:
            # Baseline
            base_q = select(GatewayConfigurationSnapshot).where(
                GatewayConfigurationSnapshot.gateway_identity == identity,
                GatewayConfigurationSnapshot.is_baseline == True,  # noqa: E712
            )
            baseline = (await db.execute(base_q)).scalar_one_or_none()

            # Latest snapshot
            latest_q = (
                select(GatewayConfigurationSnapshot)
                .where(GatewayConfigurationSnapshot.gateway_identity == identity)
                .order_by(desc(GatewayConfigurationSnapshot.created_at))
                .limit(1)
            )
            latest = (await db.execute(latest_q)).scalar_one_or_none()

            # Latest drift
            drift_q = (
                select(GatewayConfigurationDrift)
                .where(GatewayConfigurationDrift.gateway_identity == identity)
                .order_by(desc(GatewayConfigurationDrift.created_at))
                .limit(1)
            )
            latest_drift = (await db.execute(drift_q)).scalar_one_or_none()

            # Cert metrics
            cert_count_q = select(func.count(GatewayCertificate.id)).where(GatewayCertificate.gateway_identity == identity)
            cert_count = (await db.execute(cert_count_q)).scalar_one() or 0

            expiring_q = select(func.count(GatewayCertificate.id)).where(
                GatewayCertificate.gateway_identity == identity,
                GatewayCertificate.validity_status == ValidityStatus.EXPIRING_SOON.value,
            )
            expiring_count = (await db.execute(expiring_q)).scalar_one() or 0

            expired_q = select(func.count(GatewayCertificate.id)).where(
                GatewayCertificate.gateway_identity == identity,
                GatewayCertificate.validity_status == ValidityStatus.EXPIRED.value,
            )
            expired_count = (await db.execute(expired_q)).scalar_one() or 0

            summaries.append(
                GatewayInventorySummaryResponse(
                    gateway_identity=identity,
                    authorized_scope=scope,
                    has_baseline=baseline is not None,
                    baseline_snapshot_id=baseline.id if baseline else None,
                    baseline_version=baseline.baseline_version if baseline else None,
                    latest_snapshot_id=latest.id if latest else None,
                    latest_snapshot_digest=latest.canonical_digest if latest else None,
                    latest_snapshot_created_at=latest.created_at if latest else None,
                    latest_drift_status=latest_drift.comparison_status if latest_drift else None,
                    certificate_count=cert_count,
                    expiring_soon_certificates=expiring_count,
                    expired_certificates=expired_count,
                )
            )

        return summaries
