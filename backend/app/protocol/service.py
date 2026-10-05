"""Protocol Forensics Engine Service orchestrating TShark dissection and fact normalization."""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AnalysisNotFoundError, CaptureNotFoundError
from app.db.models.capture import AnalysisRun, Capture, ProtocolObservation
from app.protocol.normalization.ah import parse_ah_layer
from app.protocol.normalization.esp import parse_esp_layer
from app.protocol.normalization.ike import parse_ike_layer
from app.protocol.normalization.ip import parse_ip_layer
from app.protocol.normalization.models import (
    CryptoObservationDTO,
    NormalizedFrame,
    NormalizedObservation,
    ObservationCategory,
    ParserProvenance,
    ProtocolSummaryDTO,
)
from app.protocol.tshark.binary import get_toolchain
from app.protocol.tshark.process import TSharkProcessRunner
from app.services.storage import get_storage_provider

logger = logging.getLogger(__name__)


class ProtocolForensicsService:
    """Orchestrates deterministic packet dissection, normalization, and summary generation."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.storage = get_storage_provider()
        self.runner = TSharkProcessRunner()
        self.toolchain = get_toolchain()

    async def execute_analysis(self, analysis_id: uuid.UUID) -> ProtocolSummaryDTO:
        """Execute deterministic protocol analysis on the specified AnalysisRun.

        Args:
            analysis_id: UUID of the pending or running AnalysisRun.

        Returns:
            ProtocolSummaryDTO containing normalized observed facts.

        Raises:
            AnalysisNotFoundError: If analysis record does not exist.
            ParserError: If TShark fails or capture cannot be accessed.
        """
        # 1. Fetch AnalysisRun and related Capture
        res = await self.db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
        analysis = res.scalar_one_or_none()
        if not analysis:
            raise AnalysisNotFoundError(str(analysis_id))

        res_cap = await self.db.execute(select(Capture).where(Capture.id == analysis.capture_id))
        capture = res_cap.scalar_one_or_none()
        if not capture:
            raise CaptureNotFoundError(str(analysis.capture_id))

        # 2. Update status to RUNNING
        tshark_ver = self.toolchain.get_version("tshark")
        analysis.status = "RUNNING"
        analysis.current_stage = "PROTOCOL_ANALYSIS"
        analysis.parser_engine = "tshark"
        analysis.parser_version = tshark_ver
        analysis.started_at = datetime.now(timezone.utc)
        await self.db.commit()

        # 3. Resolve capture path
        full_pcap_path = self.storage.resolve_safe_path(capture.storage_path)

        try:
            # 4. Execute TShark unprivileged dissection
            raw_packets = self.runner.run_dissection(full_pcap_path)

            # 5. Normalize packet frames
            frames, all_obs, all_crypto, counters = self._normalize_packets(
                raw_packets, str(analysis.id), tshark_ver
            )

            # 6. Check if IPsec or other network traffic was observed
            ipsec_detected = (counters["ike"] + counters["esp"] + counters["ah"]) > 0
            if ipsec_detected:
                if counters["ike"] > 0 and counters["esp"] > 0:
                    outcome = "IPSEC_OBSERVED"
                elif counters["esp"] > 0:
                    outcome = "ESP_DATAPLANE_OBSERVED"
                else:
                    outcome = "IKE_HANDSHAKE_ONLY"
            else:
                has_wg = any(o.protocol == "WireGuard" for o in all_obs)
                has_ovpn = any(o.protocol == "OpenVPN" for o in all_obs)
                has_icmp = any(o.protocol == "ICMP" for o in all_obs)
                if has_wg:
                    outcome = "WIREGUARD_OBSERVED"
                elif has_ovpn:
                    outcome = "OPENVPN_OBSERVED"
                elif has_icmp:
                    outcome = "PLAINTEXT_ICMP_OBSERVED"
                else:
                    outcome = "NON_IPSEC_TRAFFIC"

            # 7. Persist protocol observations in bulk
            if all_obs:
                db_obs_list = [
                    ProtocolObservation(
                        id=uuid.uuid4(),
                        analysis_id=analysis.id,
                        frame_number=obs.frame_number,
                        packet_time=obs.packet_time,
                        protocol=obs.protocol,
                        category=obs.category.value,
                        field_name=obs.field_name,
                        normalized_value=obs.normalized_value,
                        raw_value=obs.raw_value,
                        raw_numeric_id=obs.raw_numeric_id,
                        source_field=obs.source_field,
                        source_tool=obs.source_tool,
                        source_tool_version=obs.source_tool_version,
                        evidence_state=obs.evidence_state.value,
                        src_ip=obs.src_ip,
                        dst_ip=obs.dst_ip,
                        src_port=obs.src_port,
                        dst_port=obs.dst_port,
                        extra_attributes=obs.extra_attributes or None,
                    )
                    for obs in all_obs
                ]
                self.db.add_all(db_obs_list)

            # 8. Mark AnalysisRun as COMPLETED
            analysis.status = "COMPLETED"
            analysis.current_stage = "COMPLETED"
            analysis.completed_at = datetime.now(timezone.utc)
            await self.db.commit()

            # 9. Build and return summary DTO
            summary = self._build_summary(
                analysis_id=analysis.id,
                capture_id=capture.id,
                ipsec_detected=ipsec_detected,
                outcome=outcome,
                all_obs=all_obs,
                crypto_obs=all_crypto,
                counters=counters,
                tshark_ver=tshark_ver,
            )
            return summary

        except Exception as exc:
            logger.error(f"Analysis '{analysis_id}' failed: {exc}")
            analysis.status = "FAILED"
            analysis.current_stage = "FAILED"
            analysis.completed_at = datetime.now(timezone.utc)
            analysis.error_code = getattr(exc, "code", "PARSER_FAILED")
            analysis.error_message = str(exc)
            await self.db.commit()
            raise

    def _normalize_packets(
        self,
        raw_packets: list[dict[str, Any]],
        analysis_id: str,
        tshark_ver: str,
    ) -> tuple[
        list[NormalizedFrame],
        list[NormalizedObservation],
        list[CryptoObservationDTO],
        dict[str, int],
    ]:
        """Iterate over TShark packet layer dictionaries and extract normalized observations."""
        frames: list[NormalizedFrame] = []
        all_obs: list[NormalizedObservation] = []
        all_crypto: list[CryptoObservationDTO] = []

        seen_ike_frames: set[int] = set()
        seen_ikev1_frames: set[int] = set()
        seen_ikev2_frames: set[int] = set()
        seen_esp_frames: set[int] = set()
        seen_ah_frames: set[int] = set()
        seen_natt_frames: set[int] = set()

        for pkt in raw_packets:
            source = pkt.get("_source", {})
            layers = source.get("layers", {})
            frame_data = layers.get("frame", {})

            # Frame basics
            frame_num = int(frame_data.get("frame.number", 0))
            frame_len = int(frame_data.get("frame.len", 0))
            raw_epoch = frame_data.get("frame.time_epoch") or frame_data.get("frame.time") or "0.0"
            try:
                time_epoch = float(str(raw_epoch))
            except (ValueError, TypeError):
                try:
                    clean_iso = str(raw_epoch).rstrip("Z")
                    if "." in clean_iso:
                        pfx, frac = clean_iso.split(".", 1)
                        clean_iso = f"{pfx}.{frac[:6]}"
                    dt = datetime.fromisoformat(clean_iso)
                    time_epoch = dt.timestamp()
                except Exception:
                    time_epoch = 0.0

            # 1. IP & UDP & NAT-T layer
            src_ip, dst_ip, ip_ver, src_port, dst_port, is_natt, ip_obs = parse_ip_layer(
                layers, frame_num, time_epoch, tshark_ver
            )
            all_obs.extend(ip_obs)
            if is_natt:
                seen_natt_frames.add(frame_num)

            frame_protocols: list[str] = []
            if ip_ver:
                frame_protocols.append(ip_ver)

            # 2. IKE layer
            if "isakmp" in layers:
                seen_ike_frames.add(frame_num)
                ike_obs, crypto_obs = parse_ike_layer(
                    layers["isakmp"],
                    frame_num,
                    time_epoch,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    tshark_ver,
                )
                for io in ike_obs:
                    if io.field_name == "ike.version":
                        if io.normalized_value == "IKEv1":
                            seen_ikev1_frames.add(frame_num)
                        elif io.normalized_value == "IKEv2":
                            seen_ikev2_frames.add(frame_num)
                all_obs.extend(ike_obs)
                all_crypto.extend(crypto_obs)
                frame_protocols.append("IKE")

            # 3. ESP layer
            if "esp" in layers:
                seen_esp_frames.add(frame_num)
                esp_obs = parse_esp_layer(
                    layers["esp"],
                    frame_num,
                    time_epoch,
                    frame_len,
                    src_ip,
                    dst_ip,
                    is_natt,
                    tshark_ver,
                )
                all_obs.extend(esp_obs)
                frame_protocols.append("ESP")

            # 4. AH layer
            if "ah" in layers:
                seen_ah_frames.add(frame_num)
                ah_obs = parse_ah_layer(
                    layers["ah"],
                    frame_num,
                    time_epoch,
                    frame_len,
                    src_ip,
                    dst_ip,
                    tshark_ver,
                )
                all_obs.extend(ah_obs)
                frame_protocols.append("AH")

            # 5. Non-IPsec Transport / Application layers
            proto_str = str(layers.get("frame", {}).get("frame.protocols", ""))
            if "icmp" in layers or "icmpv6" in layers:
                frame_protocols.append("ICMP")
            if "wg" in layers or src_port == 51820 or dst_port == 51820 or "wg" in proto_str:
                frame_protocols.append("WireGuard")
            if "openvpn" in layers or src_port == 1194 or dst_port == 1194 or "openvpn" in proto_str:
                frame_protocols.append("OpenVPN")
            if "tcp" in layers and "OpenVPN" not in frame_protocols:
                frame_protocols.append("TCP")
            if "udp" in layers and not any(p in frame_protocols for p in ("IKE", "ESP", "AH", "NAT-T", "WireGuard", "OpenVPN")):
                frame_protocols.append("UDP")

            frames.append(
                NormalizedFrame(
                    frame_number=frame_num,
                    packet_time=time_epoch,
                    packet_len=frame_len,
                    protocols=frame_protocols,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ip_version=ip_ver,
                    src_port=src_port,
                    dst_port=dst_port,
                )
            )

        counters = {
            "total": len(raw_packets),
            "ike": len(seen_ike_frames),
            "ikev1": len(seen_ikev1_frames),
            "ikev2": len(seen_ikev2_frames),
            "esp": len(seen_esp_frames),
            "ah": len(seen_ah_frames),
            "natt": len(seen_natt_frames),
            "ipsec": len(seen_ike_frames | seen_esp_frames | seen_ah_frames),
        }

        return frames, all_obs, all_crypto, counters

    def _build_summary(
        self,
        analysis_id: uuid.UUID,
        capture_id: uuid.UUID,
        ipsec_detected: bool,
        outcome: str,
        all_obs: list[NormalizedObservation],
        crypto_obs: list[CryptoObservationDTO],
        counters: dict[str, int],
        tshark_ver: str,
    ) -> ProtocolSummaryDTO:
        """Synthesize normalized observations into an authoritative ProtocolSummaryDTO."""
        protocols_set = set()
        ip_versions_set = set()
        ike_versions_set = set()
        exchange_types_set = set()
        initiator_spis_set = set()
        responder_spis_set = set()
        transport_mode_observed: bool | None = None

        for obs in all_obs:
            if obs.protocol in ("IKEv1", "IKEv2", "ESP", "AH", "WireGuard", "OpenVPN", "ICMP", "TCP", "UDP"):
                protocols_set.add(obs.protocol)
            if obs.protocol in ("IPv4", "IPv6"):
                ip_versions_set.add(obs.protocol)

            if obs.field_name == "ike.version":
                ike_versions_set.add(obs.normalized_value)
            elif obs.field_name == "ike.exchange_type":
                exchange_types_set.add(obs.normalized_value)
            elif obs.field_name == "ike.initiator_spi":
                initiator_spis_set.add(obs.normalized_value)
            elif obs.field_name == "ike.responder_spi" and obs.normalized_value not in ("0000000000000000", "0"):
                responder_spis_set.add(obs.normalized_value)
            elif obs.field_name == "ike.notify.type" and obs.normalized_value == "USE_TRANSPORT_MODE":
                transport_mode_observed = True

        observed_ciphers = sorted({c.transform_name for c in crypto_obs if c.transform_type == "ENCR"})
        observed_dh = sorted({c.transform_name for c in crypto_obs if c.transform_type == "DH"})
        observed_exchanges = sorted(exchange_types_set)

        has_ike = counters.get("ike", 0) > 0
        evidence_states = {
            "cipher_suites": "VERIFIED" if observed_ciphers else "UNKNOWN",
            "dh_groups": "VERIFIED" if observed_dh else "UNKNOWN",
            "exchanges": "VERIFIED" if observed_exchanges else "UNKNOWN",
            "nat_t": "VERIFIED" if counters.get("natt", 0) > 0 else ("NOT_DETECTED" if has_ike else "NOT_OBSERVED"),
        }

        return ProtocolSummaryDTO(
            analysis_id=analysis_id,
            capture_id=capture_id,
            ipsec_detected=ipsec_detected,
            outcome=outcome,
            protocols_observed=sorted(protocols_set),
            ip_versions_observed=sorted(ip_versions_set),
            natt_observed=counters.get("natt", 0) > 0,
            packet_counts=counters,
            ike_versions_observed=sorted(ike_versions_set),
            exchange_types_observed=observed_exchanges,
            crypto_observations=crypto_obs,
            transport_mode_notify_observed=transport_mode_observed,
            parser=ParserProvenance(
                engine="tshark",
                actual_version=tshark_ver,
                schema_version="1.0.0",
            ),
            total_packets_inspected=counters.get("total", 0),
            ipsec_packet_count=counters.get("ipsec", 0),
            ikev1_packet_count=counters.get("ikev1", 0),
            ikev2_packet_count=counters.get("ikev2", 0),
            esp_packet_count=counters.get("esp", 0),
            ah_packet_count=counters.get("ah", 0),
            nat_t_detected=counters.get("natt", 0) > 0,
            observed_initiator_spis=sorted(initiator_spis_set),
            observed_responder_spis=sorted(responder_spis_set),
            observed_cipher_suites=observed_ciphers,
            observed_dh_groups=observed_dh,
            observed_exchange_types=observed_exchanges,
            evidence_states=evidence_states,
        )

    async def get_protocol_summary(self, analysis_id: uuid.UUID) -> ProtocolSummaryDTO:
        """Retrieve existing protocol summary from persisted database observations."""
        res = await self.db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
        analysis = res.scalar_one_or_none()
        if not analysis:
            raise AnalysisNotFoundError(str(analysis_id))

        # Query all observations for this analysis
        obs_res = await self.db.execute(
            select(ProtocolObservation)
            .where(ProtocolObservation.analysis_id == analysis_id)
            .order_by(ProtocolObservation.frame_number.asc())
        )
        db_obs = list(obs_res.scalars().all())

        # Reconstruct NormalizedObservation and CryptoObservationDTO
        all_obs: list[NormalizedObservation] = []
        crypto_obs: list[CryptoObservationDTO] = []
        seen_frames: set[int] = set()
        seen_ike_frames: set[int] = set()
        seen_ikev1_frames: set[int] = set()
        seen_ikev2_frames: set[int] = set()
        seen_esp_frames: set[int] = set()
        seen_ah_frames: set[int] = set()
        seen_natt_frames: set[int] = set()

        for o in db_obs:
            seen_frames.add(o.frame_number)
            if o.protocol == "IKEv1":
                seen_ike_frames.add(o.frame_number)
                seen_ikev1_frames.add(o.frame_number)
            elif o.protocol == "IKEv2":
                seen_ike_frames.add(o.frame_number)
                seen_ikev2_frames.add(o.frame_number)
            elif o.protocol == "ESP":
                seen_esp_frames.add(o.frame_number)
            elif o.protocol == "AH":
                seen_ah_frames.add(o.frame_number)
            elif o.protocol == "NAT-T":
                seen_natt_frames.add(o.frame_number)

            if o.category == "IKE_TRANSFORM":
                extra = o.extra_attributes or {}
                crypto_obs.append(
                    CryptoObservationDTO(
                        frame_number=o.frame_number,
                        transform_type=o.field_name.split(".")[-1].upper(),
                        transform_id=o.raw_numeric_id,
                        transform_name=o.normalized_value,
                        key_length_bits=extra.get("key_length_bits"),
                        evidence_state=o.evidence_state,
                    )
                )

            all_obs.append(
                NormalizedObservation(
                    frame_number=o.frame_number,
                    packet_time=o.packet_time,
                    protocol=o.protocol,
                    category=ObservationCategory(o.category),
                    field_name=o.field_name,
                    normalized_value=o.normalized_value,
                    raw_value=o.raw_value,
                    raw_numeric_id=o.raw_numeric_id,
                    source_field=o.source_field,
                    source_tool=o.source_tool,
                    source_tool_version=o.source_tool_version,
                    evidence_state=o.evidence_state,
                    src_ip=o.src_ip,
                    dst_ip=o.dst_ip,
                    src_port=o.src_port,
                    dst_port=o.dst_port,
                )
            )

        counters = {
            "total": len(seen_frames),
            "ike": len(seen_ike_frames),
            "ikev1": len(seen_ikev1_frames),
            "ikev2": len(seen_ikev2_frames),
            "esp": len(seen_esp_frames),
            "ah": len(seen_ah_frames),
            "natt": len(seen_natt_frames),
            "ipsec": len(seen_ike_frames | seen_esp_frames | seen_ah_frames),
        }
        ipsec_detected = counters["ipsec"] > 0
        outcome = "IPSEC_OBSERVED" if ipsec_detected else "NO_IPSEC_FOUND"

        return self._build_summary(
            analysis_id=analysis.id,
            capture_id=analysis.capture_id,
            ipsec_detected=ipsec_detected,
            outcome=outcome,
            all_obs=all_obs,
            crypto_obs=crypto_obs,
            counters=counters,
            tshark_ver=analysis.parser_version,
        )

