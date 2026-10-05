"""ESP Flow Aggregator: Aggregates directional streams and pairs bidirectional encrypted flows."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from app.db.models.capture import ProtocolObservation
from app.reconstruction.models import (
    FlowAssociationState,
    FlowEndReason,
    OrientationBasis,
    ReconstructedChildSA,
    ReconstructedESPFlow,
    ReconstructedESPStream,
)

# Configurable defaults (empirical implementation defaults, not standards requirements)
DEFAULT_FLOW_IDLE_TIMEOUT_SEC: float = 15.0
DEFAULT_FLOW_MAX_DURATION_SEC: float = 300.0


class ESPFlowAggregator:
    """Aggregates individual ESP packets into statistical flows while preserving SA directionality."""

    def __init__(
        self,
        analysis_id: uuid.UUID,
        idle_timeout_sec: float = DEFAULT_FLOW_IDLE_TIMEOUT_SEC,
        max_duration_sec: float = DEFAULT_FLOW_MAX_DURATION_SEC,
    ) -> None:
        self.analysis_id = analysis_id
        self.idle_timeout_sec = idle_timeout_sec
        self.max_duration_sec = max_duration_sec

    def extract_packets(
        self, observations: list[ProtocolObservation]
    ) -> list[dict[str, Any]]:
        """Extract frame-level packet metadata supporting ESP, NAT-T, and non-IPsec flows."""
        packets_by_frame: dict[int, dict[str, Any]] = {}
        has_esp = any(obs.protocol in ("ESP", "NAT-T") for obs in observations)

        for obs in observations:
            if has_esp and obs.protocol not in ("ESP", "NAT-T"):
                continue

            fn = obs.frame_number
            if fn not in packets_by_frame:
                ip_ver = "IPv6" if (obs.src_ip and ":" in obs.src_ip) else "IPv4"
                packets_by_frame[fn] = {
                    "frame_number": fn,
                    "packet_time": obs.packet_time,
                    "spi": None,
                    "sequence_number": None,
                    "packet_length": 0,
                    "src_ip": obs.src_ip or "0.0.0.0",
                    "dst_ip": obs.dst_ip or "0.0.0.0",
                    "ip_version": ip_ver,
                    "is_nat_t": False,
                    "protocol": obs.protocol or "IP",
                }

            p = packets_by_frame[fn]
            if obs.protocol == "NAT-T" or obs.src_port == 4500 or obs.dst_port == 4500 or obs.field_name == "natt.detected":
                p["is_nat_t"] = True

            # Extract packet length from extra_attributes if present
            if obs.extra_attributes and isinstance(obs.extra_attributes, dict):
                len_val = (
                    obs.extra_attributes.get("packet_len_bytes")
                    or obs.extra_attributes.get("length")
                    or obs.extra_attributes.get("frame_len")
                )
                if len_val is not None:
                    try:
                        p["packet_length"] = int(len_val)
                    except (ValueError, TypeError):
                        pass

            if obs.field_name == "esp.spi":
                p["spi"] = obs.normalized_value.lower()
            elif obs.field_name == "esp.sequence":
                try:
                    p["sequence_number"] = int(obs.normalized_value)
                except (ValueError, TypeError):
                    pass
            elif obs.field_name in ("esp.packet_length", "esp.length", "frame.len"):
                try:
                    p["packet_length"] = int(obs.normalized_value or obs.raw_value or 0)
                except (ValueError, TypeError):
                    pass
            elif obs.field_name == "icmp.seq":
                try:
                    p["sequence_number"] = int(obs.normalized_value or obs.raw_value or 0)
                except (ValueError, TypeError):
                    pass

        # For non-ESP observations, assign synthetic SPI based on protocol and flow endpoints
        if not has_esp:
            for fn, p in packets_by_frame.items():
                if p["spi"] is None:
                    proto_tag = (p.get("protocol") or "NET").lower()
                    flow_hash = hashlib.md5(f"{proto_tag}:{p['src_ip']}:{p['dst_ip']}".encode()).hexdigest()[:8]
                    p["spi"] = f"0x{flow_hash}"
                if p["sequence_number"] is None:
                    p["sequence_number"] = fn

        # Ensure packet length has reasonable non-zero fallback
        for p in packets_by_frame.values():
            if not p["packet_length"] or p["packet_length"] <= 0:
                p["packet_length"] = 64

        # Sort packets by packet_time
        sorted_pkts = [
            p for p in packets_by_frame.values() if p["spi"] is not None and p["packet_length"] > 0
        ]
        sorted_pkts.sort(key=lambda p: (p["packet_time"], p["frame_number"]))
        return sorted_pkts

    def build_directional_streams(
        self, packets: list[dict[str, Any]]
    ) -> list[ReconstructedESPStream]:
        """Group packets into directional streams with idle timeout boundary enforcement."""
        streams: list[ReconstructedESPStream] = []
        active_streams: dict[tuple[str, str, str], ReconstructedESPStream] = {}

        for pkt in packets:
            key = (pkt["src_ip"], pkt["dst_ip"], pkt["spi"])

            if key in active_streams:
                curr = active_streams[key]
                # Check idle timeout boundary
                if (pkt["packet_time"] - curr.end_time) > self.idle_timeout_sec:
                    streams.append(curr)
                    # Start new stream generation
                    active_streams[key] = ReconstructedESPStream(
                        spi=pkt["spi"],
                        src_ip=pkt["src_ip"],
                        dst_ip=pkt["dst_ip"],
                        ip_version=pkt["ip_version"],
                        is_nat_t=pkt["is_nat_t"],
                        start_time=pkt["packet_time"],
                        end_time=pkt["packet_time"],
                        packet_count=1,
                        byte_count=pkt["packet_length"],
                        sequence_numbers=[pkt["sequence_number"]] if pkt["sequence_number"] is not None else [],
                        frame_numbers=[pkt["frame_number"]],
                    )
                else:
                    curr.packet_count += 1
                    curr.byte_count += pkt["packet_length"]
                    curr.end_time = pkt["packet_time"]
                    if pkt["sequence_number"] is not None:
                        curr.sequence_numbers.append(pkt["sequence_number"])
                    curr.frame_numbers.append(pkt["frame_number"])
                    if pkt["is_nat_t"]:
                        curr.is_nat_t = True
            else:
                active_streams[key] = ReconstructedESPStream(
                    spi=pkt["spi"],
                    src_ip=pkt["src_ip"],
                    dst_ip=pkt["dst_ip"],
                    ip_version=pkt["ip_version"],
                    is_nat_t=pkt["is_nat_t"],
                    start_time=pkt["packet_time"],
                    end_time=pkt["packet_time"],
                    packet_count=1,
                    byte_count=pkt["packet_length"],
                    sequence_numbers=[pkt["sequence_number"]] if pkt["sequence_number"] is not None else [],
                    frame_numbers=[pkt["frame_number"]],
                )

        streams.extend(active_streams.values())
        return streams

    def pair_flows(
        self,
        streams: list[ReconstructedESPStream],
        child_sas: list[ReconstructedChildSA],
    ) -> list[ReconstructedESPFlow]:
        """Pair directional streams into bidirectional flows or preserve as unidirectional."""
        flows: list[ReconstructedESPFlow] = []
        consumed_streams: set[int] = set()

        # Build Child SA lookup by (inbound_spi, outbound_spi)
        child_sa_by_spis = {}
        for csa in child_sas:
            if csa.outbound_spi:
                child_sa_by_spis[(csa.inbound_spi, csa.outbound_spi)] = csa
                child_sa_by_spis[(csa.outbound_spi, csa.inbound_spi)] = csa
            else:
                child_sa_by_spis[(csa.inbound_spi, None)] = csa

        # 1. First pass: Pair streams matching Child SA known SPI pairs
        for i, s1 in enumerate(streams):
            if i in consumed_streams:
                continue

            paired_j = None
            matched_csa = None

            for j in range(i + 1, len(streams)):
                if j in consumed_streams:
                    continue
                s2 = streams[j]
                if s1.src_ip == s2.dst_ip and s1.dst_ip == s2.src_ip:
                    # Check if matching Child SA links them
                    if (s1.spi, s2.spi) in child_sa_by_spis:
                        paired_j = j
                        matched_csa = child_sa_by_spis[(s1.spi, s2.spi)]
                        break
                    # Or reverse endpoint correlation between same hosts ONLY if neither SPI has a conflicting known Child SA
                    known_spis = {csa.inbound_spi for csa in child_sas if csa.inbound_spi} | {csa.outbound_spi for csa in child_sas if csa.outbound_spi}
                    if paired_j is None and not (s1.spi in known_spis or s2.spi in known_spis):
                        paired_j = j

            if paired_j is not None:
                s2 = streams[paired_j]
                consumed_streams.add(i)
                consumed_streams.add(paired_j)

                # Determine forward stream based on first packet timestamp
                if s1.start_time <= s2.start_time:
                    fwd, rev = s1, s2
                else:
                    fwd, rev = s2, s1

                start_t = min(fwd.start_time, rev.start_time)
                end_t = max(fwd.end_time, rev.end_time)

                flow = ReconstructedESPFlow(
                    id=uuid.uuid4(),
                    analysis_id=self.analysis_id,
                    child_sa_id=matched_csa.id if matched_csa else None,
                    spi=fwd.spi,
                    reverse_spi=rev.spi,
                    src_ip=fwd.src_ip,
                    dst_ip=fwd.dst_ip,
                    ip_version=fwd.ip_version,
                    is_nat_t=fwd.is_nat_t or rev.is_nat_t,
                    orientation_basis=OrientationBasis.FIRST_SEEN,
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=max(0.0, end_t - start_t),
                    packet_count=fwd.packet_count + rev.packet_count,
                    byte_count=fwd.byte_count + rev.byte_count,
                    forward_packets=fwd.packet_count,
                    forward_bytes=fwd.byte_count,
                    reverse_packets=rev.packet_count,
                    reverse_bytes=rev.byte_count,
                    association_state=FlowAssociationState.PAIRED_BIDIRECTIONAL,
                    end_reason=FlowEndReason.CAPTURE_ENDED,
                )
                flows.append(flow)
            else:
                # Unpaired unidirectional stream
                consumed_streams.add(i)
                flow = ReconstructedESPFlow(
                    id=uuid.uuid4(),
                    analysis_id=self.analysis_id,
                    child_sa_id=None,
                    spi=s1.spi,
                    reverse_spi=None,
                    src_ip=s1.src_ip,
                    dst_ip=s1.dst_ip,
                    ip_version=s1.ip_version,
                    is_nat_t=s1.is_nat_t,
                    orientation_basis=OrientationBasis.FIRST_SEEN,
                    start_time=s1.start_time,
                    end_time=s1.end_time,
                    duration_seconds=max(0.0, s1.end_time - s1.start_time),
                    packet_count=s1.packet_count,
                    byte_count=s1.byte_count,
                    forward_packets=s1.packet_count,
                    forward_bytes=s1.byte_count,
                    reverse_packets=0,
                    reverse_bytes=0,
                    association_state=FlowAssociationState.UNPAIRED_UNIDIRECTIONAL,
                    end_reason=FlowEndReason.CAPTURE_ENDED,
                )
                flows.append(flow)

        return flows
