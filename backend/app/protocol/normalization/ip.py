"""Deterministic normalization for IPv4, IPv6, UDP, and NAT-Traversal."""

import logging
from typing import Any

from app.protocol.normalization.models import (
    EvidenceState,
    NormalizedObservation,
    ObservationCategory,
)

logger = logging.getLogger(__name__)


def parse_ip_layer(
    layers: dict[str, Any],
    frame_number: int,
    packet_time: float,
    tool_version: str,
) -> tuple[str | None, str | None, str | None, int | None, int | None, bool, list[NormalizedObservation]]:
    """Parse outer IP and UDP/NAT-T layers from TShark layers dictionary.

    Returns:
        tuple of (src_ip, dst_ip, ip_version, src_port, dst_port, is_natt, observations)
    """
    observations: list[NormalizedObservation] = []
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    is_natt = False

    frame_dict = layers.get("frame", {})
    frame_len_val = None
    if isinstance(frame_dict, dict):
        frame_len_val = frame_dict.get("frame.len")
    if frame_len_val is None and "frame.len" in layers:
        frame_len_val = layers.get("frame.len")
    try:
        frame_len_int = int(frame_len_val) if frame_len_val is not None else 64
    except (ValueError, TypeError):
        frame_len_int = 64
    extra_attrs = {"packet_len_bytes": frame_len_int, "frame_len": frame_len_int}

    # 1. IPv4 Check
    if "ip" in layers:
        ip_data = layers["ip"]
        if isinstance(ip_data, list):
            ip_data = ip_data[0] if ip_data else {}
        ip_version = "IPv4"
        src_ip = ip_data.get("ip.src") or ip_data.get("ip.addr")
        dst_ip = ip_data.get("ip.dst")

        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol="IPv4",
                category=ObservationCategory.IPV4,
                field_name="ip.version",
                normalized_value="IPv4",
                source_field="ip.version",
                source_tool_version=tool_version,
                src_ip=src_ip,
                dst_ip=dst_ip,
                extra_attributes=extra_attrs,
            )
        )

    # 2. IPv6 Check
    elif "ipv6" in layers:
        ipv6_data = layers["ipv6"]
        if isinstance(ipv6_data, list):
            ipv6_data = ipv6_data[0] if ipv6_data else {}
        ip_version = "IPv6"
        src_ip = ipv6_data.get("ipv6.src") or ipv6_data.get("ipv6.addr")
        dst_ip = ipv6_data.get("ipv6.dst")

        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol="IPv6",
                category=ObservationCategory.IPV6,
                field_name="ipv6.version",
                normalized_value="IPv6",
                source_field="ipv6.version",
                source_tool_version=tool_version,
                src_ip=src_ip,
                dst_ip=dst_ip,
                extra_attributes=extra_attrs,
            )
        )

    # 3. UDP & Transport Protocol Checks
    if "udp" in layers:
        udp_data = layers["udp"]
        if isinstance(udp_data, list):
            udp_data = udp_data[0] if udp_data else {}
        s_port_raw = udp_data.get("udp.srcport")
        d_port_raw = udp_data.get("udp.dstport")
        try:
            src_port = int(str(s_port_raw)) if s_port_raw else None
            dst_port = int(str(d_port_raw)) if d_port_raw else None
        except (ValueError, TypeError):
            pass

        # Check NAT-Traversal port 4500 or udpencap
        proto_str = str(layers.get("frame", {}).get("frame.protocols", ""))
        if (
            src_port == 4500
            or dst_port == 4500
            or "udpencap" in layers
            or "udpencap" in proto_str
        ):
            is_natt = True
            observations.append(
                NormalizedObservation(
                    frame_number=frame_number,
                    packet_time=packet_time,
                    protocol="NAT-T",
                    category=ObservationCategory.NAT_T,
                    field_name="natt.detected",
                    normalized_value="UDP_PORT_4500_ENCAPSULATION",
                    raw_value=f"src={src_port},dst={dst_port}",
                    source_field="udp.port / udpencap",
                    source_tool_version=tool_version,
                    evidence_state=EvidenceState.VERIFIED,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                )
            )
        elif "wg" in layers or src_port == 51820 or dst_port == 51820 or "wg" in proto_str:
            observations.append(
                NormalizedObservation(
                    frame_number=frame_number,
                    packet_time=packet_time,
                    protocol="WireGuard",
                    category=ObservationCategory.NON_IPSEC,
                    field_name="wireguard.detected",
                    normalized_value="WIREGUARD_VPN_TRAFFIC",
                    raw_value=f"port={src_port or dst_port}",
                    source_field="udp.port / wg",
                    source_tool_version=tool_version,
                    evidence_state=EvidenceState.VERIFIED,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                )
            )
        elif "openvpn" in layers or src_port == 1194 or dst_port == 1194 or "openvpn" in proto_str:
            observations.append(
                NormalizedObservation(
                    frame_number=frame_number,
                    packet_time=packet_time,
                    protocol="OpenVPN",
                    category=ObservationCategory.NON_IPSEC,
                    field_name="openvpn.detected",
                    normalized_value="OPENVPN_TUNNEL_TRAFFIC",
                    raw_value=f"port={src_port or dst_port}",
                    source_field="udp.port / openvpn",
                    source_tool_version=tool_version,
                    evidence_state=EvidenceState.VERIFIED,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                )
            )
        else:
            observations.append(
                NormalizedObservation(
                    frame_number=frame_number,
                    packet_time=packet_time,
                    protocol="UDP",
                    category=ObservationCategory.UDP,
                    field_name="udp.port",
                    normalized_value=f"{src_port}->{dst_port}",
                    raw_value=f"src={src_port},dst={dst_port}",
                    source_field="udp.srcport,udp.dstport",
                    source_tool_version=tool_version,
                    evidence_state=EvidenceState.VERIFIED,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                )
            )

    # 4. TCP Check
    elif "tcp" in layers:
        tcp_data = layers["tcp"]
        if isinstance(tcp_data, list):
            tcp_data = tcp_data[0] if tcp_data else {}
        s_port_raw = tcp_data.get("tcp.srcport")
        d_port_raw = tcp_data.get("tcp.dstport")
        try:
            src_port = int(str(s_port_raw)) if s_port_raw else None
            dst_port = int(str(d_port_raw)) if d_port_raw else None
        except (ValueError, TypeError):
            pass

        proto_str = str(layers.get("frame", {}).get("frame.protocols", ""))
        if "openvpn" in layers or src_port == 1194 or dst_port == 1194 or "openvpn" in proto_str:
            observations.append(
                NormalizedObservation(
                    frame_number=frame_number,
                    packet_time=packet_time,
                    protocol="OpenVPN",
                    category=ObservationCategory.NON_IPSEC,
                    field_name="openvpn.detected",
                    normalized_value="OPENVPN_TCP_TUNNEL_TRAFFIC",
                    raw_value=f"port={src_port or dst_port}",
                    source_field="tcp.port / openvpn",
                    source_tool_version=tool_version,
                    evidence_state=EvidenceState.VERIFIED,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    extra_attributes=extra_attrs,
                )
            )
        else:
            observations.append(
                NormalizedObservation(
                    frame_number=frame_number,
                    packet_time=packet_time,
                    protocol="TCP",
                    category=ObservationCategory.TCP,
                    field_name="tcp.port",
                    normalized_value=f"{src_port}->{dst_port}",
                    raw_value=f"src={src_port},dst={dst_port}",
                    source_field="tcp.srcport,tcp.dstport",
                    source_tool_version=tool_version,
                    evidence_state=EvidenceState.VERIFIED,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    extra_attributes=extra_attrs,
                )
            )

    # 5. ICMP / ICMPv6 Check
    if "icmp" in layers or "icmpv6" in layers:
        icmp_data = layers.get("icmp") or layers.get("icmpv6") or {}
        if isinstance(icmp_data, list):
            icmp_data = icmp_data[0] if icmp_data else {}
        itype = icmp_data.get("icmp.type") or icmp_data.get("icmpv6.type") or "ECHO"
        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol="ICMP",
                category=ObservationCategory.ICMP,
                field_name="icmp.type",
                normalized_value=str(itype),
                raw_value="PLAINTEXT_ICMP_FRAME",
                source_field="icmp.type",
                source_tool_version=tool_version,
                evidence_state=EvidenceState.VERIFIED,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                extra_attributes=extra_attrs,
            )
        )

    return src_ip, dst_ip, ip_version, src_port, dst_port, is_natt, observations
