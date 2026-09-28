# Curated Test Fixtures & Manifest

This directory contains authentic lab traces, protocol baselines, and deterministic edge-case captures used to rigorously verify the TunnelTrace AI platform without modifying production or demo databases.

| ID | Filename | Format | Size (B) | Packets | Category | SHA-256 | Expected Disposition |
|---|---|---|---|---|---|---|---|
| `FIX-VERIF-01-IKEV2-GCM` | `01_strongswan_ikev2_esp_aes_gcm.pcapng` | PCAPNG (pcapng_shb) | 3048 | 12 | GENUINE_IPSEC_TUNNEL | `949531329196...` | Score: 100, Cov: 85.7% (6/7 assessed, 1 unknown) |
| `FIX-VERIF-02-ESP-ONLY` | `02_strongswan_esp_only_partial.pcapng` | PCAPNG (pcapng_shb) | 1588 | 8 | PARTIAL_EVIDENCE | `76b74be5fc6e...` | Score: 100, Cov: 14.3% (1/7 assessed, 6 unknown) |
| `FIX-VERIF-03-NATT-UDP4500` | `03_strongswan_natt_udp4500.pcap` | PCAP (pcap_usec_le) | 2838 | 12 | GENUINE_IPSEC_TUNNEL | `7b63a0fd4552...` | Score: 100, Cov: 85.7% |
| `FIX-VERIF-04-PLAINTEXT-ICMP` | `04_plaintext_icmp_non_ipsec.pcap` | PCAP (pcap_usec_le) | 1108 | 10 | NON_IPSEC_BASELINE | `b37aa527dd51...` | NO_IPSEC_FOUND |
| `FIX-VERIF-05-WIREGUARD` | `05_wireguard_tunnel_non_ipsec.pcapng` | PCAPNG (pcapng_shb) | 5912 | 22 | NON_IPSEC_BASELINE | `39785eb5e094...` | NOT_IPSEC |
| `FIX-VERIF-06-OPENVPN-CHAT` | `06_openvpn_chat_sample_non_ipsec.pcap` | PCAP (pcap_usec_le) | 14163 | 50 | NON_IPSEC_BASELINE | `2d50afea4943...` | NOT_IPSEC / INSUFFICIENT_EVIDENCE |
| `FIX-VERIF-07-TRUNCATED-FRAME` | `07_edge_truncated_pcap_frame.pcap` | PCAP (pcap_usec_le) | 56 | N/A | EDGE_CASE_PARSER_INTEGRITY | `bddfc3c80c07...` | PASS |
| `FIX-VERIF-08-CORRUPTED-MAGIC` | `08_edge_corrupted_magic_bytes.pcap` | REJECTED (CAPTURE_INVALID_FORMAT) | 46 | N/A | EDGE_CASE_VALIDATION_REJECTION | `bb50b43e626c...` | CAPTURE_INVALID_FORMAT |
| `FIX-VERIF-09-CORRUPTED-SPI-ZERO` | `09_edge_corrupted_spi_zero.pcap` | PCAP (pcap_usec_le) | 2838 | 12 | EDGE_CASE_SECURITY_ANOMALY | `c41784ea9b5c...` | PASS |
| `FIX-VERIF-10-ESP-SEQ-REPLAY` | `10_edge_esp_seq_jump_replay.pcap` | PCAP (pcap_usec_le) | 2838 | 12 | EDGE_CASE_SECURITY_ANOMALY | `f0cb561a3be5...` | PASS |

## Detailed Fixture Specifications

### `FIX-VERIF-01-IKEV2-GCM`: 01_strongswan_ikev2_esp_aes_gcm.pcapng
- **Category**: `GENUINE_IPSEC_TUNNEL`
- **Provenance / Source**: strongSwan Lab (scn-01-tunnel-v4-gcm-pfs)
- **SHA-256**: `949531329196d1fbc836ee0685efe8a204c68d6d8da5a5b75ecaa0128c59e04d`
- **Size**: 3048 bytes
- **Packet Count**: 12
- **Format Validation**: `PCAPNG (pcapng_shb)`
- **Description**: Full strongSwan IKEv2 negotiation and ESP AES-GCM data transfer.
- **Expected Analytical Behavior**:
  - **validation**: `PASS`
  - **ipsec_detected**: `True`
  - **ike_version**: `IKEv2`
  - **esp_detected**: `True`
  - **encryption**: `AES-GCM-16-256`
  - **dh_group**: `ECP-256 (DH19)`
  - **expected_score**: `100`
  - **evidence_coverage**: `85.7% (6/7 assessed, 1 unknown)`
  - **traffic_ml_disposition**: `OUT_OF_DISTRIBUTION (OOD Abstention) or low confidence`

### `FIX-VERIF-02-ESP-ONLY`: 02_strongswan_esp_only_partial.pcapng
- **Category**: `PARTIAL_EVIDENCE`
- **Provenance / Source**: strongSwan Lab (frames 5-12 isolated)
- **SHA-256**: `76b74be5fc6e60d931c1bcf959360c84b59d7f70bada30b46af8938bff339bdd`
- **Size**: 1588 bytes
- **Packet Count**: 8
- **Format Validation**: `PCAPNG (pcapng_shb)`
- **Description**: ESP ciphertext frames only without preceding IKE negotiation handshake.
- **Expected Analytical Behavior**:
  - **validation**: `PASS`
  - **ipsec_detected**: `True`
  - **ike_version**: `None`
  - **esp_detected**: `True`
  - **expected_score**: `100`
  - **evidence_coverage**: `14.3% (1/7 assessed, 6 unknown)`
  - **traffic_ml_disposition**: `PARTIAL_METADATA_EXTRACTED`

### `FIX-VERIF-03-NATT-UDP4500`: 03_strongswan_natt_udp4500.pcap
- **Category**: `GENUINE_IPSEC_TUNNEL`
- **Provenance / Source**: strongSwan Lab (scn-06-tunnel-v4-natt)
- **SHA-256**: `7b63a0fd455202ac286de8d5c1dd8e499fc988680b9bdcb6c8afe6567f7f21fa`
- **Size**: 2838 bytes
- **Packet Count**: 12
- **Format Validation**: `PCAP (pcap_usec_le)`
- **Description**: IKEv2 negotiation migrating from UDP 500 to UDP 4500 with UDP-encapsulated ESP.
- **Expected Analytical Behavior**:
  - **validation**: `PASS`
  - **ipsec_detected**: `True`
  - **natt_detected**: `True`
  - **esp_encapsulation**: `UDP_ENCAPSULATED_ESP`
  - **udp_port**: `4500`
  - **expected_score**: `100`
  - **evidence_coverage**: `85.7%`

### `FIX-VERIF-04-PLAINTEXT-ICMP`: 04_plaintext_icmp_non_ipsec.pcap
- **Category**: `NON_IPSEC_BASELINE`
- **Provenance / Source**: strongSwan Lab (client plaintext probe)
- **SHA-256**: `b37aa527dd51c80a1b003cc305f56bc77f53ba44da0ec3d4144fc29efb1ad61c`
- **Size**: 1108 bytes
- **Packet Count**: 10
- **Format Validation**: `PCAP (pcap_usec_le)`
- **Description**: Plaintext ICMP echo requests and replies before IPsec tunnel establishment.
- **Expected Analytical Behavior**:
  - **validation**: `PASS`
  - **ipsec_detected**: `False`
  - **disposition**: `NO_IPSEC_FOUND`
  - **expected_score**: `None`
  - **evidence_coverage**: `0.0%`

### `FIX-VERIF-05-WIREGUARD`: 05_wireguard_tunnel_non_ipsec.pcapng
- **Category**: `NON_IPSEC_BASELINE`
- **Provenance / Source**: Controlled Capture (WireGuard ping tcp)
- **SHA-256**: `39785eb5e094d2ad57163d3b7f8ab009a3934c978c76c8ff0e012b01817e1e41`
- **Size**: 5912 bytes
- **Packet Count**: 22
- **Format Validation**: `PCAPNG (pcapng_shb)`
- **Description**: Non-IPsec VPN traffic consisting of WireGuard handshake and encrypted transport.
- **Expected Analytical Behavior**:
  - **validation**: `PASS`
  - **ipsec_detected**: `False`
  - **disposition**: `NOT_IPSEC`
  - **protocol**: `WIREGUARD`

### `FIX-VERIF-06-OPENVPN-CHAT`: 06_openvpn_chat_sample_non_ipsec.pcap
- **Category**: `NON_IPSEC_BASELINE`
- **Provenance / Source**: Controlled Capture (OpenVPN application session sample)
- **SHA-256**: `2d50afea494353b793a8b03074ec7905c93e10f5028b73136e8b4a8796c50439`
- **Size**: 14163 bytes
- **Packet Count**: 50
- **Format Validation**: `PCAP (pcap_usec_le)`
- **Description**: Non-IPsec VPN capture containing OpenVPN transport frames.
- **Expected Analytical Behavior**:
  - **validation**: `PASS`
  - **ipsec_detected**: `False`
  - **disposition**: `NOT_IPSEC / INSUFFICIENT_EVIDENCE`
  - **protocol**: `OPENVPN`

### `FIX-VERIF-07-TRUNCATED-FRAME`: 07_edge_truncated_pcap_frame.pcap
- **Category**: `EDGE_CASE_PARSER_INTEGRITY`
- **Provenance / Source**: Synthetic deterministic generation
- **SHA-256**: `bddfc3c80c0782c663360d86d20ee98fdc2c8838c15803d25219c650a0dacfe7`
- **Size**: 56 bytes
- **Packet Count**: N/A
- **Format Validation**: `PCAP (pcap_usec_le)`
- **Description**: PCAP with truncated frame length to verify parser doesn't crash on incomplete frames.
- **Expected Analytical Behavior**:
  - **validation**: `PASS (Header valid) / Parser handled safely`
  - **error_handling**: `GRACEFUL_TRUNCATION_HANDLING`

### `FIX-VERIF-08-CORRUPTED-MAGIC`: 08_edge_corrupted_magic_bytes.pcap
- **Category**: `EDGE_CASE_VALIDATION_REJECTION`
- **Provenance / Source**: Synthetic deterministic generation
- **SHA-256**: `bb50b43e626c510d9c19c981f4141a61a7586de22febabb8e29b4a9a165730af`
- **Size**: 46 bytes
- **Packet Count**: N/A
- **Format Validation**: `REJECTED (CAPTURE_INVALID_FORMAT)`
- **Description**: Non-PCAP binary header to verify upload endpoint rejects invalid magic bytes.
- **Expected Analytical Behavior**:
  - **validation**: `FAIL`
  - **error_code**: `CAPTURE_INVALID_FORMAT`
  - **http_status**: `400`

### `FIX-VERIF-09-CORRUPTED-SPI-ZERO`: 09_edge_corrupted_spi_zero.pcap
- **Category**: `EDGE_CASE_SECURITY_ANOMALY`
- **Provenance / Source**: Synthetic mutation from strongSwan NAT-T
- **SHA-256**: `c41784ea9b5cffcbc110ea9ef7b8ec3a17fdada8e776049b201d011317d57c81`
- **Size**: 2838 bytes
- **Packet Count**: 12
- **Format Validation**: `PCAP (pcap_usec_le)`
- **Description**: ESP packet with SPI = 0x00000000 violating RFC 4303 Section 2.1.
- **Expected Analytical Behavior**:
  - **validation**: `PASS`
  - **ipsec_detected**: `True`
  - **anomaly_flag**: `RFC_4303_RESERVED_SPI_ZERO`

### `FIX-VERIF-10-ESP-SEQ-REPLAY`: 10_edge_esp_seq_jump_replay.pcap
- **Category**: `EDGE_CASE_SECURITY_ANOMALY`
- **Provenance / Source**: Synthetic mutation from strongSwan NAT-T
- **SHA-256**: `f0cb561a3be595b59b21aac8f67b746251370faa105d91e0c5b31886ea879790`
- **Size**: 2838 bytes
- **Packet Count**: 12
- **Format Validation**: `PCAP (pcap_usec_le)`
- **Description**: ESP frame sequence jump / replay (sequence number duplicate).
- **Expected Analytical Behavior**:
  - **validation**: `PASS`
  - **ipsec_detected**: `True`
  - **anomaly_flag**: `ESP_SEQUENCE_REPLAY_DETECTED`

