import sqlite3

conn = sqlite3.connect('backend/soc_dev.sqlite')
cur = conn.cursor()

run_id = '9a79a13be0a746e4ad40d1c67debf4fe'
cur.execute('SELECT id, capture_id, status, schema_version, parser_version, replay_mode, provenance_metadata, created_at FROM analysis_runs WHERE id=?', (run_id,))
print("RUN:", cur.fetchone())

cur.execute('SELECT id, initiator_ip, responder_ip, initiator_spi, responder_spi, packet_count, evidence_state FROM ike_sessions WHERE analysis_id=?', (run_id,))
print("IKE SESSIONS:", cur.fetchall())

cur.execute('SELECT id, inbound_spi, outbound_spi, protocol, mode, mode_evidence_state, evidence_state FROM child_security_associations WHERE analysis_id=?', (run_id,))
print("CHILD SAS:", cur.fetchall())

cur.execute('SELECT id, spi, reverse_spi, src_ip, dst_ip, packet_count, byte_count, forward_packets, reverse_packets FROM esp_flows WHERE analysis_id=?', (run_id,))
print("ESP FLOWS:", cur.fetchall())
