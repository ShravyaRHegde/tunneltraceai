# TunnelTrace AI — Master End-to-End Context & Operational Handover
**Target Audience:** Autonomous Coding Agents & Core Developers (Antigravity CLI / Antigravity Agent Runtime)  
**System Reference:** Smart India Hackathon 2026 / Problem Statement ID: `26160` (PS 160)  
**Sponsoring Organization:** National Technical Research Organisation (NTRO)  
**Classification:** Confidential / Sovereign Network Defense & Security Assessment  
**Repository Path:** `c:\SHARAN PROJECTS\TunnelTrace AI`  

---

## 1. Executive Summary & Problem Statement (The "Why")

### Problem Statement 26160 Context
- **Title:** *AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework*
- **Sponsoring Body:** National Technical Research Organisation (NTRO).
- **Core Challenge:** IPsec VPNs form the sovereign backbone of military, governmental, and critical infrastructure communications. However, security operations centers (SOCs) face four critical blind spots:
  1. **Encrypted Payload Blindness:** Once ESP (Encapsulating Security Payload) encryption is negotiated, deep packet inspection (DPI) fails. Analysts cannot tell whether a tunnel carries command-and-control (C2), data exfiltration, or legitimate VoIP/HTTPS without decrypting inner payloads (which breaks privacy or is cryptographically impossible).
  2. **Complex Protocol Misconfiguration & Downgrades:** IKEv1/IKEv2 negotiations involve hundreds of cryptographic proposal permutations (encryption algorithms, PRFs, integrity checksums, Diffie-Hellman groups). Administrators inadvertently allow deprecated ciphers (e.g., 3DES, DES, Blowfish, RC4, MD5, SHA-1, DH groups 1, 2, 5) or disable Perfect Forward Secrecy (PFS), exposing encrypted historical traffic to quantum or key-compromise retrospective decryption.
  3. **Lack of Closed-Loop Remediation:** Existing scanners point out flaws in configuration or PCAPs but do not prove that fixing them works without bringing down critical production tunnels or causing negotiation regressions.
  4. **Forensic Unreliability & AI Hallucinations:** Generic security dashboards often invent scan findings or rely on ungrounded LLMs that hallucinate RFC compliance or tamper with forensic evidence chains.

### The TunnelTrace AI Solution
TunnelTrace AI is an enterprise-grade, evidence-first **IPsec Security Intelligence and Protocol Forensics Framework**. It:
1. Ingests raw `.pcap` / `.pcapng` packet captures or taps live network interfaces.
2. Dissects IKEv1, IKEv2, ESP, AH, and NAT-Traversal without modifying wire facts.
3. Reconstructs stateful Security Associations (SAs) and directional ESP flows into an interactive hierarchical DAG.
4. Classifies inner encrypted applications **strictly without payload decryption** using early-packet timing and size bursts fed into calibrated Machine Learning (Lightweight 1D-CNN + BiLSTM + Temperature Scaling + OOD gating).
5. Deterministically audits cryptographic configurations against normative standards (NIST SP 800-77 Rev. 1, RFC 8221, RFC 7296, RFC 8247, RFC 4301) using pure Kleene 3-valued logic.
6. Projections fixes through a **Configuration Security Twin**, generating syntactically valid strongSwan (`swanctl.conf`) remediations.
7. Validates remediations in a closed-loop Linux namespace testbed before operator deployment.
8. Provides a local, citation-grounded **AI Analyst** powered by Ollama that only explains verified facts and normative text, with zero authority to invent findings.

---

## 2. System Architecture & End-to-End Pipeline

The processing pipeline is organized into deterministic stages where each stage consumes artifacts from prior stages and emits cryptographically signed, immutable records.

```
  [ Raw Capture: PCAP / PCAPNG ]  (Stage 3: Ingestion & Integrity Hash)
                 │
                 ▼
  [ Protocol Forensics Dissector ] (Stage 3: TShark / PyShark Streaming)
                 │
                 ▼
  [ SA & ESP Flow Reconstruction ] (Stage 4: IKE Sessions, Child SAs, SPI Pairs)
                 │
                 ├───────────────────────────────────────┐
                 ▼                                       ▼
  [ Encrypted Traffic ML Engine ]             [ Security & Policy Engine ]
  - 1D-CNN + BiLSTM Sequence Features         - NIST SP 800-77 / RFC Rules
  - Flow Burst Extraction (Size/Timing)       - Pure Kleene 3-Valued Logic
  - Temperature Scaling Calibration           - 0-100 Deduction Scoring
  - Shannon Entropy OOD Gate                  - Threat Matrix THR-001..008
  - Isolation Forest Anomaly Gate             - Metadata Fingerprintability
  (Stage 6/7/17: Decoupled & Honest)          (Stage 8: Deterministic Engine)
                 │                                       │
                 └───────────────────┬───────────────────┘
                                     ▼
                      [ Evidence DAG & Forensic Ledger ]
                      - SHA-256 Provenance Manifest
                      - Cryptographic Fact Nodes
                      - Parent-Child Replay Comparison
                      (Stage 8, 18)
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
  [ Configuration Security Twin ]             [ Epistemic AI Analyst ]
  - Typed Configuration IR                    - Local RAG (Ollama / Qwen)
  - strongSwan (swanctl.conf) Synthesizer     - 7 Normative Standards Chunks
  - Projected Delta Scoring                   - FactLockContext Hash Guard
  - Closed-Loop Testbed Verification          - Explanatory Boundary (Zero Authority)
  (Stage 10)                                  (Stage 11)
                                     │
                                     ▼
                [ Multi-Tier SOC User Interface & Reporting ]
                - Next.js 16 App Router / React 19 / High-Contrast Light Theme
                - Executive & Technical HTML/PDF Reports
                - Operations & Telemetry Live Monitoring
                (Stage 9, 14, 19, Rehearsal)
```

---

## 3. Subsystem Breakdown (What We Built & Technologies Used)

### A. Core Runtime & Backend Architecture
- **Framework:** FastAPI with asynchronous ASGI execution, Python 3.10+, Starlette, Pydantic v2.
- **Database & ORM:** SQLite (`backend/soc_dev.sqlite`) running via `aiosqlite` and SQLAlchemy 2.0 with strict typed `Mapped[]` models. Linear Alembic migrations (`0001` through `0015`).
- **Distributed Queue:** Celery with Redis for asynchronous PCAP processing and long-running lab experiments.
- **Process & Environment Isolation:** Runs unprivileged for web endpoints; uses privileged helper bridges for kernel namespaces.

### B. Stage 2: Linux Namespace & strongSwan IPsec Testbed
- **Location:** `lab/`
- **Topologies:**
  - **Family A (Site-to-Site Tunnel Mode):** 5 isolated network namespaces (`client`, `gw_a`, `wan`, `gw_b`, `server`), veth pairs, WAN bridge `br-wan`, forwarding enabled on gateways.
  - **Family B (Host-to-Host Transport Mode):** 3 isolated namespaces (`peer_a`, `wan`, `peer_b`).
- **strongSwan Suite:** strongSwan 6.0.4 (`charon`, `swanctl`) configured via `/etc/swanctl/swanctl.conf`.
- **Private Mount Namespaces:** Uses `unshare -m` per charon daemon to isolate `/var/run` tmpfs, preventing PID collisions.
- **Traffic Impairment:** Linux `tc` (Traffic Control) with `netem` for real packet delay, jitter, and loss injection.
- **Process Ownership:** Strict termination of namespace-owned PIDs via `ip netns pids <ns>` with signal escalation (`SIGTERM` -> `SIGKILL`). Zero global `pkill` calls.

### C. Stage 3 & 4: Ingestion, TShark Dissection & SA Reconstruction
- **Location:** `backend/app/parsers/`, `backend/app/protocols/`
- **PCAP Ingestion:** Computes SHA-256 immediately upon upload. Accepts `.pcap` and `.pcapng` up to 250 MiB.
- **TShark Streaming Dissector:** Invokes TShark in non-blocking streaming mode, parsing IKE SPIs, message IDs, exchange types, transform proposals (ENCR, PRF, INTEG, D-H, ESN), ESP SPIs, sequence numbers, and ICMP/TCP inner indicators.
- **SA & Flow DAG Builder:** Reconstructs:
  - `Peer` (IP, Port, NAT status)
  - `IKE Session` (Initiator/Responder SPI pair, version)
  - `IKE SA` (Proposal negotiated, key exchange status)
  - `Child SA` (Inbound & Outbound ESP SPIs, Mode: Tunnel vs. Transport, PFS status & DH group)
  - `ESP Flow` (Directional packet count, byte volume, timing deltas)

### D. Stages 5, 6, 7 & 17: Machine Learning & Encrypted Traffic Intelligence
- **Philosophy:** **ZERO PAYLOAD DECRYPTION**. All inferences are computed strictly from outer headers, packet sizes, arrival times, and directional burst statistics.
- **Features Extracted (F01–F24):**
  - Burst length, burst packet counts, inter-arrival time mean/variance, direction transition count, early-window cumulative payload byte curves.
- **Models Implemented:**
  1. **Tabular XGBoost:** High-speed baseline for flow classification.
  2. **1D-CNN + BiLSTM (PyTorch / TorchScript):** Sequential model processing early packet size/direction sequences $[-1500, +1500]$.
  3. **Temperature Scaling Calibration:** Calibrates raw softmax logits using Platt-style learned temperature $T$, producing reliable Bayesian confidence probabilities.
  4. **Shannon Entropy OOD Gate:** Flags flows with high prediction entropy or low confidence as Out-Of-Distribution (OOD), avoiding false classification.
  5. **Isolation Forest:** JSON-serialized anomaly detector highlighting irregular burst behaviors.
- **Honest Production Gate:** If no validated model bundle is present in `models/active/`, the runtime honestly reports `ml_run_status = "NOT_CONFIGURED"`. It **never** fabricates synthetic application labels.

### E. Stage 8: Policy Engine, Kleene Logic & Risk Assessment
- **Location:** `backend/app/security/`
- **Kleene 3-Valued Logic:** Every rule evaluates to `PASS`, `FAIL`, `UNKNOWN` (insufficient evidence), or `NOT_APPLICABLE`. If a PCAP contains ESP traffic but missed the initial IKE handshake, PFS is evaluated as `UNKNOWN (EVIDENCE GAP)` rather than falsely failing or passing.
- **Standards Enforced:**
  - **NIST SP 800-77 Rev. 1:** Guide to IPsec VPNs.
  - **RFC 8221 / RFC 8247:** Cryptographic Algorithm Implementation Requirements for ESP/AH and IKEv2.
  - **RFC 7296:** Internet Key Exchange Protocol Version 2 (IKEv2).
  - **RFC 4301 / RFC 4303:** IPsec Architecture & ESP Specification.
- **Scoring Engine (0–100):**
  - Starts at 100.0.
  - Applies root-cause deduplicated penalties (Critical: -25, High: -15, Medium: -8, Low: -3).
  - Emits an itemized deduction audit.
  - Computes an independent **Evidence Coverage** metric $[0.0, 1.0]$.
- **Threat Matrix (THR-001..THR-008):** Maps findings to concrete attack primitives (e.g., Sweet32 birthday attacks on 64-bit ciphers, downgrade to unauthenticated IKEv1, retrospective harvest-now-decrypt-later when PFS is missing).
- **Metadata Fingerprintability Index:** Computes empirical vulnerability to side-channel traffic analysis based on packet padding consistency and timing entropy.

### F. Stage 10: Configuration Security Twin & Closed-Loop Remediation
- **Location:** `backend/app/remediation/`
- **Typed Configuration IR:** Abstracts `swanctl.conf` into memory structures representing connections, proposals, remote endpoints, and local secrets.
- **Safe Parser & Secret Redactor:** Parses strongSwan configurations up to 10,000 lines, scrubbing passwords, PSKs, and private keys into `[REDACTED_SECRET]`.
- **Deterministic Remediation Engine:** Converts Stage 8 findings into exact strongSwan directives (e.g., updating `proposals = aes256gcm16-prfsha384-ecp384`, enabling `esp_proposals = aes256gcm16-ecp384` for PFS).
- **Delta Scoring:** Computes the exact projected security score improvement. If baseline is 100, delta is truthfully 0.0.
- **SAGA Execution Runner:** Executes testbed remediation with pre-apply snapshotting, atomic rollback upon test failure, and fresh-SA establishment verification.

### G. Stage 11: Grounded AI Analyst (Local RAG)
- **Location:** `backend/app/ai_analyst/`
- **Engine:** Local Ollama runtime hosting open-weight instruction models (Qwen 2.5 / Gemma).
- **Hybrid RAG:** Vector embeddings over 7 normative RFC and NIST standards chunks, combined with SQLite keyword matching.
- **FactLockContext:** Binds the prompt to an immutable JSON representation of wire findings, signed with SHA-256.
- **Epistemic Guardrails:** The LLM is strictly an **explainer**. It cannot evaluate rules, invent findings, modify database records, or declare compliance. If prompted about unobserved aspects, it is constrained to abstain.

### H. Stage 14: Configuration & Certificate Inventory
- **Location:** `backend/app/inventory/`, `frontend/src/app/inventory/`
- **Snapshot Management:** Stores strongSwan configuration baselines with SHA-256 canonical hashing.
- **Drift Engine:** Compares observed gateway configuration against baseline snapshots, categorizing fields as `MATCHED`, `CHANGED`, `MISSING`, or `UNSUPPORTED`.
- **X.509 Certificate Intelligence:** Uses `cryptography.x509` to parse gateway certificates, tracking expiry windows (valid, expiring soon, expired) and key usages, strictly barring private key uploads.

### I. Frontend Architecture (Next.js 16 / React 19)
- **Location:** `frontend/`
- **Framework:** Next.js 16.3.6 (Turbopack), React 19, TypeScript 5, Tailwind CSS.
- **Theme:** High-contrast, clean light theme with rich typography (mono + sans-serif), zero dark-background visual artifacts.
- **Visualization:**
  - `@xyflow/react` (React Flow) for the 5-column hierarchical SA Topology DAG.
  - Apache ECharts (`echarts-for-react`) for itemized deduction bars, traffic burst profiles, and score gauges.
- **Real-Time Updates:** Native WebSocket connection to `/api/v1/ws` and `/api/v1/ws/analyses/{id}` for live pipeline progress.
- **18 Production Routes Built & Verified:**
  - `/` (Command Center & Readiness Health)
  - `/analyses` (Analysis History & Catalog)
  - `/analyses/new` (Capture Ingestion, PCAP Upload & Preflight)
  - `/analyses/[analysisId]/overview` (Executive Posture & Findings Summary)
  - `/analyses/[analysisId]/protocol` (Dissected Packets & Transform Tables)
  - `/analyses/[analysisId]/sas` (5-Tier SA Topology DAG & SPI Inspector)
  - `/analyses/[analysisId]/traffic` (Encrypted Flow Bursts & Classifier Intelligence)
  - `/analyses/[analysisId]/security` (Rule-by-Rule Kleene Posture & Deductions)
  - `/analyses/[analysisId]/compliance` (NIST / RFC Compliance Verification Matrix)
  - `/analyses/[analysisId]/threats` (THR-001..008 Attack Surface & Matrix)
  - `/analyses/[analysisId]/evidence` (Cryptographic Lineage & Facts Graph)
  - `/analyses/[analysisId]/reports` (Executive & Technical HTML/PDF Generation)
  - `/analyses/[analysisId]/ai-analyst` (Epistemic Grounded RAG Assistant)
  - `/analyses/[analysisId]/remediation` (Configuration Security Twin & Diff)
  - `/discovery` (Gateway & Network Discovery, Nmap State Machine)
  - `/inventory` (strongSwan Snapshots, Drift & X.509 Certificates)
  - `/lab` (Linux Namespace Testbed & Scenario Automation)
  - `/monitoring` (Fleet Telemetry & Sensor Heartbeats)
  - `/vulnerabilities` (CVE & Known IPsec Vulnerability Knowledgebase)

---

## 4. Current State & Invariants (Ground Truth)

### System State Right Now
- **Backend API:** Active on `http://127.0.0.1:8002` (FastAPI / uvicorn).
- **Frontend App:** Active on `http://localhost:3002` (Next.js dev / Turbopack).
- **Database:** `backend/soc_dev.sqlite` contains 10 real and verified analysis runs:
  - `9a79a13b...` (`ikev2_perimeter_audit.pcap`): Reference demo seed, Score 74.0, 1 Critical (3DES), 1 High finding, Risk tier CRITICAL.
  - `162b260f...` (`real_tunnel_gcm.pcapng`): Score 100.0, verified AES-GCM tunnel.
  - `a0faad23...` (`real_esp_only.pcap`): Score 100.0, ESP-only traffic (honest Kleene `UNKNOWN` for missing IKE).
  - `29585b85...` (`real_tunnel_gcm.pcapng`): Score 100.0.
  - `97843b7b...` (`real_tunnel_gcm.pcapng`): Score 100.0.
  - `03c0867e...` (`vpn_youtube_A.pcap`): Verified streaming traffic, AI Analyst RAG verified.
  - `927e3ac2...` (`real_tunnel_gcm.pcapng`): Score 100.0.
  - `ee299b87...` (`wireguard-ping-tcp-dsb.pcapng`): WireGuard comparative capture.
  - `765db0f0...` (`vpn_email2b.pcap`): Email VPN traffic capture.
  - `41a80f80...` (`real_tunnel_gcm.pcapng`): Score 100.0.
- **Unit Test Status:** `python -m pytest tests/unit -q` passes with 100% pass rate.
- **Frontend Build Status:** `npm run build` passes with exit code 0 across all 18 routes.

### Strict Operational Invariants (MUST OBSERVE)
1. **ZERO GIT OPERATIONS:** Under no circumstances should you run `git commit`, `git push`, `git checkout`, `git merge`, or `git pull`. All modifications remain in the working tree for user review.
2. **NO ACTIVE NETWORK PROBES:** Never launch Nmap scans, Scapy live packet transmissions, IKE-scan, or vulnerability scanners against external networks, physical host interfaces, or unapproved targets.
3. **PRESERVE DATABASE INTEGRITY:** Never delete, drop, wipe, or overwrite `backend/soc_dev.sqlite`.
4. **HONEST REPORTING OVER FABRICATION:**
   - If an ML model is not loaded, report `NOT_CONFIGURED`. Never emit random or fake classifications.
   - If a host cannot perform live raw socket captures (e.g., Windows node lacking WinPcap/Npcap privileges), clearly indicate `UNAVAILABLE ON THIS HOST` with CTAs to upload PCAPs.
   - If an analysis scored 100/100, the Configuration Twin projected delta must be `0.0`, never a phantom delta.
5. **KLEENE 3-VALUED LOGIC:** Missing evidence must result in `UNKNOWN` or `INSUFFICIENT_EVIDENCE`, never a false `PASS` or false `FAIL`.

---

## 5. How to Proceed in Future Sessions

When starting a new agent session or continuing development:
1. Verify backend health:
   ```powershell
   curl http://127.0.0.1:8002/api/v1/system/health/live
   ```
2. Verify test suite integrity:
   ```powershell
   cd "c:\SHARAN PROJECTS\TunnelTrace AI"
   python -m pytest tests/unit -q
   ```
3. Verify frontend build:
   ```powershell
   cd "c:\SHARAN PROJECTS\TunnelTrace AI\frontend"
   npm run build
   ```
4. If working on specific modules, refer directly to:
   - Ingestion & Forensics: `backend/app/parsers/` & `backend/app/protocols/`
   - Policy & Scoring: `backend/app/security/`
   - ML Pipeline: `backend/app/ml/`
   - Remediation Twin: `backend/app/remediation/`
   - AI Analyst RAG: `backend/app/ai_analyst/`
   - Frontend Pages: `frontend/src/app/`
