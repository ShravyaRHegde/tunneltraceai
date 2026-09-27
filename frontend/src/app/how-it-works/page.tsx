"use client";

import React, { useState } from "react";
import Link from "next/link";
import { Card } from "@/components/ui/card";
import {
  UploadCloud,
  Globe,
  Network,
  ShieldCheck,
  Radio,
  ShieldAlert,
  Bot,
  FileText,
  FlaskConical,
  ChevronRight,
  ChevronLeft,
  ArrowRight,
  CheckCircle2,
  HelpCircle,
  Layers,
  Lock,
  Zap,
  Activity,
  FileCode2,
} from "lucide-react";

interface StepDetail {
  id: number;
  title: string;
  shortLabel: string;
  tagline: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  inputs: string[];
  outputs: string[];
  standards: string[];
  liveLink: string;
  liveLinkLabel: string;
}

const STEPS: StepDetail[] = [
  {
    id: 1,
    title: "Step 1: Capture Ingestion & Provenance Lineage",
    shortLabel: "1. Ingestion",
    tagline: "Cryptographic hashing, header validation, and immutable storage",
    icon: UploadCloud,
    description:
      "The system accepts standard binary packet capture files (.pcap and .pcapng). Upon upload, it instantly calculates SHA-256 and MD5 cryptographic digests, inspects the capture magic numbers, validates file size limits, and persists the raw artifact into immutable storage. A tamper-evident lineage record is bound to every subsequent analysis.",
    inputs: [".pcap or .pcapng binary capture files", "Capture profile preset (IPsec-relevant)"],
    outputs: ["Immutable Capture record (UUID)", "Cryptographic SHA-256 digest", "Packet count & duration metadata"],
    standards: ["PCAP / PCAPNG Specification", "FIPS 180-4 (SHA-256 Hashing)"],
    liveLink: "/analyses/new",
    liveLinkLabel: "Go to Ingest Capture",
  },
  {
    id: 2,
    title: "Step 2: Authorized Asset Discovery & Pre-Scan",
    shortLabel: "2. Discovery",
    tagline: "Bounded Nmap port scanning for IKE and NAT-Traversal endpoints",
    icon: Globe,
    description:
      "Before or alongside capture analysis, authorized asset discovery scans approved IP subnets for active VPN gateways on UDP port 500 (IKE) and UDP port 4500 (NAT-Traversal / ESP encapsulation). The system preserves observational ambiguity: UDP states like 'open|filtered' are faithfully retained rather than being forced into false certainty.",
    inputs: ["Approved target IP / CIDR scope", "Operator authorization attestation code"],
    outputs: ["Discovered VPN gateway host records", "Service identifications (isakmp, ipsec-nat-t)", "Preserved port states (open, open|filtered)"],
    standards: ["RFC 7296 §3.1 (IKE UDP Port 500)", "RFC 3948 (UDP Port 4500 NAT-T)"],
    liveLink: "/discovery",
    liveLinkLabel: "Go to Asset Discovery",
  },
  {
    id: 3,
    title: "Step 3: Headless Protocol Dissection & State Reconstruction",
    shortLabel: "3. Dissection",
    tagline: "Headless TShark/Scapy parsing of IKEv1, IKEv2, and ESP tunnels",
    icon: Network,
    description:
      "Headless dissection engines (TShark and Scapy) parse the binary capture into structured JSON protocol trees. The system reconstructs IKE Security Associations (IKE_SA_INIT, IKE_AUTH) and Child SA ESP tunnels, mapping SPI identifiers, Diffie-Hellman public values, encryption transforms, and PRF algorithms at exact packet byte offsets.",
    inputs: ["Verified raw PCAP/PCAPNG file", "Link-layer frame sequence"],
    outputs: ["Hierarchical protocol observation tree", "IKE SA proposals & transform matrices", "ESP unidirectional flow records (SPI, packets, bytes)"],
    standards: ["RFC 7296 (IKEv2 Protocol)", "RFC 4303 (IPsec ESP)", "RFC 2409 (IKEv1)"],
    liveLink: "/analyses",
    liveLinkLabel: "Select an Analysis to Inspect Dissection",
  },
  {
    id: 4,
    title: "Step 4: Deterministic Cryptographic Policy & Posture Scoring",
    shortLabel: "4. Policy & Scoring",
    tagline: "NIST SP 800-77 & RFC 8247 compliance audit with mathematical scoring",
    icon: ShieldCheck,
    description:
      "The policy engine evaluates observed cryptographic transforms against authoritative guidelines (NIST SP 800-77 Rev. 1, RFC 8247, RFC 8221, and ANSSI). Violations (e.g. deprecated 3DES, MD5, small DH groups) incur deterministic point deductions. Posture score is gated by evidence coverage—if a capture has 0 IPsec packets, it is labeled NOT ASSESSABLE instead of receiving a fake 100/100 score.",
    inputs: ["Negotiated cryptographic transforms", "Observed transform IDs", "Rekey & lifetime parameters"],
    outputs: ["Itemized security findings (CRIT, HIGH, MED, LOW)", "Compliance matrix pass/fail scorecards", "Evidence-weighted posture score (0–100 or NOT ASSESSABLE)"],
    standards: ["NIST SP 800-77 Rev. 1", "RFC 8247 (IKEv2 Cryptographic Algorithms)", "RFC 8221 (ESP & AH Suites)"],
    liveLink: "/analyses",
    liveLinkLabel: "View Security Assessments",
  },
  {
    id: 5,
    title: "Step 5: Multimodal Machine Learning Traffic Profiling",
    shortLabel: "5. Traffic ML",
    tagline: "1D-CNN + XGBoost encrypted flow classification with TreeSHAP explainability",
    icon: Radio,
    description:
      "Without decrypting ciphertext payloads, the ML engine profiles application traffic traversing encrypted ESP tunnels. A 1D-CNN inspects packet length and direction sequences, while XGBoost classifies statistical flow features (inter-arrival times, burst entropy, byte ratios). Calibrated probabilities, out-of-distribution (OOD) detection, and TreeSHAP explainability indicate exactly why a flow was classified as VoIP, Video, Web, or DNS.",
    inputs: ["ESP packet sequences (length, direction, timestamp)", "Statistical flow aggregates (duration, byte volume)"],
    outputs: ["Predicted application class (VoIP, Video, Web, etc.)", "Calibrated confidence score & OOD flag", "TreeSHAP feature importance ranking"],
    standards: ["Encrypted Traffic Analysis (ETA) Standards", "TreeSHAP Explainability (Lundberg et al.)"],
    liveLink: "/analyses",
    liveLinkLabel: "View Traffic & ML Intelligence",
  },
  {
    id: 6,
    title: "Step 6: Vulnerability Intelligence & Threat Matrix",
    shortLabel: "6. Threat Matrix",
    tagline: "Greenbone OpenVAS CVE correlation and MITRE ATT&CK mapping",
    icon: ShieldAlert,
    description:
      "Discovered VPN vendor implementations (strongSwan, Cisco ASA, Fortinet FortiOS) and protocol weaknesses are correlated against National Vulnerability Database (NVD) CVE feeds via Greenbone OpenVAS reports. Vulnerabilities are mapped to MITRE ATT&CK tactics (Initial Access, Defense Evasion, Impact) with tailored remediation playbooks.",
    inputs: ["Greenbone OpenVAS XML reports", "Vendor ID fingerprint observations", "Discovered software versions"],
    outputs: ["Correlated CVE records (e.g. CVE-2023-35945)", "CVSS v3.1 severity metrics", "MITRE ATT&CK enterprise technique mappings"],
    standards: ["MITRE ATT&CK Enterprise Matrix", "NIST NVD / CVSS v3.1 Specification"],
    liveLink: "/vulnerabilities",
    liveLinkLabel: "View Vulnerability Feed",
  },
  {
    id: 7,
    title: "Step 7: Grounded AI Security Analyst (Dual-Mode)",
    shortLabel: "7. AI Analyst",
    tagline: "Instant zero-latency database fact search + Local Ollama conversational RAG",
    icon: Bot,
    description:
      "TunnelTrace AI features a grounded dual-mode AI Analyst. In 'Evidence Search' mode, users get sub-millisecond, deterministic retrieval of database facts and RFC citations without model latency. In 'Local Ollama' mode, on-premise models (Qwen, Gemma) synthesize findings under a strict Fact-Lock and Claim Gate that rejects unverified citations and enforces canonical abstention on unassessable captures.",
    inputs: ["User security questions", "Fact-locked database context store", "Normative RFC/NIST vector chunks"],
    outputs: ["Sub-millisecond structured evidence tables", "Grounded remediation narratives", "Claim-gate verified RFC & CVE citations"],
    standards: ["RFC 8247, RFC 8221, NIST SP 800-77", "Claim-Gated Grounded RAG Architecture"],
    liveLink: "/analyses",
    liveLinkLabel: "Test AI Security Analyst",
  },
  {
    id: 8,
    title: "Step 8: Publication-Grade Audit Reports & Lineage Verification",
    shortLabel: "8. Reports",
    tagline: "Cryptographic SHA-256 bound PDF, JSON, and CSV exports for SOC compliance",
    icon: FileText,
    description:
      "The platform generates deterministic, immutable compliance and forensic reports. Reports embed the source PCAP's SHA-256 hash, NIST compliance scorecards, packet hex dump references, and step-by-step remediation snippets. Downloadable in JSON (STIX 2.1-ready), executive PDF, and CSV formats for SIEM ingestion.",
    inputs: ["Completed analysis snapshot", "Integrity-verified source capture artifact"],
    outputs: ["Audit-ready Executive Summary PDF", "STIX 2.1 JSON assessment bundle", "Tabular CSV findings log"],
    standards: ["NIST SP 800-77 Audit Guidelines", "STIX 2.1 Machine-Readable Security Bundles"],
    liveLink: "/analyses",
    liveLinkLabel: "Download Audit Reports",
  },
];

export default function HowItWorksPage() {
  const [activeStepId, setActiveStepId] = useState<number>(1);
  const currentStep = STEPS.find((s) => s.id === activeStepId) || STEPS[0];
  const Icon = currentStep.icon;

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12">
      {/* Top Hero Banner */}
      <div className="p-6 bg-white dark:bg-[#111113] border border-neutral-300 dark:border-neutral-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-neutral-200 dark:border-neutral-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded bg-[#FF3D00] flex items-center justify-center text-white font-mono font-bold text-sm shrink-0 shadow-md">
              TT
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold text-[#FF3D00] uppercase tracking-wider">
                  SYSTEM ARCHITECTURE & INVESTIGATION FLOW
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 bg-neutral-100 dark:bg-neutral-900 font-bold uppercase">
                  SIH 2026 · PS 26160
                </span>
              </div>
              <h1 className="text-xl sm:text-2xl font-bold font-mono text-neutral-900 dark:text-white uppercase tracking-tight mt-0.5">
                How TunnelTrace AI Works
              </h1>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Link
              href="/analyses/new"
              className="px-3.5 py-2 text-xs font-mono font-bold bg-[#FF3D00] hover:bg-[#E03600] text-white rounded transition-colors shadow-xs"
            >
              TRY LIVE INGESTION →
            </Link>
          </div>
        </div>
        <p className="text-xs sm:text-sm text-neutral-600 dark:text-neutral-300 leading-relaxed max-w-4xl">
          TunnelTrace AI is an epistemically honest IPsec VPN protocol analyzer designed for the National Technical Research Organisation (NTRO). It replaces black-box guessing with deterministic mathematical scoring, headless packet dissection, local machine learning, and claim-gated AI analyst assistance.
        </p>
      </div>

      {/* Special Callout: What is the Lab & Testbed? */}
      <div className="p-5 bg-blue-50 dark:bg-blue-950/30 border-l-4 border-blue-600 text-blue-950 dark:text-blue-200 space-y-2">
        <div className="flex items-center space-x-2 font-mono font-bold text-sm text-blue-900 dark:text-blue-300">
          <FlaskConical className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
          <span>What is the Lab & Testbed? (And Why Does It Exist?)</span>
        </div>
        <p className="text-xs font-mono leading-relaxed text-blue-800 dark:text-blue-300/90">
          Evaluators often ask: <em>&ldquo;How do we safely test weak or obsolete VPN configurations without attacking our live network?&rdquo;</em>
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs font-mono">
          <div className="p-3 bg-white dark:bg-neutral-900 border border-blue-200 dark:border-blue-900/60 rounded">
            <div className="font-bold text-neutral-900 dark:text-white flex items-center gap-1.5 mb-1">
              <span className="w-2 h-2 rounded-full bg-blue-600"></span>
              <span>1. Dual-strongSwan Testbed</span>
            </div>
            <p className="text-neutral-600 dark:text-neutral-400 text-[11px] leading-relaxed">
              Spins up two isolated Linux network namespaces (Client & Gateway) connected by a virtual bridge.
            </p>
          </div>
          <div className="p-3 bg-white dark:bg-neutral-900 border border-blue-200 dark:border-blue-900/60 rounded">
            <div className="font-bold text-neutral-900 dark:text-white flex items-center gap-1.5 mb-1">
              <span className="w-2 h-2 rounded-full bg-blue-600"></span>
              <span>2. 9 Standard Scenarios</span>
            </div>
            <p className="text-neutral-600 dark:text-neutral-400 text-[11px] leading-relaxed">
              Pre-configured profiles: Modern AES-GCM (RFC 8221), Legacy 3DES-CBC, IPv6 Site-to-Site, NAT-T 4500, and Netem WAN loss.
            </p>
          </div>
          <div className="p-3 bg-white dark:bg-neutral-900 border border-blue-200 dark:border-blue-900/60 rounded">
            <div className="font-bold text-neutral-900 dark:text-white flex items-center gap-1.5 mb-1">
              <span className="w-2 h-2 rounded-full bg-blue-600"></span>
              <span>3. Ground-Truth PCAPs</span>
            </div>
            <p className="text-neutral-600 dark:text-neutral-400 text-[11px] leading-relaxed">
              Generates genuine, reproducible PCAPs with known keys for forensic verification and compliance benchmarking.
            </p>
          </div>
        </div>
        <div className="pt-1">
          <Link
            href="/lab"
            className="inline-flex items-center gap-1 text-xs font-mono font-bold text-blue-700 dark:text-blue-300 hover:underline"
          >
            Explore the 9 Lab Scenarios in Lab Orchestrator →
          </Link>
        </div>
      </div>

      {/* Interactive Step-by-Step Flowchart */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-neutral-300 dark:border-neutral-800 pb-2">
          <div>
            <span className="text-[10px] font-mono text-neutral-400 uppercase tracking-wider">
              INTERACTIVE PIPELINE WIZARD
            </span>
            <h2 className="text-lg font-bold font-mono uppercase text-neutral-900 dark:text-white">
              The 8-Stage Investigation Flow
            </h2>
          </div>
          <span className="text-xs font-mono text-neutral-500">
            Step {activeStepId} of {STEPS.length}
          </span>
        </div>

        {/* Horizontal Stepper Chips */}
        <div className="flex items-center gap-1 overflow-x-auto pb-2 scrollbar-thin">
          {STEPS.map((s) => {
            const StepIcon = s.icon;
            const isActive = s.id === activeStepId;
            return (
              <button
                key={s.id}
                onClick={() => setActiveStepId(s.id)}
                className={`flex items-center space-x-1.5 px-3 py-2 text-xs font-mono whitespace-nowrap transition-all border shrink-0 ${
                  isActive
                    ? "bg-[#FF3D00] text-white border-[#FF3D00] font-bold shadow-sm"
                    : "bg-white dark:bg-[#141416] text-neutral-600 dark:text-neutral-400 border-neutral-300 dark:border-neutral-800 hover:bg-neutral-100 dark:hover:bg-neutral-800 hover:text-neutral-900 dark:hover:text-white"
                }`}
              >
                <StepIcon className="w-3.5 h-3.5 shrink-0" />
                <span>{s.shortLabel}</span>
              </button>
            );
          })}
        </div>

        {/* Active Step Detailed Card */}
        <Card className="p-6 bg-white dark:bg-[#141416] border-neutral-300 dark:border-neutral-800 space-y-6">
          <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 border-b border-neutral-200 dark:border-neutral-800 pb-4">
            <div className="flex items-start space-x-3">
              <div className="w-10 h-10 rounded-sm bg-[#FF3D00]/10 border border-[#FF3D00]/30 flex items-center justify-center text-[#FF3D00] shrink-0 mt-0.5">
                <Icon className="w-5 h-5" />
              </div>
              <div>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-700 dark:text-neutral-300 font-bold">
                  STAGE {currentStep.id} OF 8
                </span>
                <h3 className="text-xl font-bold font-mono text-neutral-900 dark:text-white uppercase mt-1">
                  {currentStep.title}
                </h3>
                <p className="text-xs font-mono text-neutral-500 mt-0.5">
                  {currentStep.tagline}
                </p>
              </div>
            </div>

            <Link
              href={currentStep.liveLink}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-mono font-bold bg-neutral-900 hover:bg-neutral-800 text-white dark:bg-white dark:text-neutral-900 dark:hover:bg-neutral-200 rounded transition-colors shrink-0 shadow-xs"
            >
              <span>{currentStep.liveLinkLabel}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {/* Description */}
          <div className="text-sm font-sans text-neutral-700 dark:text-neutral-300 leading-relaxed bg-neutral-50 dark:bg-neutral-900/50 p-4 border border-neutral-200 dark:border-neutral-800/80 rounded-sm">
            {currentStep.description}
          </div>

          {/* 3 Technical Matrices: Inputs, Outputs, Standards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            {/* Column 1: Inputs */}
            <div className="p-4 bg-white dark:bg-[#111113] border border-neutral-300 dark:border-neutral-800 space-y-2">
              <div className="text-[10px] font-bold text-neutral-500 uppercase tracking-wider flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
                <span>DATA INPUTS</span>
              </div>
              <ul className="space-y-1.5 text-neutral-700 dark:text-neutral-300 text-[11px]">
                {currentStep.inputs.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <span className="text-[#FF3D00] font-bold">▸</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Column 2: Outputs */}
            <div className="p-4 bg-white dark:bg-[#111113] border border-neutral-300 dark:border-neutral-800 space-y-2">
              <div className="text-[10px] font-bold text-neutral-500 uppercase tracking-wider flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                <span>STAGE OUTPUTS</span>
              </div>
              <ul className="space-y-1.5 text-neutral-700 dark:text-neutral-300 text-[11px]">
                {currentStep.outputs.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <span className="text-emerald-500 font-bold">✔</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Column 3: Standards */}
            <div className="p-4 bg-white dark:bg-[#111113] border border-neutral-300 dark:border-neutral-800 space-y-2">
              <div className="text-[10px] font-bold text-neutral-500 uppercase tracking-wider flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
                <span>NORMATIVE STANDARDS</span>
              </div>
              <ul className="space-y-1.5 text-neutral-700 dark:text-neutral-300 text-[11px]">
                {currentStep.standards.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <span className="text-amber-500 font-bold">§</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Stepper Navigation Footer */}
          <div className="flex items-center justify-between pt-4 border-t border-neutral-200 dark:border-neutral-800 text-xs font-mono">
            <button
              onClick={() => setActiveStepId((prev) => Math.max(1, prev - 1))}
              disabled={activeStepId === 1}
              className="flex items-center gap-1.5 px-3 py-1.5 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
              <span>PREVIOUS STAGE</span>
            </button>

            <span className="text-neutral-400 font-bold">
              {activeStepId} / {STEPS.length}
            </span>

            <button
              onClick={() => setActiveStepId((prev) => Math.min(STEPS.length, prev + 1))}
              disabled={activeStepId === STEPS.length}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#FF3D00] hover:bg-[#E03600] text-white font-bold rounded disabled:opacity-40 disabled:cursor-not-allowed transition-colors shadow-xs"
            >
              <span>NEXT STAGE</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </Card>
      </div>

      {/* Frequently Asked Questions / Epistemic Invariants */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold font-mono uppercase text-neutral-900 dark:text-white border-b border-neutral-300 dark:border-neutral-800 pb-2">
          Key Platform Questions & Design Principles
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <Card className="p-4 bg-white dark:bg-[#141416] border-neutral-300 dark:border-neutral-800 space-y-2">
            <div className="font-bold text-neutral-900 dark:text-white flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-[#FF3D00]" />
              <span>What packet files does the system support?</span>
            </div>
            <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed text-[11px]">
              The system supports all standard binary <strong>.pcap</strong> and <strong>.pcapng</strong> capture files containing IKEv1, IKEv2, ESP, and AH protocol exchanges. Uploading non-IPsec captures (e.g. WireGuard, raw HTTP) is handled gracefully and labeled as unassessable.
            </p>
          </Card>

          <Card className="p-4 bg-white dark:bg-[#141416] border-neutral-300 dark:border-neutral-800 space-y-2">
            <div className="font-bold text-neutral-900 dark:text-white flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-[#FF3D00]" />
              <span>Why does a zero-evidence capture show NOT ASSESSABLE?</span>
            </div>
            <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed text-[11px]">
              If a capture has 0 IKE handshakes and 0 ESP tunnels, giving it a 100/100 score would be a dangerous security lie. TunnelTrace AI strictly enforces <strong>epistemic honesty</strong>: zero evidence yields 0.0% coverage and a clear &lsquo;NOT ASSESSABLE&rsquo; status.
            </p>
          </Card>

          <Card className="p-4 bg-white dark:bg-[#141416] border-neutral-300 dark:border-neutral-800 space-y-2">
            <div className="font-bold text-neutral-900 dark:text-white flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-[#FF3D00]" />
              <span>How does Live Monitoring work without active VPN sensors?</span>
            </div>
            <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed text-[11px]">
              The live monitoring dashboard connects via WebSocket to listen for heartbeat telemetry from remote Linux strongSwan collector sensors. In local development where no live VPN appliance is streaming, it honestly reports &lsquo;SENSORS STALE&rsquo;. You can click &lsquo;TEST LIVE PULSE&rsquo; to verify the live WebSocket streaming engine anytime.
            </p>
          </Card>

          <Card className="p-4 bg-white dark:bg-[#141416] border-neutral-300 dark:border-neutral-800 space-y-2">
            <div className="font-bold text-neutral-900 dark:text-white flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-[#FF3D00]" />
              <span>Does Machine Learning decrypt encrypted ESP payloads?</span>
            </div>
            <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed text-[11px]">
              No. AES-GCM and AES-CBC ciphertext cannot be decrypted without key material. Instead, the 1D-CNN and XGBoost models profile statistical packet metadata (packet length patterns, inter-arrival times, burst entropy) to infer traffic categories (VoIP, Video, Web) with explainable TreeSHAP feature rankings.
            </p>
          </Card>
        </div>
      </div>
    </div>
  );
}
