"use client";

import React, { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import {
  X,
  HelpCircle,
  CheckCircle2,
  AlertTriangle,
  XCircle,
} from "lucide-react";

interface ContextHelpPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

export function ContextHelpPanel({ isOpen, onClose }: ContextHelpPanelProps) {
  const pathname = usePathname();
  const [activeTab, setActiveTab] = useState<"page-guide" | "workflow-path" | "monitor-setup" | "host-limits">("page-guide");

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  // Context-sensitive copy based on pathname
  let pageTitle = "SOC Workbench Overview";
  let whatThisPageShows = "The SOC Workbench provides consolidated visibility into recent investigations, system readiness probes, and primary operational workflows.";
  let whatToDoNext = "Click 'Analyze a Capture' to ingest a PCAP, or select an existing investigation from the table to inspect cryptographic evidence.";

  if (pathname.includes("/analyses/new")) {
    pageTitle = "New Capture Ingestion";
    whatThisPageShows = "Accepts standard binary PCAP and PCAPNG files. On upload, the server validates file headers, computes SHA-256 digests, and executes TShark protocol extraction in a tamper-evident pipeline.";
    whatToDoNext = "Drag & drop a genuine capture file (e.g. strongSwan IKEv2 or ESP capture) or pick one of the sample captures to start deterministic analysis.";
  } else if (pathname.includes("/analyses") && pathname.includes("/overview")) {
    pageTitle = "Investigation Overview";
    whatThisPageShows = "Consolidated forensic overview showing NIST SP 800-77 security posture score, evidence coverage percentage, unknown controls count, flow counts, and protocol observations.";
    whatToDoNext = "Review the evidence coverage badge. A score of 100/100 evaluates observable evidence (e.g. 6/7 controls); examine the Security & Compliance tabs for itemized audits.";
  } else if (pathname.includes("/analyses") && pathname.includes("/traffic")) {
    pageTitle = "Encrypted Traffic ML Intelligence";
    whatThisPageShows = "Analyzes 24 flow-level statistical features (packet sizes, inter-arrival timing, burstiness) without decrypting ESP payload. Current active manifest is EXPERIMENTAL.";
    whatToDoNext = "Inspect detected candidate classes. Flows rejected as Out-Of-Distribution (OOD) or insufficient packet count abstain from false classification.";
  } else if (pathname.includes("/analyses") && pathname.includes("/remediation")) {
    pageTitle = "Configuration Twin & Remediation";
    whatThisPageShows = "Maps observable wire facts from PCAP into an epistemic configuration baseline. Proposes swanctl.conf remediation patches with counterfactual score delta projections.";
    whatToDoNext = "Inspect the semantic diff. Observable facts (IKEv2, AES-GCM, DH group) appear as verified wire facts. Deploy only to controlled lab testbeds.";
  } else if (pathname.includes("/analyses")) {
    pageTitle = "Investigation Catalog & Replay Lineage";
    whatThisPageShows = "Authoritative history of all ingested captures. Identical SHA-256 captures form replay clusters evaluated for determinism across pipeline versions.";
    whatToDoNext = "Inspect cluster badges. Clusters with matching outputs under pinned versions show DETERMINISTIC. Divergent versions show NOT COMPARABLE.";
  } else if (pathname.includes("/monitoring")) {
    pageTitle = "Continuous Telemetry Monitoring";
    whatThisPageShows = "Real-time gateway telemetry, sensor fleet health, and projected Security Associations. Browser WebSocket connection indicates transport availability only.";
    whatToDoNext = "To stream real events, configure the standalone gateway collector on a Linux strongSwan router. Synthetic pulses are quarantined from operational projections.";
  } else if (pathname.includes("/lab")) {
    pageTitle = "Controlled strongSwan Testbed";
    whatThisPageShows = "Containerized network namespace simulation with netem impairments (loss, jitter, reordering), asymmetric proposals, and negative test profiles.";
    whatToDoNext = "Execute a scenario profile to produce fresh, immutable lab captures. Requires privileged Linux host with CAP_NET_ADMIN.";
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-xs transition-opacity animate-in fade-in">
      <div className="w-full max-w-xl bg-white dark:bg-[#111113] border-l border-neutral-300 dark:border-neutral-800 shadow-2xl flex flex-col h-full overflow-hidden">
        {/* Panel Header */}
        <div className="p-4 border-b border-neutral-200 dark:border-neutral-800 flex items-center justify-between bg-neutral-50 dark:bg-neutral-900/60 shrink-0">
          <div className="flex items-center space-x-2">
            <HelpCircle className="w-5 h-5 text-[#FF3D00]" />
            <div>
              <h2 className="text-sm font-bold font-mono text-neutral-900 dark:text-white uppercase tracking-wider">
                Operator Guide & Context Help
              </h2>
              <p className="text-[10px] font-mono text-neutral-500">
                TunnelTrace AI · Verification Standards & Methodology
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 border border-neutral-300 dark:border-neutral-700 text-neutral-500 hover:text-neutral-900 dark:hover:text-white transition-colors"
            title="Close help panel (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-neutral-200 dark:border-neutral-800 bg-neutral-100/50 dark:bg-neutral-900/40 text-xs font-mono shrink-0">
          <button
            onClick={() => setActiveTab("page-guide")}
            className={`flex-1 py-2.5 px-3 text-center border-b-2 font-bold uppercase transition-colors ${
              activeTab === "page-guide"
                ? "border-[#FF3D00] text-[#FF3D00] bg-white dark:bg-[#111113]"
                : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            Current Screen
          </button>
          <button
            onClick={() => setActiveTab("workflow-path")}
            className={`flex-1 py-2.5 px-3 text-center border-b-2 font-bold uppercase transition-colors ${
              activeTab === "workflow-path"
                ? "border-[#FF3D00] text-[#FF3D00] bg-white dark:bg-[#111113]"
                : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            1–5 Analysis Path
          </button>
          <button
            onClick={() => setActiveTab("monitor-setup")}
            className={`flex-1 py-2.5 px-3 text-center border-b-2 font-bold uppercase transition-colors ${
              activeTab === "monitor-setup"
                ? "border-[#FF3D00] text-[#FF3D00] bg-white dark:bg-[#111113]"
                : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            Live Monitor Setup
          </button>
          <button
            onClick={() => setActiveTab("host-limits")}
            className={`flex-1 py-2.5 px-3 text-center border-b-2 font-bold uppercase transition-colors ${
              activeTab === "host-limits"
                ? "border-[#FF3D00] text-[#FF3D00] bg-white dark:bg-[#111113]"
                : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            Host Limitations
          </button>
        </div>

        {/* Panel Content Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6 text-xs font-sans">
          {activeTab === "page-guide" && (
            <div className="space-y-4">
              <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-1.5">
                <span className="text-[10px] font-mono font-bold text-[#FF3D00] uppercase tracking-wider">
                  Active Context
                </span>
                <h3 className="font-mono font-bold text-sm text-neutral-900 dark:text-white">
                  {pageTitle}
                </h3>
                <p className="text-neutral-600 dark:text-neutral-300 leading-relaxed">
                  {whatThisPageShows}
                </p>
              </div>

              <div className="p-3 bg-emerald-50/50 dark:bg-emerald-950/20 border-l-4 border-emerald-500 space-y-1">
                <span className="text-[10px] font-mono font-bold text-emerald-800 dark:text-emerald-300 uppercase tracking-wider">
                  Recommended Action
                </span>
                <p className="text-emerald-900 dark:text-emerald-200 leading-relaxed text-xs">
                  {whatToDoNext}
                </p>
              </div>

              <div className="space-y-2 pt-2">
                <h4 className="font-mono font-bold text-xs uppercase tracking-wider text-neutral-800 dark:text-neutral-200">
                  Epistemic Ground Rules
                </h4>
                <ul className="space-y-1.5 text-neutral-600 dark:text-neutral-400 font-sans text-xs">
                  <li className="flex items-start space-x-2">
                    <span className="text-[#FF3D00] font-bold">•</span>
                    <span><strong>Evidence Coverage:</strong> A score evaluates observable evidence. If rekey traffic is missing from a short capture, that control is explicitly marked UNKNOWN rather than assumed compliant.</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-[#FF3D00] font-bold">•</span>
                    <span><strong>ML Abstention:</strong> Flows lacking statistical significance or falling outside the training distribution abstain via Out-Of-Distribution (OOD) rejection.</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-[#FF3D00] font-bold">•</span>
                    <span><strong>Zero Secret Ingestion:</strong> TunnelTrace never requires or inspects private keys or preshared keys. All analysis operates strictly over wire headers and statistical flow dynamics.</span>
                  </li>
                </ul>
              </div>
            </div>
          )}

          {activeTab === "workflow-path" && (
            <div className="space-y-4">
              <p className="text-neutral-600 dark:text-neutral-400 text-xs">
                Every packet capture undergoes a deterministic, verifiable 5-step analysis pipeline:
              </p>

              <div className="space-y-3 font-mono">
                {/* Step 1 */}
                <div className="p-3 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-[#FF3D00]">1. Ingest & Hash Validation</span>
                    <span className="text-[10px] text-neutral-400">SHA-256</span>
                  </div>
                  <p className="text-[11px] text-neutral-500 font-sans">
                    Validates binary PCAP magic headers and registers immutable SHA-256 digest in local storage.
                  </p>
                </div>

                {/* Step 2 */}
                <div className="p-3 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-neutral-900 dark:text-white">2. TShark Forensic Dissection</span>
                    <span className="text-[10px] text-neutral-400">RFC 7296</span>
                  </div>
                  <p className="text-[11px] text-neutral-500 font-sans">
                    Extracts IKE_SA_INIT and IKE_AUTH transforms (ciphers, DH groups, PRFs) and correlates Child SAs.
                  </p>
                </div>

                {/* Step 3 */}
                <div className="p-3 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-neutral-900 dark:text-white">3. Review Evidence & Coverage</span>
                    <span className="text-[10px] text-neutral-400">Epistemic Logic</span>
                  </div>
                  <p className="text-[11px] text-neutral-500 font-sans">
                    Quantifies evidence coverage. Unobserved facts remain UNKNOWN; zero findings on partial evidence never implies low risk.
                  </p>
                </div>

                {/* Step 4 */}
                <div className="p-3 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-neutral-900 dark:text-white">4. Deterministic Policy Evaluation</span>
                    <span className="text-[10px] text-neutral-400">NIST SP 800-77</span>
                  </div>
                  <p className="text-[11px] text-neutral-500 font-sans">
                    Applies 8 deterministic security rules. Evaluates cryptographic posture score (0–100) and itemized deductions.
                  </p>
                </div>

                {/* Step 5 */}
                <div className="p-3 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-neutral-900 dark:text-white">5. Forensic Report & Remediation</span>
                    <span className="text-[10px] text-neutral-400">PDF / JSON / Twin</span>
                  </div>
                  <p className="text-[11px] text-neutral-500 font-sans">
                    Generates verifiable PDF reports with cryptographic hashes and provides corrected strongSwan swanctl.conf templates.
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeTab === "monitor-setup" && (
            <div className="space-y-4">
              <div className="p-3 bg-amber-50 dark:bg-amber-950/30 border-l-4 border-amber-500 text-xs text-amber-900 dark:text-amber-200 space-y-1">
                <span className="font-mono font-bold uppercase tracking-wider flex items-center space-x-1">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                  <span>Remote Gateway Architecture</span>
                </span>
                <p className="leading-relaxed">
                  Continuous live monitoring connects to authorized strongSwan Linux gateways via authenticated telemetry tokens. Synthetic pulse tests are quarantined and do not affect operational statistics.
                </p>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <h4 className="font-bold text-neutral-900 dark:text-white uppercase tracking-wider">
                  Collector Deployment Steps
                </h4>

                <div className="p-2.5 bg-neutral-900 text-neutral-200 rounded border border-neutral-800 space-y-2">
                  <div className="text-[11px] text-neutral-400">1. Export authentication token on gateway:</div>
                  <code className="text-emerald-400 text-[10px] block select-all">
                    export TUNNELTRACE_SENSOR_TOKEN=&quot;&lt;REGISTERED_SENSOR_TOKEN&gt;&quot;
                  </code>

                  <div className="text-[11px] text-neutral-400 pt-1">2. Run standalone gateway collector:</div>
                  <code className="text-emerald-400 text-[10px] block select-all">
                    python scripts/gateway_collector.py \<br />
                    &nbsp;&nbsp;--api-url &quot;http://&lt;API_HOST&gt;:8002/api/v1&quot; \<br />
                    &nbsp;&nbsp;--gateway-id &quot;&lt;GATEWAY_ID&gt;&quot; \<br />
                    &nbsp;&nbsp;--sensor-id &quot;&lt;SENSOR_ID&gt;&quot; \<br />
                    &nbsp;&nbsp;--scope &quot;198.51.100.0/24&quot; \<br />
                    &nbsp;&nbsp;--interface eth0
                  </code>
                </div>
              </div>

              <p className="text-[11px] text-neutral-500 leading-relaxed font-sans">
                The collector queries <code className="font-mono">swanctl --list-sas</code> and directional ESP xfrm metrics, batching authenticated JSON events to <code className="font-mono">POST /api/v1/monitoring/events</code> over TLS.
              </p>
            </div>
          )}

          {activeTab === "host-limits" && (
            <div className="space-y-4">
              <div className="p-3 bg-neutral-100 dark:bg-neutral-800/80 border border-neutral-300 dark:border-neutral-700 space-y-1.5">
                <span className="text-[10px] font-mono font-bold text-neutral-500 uppercase tracking-wider">
                  Development Host Status: Windows NT
                </span>
                <h4 className="font-mono font-bold text-xs text-neutral-900 dark:text-white">
                  Local Windows vs Linux Production Capabilities
                </h4>
                <p className="text-neutral-600 dark:text-neutral-300 leading-relaxed text-xs">
                  TunnelTrace AI operates truthfully within the security boundaries of the current host:
                </p>
              </div>

              <div className="space-y-2.5 text-xs font-mono">
                <div className="p-2.5 border border-neutral-200 dark:border-neutral-800 flex items-start space-x-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold text-neutral-900 dark:text-white">Offline PCAP Analysis: FULLY FUNCTIONAL</span>
                    <p className="text-[11px] text-neutral-500 font-sans">
                      TShark 4.6.4, SQLite, policy engine, and ML inference run locally without elevated privileges.
                    </p>
                  </div>
                </div>

                <div className="p-2.5 border border-neutral-200 dark:border-neutral-800 flex items-start space-x-2">
                  <XCircle className="w-4 h-4 text-neutral-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold text-neutral-900 dark:text-white">Direct Live Capture: UNAVAILABLE ON WINDOWS</span>
                    <p className="text-[11px] text-neutral-500 font-sans">
                      Raw socket packet sniffing and Linux network namespaces (`ip netns`) require a Linux kernel with `CAP_NET_ADMIN`. Use the authorized remote Linux collector setup.
                    </p>
                  </div>
                </div>

                <div className="p-2.5 border border-neutral-200 dark:border-neutral-800 flex items-start space-x-2">
                  <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold text-neutral-900 dark:text-white">ML Model State: EXPERIMENTAL BASELINE</span>
                    <p className="text-[11px] text-neutral-500 font-sans">
                      Model weights operate on a 24-feature statistical baseline. Unseen traffic is safely rejected via OOD abstention.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Panel Footer */}
        <div className="p-3 border-t border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/60 flex items-center justify-between text-[11px] font-mono text-neutral-500 shrink-0">
          <span>TunnelTrace AI · NTRO PS 26160</span>
          <button
            onClick={onClose}
            className="px-3 py-1 bg-neutral-900 hover:bg-neutral-800 dark:bg-white dark:hover:bg-neutral-200 text-white dark:text-neutral-900 font-bold uppercase transition-colors"
          >
            Close Guide
          </button>
        </div>
      </div>
    </div>
  );
}
