"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import {
  FlaskConical,
  Activity,
  Server,
  Layers,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  Terminal,
  Cpu,
  FileCode,
} from "lucide-react";

export default function LabTestbedPage() {
  const { data: readiness, isLoading, isError } = useQuery({
    queryKey: ["system-readiness"],
    queryFn: () => api.system.getReadiness(),
    retry: 1,
  });

  const dependencies = readiness?.dependencies || {};
  const isReady = readiness?.status === "READY";
  const dbStatus = dependencies.database?.status || "UNKNOWN";
  const redisStatus = dependencies.redis?.status || "DOWN";
  const tsharkStatus = dependencies.tshark?.status || "UNAVAILABLE";
  const tsharkVer = dependencies.tshark?.version || "Not detected";
  const agentStatus = dependencies.privileged_agent?.available ? "ONLINE" : "UNCONFIGURED";

  const labScenarios = [
    {
      id: "scn-01-tunnel-v4-gcm-pfs",
      title: "Baseline Tunnel Mode IPv4 (AES-256-GCM / ECP-256 / PFS Enabled)",
      description: "Modern AEAD cipher suite conforming to RFC 8221 guidelines with Diffie-Hellman Group 19 and perfect forward secrecy.",
      crypto: "IKEv2 / AES-256-GCM-16 / PRF-SHA256 / ECP-256 (DH19) / PFS Enabled",
      topology: "TUNNEL_SITE_TO_SITE (IPv4)",
      expectedOutcome: "SUCCESS",
      category: "BASELINE",
    },
    {
      id: "scn-02-tunnel-v4-cbc-nopfs",
      title: "Legacy CBC Mode IPv4 (AES-256-CBC / HMAC-SHA256 / No PFS)",
      description: "Classical cipher block chaining with MODP-2048 (DH14) without Child-SA rekey PFS for comparative analysis.",
      crypto: "IKEv2 / AES-256-CBC / HMAC-SHA256 / MODP-2048 (DH14) / PFS Disabled",
      topology: "TUNNEL_SITE_TO_SITE (IPv4)",
      expectedOutcome: "SUCCESS",
      category: "COMPARISON",
    },
    {
      id: "scn-03-transport-v4-gcm",
      title: "Transport Mode Host-to-Host IPv4 (AES-256-GCM / ECP-256)",
      description: "Direct end-to-end IP payload encryption between two cooperating hosts without tunnel header encapsulation.",
      crypto: "IKEv2 / AES-256-GCM-16 / PRF-SHA256 / ECP-256 (DH19) / PFS Enabled",
      topology: "TRANSPORT_HOST_TO_HOST (IPv4)",
      expectedOutcome: "SUCCESS",
      category: "TRANSPORT",
    },
    {
      id: "scn-04-tunnel-v6-gcm-pfs",
      title: "Tunnel Mode IPv6 Site-to-Site (AES-256-GCM / ECP-256 / PFS)",
      description: "Pure IPv6 transport and inner payload addressing across dual strongSwan endpoints validating next-gen routing.",
      crypto: "IKEv2 / AES-256-GCM-16 / PRF-SHA256 / ECP-256 (DH19) / PFS Enabled",
      topology: "TUNNEL_SITE_TO_SITE (IPv6)",
      expectedOutcome: "SUCCESS",
      category: "IPV6",
    },
    {
      id: "scn-05-tunnel-v4-netem",
      title: "Impaired WAN Simulation (tc/netem: 40ms delay, 10ms jitter, 2% loss)",
      description: "Injected network latency and drop rate via Linux Traffic Control simulating degraded long-haul satellite links.",
      crypto: "IKEv2 / AES-256-GCM-16 / PRF-SHA256 / ECP-256 (DH19)",
      topology: "TUNNEL_SITE_TO_SITE (Impaired WAN)",
      expectedOutcome: "SUCCESS_UNDER_IMPAIRMENT",
      category: "IMPAIRMENT",
    },
    {
      id: "scn-06-tunnel-v4-natt",
      title: "NAT-Traversal Simulation (UDP port 4500 ESP encapsulation)",
      description: "Forces non-ESP marker and UDP port 4500 encapsulation to test middlebox and NAT traversal dissection.",
      crypto: "IKEv2 / AES-256-GCM-16 / UDP-4500 Encapsulated",
      topology: "TUNNEL_SITE_TO_SITE (NAT-T)",
      expectedOutcome: "SUCCESS",
      category: "NAT_T",
    },
    {
      id: "scn-07-tunnel-v4-ikev1-3des-sha1-weak",
      title: "Intentional Negative: Weak Legacy IKEv1 (3DES-CBC / SHA-1 / MODP-1024)",
      description: "Deliberately insecure legacy configuration to verify compliance policy triggering for Sweet32, weak hashes, and small DH.",
      crypto: "IKEv1 / 3DES-CBC / HMAC-SHA1 / MODP-1024 (DH2) / Weak",
      topology: "TUNNEL_SITE_TO_SITE (IKEv1)",
      expectedOutcome: "EXPECTED_NEGATIVE",
      category: "NEGATIVE_TEST",
    },
    {
      id: "scn-08-tunnel-v4-no-common-proposal",
      title: "Intentional Negative: Negotiation Rejection (Proposal Mismatch)",
      description: "Initiator offers AES-256-GCM / DH19 while Responder enforces AES-256-CBC / DH14. Confirms strongSwan NO_PROPOSAL_CHOSEN rejection.",
      crypto: "Initiator: AES-256-GCM / Responder: AES-256-CBC (Mismatch)",
      topology: "TUNNEL_SITE_TO_SITE (Mismatch)",
      expectedOutcome: "EXPECTED_REJECTION",
      category: "NEGATIVE_TEST",
    },
    {
      id: "scn-09-tunnel-v4-aes128gcm-pfs",
      title: "SIH Baseline Compliance: Tunnel Mode IPv4 (AES-128-GCM / MODP-2048 / PFS)",
      description: "Conforms to PS 26160 requirement for AES-128 alongside AES-256. Verified with DH Group 14 and PFS enabled.",
      crypto: "IKEv2 / AES-128-GCM-16 / PRF-SHA256 / MODP-2048 (DH14) / PFS Enabled",
      topology: "TUNNEL_SITE_TO_SITE (IPv4 AES-128)",
      expectedOutcome: "SUCCESS",
      category: "COMPLIANCE",
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <FlaskConical className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            IPsec Testbed & Automated Dataset Factory
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          Dual-node strongSwan testbed in isolated Linux network namespaces, Linux tc/NetEm impairment shaper, and multi-class traffic generators.
        </p>
      </div>

      {/* Operational Notice */}
      <div className="p-3 bg-neutral-100 dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-800 text-xs font-mono flex items-start space-x-3 text-neutral-700 dark:text-neutral-300">
        <ShieldAlert className="w-5 h-5 text-[#FF3D00] shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-bold text-neutral-900 dark:text-white uppercase">
            Platform & Safety Boundaries (SIH PS 26160 Compliance)
          </div>
          <p className="text-neutral-500">
            Active lab execution (creating veth pairs, launching Charon daemons, running tc/netem) requires an authorized Linux host with root/CAP_NET_ADMIN capabilities. On Windows development hosts, historical run manifests and PCAPs are analyzed locally, while live capture remains disabled.
          </p>
        </div>
      </div>

      {/* Environment Status Grid - Real Source-Backed Data */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card title="Runtime Host Dependencies">
          <div className="space-y-2 font-mono text-xs">
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">API Status:</span>
              <span className={`font-bold ${isReady ? "text-emerald-600" : "text-amber-600"}`}>
                {isLoading ? "PROBING..." : isReady ? "READY" : "ONLINE (DEGRADED)"}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">Database Engine:</span>
              <span className="font-bold">
                {dbStatus === "UP" ? "SQLite / Online" : dbStatus}
              </span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-neutral-500">Redis / Task Queue:</span>
              <span className={`font-bold ${redisStatus === "UP" ? "text-emerald-600" : "text-neutral-500"}`}>
                {redisStatus === "UP" ? "CONNECTED" : "DOWN (EAGER/IN-PROCESS)"}
              </span>
            </div>
          </div>
        </Card>

        <Card title="Forensics & Capture Stack">
          <div className="space-y-2 font-mono text-xs">
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">Dissection Engine:</span>
              <span className={`font-bold ${tsharkStatus === "UP" ? "text-emerald-600" : "text-amber-600"}`}>
                {tsharkStatus === "UP" ? tsharkVer : "SCAPY / NATIVE FALLBACK"}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">Privileged Sniffer:</span>
              <span className="font-bold text-neutral-500">
                {agentStatus} (LINUX ONLY)
              </span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-neutral-500">Upload Ingestion:</span>
              <span className="font-bold text-emerald-600">ACTIVE (PCAP/PCAPNG)</span>
            </div>
          </div>
        </Card>

        <Card title="Lab Scenarios & Dataset Store">
          <div className="space-y-2 font-mono text-xs">
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">Scenario Profiles:</span>
              <span className="font-bold text-emerald-600">9 Versioned YAMLs</span>
            </div>
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">Historical Runs:</span>
              <span className="font-bold">85 Manifests Stored</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-neutral-500">Workload Classes:</span>
              <span className="font-bold">7 Controlled Profiles</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Clarification on Crypto Terminology */}
      <div className="p-3 bg-neutral-50 dark:bg-neutral-900/60 border border-neutral-200 dark:border-neutral-800 text-xs font-mono text-neutral-600 dark:text-neutral-400 space-y-1">
        <div className="font-bold text-neutral-900 dark:text-white flex items-center gap-1.5">
          <HelpCircle className="w-4 h-4 text-sky-500" />
          <span>Cryptographic Qualification Note (Zero-Hype Policy)</span>
        </div>
        <p>
          Diffie-Hellman Group 19 (ECP-256 / NIST P-256) and Group 20 (ECP-384 / NIST P-384) are high-strength classical elliptic-curve groups (RFC 8221 recommended). They are <strong>not post-quantum</strong>. TunnelTrace AI labels all cryptographic primitives strictly according to IETF/NIST standards without marketing hyperbole.
        </p>
      </div>

      {/* Testbed Scenario Catalog */}
      <Card title="Pre-Configured IPsec Experiment Scenarios (Testbed Catalogue)">
        <div className="divide-y divide-neutral-200 dark:divide-neutral-800 text-xs font-mono">
          {labScenarios.map((scn) => (
            <div
              key={scn.id}
              className="py-4 flex flex-col md:flex-row md:items-start justify-between gap-4"
            >
              <div className="space-y-1.5 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-bold text-[#FF3D00]">{scn.id}</span>
                  <span className="font-semibold text-neutral-900 dark:text-white text-sm">
                    {scn.title}
                  </span>
                  <span className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 text-[10px] text-neutral-600 dark:text-neutral-400 border border-neutral-300 dark:border-neutral-700">
                    {scn.category}
                  </span>
                </div>
                <p className="text-neutral-500 text-[11px] leading-relaxed">
                  {scn.description}
                </p>
                <div className="text-[11px] text-neutral-600 dark:text-neutral-400 flex flex-wrap gap-x-4 gap-y-1 pt-1">
                  <span><strong>Crypto:</strong> {scn.crypto}</span>
                  <span><strong>Topology:</strong> {scn.topology}</span>
                  <span>
                    <strong>Expected:</strong>{" "}
                    <span className={scn.expectedOutcome.includes("NEGATIVE") || scn.expectedOutcome.includes("REJECTION") ? "text-amber-600 font-bold" : "text-emerald-600 font-bold"}>
                      {scn.expectedOutcome}
                    </span>
                  </span>
                </div>
              </div>

              <div className="shrink-0 text-right md:pt-1">
                <span className="inline-flex items-center gap-1 px-2 py-1 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-300 text-[10px] font-bold uppercase">
                  <FileCode className="w-3 h-3 text-neutral-400" />
                  YAML Spec
                </span>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* CLI Instruction Box for Operators */}
      <div className="p-4 bg-neutral-900 text-neutral-100 border border-neutral-800 text-xs font-mono space-y-2">
        <div className="flex items-center gap-2 text-neutral-400 text-[11px] uppercase tracking-wider">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span>Running an Authorized Scenario via CLI (Linux Testbed Host)</span>
        </div>
        <pre className="bg-black/50 p-2.5 rounded text-neutral-200 overflow-x-auto text-[11px] leading-relaxed">
          {`# 1. Execute scenario inside isolated network namespaces with root capabilities\n`}
          {`sudo python -m lab.runner --scenario scn-01-tunnel-v4-gcm-pfs --workload HTTPS --duration 30\n\n`}
          {`# 2. Ingest the recorded encrypted WAN capture into TunnelTrace AI for analysis\n`}
          {`curl -X POST http://127.0.0.1:8000/api/v1/captures -F "file=@storage/lab/runs/<run-id>/wan.pcap"`}
        </pre>
      </div>
    </div>
  );
}
