"use client";

import React, { use } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { EvidenceStateBadge } from "@/components/ui/badge";
import { CopyableValue } from "@/components/ui/table";
import { Network, AlertCircle, CheckCircle, ShieldAlert, HelpCircle } from "lucide-react";

export default function ProtocolIntelligencePage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);

  const {
    data: protocol,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["protocol", analysisId],
    queryFn: () => api.analyses.getProtocol(analysisId),
  });

  if (isLoading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
        Dissecting protocol frames and extracting IKE/ESP parameters...
      </div>
    );
  }

  if (isError || !protocol) {
    return (
      <div className="p-6 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 text-center space-y-2 font-mono text-xs text-rose-600">
        <AlertCircle className="w-6 h-6 mx-auto" />
        <p>Failed to load protocol intelligence: {(error as any)?.message || "Unknown error"}</p>
      </div>
    );
  }

  const { evidence_states } = protocol;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <Network className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            Protocol Intelligence & Cryptographic Handshake Forensics
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          <strong className="text-neutral-700 dark:text-neutral-300">What this shows:</strong> Which IPsec protocol version, mode, and cryptographic suites we could actually verify from the packets — anything not observed is marked UNKNOWN, never guessed.
        </p>
      </div>

      {/* Primary Status Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card title="IPsec Protocol Status">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className={`text-2xl font-mono font-bold ${protocol.ipsec_detected ? "text-emerald-600" : "text-neutral-400"}`}>
                {protocol.ipsec_detected ? "DETECTED" : "NOT OBSERVED"}
              </span>
            </div>
            <p className="text-[11px] font-mono text-neutral-500">
              Total frames inspected: {protocol.total_packets_inspected}
            </p>
          </div>
        </Card>

        <Card title="IKE Negotiation Packets">
          <div className="space-y-1 font-mono">
            <div className="text-2xl font-bold text-neutral-900 dark:text-white">
              {protocol.ikev1_packet_count + protocol.ikev2_packet_count}
            </div>
            <div className="text-[11px] text-neutral-500 flex space-x-3">
              <span>IKEv1: {protocol.ikev1_packet_count}</span>
              <span>IKEv2: {protocol.ikev2_packet_count}</span>
            </div>
          </div>
        </Card>

        <Card title="Encapsulation (ESP / AH)">
          <div className="space-y-1 font-mono">
            <div className="text-2xl font-bold text-neutral-900 dark:text-white">
              {protocol.esp_packet_count + protocol.ah_packet_count}
            </div>
            <div className="text-[11px] text-neutral-500 flex space-x-3">
              <span>ESP: {protocol.esp_packet_count}</span>
              <span>AH: {protocol.ah_packet_count}</span>
            </div>
          </div>
        </Card>

        <Card title="NAT-T Traversal Status">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className={`text-2xl font-mono font-bold ${
                protocol.nat_t_detected
                  ? "text-sky-600"
                  : (protocol.ikev1_packet_count + protocol.ikev2_packet_count > 0)
                    ? "text-neutral-700 dark:text-neutral-300"
                    : "text-amber-600 dark:text-amber-400"
              }`}>
                {protocol.nat_t_detected
                  ? "UDP 4500 (NAT-T)"
                  : (protocol.ikev1_packet_count + protocol.ikev2_packet_count > 0)
                    ? "DIRECT / UDP 500"
                    : "NOT OBSERVED (NO IKE)"}
              </span>
            </div>
            <p className="text-[11px] font-mono text-neutral-500">
              {protocol.nat_t_detected
                ? "UDP encapsulation with non-ESP marker detected."
                : (protocol.ikev1_packet_count + protocol.ikev2_packet_count > 0)
                  ? "Standard direct UDP 500 handshake without NAT encapsulation."
                  : "No IKE handshake observed in capture. Direct ESP over raw IP (protocol 50)."}
            </p>
          </div>
        </Card>
      </div>

      {/* Dissected Handshake Parameters */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Cryptographic Transforms & DH Groups */}
        <div className="space-y-6">
          <Card
            title="Negotiated & Proposed Cryptographic Transforms"
            badge={<EvidenceStateBadge state={evidence_states?.cipher_suites || "INFERRED"} />}
          >
            <div className="space-y-4">
              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-500 block mb-2">
                  Cipher Suites (Encryption Algorithms)
                </span>
                {protocol.observed_cipher_suites && protocol.observed_cipher_suites.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {protocol.observed_cipher_suites.map((cipher: string, idx: number) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 text-xs font-mono font-bold bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-900 dark:text-white"
                      >
                        {cipher}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs font-mono text-neutral-500">
                    No cipher transforms observed in unencrypted handshake frames (session may have been captured mid-stream).
                  </div>
                )}
              </div>

              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-500 block mb-2">
                  Diffie-Hellman / Key Exchange Groups
                </span>
                {protocol.observed_dh_groups && protocol.observed_dh_groups.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {protocol.observed_dh_groups.map((dh: string, idx: number) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 text-xs font-mono font-bold bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-900 dark:text-white"
                      >
                        {dh}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs font-mono text-neutral-500">
                    Diffie-Hellman parameters not observed in capture window. State: UNKNOWN.
                  </div>
                )}
              </div>

              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-500 block mb-2">
                  Observed IKE Exchange Types
                </span>
                {protocol.observed_exchange_types && protocol.observed_exchange_types.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {protocol.observed_exchange_types.map((ex: string, idx: number) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 text-xs font-mono bg-sky-50 dark:bg-sky-950/20 text-sky-900 dark:text-sky-300 border border-sky-300 dark:border-sky-800"
                      >
                        {ex}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-neutral-500">
                    No discrete IKE exchange headers detected.
                  </div>
                )}
              </div>
            </div>
          </Card>
        </div>

        {/* Right: Security Parameter Index (SPI) Observation Table */}
        <div className="space-y-6">
          <Card title="Observed Session SPI Identifiers">
            <div className="space-y-4">
              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-500 block mb-2">
                  Initiator SPIs ({protocol.observed_initiator_spis?.length || 0})
                </span>
                {protocol.observed_initiator_spis && protocol.observed_initiator_spis.length > 0 ? (
                  <div className="space-y-1.5">
                    {protocol.observed_initiator_spis.map((spi: string, idx: number) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-2 bg-neutral-50 dark:bg-neutral-900/60 border border-neutral-200 dark:border-neutral-800"
                      >
                        <CopyableValue value={spi} label="Initiator SPI" />
                        <span className="text-[10px] font-mono text-neutral-400">INITIATOR</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-neutral-500 p-3 border border-neutral-200 dark:border-neutral-800">
                    No initiator SPIs observed.
                  </div>
                )}
              </div>

              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-500 block mb-2">
                  Responder SPIs ({protocol.observed_responder_spis?.length || 0})
                </span>
                {protocol.observed_responder_spis && protocol.observed_responder_spis.length > 0 ? (
                  <div className="space-y-1.5">
                    {protocol.observed_responder_spis.map((spi: string, idx: number) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-2 bg-neutral-50 dark:bg-neutral-900/60 border border-neutral-200 dark:border-neutral-800"
                      >
                        <CopyableValue value={spi} label="Responder SPI" />
                        <span className="text-[10px] font-mono text-neutral-400">RESPONDER</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-neutral-500 p-3 border border-neutral-200 dark:border-neutral-800">
                    No responder SPIs observed.
                  </div>
                )}
              </div>
            </div>
          </Card>
        </div>
      </div>

      {/* Stage 3: Evidence Concordance Lane & Active IKE Probe Assessment */}
      <IkeEvidenceConcordanceSection analysisId={analysisId} protocol={protocol} />
    </div>
  );
}

function IkeEvidenceConcordanceSection({
  analysisId,
  protocol,
}: {
  analysisId: string;
  protocol: any;
}) {
  const { data: concordanceRecords, isLoading: isConcordanceLoading } = useQuery({
    queryKey: ["ikeConcordance", analysisId],
    queryFn: () => api.ikeAssessment.getConcordance(analysisId),
  });

  const { data: ikeStatus } = useQuery({
    queryKey: ["ikeStatus"],
    queryFn: () => api.ikeAssessment.getStatus(),
  });

  const latestConcordance =
    concordanceRecords && concordanceRecords.length > 0 ? concordanceRecords[0] : null;

  return (
    <div className="space-y-4 pt-6 border-t border-neutral-300 dark:border-neutral-800">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-[#FF3D00]" />
            <h2 className="text-base font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
              Evidence Concordance Lane (TShark Passive Dissection vs. IKE-scan Active Probes)
            </h2>
          </div>
          <p className="text-xs text-neutral-500 mt-0.5">
            Deterministic triangulation across passive packet captures, bounded active endpoint probes, and lab ground truth.
          </p>
        </div>

        {/* Toolchain Availability Indicator */}
        <div className="flex items-center space-x-2 font-mono text-xs">
          <span className="text-neutral-500">IKE-scan Toolchain:</span>
          {ikeStatus?.ike_scan_available ? (
            <span className="px-2 py-0.5 bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800 font-bold">
              AVAILABLE ({ikeStatus.ike_scan_version || "OPERABLE"})
            </span>
          ) : (
            <span className="px-2 py-0.5 bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-400 border border-amber-300 dark:border-amber-800 font-bold">
              UNAVAILABLE ON HOST (Live scan disabled)
            </span>
          )}
        </div>
      </div>

      {/* Concordance Status Banner */}
      <div className="p-4 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-neutral-200 dark:border-neutral-800 pb-3">
          <div className="flex items-center space-x-3">
            <span className="text-xs font-mono font-bold uppercase text-neutral-500">
              Concordance Verdict:
            </span>
            {latestConcordance ? (
              <span
                className={`px-2.5 py-1 text-xs font-mono font-bold border ${
                  latestConcordance.concordance_status === "CONSISTENT"
                    ? "bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800"
                    : latestConcordance.concordance_status === "CONFLICT"
                    ? "bg-rose-50 dark:bg-rose-950/30 text-rose-700 dark:text-rose-400 border-rose-300 dark:border-rose-800"
                    : "bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-800"
                }`}
              >
                {latestConcordance.concordance_status}
              </span>
            ) : (
              <span className="px-2.5 py-1 text-xs font-mono font-bold bg-neutral-100 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-400 border border-neutral-300 dark:border-neutral-700">
                INSUFFICIENT EVIDENCE (NO ACTIVE PROBES CONDUCTED FOR THIS CAPTURE)
              </span>
            )}
          </div>

          <div className="text-[11px] font-mono text-neutral-500">
            {latestConcordance
              ? `Evaluated: ${new Date(latestConcordance.evaluated_at).toLocaleString()}`
              : "Awaiting authorized active probe triangulation"}
          </div>
        </div>

        {/* 3-Lane Architecture Comparison */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
          {/* Lane 1: Passive Observation Lane */}
          <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-neutral-900 dark:text-white uppercase">
                Lane 1: Passive TShark Dissection
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-neutral-200 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300">
                Ground Capture Facts
              </span>
            </div>
            <div className="space-y-1 text-xs font-mono">
              <div className="flex justify-between text-neutral-600 dark:text-neutral-400">
                <span>Observed IKE Versions:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {protocol.ikev2_packet_count > 0 && protocol.ikev1_packet_count > 0
                    ? "IKEv1, IKEv2"
                    : protocol.ikev2_packet_count > 0
                    ? "IKEv2"
                    : protocol.ikev1_packet_count > 0
                    ? "IKEv1"
                    : "None Observed"}
                </span>
              </div>
              <div className="flex justify-between text-neutral-600 dark:text-neutral-400">
                <span>Negotiated Cipher:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {protocol.observed_cipher_suites?.[0] || "Not Observed in Clear"}
                </span>
              </div>
              <div className="flex justify-between text-neutral-600 dark:text-neutral-400">
                <span>Initial Handshake Frames:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {protocol.ikev1_packet_count + protocol.ikev2_packet_count > 0 ? "Present" : "Missing / Incomplete"}
                </span>
              </div>
            </div>
            <p className="text-[10px] text-neutral-500 pt-1 border-t border-neutral-200 dark:border-neutral-800">
              Passively derived from TShark 4.6.4 without emitting any network traffic.
            </p>
          </div>

          {/* Lane 2: Active Probe Lane */}
          <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-neutral-900 dark:text-white uppercase">
                Lane 2: Active IKE-scan Probe
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-amber-100 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300">
                Scanner Evidence
              </span>
            </div>
            <div className="space-y-1 text-xs font-mono">
              <div className="flex justify-between text-neutral-600 dark:text-neutral-400">
                <span>Probe Status:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {latestConcordance?.concordance_details?.active_lane?.response_categories?.[0] ||
                    (ikeStatus?.ike_scan_available ? "NO RECENT RUN" : "TOOL UNAVAILABLE")}
                </span>
              </div>
              <div className="flex justify-between text-neutral-600 dark:text-neutral-400">
                <span>Accepted Cipher:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {latestConcordance?.active_accepted_cipher || "None Recorded"}
                </span>
              </div>
              <div className="flex justify-between text-neutral-600 dark:text-neutral-400">
                <span>IKEv2 Experimental:</span>
                <span className="font-bold text-amber-600">Default Proposal Only</span>
              </div>
            </div>
            <p className="text-[10px] text-neutral-500 pt-1 border-t border-neutral-200 dark:border-neutral-800">
              Active probes prove only endpoint response capability, not tunnel authentication or security.
            </p>
          </div>

          {/* Lane 3: Lab Simulation Lane */}
          <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-neutral-900 dark:text-white uppercase">
                Lane 3: Lab Ground Truth
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-neutral-200 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300">
                Namespace Baseline
              </span>
            </div>
            <div className="space-y-1 text-xs font-mono">
              <div className="flex justify-between text-neutral-600 dark:text-neutral-400">
                <span>strongSwan Namespace:</span>
                <span className="font-bold text-neutral-900 dark:text-white">Isolated Testbed</span>
              </div>
              <div className="flex justify-between text-neutral-600 dark:text-neutral-400">
                <span>External Traffic:</span>
                <span className="font-bold text-emerald-600">ZERO (Strictly Blocked)</span>
              </div>
              <div className="flex justify-between text-neutral-600 dark:text-neutral-400">
                <span>Credential Cracking:</span>
                <span className="font-bold text-rose-600">FORBIDDEN (--pskcrack banned)</span>
              </div>
            </div>
            <p className="text-[10px] text-neutral-500 pt-1 border-t border-neutral-200 dark:border-neutral-800">
              Controlled environment reference for differential regression testing.
            </p>
          </div>
        </div>

        {/* Epistemic Honesty & Limitation Notice */}
        <div className="p-3 bg-neutral-100 dark:bg-neutral-950 border border-neutral-300 dark:border-neutral-800 text-[11px] font-mono text-neutral-600 dark:text-neutral-400 space-y-1">
          <div className="font-bold text-neutral-900 dark:text-neutral-200 flex items-center space-x-1">
            <AlertCircle className="w-3.5 h-3.5 text-amber-500 inline mr-1" />
            Epistemic Boundary & Operational Guardrails:
          </div>
          <p>
            1. <strong>Direct Observations Only:</strong> Scanner evidence reflects active probe responses, never asserted vulnerabilities or assumed tunnel completion.
          </p>
          <p>
            2. <strong>IKEv2 Experimental Limits:</strong> Upstream <code className="text-[#FF3D00]">ike-scan</code> IKEv2 implementation sends default proposals and does not comprehensively enumerate transforms.
          </p>
          <p>
            3. <strong>Intrusive Probes Prohibited:</strong> Aggressive Mode identity harvesting, <code className="text-rose-500">--pskcrack</code>, and credential guessing are strictly excluded from all adapter execution vectors.
          </p>
        </div>
      </div>
    </div>
  );
}

