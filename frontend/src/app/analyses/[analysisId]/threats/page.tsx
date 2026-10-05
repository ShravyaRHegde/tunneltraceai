"use client";

import React, { use, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { SeverityBadge, EvidenceStateBadge } from "@/components/ui/badge";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { ThreatInstanceDTO, ThreatIntelItemDTO } from "@/lib/api/types";
import {
  Grid,
  Shield,
  AlertTriangle,
  AlertCircle,
  ShieldAlert,
  ExternalLink,
  Hash,
  Database,
  Info,
  CheckCircle2,
  Clock,
} from "lucide-react";

export default function ThreatMatrixPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [selectedThreat, setSelectedThreat] = useState<ThreatInstanceDTO | null>(null);

  const {
    data: threats,
    isLoading: threatsLoading,
    isError: threatsError,
    error: threatsErr,
  } = useQuery({
    queryKey: ["threats", analysisId],
    queryFn: () => api.analyses.getThreats(analysisId),
  });

  const {
    data: threatIntel,
    isLoading: intelLoading,
  } = useQuery({
    queryKey: ["threat-intelligence", analysisId],
    queryFn: () => api.analyses.getThreatIntelligence(analysisId),
  });

  const isLoading = threatsLoading;

  if (isLoading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
        Mapping security findings against deterministic threat catalog (THR-001..THR-008) and MITRE ATT&CK...
      </div>
    );
  }

  if (threatsError || !threats) {
    return (
      <div className="p-6 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 text-center space-y-2 font-mono text-xs text-rose-600">
        <AlertCircle className="w-6 h-6 mx-auto" />
        <p>Failed to load threat matrix: {(threatsErr as any)?.message || "Unknown error"}</p>
      </div>
    );
  }

  const catalogHash = threats.length > 0 && threats[0].catalog_hash ? threats[0].catalog_hash : null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <Grid className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            Threat Matrix & Adversary Tactics Mapping
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          <strong className="text-neutral-700 dark:text-neutral-300">What this shows:</strong> Correlated adversary tactics and exploitable vectors mapped from detected protocol weaknesses to MITRE ATT&CK techniques.
        </p>
      </div>

      {/* Catalog & Epistemic Boundary Notice */}
      <div className="p-4 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 space-y-2">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="font-bold text-neutral-900 dark:text-white uppercase">
              Pre-Authored Threat Catalog
            </span>
            <span className="text-neutral-500">(THR-001 through THR-008)</span>
          </div>
          {catalogHash && (
            <div className="flex items-center space-x-1.5 font-mono text-[11px] text-neutral-500">
              <Hash className="w-3.5 h-3.5 text-neutral-400" />
              <span>Catalog Hash:</span>
              <CopyableValue
                value={catalogHash}
                truncate
              />
            </div>
          )}
        </div>
        <p className="text-[11px] font-sans text-neutral-500 leading-relaxed">
          <strong className="text-neutral-700 dark:text-neutral-300">Epistemic Boundary:</strong> MITRE ATT&CK mappings represent taxonomy context for operational risk prioritization. They are <strong className="text-neutral-700 dark:text-neutral-300">NOT</strong> assertions that an adversary executed a technique or that a gateway is compromised. Unmapped entries reflect cryptanalytic boundaries rather than execution techniques.
        </p>
      </div>

      {/* Main Workspace (12 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className={selectedThreat ? "lg:col-span-8" : "lg:col-span-12"}>
          <Card title={`Active Threat Catalog Mappings (${threats.length})`}>
            {threats.length > 0 ? (
              <Table>
                <TableHeader>
                  <tr>
                    <TableHead>Threat ID</TableHead>
                    <TableHead>Threat Title</TableHead>
                    <TableHead>Vector</TableHead>
                    <TableHead>Risk Tier</TableHead>
                    <TableHead>Likelihood / Impact</TableHead>
                    <TableHead>MITRE ATT&CK</TableHead>
                    <TableHead>Evidence</TableHead>
                  </tr>
                </TableHeader>
                <TableBody>
                  {threats.map((threat, idx) => {
                    const attackId = threat.mitre_attack_id || (threat.mitre_technique_id !== "N/A" ? threat.mitre_technique_id : null);
                    const rowKey = `${threat.threat_id}-${threat.finding_id || "nofind"}-${idx}`;
                    const isSelected = selectedThreat?.threat_id === threat.threat_id && (threat.finding_id ? selectedThreat?.finding_id === threat.finding_id : true);
                    return (
                      <TableRow
                        key={rowKey}
                        onClick={() => setSelectedThreat(threat)}
                        isSelected={isSelected}
                      >
                        <TableCell mono>
                          <span className="font-bold text-neutral-900 dark:text-white">
                            {threat.threat_id}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="font-bold text-neutral-900 dark:text-white">
                            {threat.threat_name || threat.title}
                          </span>
                        </TableCell>
                        <TableCell mono className="text-neutral-500 uppercase text-[11px]">
                          {threat.attack_vector || threat.category}
                        </TableCell>
                        <TableCell>
                          <SeverityBadge severity={threat.risk_tier} />
                        </TableCell>
                        <TableCell mono className="text-neutral-600 dark:text-neutral-300 text-[11px]">
                          {threat.likelihood} / {threat.impact}
                        </TableCell>
                        <TableCell mono>
                          {attackId ? (
                            <span className="text-[#FF3D00] font-bold flex items-center space-x-1">
                              <span>{attackId}</span>
                              <ExternalLink className="w-3 h-3 inline" />
                            </span>
                          ) : (
                            <span className="text-[10px] text-neutral-400 italic">
                              Unmapped
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <EvidenceStateBadge state={threat.evidence_state || "VERIFIED"} />
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            ) : (
              <div className="py-8 px-4 text-center font-mono text-xs space-y-2">
                <CheckCircle2 className="w-6 h-6 text-emerald-500 mx-auto" />
                <p className="font-bold text-neutral-800 dark:text-neutral-200 uppercase">
                  No Active Threat Mappings for Current Capture
                </p>
                <p className="text-neutral-500 max-w-xl mx-auto text-[11px] font-sans">
                  No policy violations were triggered on the evaluated packet evidence. MITRE ATT&CK adversary tactics are mapped strictly from verified security findings. Zero findings indicates that no prohibited transforms or protocol anomalies were observed in this capture — it is not an assertion of overall infrastructure invulnerability.
                </p>
              </div>
            )}
          </Card>
        </div>

        {/* Right Contextual Inspector */}
        {selectedThreat && (
          <div className="lg:col-span-4">
            <InspectorDrawer
              isOpen={!!selectedThreat}
              onClose={() => setSelectedThreat(null)}
              title={selectedThreat.threat_name || selectedThreat.title || selectedThreat.threat_id}
              subtitle={`Threat Catalog: ${selectedThreat.threat_id}`}
              badge={<SeverityBadge severity={selectedThreat.risk_tier} />}
            >
              <div className="space-y-4 font-mono text-xs">
                {/* Risk Parameters */}
                <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-1.5">
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Likelihood:</span>
                    <span className="font-bold text-neutral-900 dark:text-white">
                      {selectedThreat.likelihood}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Impact:</span>
                    <span className="font-bold text-neutral-900 dark:text-white">
                      {selectedThreat.impact}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Vector:</span>
                    <span className="truncate max-w-[200px]">{selectedThreat.attack_vector || selectedThreat.category}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Evidence State:</span>
                    <span>{selectedThreat.evidence_state || "VERIFIED"}</span>
                  </div>
                </div>

                {/* MITRE ATT&CK Details */}
                <div>
                  <span className="text-[10px] uppercase text-neutral-400 block mb-1">
                    MITRE ATT&CK Mapping
                  </span>
                  {selectedThreat.mitre_attack_id ? (
                    <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-bold text-[#FF3D00]">
                          {selectedThreat.mitre_attack_id}
                        </span>
                        {selectedThreat.mitre_attack_url && (
                          <a
                            href={selectedThreat.mitre_attack_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[#FF3D00] hover:underline flex items-center space-x-1 text-[11px]"
                          >
                            <span>Official Docs</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                      {selectedThreat.mitre_attack_name && (
                        <div className="font-semibold text-neutral-900 dark:text-white">
                          {selectedThreat.mitre_attack_name}
                        </div>
                      )}
                      {selectedThreat.mitre_attack_rationale && (
                        <div className="text-[11px] text-neutral-600 dark:text-neutral-400 font-sans leading-relaxed pt-1 border-t border-neutral-200 dark:border-neutral-800">
                          {selectedThreat.mitre_attack_rationale}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-[11px] text-neutral-500 font-sans leading-relaxed">
                      <p className="font-semibold text-neutral-700 dark:text-neutral-300 mb-1">
                        Intentionally Unmapped Entry
                      </p>
                      <p>
                        This threat scenario represents a mathematical or cryptanalytic limitation (e.g. Diffie-Hellman prime modulus precomputation or 64-bit block collision birthday bound) rather than an adversary execution technique in MITRE ATT&CK Enterprise.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </InspectorDrawer>
          </div>
        )}
      </div>

      {/* Offline Threat Intelligence Context (CISA KEV & FIRST EPSS) */}
      {threatIntel && (
        <Card title="Global Threat Intelligence Snapshot (Unmatched Reference Feed)">
          <div className="space-y-4">
            <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-[11px] font-sans text-neutral-600 dark:text-neutral-400 space-y-1">
              <div className="flex items-center space-x-1.5 font-mono text-xs font-bold text-neutral-700 dark:text-neutral-300 uppercase">
                <Info className="w-3.5 h-3.5 text-neutral-400 shrink-0" />
                <span>Reference Context · Not Matched to Observed Capture</span>
              </div>
              <p>
                The CVE records below represent a dated reference snapshot of known IPsec vulnerabilities from CISA KEV and FIRST EPSS for analyst situational awareness. <strong>None of these CVEs have been matched to an observed product, vendor, or version in this packet capture.</strong>
              </p>
            </div>

            <div className="flex items-center justify-between text-xs font-mono text-neutral-500 border-b border-neutral-200 dark:border-neutral-800 pb-2">
              <div className="flex items-center space-x-2">
                <Database className="w-4 h-4 text-[#FF3D00]" />
                <span>Source Status:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {threatIntel.source_freshness}
                </span>
              </div>
              <div className="flex items-center space-x-1">
                <Info className="w-3.5 h-3.5 text-neutral-400" />
                <span>Offline Verified Snapshot</span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {threatIntel.intel_items.map((item: ThreatIntelItemDTO, idx: number) => (
                <div
                  key={`${item.cve_id}-${idx}`}
                  className="p-3 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 font-mono text-xs space-y-2"
                >
                  <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-1.5">
                    <span className="font-bold text-neutral-900 dark:text-white">
                      {item.cve_id}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 text-[10px] uppercase font-bold ${
                        item.cisa_kev_status === "PRESENT"
                          ? "bg-rose-100 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400"
                          : "bg-neutral-100 dark:bg-neutral-800 text-neutral-500"
                      }`}
                    >
                      KEV: {item.cisa_kev_status}
                    </span>
                  </div>

                  {item.cisa_kev_record && (
                    <div className="space-y-1 text-[11px]">
                      <div className="text-neutral-500 font-semibold">
                        {item.cisa_kev_record.product}
                      </div>
                      <div className="text-neutral-700 dark:text-neutral-300 font-sans text-[11px] leading-tight line-clamp-2">
                        {item.cisa_kev_record.short_description}
                      </div>
                      <div className="text-[10px] text-neutral-400">
                        Date Added: {item.cisa_kev_record.date_added}
                      </div>
                    </div>
                  )}

                  {item.epss_record && (
                    <div className="pt-1.5 border-t border-neutral-200 dark:border-neutral-800 flex justify-between text-[11px]">
                      <span className="text-neutral-500">FIRST EPSS (30-day):</span>
                      <span className="font-bold text-neutral-900 dark:text-white">
                        {(item.epss_record.epss_score * 100).toFixed(1)}% (
                        {(item.epss_record.epss_percentile * 100).toFixed(0)}th percentile)
                      </span>
                    </div>
                  )}
                </div>
              ))}
            </div>

            <p className="text-[10px] font-sans text-neutral-400 italic">
              Notice: {threatIntel.disclaimer}
            </p>
          </div>
        </Card>
      )}
    </div>
  );
}
