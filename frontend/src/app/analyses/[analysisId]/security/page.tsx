"use client";

import React, { use, useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { formatCoverage } from "@/lib/format";
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
import { SecurityFindingDTO } from "@/lib/api/types";
import {
  ShieldAlert,
  Search,
  Filter,
  ArrowRight,
  ExternalLink,
  AlertCircle,
  FileSearch,
  Hash,
  Activity,
  Layers,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  FileText,
  History,
  Radio,
} from "lucide-react";
import { SocWorkflowBanner } from "@/components/soc/soc-workflow-banner";

function getFindingSource(f: SecurityFindingDTO) {
  const rid = (f.rule_id || "").toUpperCase();
  if (rid.includes("OPENVAS") || rid.includes("GREENBONE") || rid.includes("CVE")) {
    return {
      label: "SCANNER (SUPPLEMENTAL)",
      badge: "border-indigo-500/40 bg-indigo-500/10 text-indigo-500 dark:text-indigo-400",
      description: "Supplemental scanner observation imported via Greenbone/OpenVAS XML. Does not calculate core score deductions.",
    };
  }
  if (rid.includes("CONF") || rid.includes("CERT") || rid.includes("DRIFT")) {
    return {
      label: "CONFIG INVENTORY",
      badge: "border-sky-500/40 bg-sky-500/10 text-sky-500 dark:text-sky-400",
      description: "Configuration or certificate baseline drift finding from strongSwan inventory.",
    };
  }
  if (rid.includes("THREAT") || rid.includes("ATTACK") || rid.includes("MITRE")) {
    return {
      label: "THREAT INTEL",
      badge: "border-amber-500/40 bg-amber-500/10 text-amber-500 dark:text-amber-400",
      description: "Contextual STRIDE / MITRE ATT&CK tactical mapping.",
    };
  }
  return {
    label: "DETERMINISTIC POLICY",
    badge: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
    description: "Evaluated deterministically from versioned YAML policy bundle (NIST SP 800-77 / RFC 8221).",
  };
}

export default function SecurityAssessmentPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [selectedFinding, setSelectedFinding] = useState<SecurityFindingDTO | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [search, setSearch] = useState<string>("");

  const {
    data: findings,
    isLoading: findingsLoading,
    isError: findingsError,
    error: findingsErr,
  } = useQuery({
    queryKey: ["findings", analysisId],
    queryFn: () => api.analyses.getFindings(analysisId),
  });

  const {
    data: riskAssessment,
    isLoading: riskLoading,
  } = useQuery({
    queryKey: ["risk", analysisId],
    queryFn: () => api.analyses.getRisk(analysisId),
  });

  const isLoading = findingsLoading || riskLoading;

  if (isLoading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
        Evaluating cryptographic policies, calculating score deductions, and compiling findings...
      </div>
    );
  }

  if (findingsError || !findings) {
    return (
      <div className="p-6 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 text-center space-y-2 font-mono text-xs text-rose-600">
        <AlertCircle className="w-6 h-6 mx-auto" />
        <p>Failed to load security findings: {(findingsErr as any)?.message || "Unknown error"}</p>
      </div>
    );
  }

  const filteredFindings = findings.filter((f) => {
    const matchesSeverity =
      severityFilter === "ALL" || f.severity.toUpperCase() === severityFilter;
    const matchesSearch =
      search === "" ||
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.rule_id.toLowerCase().includes(search.toLowerCase()) ||
      f.affected_entity.toLowerCase().includes(search.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  // Find matching risk item for selected finding
  const selectedRiskItem = selectedFinding && riskAssessment?.items
    ? riskAssessment.items.find((item) => item.finding_id === selectedFinding.finding_id)
    : null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            Security Assessment & Deterministic Policy Findings
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          Stage-8 rule evaluation, cryptographic standard violations, itemized posture score deductions, and deterministic remediation directives.
        </p>
      </div>

      {/* SOC Analyst Workflow Stepper */}
      <SocWorkflowBanner
        activeStep={4}
        analysisId={analysisId}
        evidenceCoverage={riskAssessment?.evidence_coverage ?? null}
      />

      {/* Methodology & Evidence-Based Risk Banner */}
      {riskAssessment && (
        <div className="p-4 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 space-y-3">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-neutral-200 dark:border-neutral-800 pb-3">
            <div className="flex items-center space-x-3">
              <span className="font-mono text-xs text-neutral-500 uppercase font-semibold">
                Aggregate Risk Posture:
              </span>
              {riskAssessment.overall_risk_tier === "CRITICAL" && (
                <span className="px-2.5 py-1 text-xs font-mono font-bold uppercase bg-rose-600 text-white">
                  CRITICAL
                </span>
              )}
              {riskAssessment.overall_risk_tier === "HIGH" && (
                <span className="px-2.5 py-1 text-xs font-mono font-bold uppercase bg-amber-600 text-white">
                  HIGH
                </span>
              )}
              {riskAssessment.overall_risk_tier === "MEDIUM" && (
                <span className="px-2.5 py-1 text-xs font-mono font-bold uppercase bg-yellow-500 text-neutral-950 font-bold">
                  MEDIUM
                </span>
              )}
              {riskAssessment.overall_risk_tier === "LOW" && (
                <span className="px-2.5 py-1 text-xs font-mono font-bold uppercase bg-emerald-600 text-white">
                  LOW
                </span>
              )}
              {riskAssessment.overall_risk_tier === "NO_FINDINGS_UNDER_THIS_POLICY" && (
                <span className="px-2.5 py-1 text-xs font-mono font-bold uppercase bg-emerald-700 text-white flex items-center space-x-1">
                  <CheckCircle2 className="w-3.5 h-3.5 inline mr-1" />
                  NO FINDINGS UNDER ACTIVE POLICY
                </span>
              )}
              {riskAssessment.overall_risk_tier === "INSUFFICIENT_EVIDENCE" && (
                <span className="px-2.5 py-1 text-xs font-mono font-bold uppercase bg-neutral-600 text-white flex items-center space-x-1">
                  <HelpCircle className="w-3.5 h-3.5 inline mr-1" />
                  INSUFFICIENT EVIDENCE (GAPS OBSERVED)
                </span>
              )}
            </div>

            <div className="flex items-center space-x-4 font-mono text-xs text-neutral-600 dark:text-neutral-400">
              <div className="flex items-center space-x-1">
                <Activity className="w-3.5 h-3.5 text-[#FF3D00]" />
                <span>Evidence Coverage:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {formatCoverage(riskAssessment.evidence_coverage)}
                </span>
              </div>
              <div className="flex items-center space-x-1">
                <Layers className="w-3.5 h-3.5 text-neutral-500" />
                <span>Gaps:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {riskAssessment.evidence_gaps_count ?? 0}
                </span>
              </div>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] font-mono text-neutral-500">
            <div>
              <span className="text-neutral-400">Methodology:</span>{" "}
              <span className="text-neutral-700 dark:text-neutral-300 font-semibold">
                {riskAssessment.methodology_type || "DETERMINISTIC_PRIORITIZATION_HEURISTIC"}
              </span>{" "}
              ({riskAssessment.risk_policy_id} v{riskAssessment.risk_policy_version})
            </div>
            <div className="flex items-center space-x-1">
              <Hash className="w-3 h-3 text-neutral-400" />
              <span>Policy Hash:</span>
              <CopyableValue
                value={riskAssessment.risk_policy_hash}
                truncate
              />
            </div>
          </div>

          <p className="text-[10px] font-sans text-neutral-400 italic">
            Notice: {riskAssessment.disclaimer || "Internal deterministic heuristic. Not an empirically calibrated probability."}
          </p>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-2 flex-1 max-w-md">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-neutral-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search findings by rule ID, title, or entity..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-xs bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 font-mono text-neutral-900 dark:text-white placeholder-neutral-400 focus:outline-none focus:border-[#FF3D00]"
            />
          </div>
        </div>

        {/* Severity Filter Buttons */}
        <div className="flex items-center space-x-1 font-mono text-xs overflow-x-auto">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 border transition-colors ${
                severityFilter === sev
                  ? "bg-neutral-900 dark:bg-white text-white dark:text-neutral-900 font-bold border-neutral-900 dark:border-white"
                  : "bg-white dark:bg-[#141416] text-neutral-600 dark:text-neutral-400 border-neutral-300 dark:border-neutral-800 hover:border-neutral-400"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Main Workspace (12 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Findings Table */}
        <div className={selectedFinding ? "lg:col-span-7" : "lg:col-span-12"}>
          <Card title={`Evaluated Findings (${filteredFindings.length})`}>
            {filteredFindings.length > 0 ? (
              <Table>
                <TableHeader>
                  <tr>
                    <TableHead>Severity</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Rule ID</TableHead>
                    <TableHead>Finding Title</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Affected Entity</TableHead>
                    <TableHead>Deduction</TableHead>
                    <TableHead>Evidence</TableHead>
                  </tr>
                </TableHeader>
                <TableBody>
                  {filteredFindings.map((finding) => {
                    const src = getFindingSource(finding);
                    return (
                      <TableRow
                        key={finding.finding_id}
                        onClick={() => setSelectedFinding(finding)}
                        isSelected={selectedFinding?.finding_id === finding.finding_id}
                      >
                        <TableCell>
                          <SeverityBadge severity={finding.severity} />
                        </TableCell>
                        <TableCell>
                          <span
                            className={`px-1.5 py-0.5 text-[9px] font-mono font-bold uppercase border ${src.badge}`}
                          >
                            {src.label}
                          </span>
                        </TableCell>
                        <TableCell mono>
                          <span className="font-semibold text-neutral-900 dark:text-white">
                            {finding.rule_id}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="font-bold text-neutral-900 dark:text-white">
                            {finding.title}
                          </span>
                        </TableCell>
                        <TableCell mono className="text-neutral-500 uppercase text-[11px]">
                          {finding.category}
                        </TableCell>
                        <TableCell mono className="text-neutral-600 dark:text-neutral-300 text-[11px]">
                          {finding.affected_entity}
                        </TableCell>
                        <TableCell mono>
                          <span className="font-bold text-rose-600">
                            -{finding.score_deduction}
                          </span>
                        </TableCell>
                        <TableCell>
                          <EvidenceStateBadge state={finding.evidence_state} />
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            ) : (
              <div className="py-12 text-center font-mono text-xs text-neutral-500 space-y-2">
                <p>No security findings match the current filter.</p>
                {riskAssessment?.overall_risk_tier === "INSUFFICIENT_EVIDENCE" && (
                  <p className="text-amber-500 font-semibold">
                    Evidence coverage ({formatCoverage(riskAssessment.evidence_coverage)}) is below policy threshold.
                    Inadequate evidence is preserved as an explicit gap, not assumed safe.
                  </p>
                )}
                {riskAssessment?.overall_risk_tier === "NO_FINDINGS_UNDER_THIS_POLICY" && (
                  <p className="text-emerald-500 font-semibold">
                    Zero rule violations identified with {formatCoverage(riskAssessment.evidence_coverage)} evaluated evidence coverage.
                  </p>
                )}
              </div>
            )}
          </Card>
        </div>

        {/* Right Contextual Inspector & Factor Breakdown */}
        {selectedFinding && (
          <div className="lg:col-span-5">
            <InspectorDrawer
              isOpen={!!selectedFinding}
              onClose={() => setSelectedFinding(null)}
              title={selectedFinding.title}
              subtitle={`Rule: ${selectedFinding.rule_id}`}
              badge={<SeverityBadge severity={selectedFinding.severity} />}
              actions={
                <div className="flex items-center space-x-1.5">
                  <Link
                    href={`/analyses/${analysisId}/evidence?findingId=${selectedFinding.finding_id}`}
                    className="flex items-center space-x-1 px-2.5 py-1.5 bg-[#FF3D00] hover:bg-[#e03600] text-white text-xs font-mono font-bold uppercase transition-colors"
                  >
                    <FileSearch className="w-3.5 h-3.5" />
                    <span>Evidence DAG</span>
                  </Link>
                  <Link
                    href={`/analyses/${analysisId}/reports`}
                    className="flex items-center space-x-1 px-2.5 py-1.5 bg-neutral-100 hover:bg-neutral-200 dark:bg-neutral-800 dark:hover:bg-neutral-700 text-neutral-800 dark:text-neutral-200 text-xs font-mono font-bold uppercase transition-colors border border-neutral-300 dark:border-neutral-700"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Report</span>
                  </Link>
                </div>
              }
            >
              <div className="space-y-4">
                {/* Provenance Source Attribution */}
                {(() => {
                  const src = getFindingSource(selectedFinding);
                  return (
                    <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-neutral-500 text-[10px] uppercase font-bold">Provenance Source</span>
                        <span className={`px-1.5 py-0.5 text-[9px] font-mono font-bold uppercase border ${src.badge}`}>
                          {src.label}
                        </span>
                      </div>
                      <p className="text-[11px] text-neutral-600 dark:text-neutral-400">
                        {src.description}
                      </p>
                    </div>
                  );
                })()}

                {/* Score & Risk Summary */}
                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2.5 bg-rose-50 dark:bg-rose-950/20 border border-rose-300 dark:border-rose-900 font-mono text-xs">
                    <span className="text-neutral-500 block text-[10px]">Score Deduction:</span>
                    <span className="font-bold text-rose-600 text-sm">
                      -{selectedFinding.score_deduction} Points
                    </span>
                  </div>
                  <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-800 font-mono text-xs">
                    <span className="text-neutral-500 block text-[10px]">Realized Risk Tier:</span>
                    <span className="font-bold text-neutral-900 dark:text-white text-sm">
                      {selectedRiskItem?.risk_tier || selectedFinding.severity}
                    </span>
                  </div>
                </div>

                {/* Transparent Factor Breakdown */}
                {selectedRiskItem && selectedRiskItem.factors && selectedRiskItem.factors.length > 0 && (
                  <div>
                    <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1.5 font-bold">
                      Deterministic Risk Factor Breakdown
                    </span>
                    <div className="border border-neutral-300 dark:border-neutral-800 overflow-hidden">
                      <table className="w-full text-left font-mono text-[11px]">
                        <thead className="bg-neutral-100 dark:bg-neutral-900 border-b border-neutral-200 dark:border-neutral-800 text-[10px] text-neutral-500 uppercase">
                          <tr>
                            <th className="p-1.5">Factor</th>
                            <th className="p-1.5">Value</th>
                            <th className="p-1.5">Role</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800">
                          {selectedRiskItem.factors.map((f, idx) => (
                            <tr key={idx} className="hover:bg-neutral-50 dark:hover:bg-neutral-900/50">
                              <td className="p-1.5 font-semibold text-neutral-700 dark:text-neutral-300">
                                {f.factor_name}
                              </td>
                              <td className="p-1.5">
                                <span
                                  className={`px-1.5 py-0.5 text-[10px] ${
                                    f.factor_value === "NOT_ASSESSED"
                                      ? "bg-neutral-200 dark:bg-neutral-800 text-neutral-500"
                                      : "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-bold"
                                  }`}
                                >
                                  {f.factor_value}
                                </span>
                              </td>
                              <td className="p-1.5 text-[10px] text-neutral-500">
                                {f.aggregation_role}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Technical Description */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    Technical Forensics Description
                  </span>
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs text-neutral-700 dark:text-neutral-300 leading-relaxed font-sans">
                    {selectedFinding.technical_description}
                  </div>
                </div>

                {/* Deterministic Remediation Guidance */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    Deterministic Remediation Directive
                  </span>
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs font-mono text-neutral-800 dark:text-neutral-200 leading-relaxed whitespace-pre-wrap">
                    {selectedFinding.remediation_guidance}
                  </div>
                </div>

                {/* Affected Entities & References */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    Target Entity & Forensic Lineage
                  </span>
                  <div className="space-y-1 font-mono text-xs bg-neutral-50 dark:bg-neutral-900 p-2.5 border border-neutral-200 dark:border-neutral-800">
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Affected Entity:</span>
                      <span className="font-bold">{selectedFinding.affected_entity}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Evidence State:</span>
                      <span>{selectedFinding.evidence_state}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Root Cause Key:</span>
                      <span>{selectedFinding.root_cause_key}</span>
                    </div>
                    {selectedRiskItem && (
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Aggregate Contribution:</span>
                        <span className="font-semibold text-neutral-700 dark:text-neutral-300">
                          {selectedRiskItem.aggregation_role}
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* SOC Analyst Workflow Transitions */}
                <div className="pt-2 border-t border-neutral-200 dark:border-neutral-800 space-y-1.5">
                  <span className="text-[10px] text-neutral-400 uppercase font-bold block">
                    SOC Analyst Workflow Transitions
                  </span>
                  <div className="grid grid-cols-2 gap-2">
                    <Link
                      href={`/analyses/${analysisId}/evidence?view=replay`}
                      className="flex items-center justify-center space-x-1.5 py-1.5 px-2 text-[11px] font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-800 dark:text-neutral-200"
                    >
                      <History className="w-3.5 h-3.5 text-blue-500" />
                      <span>Replay Lineage</span>
                    </Link>
                    <Link
                      href="/monitoring"
                      className="flex items-center justify-center space-x-1.5 py-1.5 px-2 text-[11px] font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-800 dark:text-neutral-200"
                    >
                      <Radio className="w-3.5 h-3.5 text-[#FF3D00]" />
                      <span>Fleet Telemetry</span>
                    </Link>
                  </div>
                </div>
              </div>
            </InspectorDrawer>
          </div>
        )}
      </div>
    </div>
  );
}
