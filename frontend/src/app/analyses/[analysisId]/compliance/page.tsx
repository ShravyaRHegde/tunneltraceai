"use client";

import React, { use, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { ComplianceBadge, SeverityBadge, EvidenceStateBadge } from "@/components/ui/badge";
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
import { ComplianceEvaluationDTO } from "@/lib/api/types";
import {
  FileCheck2,
  Search,
  Filter,
  CheckCircle,
  XCircle,
  HelpCircle,
  MinusCircle,
  AlertCircle,
} from "lucide-react";

export default function ComplianceScorecardPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [selectedRule, setSelectedRule] = useState<ComplianceEvaluationDTO | null>(null);
  const [resultFilter, setResultFilter] = useState<string>("ALL");
  const [search, setSearch] = useState<string>("");

  const {
    data: compliance,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["compliance", analysisId],
    queryFn: () => api.analyses.getCompliance(analysisId),
  });

  if (isLoading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
        Executing compliance policy evaluations across standards profiles...
      </div>
    );
  }

  if (isError || !compliance) {
    return (
      <div className="p-6 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 text-center space-y-2 font-mono text-xs text-rose-600">
        <AlertCircle className="w-6 h-6 mx-auto" />
        <p>Failed to load compliance scorecard: {(error as any)?.message || "Unknown error"}</p>
      </div>
    );
  }

  const filteredEvaluations = (compliance.evaluations || []).filter((ev) => {
    const matchesResult =
      resultFilter === "ALL" || ev.compliance_state.toUpperCase() === resultFilter;
    const matchesSearch =
      search === "" ||
      ev.rule_id.toLowerCase().includes(search.toLowerCase()) ||
      (ev.rule_title || "").toLowerCase().includes(search.toLowerCase()) ||
      (ev.category || "").toLowerCase().includes(search.toLowerCase()) ||
      (ev.standard || "").toLowerCase().includes(search.toLowerCase());
    return matchesResult && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <FileCheck2 className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            Standards & Policy Compliance Scorecard
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          <strong className="text-neutral-700 dark:text-neutral-300">What this shows:</strong> Automated pass/fail/unknown checks against NIST SP 800-77 Rev 1 and RFC 8221 standards. Rules with uncaptured packet evidence are truthfully labeled UNKNOWN.
        </p>
      </div>

      {/* Profile & Counts Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card
          title="Evaluated Profile"
          badge={
            <span className="text-[10px] font-mono px-1 border border-neutral-300 dark:border-neutral-700">
              {compliance.profile_id}
            </span>
          }
        >
          <div className="space-y-1">
            <div className="text-base font-mono font-bold text-neutral-900 dark:text-white">
              {compliance.profile_name}
            </div>
            <p className="text-[11px] font-mono text-neutral-500">
              Bundle Hash: {compliance.policy_bundle_hash ? `${compliance.policy_bundle_hash.slice(0, 12)}...` : "N/A"}
            </p>
          </div>
        </Card>

        <Card title="Compliance Results Overview">
          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="flex items-center space-x-1.5 text-emerald-600">
              <CheckCircle className="w-3.5 h-3.5" />
              <span className="font-bold">{compliance.pass_count} PASS</span>
            </div>
            <div className="flex items-center space-x-1.5 text-rose-600">
              <XCircle className="w-3.5 h-3.5" />
              <span className="font-bold">{compliance.fail_count} FAIL</span>
            </div>
            <div className="flex items-center space-x-1.5 text-neutral-500">
              <HelpCircle className="w-3.5 h-3.5" />
              <span>{compliance.unknown_count} UNKNOWN</span>
            </div>
            <div className="flex items-center space-x-1.5 text-neutral-400">
              <MinusCircle className="w-3.5 h-3.5" />
              <span>{compliance.not_applicable_count} N/A</span>
            </div>
          </div>
        </Card>

        <Card title="Total Rule Evaluations">
          <div className="space-y-1 font-mono">
            <div className="text-2xl font-bold text-neutral-900 dark:text-white">
              {compliance.total_evaluations}
            </div>
            <p className="text-[11px] text-neutral-500">
              Deterministic rule assertions.
            </p>
          </div>
        </Card>

        <Card title="Epistemic Integrity Notice">
          <div className="text-[11px] font-mono text-neutral-500 space-y-1">
            <p>
              • UNKNOWN is never coerced to FAIL.
            </p>
            <p>
              • NOT_APPLICABLE is never counted as PASS.
            </p>
          </div>
        </Card>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-2 flex-1 max-w-md">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-neutral-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search rules by ID, standard, or title..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-xs bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 font-mono text-neutral-900 dark:text-white placeholder-neutral-400 focus:outline-none focus:border-[#FF3D00]"
            />
          </div>
        </div>

        {/* State Filter Buttons */}
        <div className="flex items-center space-x-1 font-mono text-xs overflow-x-auto">
          {["ALL", "PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"].map((st) => (
            <button
              key={st}
              onClick={() => setResultFilter(st)}
              className={`px-3 py-1.5 border transition-colors ${
                resultFilter === st
                  ? "bg-neutral-900 dark:bg-white text-white dark:text-neutral-900 font-bold border-neutral-900 dark:border-white"
                  : "bg-white dark:bg-[#141416] text-neutral-600 dark:text-neutral-400 border-neutral-300 dark:border-neutral-800 hover:border-neutral-400"
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Main Workspace (12 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Rules Table */}
        <div className={selectedRule ? "lg:col-span-8" : "lg:col-span-12"}>
          <Card title={`Evaluated Compliance Rules (${filteredEvaluations.length})`}>
            {filteredEvaluations.length > 0 ? (
              <Table>
                <TableHeader>
                  <tr>
                    <TableHead>Result</TableHead>
                    <TableHead>Rule ID</TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Standard</TableHead>
                    <TableHead>Severity</TableHead>
                  </tr>
                </TableHeader>
                <TableBody>
                  {filteredEvaluations.map((ev) => (
                    <TableRow
                      key={ev.rule_id}
                      onClick={() => setSelectedRule(ev)}
                      isSelected={selectedRule?.rule_id === ev.rule_id}
                    >
                      <TableCell>
                        <ComplianceBadge state={ev.compliance_state} />
                      </TableCell>
                      <TableCell mono>
                        <span className="font-semibold text-neutral-900 dark:text-white">
                          {ev.rule_id}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="font-bold text-neutral-900 dark:text-white">
                          {ev.rule_title}
                        </span>
                      </TableCell>
                      <TableCell mono className="text-neutral-500 uppercase text-[11px]">
                        {ev.category}
                      </TableCell>
                      <TableCell mono className="text-neutral-600 dark:text-neutral-300 text-[11px]">
                        {ev.standard}
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={ev.severity} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="py-12 text-center font-mono text-xs text-neutral-500">
                No compliance rules match the active filter.
              </div>
            )}
          </Card>
        </div>

        {/* Right Contextual Inspector */}
        {selectedRule && (
          <div className="lg:col-span-4">
            <InspectorDrawer
              isOpen={!!selectedRule}
              onClose={() => setSelectedRule(null)}
              title={selectedRule.rule_title}
              subtitle={`Standard: ${selectedRule.standard}`}
              badge={<ComplianceBadge state={selectedRule.compliance_state} />}
            >
              <div className="space-y-4">
                {/* Rule Identity */}
                <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs font-mono space-y-1">
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Rule ID:</span>
                    <span className="font-bold">{selectedRule.rule_id}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Category:</span>
                    <span>{selectedRule.category}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Evidence State:</span>
                    <span>{selectedRule.evidence_state}</span>
                  </div>
                </div>

                {/* Values Comparison */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    Value Comparison Forensics
                  </span>
                  <div className="space-y-2 font-mono text-xs">
                    <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-0.5">
                      <span className="text-[10px] text-neutral-500 uppercase">Observed Value</span>
                      <pre className="text-neutral-900 dark:text-white font-bold whitespace-pre-wrap">
                        {JSON.stringify(selectedRule.observed_value, null, 2) || "None"}
                      </pre>
                    </div>

                    <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-0.5">
                      <span className="text-[10px] text-neutral-500 uppercase">Expected Requirement</span>
                      <pre className="text-neutral-900 dark:text-white font-bold whitespace-pre-wrap">
                        {JSON.stringify(selectedRule.expected_value, null, 2) || "None"}
                      </pre>
                    </div>
                  </div>
                </div>

                {/* Evaluation Rationale */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    Evaluation Rationale
                  </span>
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs text-neutral-700 dark:text-neutral-300 leading-relaxed font-sans">
                    {selectedRule.rationale}
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
