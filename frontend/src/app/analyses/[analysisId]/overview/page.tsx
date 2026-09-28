"use client";

import React, { use } from "react";
import Link from "next/link";
import { useAnalysis } from "@/lib/analysis-context";
import { Card } from "@/components/ui/card";
import { formatCoverage } from "@/lib/format";
import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { ScoreDisplay } from "@/components/ui/score-display";
import { EChartWrapper } from "@/components/charts/echart-wrapper";
import * as echarts from "echarts";
import {
  ShieldAlert,
  Radio,
  FileCheck2,
  Lock,
  Layers,
  ChevronRight,
  AlertTriangle,
  Fingerprint,
} from "lucide-react";

export default function OverviewPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const { overview, isLoading, isError, analysis } = useAnalysis();

  if (isLoading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
        Loading authoritative analysis overview and security posture...
      </div>
    );
  }

  if (isError || !overview) {
    return (
      <div className="p-6 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 text-center space-y-3 font-mono text-xs">
        <AlertTriangle className="w-8 h-8 text-rose-500 mx-auto" />
        <p className="text-neutral-700 dark:text-neutral-300 font-bold">
          UNABLE TO LOAD COMMAND CENTER FOR RUN {analysisId}
        </p>
        <p className="text-neutral-500">
          The analysis may still be initializing or experienced a pipeline failure. Check status above.
        </p>
      </div>
    );
  }

  const {
    security_posture,
    compliance_counts,
    findings_summary,
    traffic_summary,
    fingerprintability,
    protocol_summary,
  } = overview;

  // Robust Deduction Chart Parsing (supports both object dict and {audit: [...]} array)
  const rawDeductions = security_posture.itemized_deductions;
  let deductionCategories: string[] = [];
  let deductionValues: number[] = [];

  if (rawDeductions && Array.isArray((rawDeductions as any).audit)) {
    deductionCategories = (rawDeductions as any).audit.map(
      (d: any) => d.rule_id || d.finding_id || d.category || "Rule"
    );
    deductionValues = (rawDeductions as any).audit.map(
      (d: any) => Number(d.applied_deduction ?? d.raw_deduction ?? 0)
    );
  } else if (rawDeductions && typeof rawDeductions === "object") {
    deductionCategories = Object.keys(rawDeductions).filter((k) => k !== "total_deduction");
    deductionValues = deductionCategories.map((k) => Number((rawDeductions as any)[k]) || 0);
  }

  const isDemoOrSeeded = Boolean(
    analysis?.is_synthetic_demo ||
    overview?.analysis?.is_synthetic_demo ||
    overview?.capture?.filename === "ikev2_perimeter_audit.pcap" ||
    (protocol_summary?.total_observations === 0 && (findings_summary?.total || 0) > 0)
  );

  const deductionChartOptions: echarts.EChartsOption = {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { top: 20, right: 20, bottom: 30, left: 80 },
    xAxis: {
      type: "value",
      axisLabel: { color: "#888", fontSize: 10 },
      splitLine: { lineStyle: { color: "#333", type: "dashed" } },
    },
    yAxis: {
      type: "category",
      data: deductionCategories.length > 0 ? deductionCategories : ["None"],
      axisLabel: { color: "#888", fontSize: 10 },
    },
    series: [
      {
        name: "Score Deduction",
        type: "bar",
        data: deductionValues.length > 0 ? deductionValues : [0],
        itemStyle: { color: "#FF3D00" },
      },
    ],
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-3">
        <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
          Investigation Overview & Security Posture
        </h1>
        <p className="text-xs text-neutral-500 mt-1">
          <strong className="text-neutral-700 dark:text-neutral-300">What this shows:</strong> High-level executive synthesis of this capture run — overall security posture score paired with evidence coverage %, NIST SP 800-77 compliance tally, and itemized cryptographic deductions.
        </p>
      </div>

      {/* Demo Fixture / Reference Data Provenance Banner */}
      {isDemoOrSeeded && (
        <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border-l-4 border-amber-500 text-amber-900 dark:text-amber-200 text-xs font-mono space-y-1">
          <div className="flex items-center space-x-2 font-bold uppercase tracking-wider text-amber-800 dark:text-amber-300">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Demonstration Fixture Reference Data</span>
          </div>
          <p>
            This analysis run contains seeded reference demonstration findings and posture scores. Wire packet observations were not parsed from a raw PCAP stream for this fixture. 
            For empirical wire analysis with live-reconstructed IKE/ESP sessions, please ingest verified samples like <code className="font-bold">real_tunnel_gcm.pcapng</code> or upload an authorized capture.
          </p>
        </div>
      )}

      {/* Insufficient Evidence / Not Assessable Banner */}
      {!isDemoOrSeeded && (security_posture.score === null || (security_posture as any).status === "NOT_ASSESSABLE" || (security_posture as any).status === "INSUFFICIENT_EVIDENCE" || (security_posture.evidence_coverage !== undefined && security_posture.evidence_coverage < 0.5)) && (
        <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border-l-4 border-amber-500 text-amber-900 dark:text-amber-200 text-xs font-mono space-y-1">
          <div className="flex items-center space-x-2 font-bold uppercase tracking-wider text-amber-800 dark:text-amber-300">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Limited Protocol Evidence — Posture Score Withheld ({formatCoverage(security_posture.evidence_coverage)} coverage)</span>
          </div>
          <p>
            {security_posture.evidence_coverage === 0 ? (
              "No observable IPsec packet evidence (IKE handshake or ESP traffic) was found in this capture artifact. All policy rules are marked UNKNOWN."
            ) : (
              `This capture contains partial data plane traffic without the initial IKE key negotiation handshake (${compliance_counts.unknown} check(s) remain UNKNOWN). TunnelTrace AI strictly enforces epistemic honesty: an authoritative 100/100 score is withheld until complete handshake evidence is observed.`
            )}
          </p>
        </div>
      )}

      {/* KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Security Posture Score */}
        <Card
          title="Security Posture Score"
          variant={security_posture.score !== null && security_posture.score < 50 ? "danger" : "default"}
          badge={
            <span className="text-[10px] font-mono px-1 border border-neutral-300 dark:border-neutral-700">
              {security_posture.methodology_version || "INTERNAL v1"}
            </span>
          }
        >
          <div className="space-y-2">
            <ScoreDisplay
              score={security_posture.score}
              coverage={security_posture.evidence_coverage}
              riskTier={security_posture.aggregate_risk_tier}
              status={(security_posture as any).status}
              size="lg"
            />
            <p className="text-[11px] text-neutral-500 font-mono">
              Evaluated on observable packet evidence ({formatCoverage(security_posture.evidence_coverage)} coverage, {compliance_counts.unknown} unknown rules). Not a formal security certification.
            </p>
            <div className="pt-2 border-t border-neutral-200 dark:border-neutral-800 flex justify-between text-[11px] font-mono">
              <span className="text-neutral-400">Risk Tier:</span>
              <span className="font-bold text-neutral-900 dark:text-white uppercase">
                {security_posture.aggregate_risk_tier}
              </span>
            </div>
          </div>
        </Card>

        {/* Card 2: Evidence Coverage */}
        <Card title="Evidence Coverage">
          <div className="space-y-2">
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-mono font-bold text-neutral-900 dark:text-white">
                {formatCoverage(security_posture.evidence_coverage)}
              </span>
            </div>
            <p className="text-[11px] text-neutral-500 font-mono">
              Fraction of required cryptographic & protocol facts verified from observed packet evidence.
            </p>
            <div className="pt-2 border-t border-neutral-200 dark:border-neutral-800 flex justify-between text-[11px] font-mono">
              <span className="text-neutral-400">Unknown Evaluations:</span>
              <span className="font-bold text-neutral-900 dark:text-white">
                {compliance_counts.unknown}
              </span>
            </div>
          </div>
        </Card>

        {/* Card 3: Findings Summary */}
        <Card title="Security Findings">
          <div className="space-y-2">
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-mono font-bold text-rose-600">
                {findings_summary.total}
              </span>
              <span className="text-xs font-mono text-neutral-400">total</span>
            </div>
            <div className="flex items-center space-x-2 text-[11px] font-mono">
              <span className="px-1.5 py-0.5 bg-red-950 text-red-200 border border-red-800">
                {findings_summary.critical} CRIT
              </span>
              <span className="px-1.5 py-0.5 bg-rose-100 text-rose-900 border border-rose-300">
                {findings_summary.high} HIGH
              </span>
              <span className="px-1.5 py-0.5 bg-amber-100 text-amber-900 border border-amber-300">
                {findings_summary.medium} MED
              </span>
            </div>
            <div className="pt-2 border-t border-neutral-200 dark:border-neutral-800 flex justify-between text-[11px] font-mono">
              <Link
                href={`/analyses/${analysisId}/security`}
                className="text-[#FF3D00] hover:underline flex items-center space-x-1"
              >
                <span>View Findings Table</span>
                <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </div>
        </Card>

        {/* Card 4: Compliance Status */}
        <Card title="Compliance Scorecard">
          <div className="space-y-2">
            <div className="flex items-center space-x-3 text-sm font-mono font-bold">
              <span className="text-emerald-600">{compliance_counts.pass} PASS</span>
              <span className="text-neutral-300">|</span>
              <span className="text-rose-600">{compliance_counts.fail} FAIL</span>
              <span className="text-neutral-300">|</span>
              <span className="text-neutral-500">{compliance_counts.unknown} UNK</span>
            </div>
            <p className="text-[11px] text-neutral-500 font-mono">
              Automated deterministic policy evaluation against selected security profile.
            </p>
            <div className="pt-2 border-t border-neutral-200 dark:border-neutral-800 flex justify-between text-[11px] font-mono">
              <Link
                href={`/analyses/${analysisId}/compliance`}
                className="text-[#FF3D00] hover:underline flex items-center space-x-1"
              >
                <span>Inspect Scorecard</span>
                <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </div>
        </Card>
      </div>

      {/* Main Grid: 8 cols Primary Overview + 4 cols Secondary Context */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (8 cols): Top Findings & Deductions */}
        <div className="lg:col-span-8 space-y-6">
          {/* Top Material Findings */}
          <Card
            title={`Top Material Findings (${findings_summary.top_findings?.length || 0})`}
            actions={
              <Link
                href={`/analyses/${analysisId}/security`}
                className="text-[11px] font-mono text-[#FF3D00] hover:underline flex items-center space-x-0.5"
              >
                <span>ALL FINDINGS</span>
                <ChevronRight className="w-3 h-3" />
              </Link>
            }
          >
            {findings_summary.top_findings && findings_summary.top_findings.length > 0 ? (
              <div className="divide-y divide-neutral-200 dark:divide-neutral-800 text-xs">
                {findings_summary.top_findings.map((f) => (
                  <div key={f.finding_id} className="py-2.5 flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="font-mono text-neutral-400 text-[11px]">
                          {f.rule_id}
                        </span>
                        <span className="font-bold text-neutral-900 dark:text-white">
                          {f.title}
                        </span>
                      </div>
                      <p className="text-neutral-500 text-[11px] font-mono">
                        Target: {f.affected_entity} • Evidence: {f.evidence_state}
                      </p>
                    </div>
                    <div className="text-right shrink-0">
                      <span className="font-mono text-rose-600 font-bold">
                        -{f.score_deduction} pts
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-6 text-center text-xs font-mono text-emerald-600">
                No high or critical severity security findings recorded.
              </div>
            )}
          </Card>

          {/* Score Deduction Audit Chart */}
          <Card title="Score Deduction Breakdown by Category">
            {deductionCategories.length > 0 ? (
              <EChartWrapper
                options={deductionChartOptions}
                height="220px"
                accessibleSummary="Bar chart showing score point deductions grouped by category"
              />
            ) : (
              <div className="py-8 text-center text-xs font-mono text-neutral-500">
                Zero score deductions recorded for this analysis.
              </div>
            )}
          </Card>
        </div>

        {/* Right Column (4 cols): Protocol, Traffic & Fingerprintability */}
        <div className="lg:col-span-4 space-y-6">
          {/* Protocol Intelligence Snapshot */}
          <Card
            title="Protocol Discovery"
            actions={
              <Link
                href={`/analyses/${analysisId}/protocol`}
                className="text-[11px] font-mono text-[#FF3D00] hover:underline"
              >
                DETAILS
              </Link>
            }
          >
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-neutral-100 dark:border-neutral-800">
                <span className="text-neutral-500">IPsec Present:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {protocol_summary.total_observations > 0 ? "YES" : "NO"}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-neutral-100 dark:border-neutral-800">
                <span className="text-neutral-500">IKE Versions:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {protocol_summary.ike_versions?.join(", ") || "UNKNOWN"}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-neutral-100 dark:border-neutral-800">
                <span className="text-neutral-500">Protocols:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {protocol_summary.protocols_detected?.join(", ") || "UNKNOWN"}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-neutral-100 dark:border-neutral-800">
                <span className="text-neutral-500">NAT-T Traversal:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {protocol_summary.nat_detected ? "DETECTED" : "NOT OBSERVED"}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-neutral-500">Observations:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {protocol_summary.total_observations}
                </span>
              </div>
            </div>
          </Card>

          {/* Traffic Intelligence Snapshot */}
          <Card
            title="Encrypted Traffic Inference"
            actions={
              <Link
                href={`/analyses/${analysisId}/traffic`}
                className="text-[11px] font-mono text-[#FF3D00] hover:underline"
              >
                FLOWS
              </Link>
            }
          >
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-neutral-100 dark:border-neutral-800">
                <span className="text-neutral-500">Model Pipeline:</span>
                <span className={`font-bold ${traffic_summary.ml_run_status === "NOT_CONFIGURED" || traffic_summary.classified_flows === 0 ? "text-amber-600 dark:text-amber-400 text-[10px]" : "text-emerald-600 dark:text-emerald-400"}`}>
                  {traffic_summary.ml_run_status === "NOT_CONFIGURED" || traffic_summary.classified_flows === 0 ? "NOT CONFIGURED (SKIPPED)" : "ACTIVE"}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-neutral-100 dark:border-neutral-800">
                <span className="text-neutral-500">Classified Flows:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {traffic_summary.classified_flows}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-neutral-100 dark:border-neutral-800">
                <span className="text-neutral-500">Classes Detected:</span>
                <span className="font-bold text-neutral-900 dark:text-white">
                  {traffic_summary.classes_detected?.join(", ") || "None"}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-neutral-100 dark:border-neutral-800">
                <span className="text-neutral-500">OOD / Unknown:</span>
                <span className="font-bold text-amber-600">
                  {traffic_summary.ood_count}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-neutral-500">Behavioral Anomalies:</span>
                <span className="font-bold text-rose-600">
                  {traffic_summary.anomaly_count}
                </span>
              </div>
            </div>
            <p className="mt-3 text-[10px] text-neutral-400 font-mono italic">
              {traffic_summary.ml_run_status === "NOT_CONFIGURED" || traffic_summary.classified_flows === 0
                ? "No machine learning classifier bundle is deployed on this node. Inferences were safely skipped rather than producing synthetic claims."
                : "Application classes inferred from encrypted packet timing and size metadata. Payload is not decrypted."}
            </p>
          </Card>

          {/* Metadata Fingerprintability Card */}
          <Card
            title="Metadata Fingerprintability"
            badge={
              fingerprintability.is_experimental ? (
                <span className="text-[10px] font-mono px-1 bg-amber-100 dark:bg-amber-950/40 text-amber-800 dark:text-amber-400 border border-amber-300 dark:border-amber-700">
                  EXPERIMENTAL
                </span>
              ) : undefined
            }
          >
            <div className="space-y-2">
              <div className="flex items-baseline space-x-2">
                <span className="text-2xl font-mono font-bold text-neutral-900 dark:text-white">
                  {fingerprintability.overall_index}
                </span>
                <span className="text-xs font-mono text-neutral-400">/ 100</span>
              </div>
              <p className="text-[11px] text-neutral-500 font-mono">
                {fingerprintability.disclaimer ||
                  "Behavioral side-channel distinguishability of encrypted traffic under tested methodology."}
              </p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
