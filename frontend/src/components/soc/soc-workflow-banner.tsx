"use client";

import React from "react";
import Link from "next/link";
import {
  Radio,
  FileKey2,
  Layers,
  ShieldAlert,
  FileSearch,
  History,
  FileText,
  ChevronRight,
  Server,
  Activity,
  CheckCircle2,
} from "lucide-react";
import { useAnalysis } from "@/lib/analysis-context";

export type SocWorkflowStep = 1 | 2 | 3 | 4 | 5 | 6 | 7;

interface SocWorkflowBannerProps {
  activeStep: SocWorkflowStep;
  analysisId?: string | null;
  gatewayIdentity?: string | null;
  gatewayIp?: string | null;
  authorizedScope?: string | null;
  evidenceCoverage?: number | any | null;
  sensorFreshness?: "HEALTHY" | "DEGRADED" | "STALE" | "UNKNOWN" | null;
}

interface StepDef {
  step: SocWorkflowStep;
  title: string;
  shortLabel: string;
  icon: React.ComponentType<{ className?: string }>;
  getHref: (props: SocWorkflowBannerProps) => string;
}

const WORKFLOW_STEPS: StepDef[] = [
  {
    step: 1,
    title: "1. Scope & Telemetry",
    shortLabel: "1. Telemetry",
    icon: Radio,
    getHref: () => "/monitoring",
  },
  {
    step: 2,
    title: "2. Gateway Registry",
    shortLabel: "2. Gateways",
    icon: Server,
    getHref: (p) => (p.gatewayIdentity ? `/monitoring?tab=gateways&gateway=${encodeURIComponent(p.gatewayIdentity)}` : "/monitoring?tab=gateways"),
  },
  {
    step: 3,
    title: "3. Event Timeline",
    shortLabel: "3. Timeline",
    icon: Layers,
    getHref: (p) => (p.gatewayIdentity ? `/monitoring?tab=timeline&gateway=${encodeURIComponent(p.gatewayIdentity)}` : "/monitoring?tab=timeline"),
  },
  {
    step: 4,
    title: "4. Findings Triage",
    shortLabel: "4. Findings",
    icon: ShieldAlert,
    getHref: (p) => (p.analysisId ? `/analyses/${p.analysisId}/security` : "/analyses?action=select_run"),
  },
  {
    step: 5,
    title: "5. Evidence DAG",
    shortLabel: "5. Evidence",
    icon: FileSearch,
    getHref: (p) => (p.analysisId ? `/analyses/${p.analysisId}/evidence` : "/analyses?action=select_run"),
  },
  {
    step: 6,
    title: "6. Replay & Lineage",
    shortLabel: "6. Replay",
    icon: History,
    getHref: (p) => (p.analysisId ? `/analyses/${p.analysisId}/evidence?view=replay` : "/analyses?action=select_run"),
  },
  {
    step: 7,
    title: "7. Audit Report",
    shortLabel: "7. Report",
    icon: FileText,
    getHref: (p) => (p.analysisId ? `/analyses/${p.analysisId}/reports` : "/analyses?action=select_run"),
  },
];

export function SocWorkflowBanner({
  activeStep,
  analysisId,
  gatewayIdentity,
  gatewayIp,
  authorizedScope,
  evidenceCoverage,
  sensorFreshness,
}: SocWorkflowBannerProps) {
  const { activeAnalysisId } = useAnalysis();
  const effectiveAnalysisId = analysisId ?? activeAnalysisId;

  return (
    <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113] p-3 space-y-2.5 font-mono text-xs shadow-sm">
      {/* Top Bar: Title & Active Context Badges */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-neutral-200 dark:border-neutral-800 pb-2">
        <div className="flex items-center space-x-2">
          <Activity className="w-4 h-4 text-[#FF3D00]" />
          <span className="font-bold uppercase tracking-wider text-neutral-900 dark:text-neutral-100">
            SOC Analyst Investigation Workflow
          </span>
          <span className="text-[10px] px-1.5 py-0.5 border border-neutral-300 dark:border-neutral-700 bg-neutral-100 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-400 uppercase">
            OPERATOR WORKFLOW
          </span>
        </div>

        {/* Dynamic Context Chips */}
        <div className="flex items-center flex-wrap gap-2 text-[11px]">
          {gatewayIdentity && (
            <div className="flex items-center space-x-1 px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-900">
              <Server className="w-3 h-3 text-neutral-400" />
              <span className="text-neutral-500">Asset:</span>
              <span className="font-semibold text-neutral-900 dark:text-white">{gatewayIdentity}</span>
              {gatewayIp && <span className="text-neutral-400">({gatewayIp})</span>}
            </div>
          )}

          {authorizedScope && (
            <div className="px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-900">
              <span className="text-neutral-500">Scope: </span>
              <span className="font-semibold text-neutral-800 dark:text-neutral-200">{authorizedScope}</span>
            </div>
          )}

          {sensorFreshness && (
            <div
              className={`px-2 py-0.5 border text-[10px] font-bold uppercase ${
                sensorFreshness === "HEALTHY"
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                  : sensorFreshness === "STALE"
                  ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
                  : sensorFreshness === "DEGRADED"
                  ? "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400"
                  : "border-neutral-500/40 bg-neutral-500/10 text-neutral-400"
              }`}
            >
              Sensor: {sensorFreshness}
            </div>
          )}

          {(() => {
            const num =
              typeof evidenceCoverage === "number"
                ? evidenceCoverage
                : typeof evidenceCoverage === "object" && evidenceCoverage !== null && "coverage_percentage" in evidenceCoverage
                ? Number(evidenceCoverage.coverage_percentage)
                : null;
            if (num === null || isNaN(num)) return null;
            const pct = num <= 1 ? (num * 100).toFixed(0) : num.toFixed(0);
            return (
              <div className="px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-900">
                <span className="text-neutral-500">Evidence: </span>
                <span className="font-bold text-neutral-900 dark:text-white">{pct}%</span>
              </div>
            );
          })()}

          {effectiveAnalysisId && (
            <div className="px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-900">
              <span className="text-neutral-500">Run: </span>
              <span className="font-bold text-[#FF3D00]">{effectiveAnalysisId.slice(0, 8)}...</span>
            </div>
          )}
        </div>
      </div>

      {/* Workflow Stepper */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-1">
        {WORKFLOW_STEPS.map((s) => {
          const Icon = s.icon;
          const isActive = s.step === activeStep;
          const isPassed = s.step < activeStep;
          const href = s.getHref({
            activeStep,
            analysisId: effectiveAnalysisId,
            gatewayIdentity,
            gatewayIp,
            authorizedScope,
            evidenceCoverage,
            sensorFreshness,
          });

          return (
            <Link
              key={s.step}
              href={href}
              className={`flex items-center space-x-1.5 px-2 py-1.5 border transition-all text-[11px] ${
                isActive
                  ? "bg-[#FF3D00] text-white border-[#FF3D00] font-bold shadow-sm"
                  : isPassed
                  ? "bg-neutral-100 dark:bg-neutral-900/80 text-neutral-800 dark:text-neutral-200 border-neutral-300 dark:border-neutral-700 hover:border-neutral-400"
                  : "bg-transparent text-neutral-500 dark:text-neutral-400 border-neutral-200 dark:border-neutral-800 hover:border-neutral-300 hover:text-neutral-800 dark:hover:text-neutral-200"
              }`}
            >
              {isPassed ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
              ) : (
                <Icon className="w-3.5 h-3.5 shrink-0" />
              )}
              <span className="truncate">{s.shortLabel}</span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
