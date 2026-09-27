"use client";

import React, { useEffect, use } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAnalysis } from "@/lib/analysis-context";
import { StatusBadge } from "@/components/ui/badge";
import { CopyableValue } from "@/components/ui/table";
import { formatCoverage } from "@/lib/format";
import {
  CheckCircle,
  Clock,
} from "lucide-react";

const PIPELINE_STAGES = [
  { id: "VALIDATION", label: "Capture Validation" },
  { id: "PROTOCOL_DISSECTION", label: "Protocol Dissection" },
  { id: "SA_RECONSTRUCTION", label: "SA Reconstruction" },
  { id: "FLOW_RECONSTRUCTION", label: "Flow Reconstruction" },
  { id: "ML_INFERENCE", label: "Traffic ML Inference" },
  { id: "SECURITY_ASSESSMENT", label: "Security Assessment" },
  { id: "SCORING_EVIDENCE", label: "Scoring & Evidence" },
  { id: "COMPLETED", label: "Completed" },
];

export default function AnalysisLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ analysisId: string }>;
}) {
  const unwrappedParams = use(params);
  const { analysisId } = unwrappedParams;
  const { activeAnalysisId, setActiveAnalysisId, analysis, overview } = useAnalysis();
  const pathname = usePathname();

  useEffect(() => {
    if (analysisId && activeAnalysisId !== analysisId) {
      setActiveAnalysisId(analysisId);
    }
  }, [analysisId, activeAnalysisId, setActiveAnalysisId]);

  const captureFilename =
    overview?.capture?.filename || analysis?.capture_filename || "Recorded Capture";
  const captureSha256 = overview?.capture?.sha256 || analysis?.capture_sha256;
  const packetCount = overview?.capture?.packet_count;



  return (
    <div className="space-y-4">
      {/* Persistent Analysis Identity Banner */}
      <div className="p-4 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-neutral-200 dark:border-neutral-800 pb-3">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 flex items-center justify-center font-mono font-bold text-xs text-[#FF3D00]">
              ID
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono text-xs text-neutral-400">ANALYSIS RUN:</span>
                <CopyableValue value={analysisId} label="Analysis ID" />
                {analysis?.status && <StatusBadge status={analysis.status} />}
              </div>
              <div className="text-xs text-neutral-500 font-mono flex items-center space-x-2 mt-0.5">
                <span>Capture: {captureFilename}</span>
                {captureSha256 && (
                  <>
                    <span>•</span>
                    <span>SHA-256: {captureSha256.slice(0, 16)}...</span>
                  </>
                )}
                {packetCount !== undefined && packetCount !== null && (
                  <>
                    <span>•</span>
                    <span>Packets: {packetCount}</span>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Quick Metrics */}
          {overview?.security_posture && (
            <div className="flex items-center space-x-4 text-xs font-mono">
              <div className="text-right">
                <div className="text-[10px] text-neutral-400 uppercase">Score Posture</div>
                <div className="font-bold text-neutral-900 dark:text-white">
                  {overview.security_posture.score}/100
                </div>
              </div>
              <div className="text-right">
                <div className="text-[10px] text-neutral-400 uppercase">Coverage</div>
                <div className="font-bold text-neutral-900 dark:text-white">
                  {formatCoverage(overview.security_posture.evidence_coverage)}
                </div>
              </div>
              <div className="text-right">
                <div className="text-[10px] text-neutral-400 uppercase">Findings</div>
                <div className="font-bold text-rose-600">
                  {overview.findings_summary?.total || 0}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Real Pipeline Stages Progress Chips */}
        <div className="flex items-center space-x-1 overflow-x-auto text-[10px] font-mono py-1">
          <span className="text-neutral-400 uppercase mr-1">Pipeline:</span>
          {PIPELINE_STAGES.map((stage, idx) => {
            const isMlStage = stage.id === "ML_INFERENCE";
            const isMlSkipped =
              isMlStage &&
              (overview?.traffic_summary?.ml_run_status === "NOT_CONFIGURED" ||
                (overview?.traffic_summary?.classified_flows === 0 &&
                  !overview?.traffic_summary?.model_bundle_id));

            const isCompleted =
              (analysis?.status === "COMPLETED" ||
                (analysis?.current_stage &&
                  PIPELINE_STAGES.findIndex((s) => s.id === analysis.current_stage) > idx)) &&
              !isMlSkipped;
            const isCurrent = analysis?.current_stage === stage.id;

            return (
              <div
                key={stage.id}
                className={`flex items-center space-x-1 px-2 py-0.5 border whitespace-nowrap ${
                  isCurrent
                    ? "bg-[#FF3D00] text-white border-[#FF3D00] font-bold animate-pulse"
                    : isMlSkipped
                    ? "bg-amber-50 dark:bg-amber-950/20 text-amber-800 dark:text-amber-400 border-amber-300 dark:border-amber-800"
                    : isCompleted
                    ? "bg-emerald-50 dark:bg-emerald-950/20 text-emerald-800 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800"
                    : "bg-neutral-100 dark:bg-neutral-900 text-neutral-400 border-neutral-200 dark:border-neutral-800"
                }`}
              >
                {isCompleted ? (
                  <CheckCircle className="w-2.5 h-2.5" />
                ) : isCurrent ? (
                  <Clock className="w-2.5 h-2.5" />
                ) : isMlSkipped ? (
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                ) : null}
                <span>
                  {isMlSkipped ? "Traffic ML (Skipped: No Model)" : stage.label}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* View Content */}
      <div>{children}</div>
    </div>
  );
}
