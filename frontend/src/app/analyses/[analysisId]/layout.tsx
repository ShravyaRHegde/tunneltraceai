"use client";

import React, { useEffect, useState, use } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAnalysis } from "@/lib/analysis-context";
import { StatusBadge } from "@/components/ui/badge";
import { CopyableValue } from "@/components/ui/table";
import { formatCoverage } from "@/lib/format";
import { ScoreDisplay } from "@/components/ui/score-display";
import { api } from "@/lib/api/client";
import {
  CheckCircle,
  Clock,
  AlertTriangle,
  RefreshCw,
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
  const { activeAnalysisId, setActiveAnalysisId, analysis, overview, refetch } = useAnalysis();
  const pathname = usePathname();

  const [isRecomputing, setIsRecomputing] = useState(false);
  const [recomputeError, setRecomputeError] = useState<string | null>(null);

  useEffect(() => {
    if (analysisId && activeAnalysisId !== analysisId) {
      setActiveAnalysisId(analysisId);
    }
  }, [analysisId, activeAnalysisId, setActiveAnalysisId]);

  const captureFilename =
    overview?.capture?.filename || analysis?.capture_filename || "Recorded Capture";
  const captureSha256 = overview?.capture?.sha256 || analysis?.capture_sha256;
  const packetCount = overview?.capture?.packet_count;

  const isOutdated = Boolean(analysis?.is_outdated_version || (overview?.analysis as any)?.is_outdated_version);
  const pipelineVer = analysis?.pipeline_version || (overview?.analysis as any)?.pipeline_version || "1.0.0";

  const handleRecompute = async () => {
    setIsRecomputing(true);
    setRecomputeError(null);
    try {
      await api.analyses.recompute(analysisId);
      refetch();
    } catch (err: any) {
      setRecomputeError(err.message || "Failed to recompute analysis run");
    } finally {
      setIsRecomputing(false);
    }
  };

  const isDemoOrSeeded = Boolean(
    analysis?.is_synthetic_demo ||
    overview?.analysis?.is_synthetic_demo ||
    overview?.capture?.filename === "ikev2_perimeter_audit.pcap" ||
    analysis?.capture_filename === "ikev2_perimeter_audit.pcap" ||
    (overview?.analysis as any)?.replay_mode === "DEMO_SEED" ||
    (analysis as any)?.replay_mode === "DEMO_SEED" ||
    analysisId === "9a79a13b-e0a7-46e4-ad40-d1c67debf4fe"
  );

  return (
    <div className="space-y-4">
      {/* Demonstration / Seeded Reference Provenance Banner */}
      {isDemoOrSeeded && (
        <div className="p-3.5 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-700/80 text-amber-900 dark:text-amber-200 text-xs font-mono space-y-1">
          <div className="flex items-center space-x-2 font-bold uppercase tracking-wider text-amber-800 dark:text-amber-300">
            <AlertTriangle className="w-4 h-4 shrink-0 text-amber-600 dark:text-amber-400" />
            <span>DEMONSTRATION / SEEDED REFERENCE FIXTURE</span>
          </div>
          <p className="text-[11px] leading-relaxed">
            This analysis run contains seeded reference demonstration findings and posture scores. Wire packet observations were not parsed from a raw PCAP stream for this fixture. 
            For empirical wire analysis with live-reconstructed IKE/ESP sessions, please select verified captures like <span className="font-bold underline">real_tunnel_gcm.pcapng</span>.
          </p>
        </div>
      )}

      {/* Outdated Pipeline Version Warning Banner */}
      {isOutdated && (
        <div className="p-3 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-700 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center space-x-2 text-amber-900 dark:text-amber-200">
            <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
            <div>
              <span className="font-bold">OUTDATED PIPELINE VERSION (v{pipelineVer}): </span>
              <span>This analysis was generated under legacy pipeline rules. Recompute using current pipeline v2.0.0 for accurate evidence coverage and compliance scoring.</span>
            </div>
          </div>
          <button
            onClick={handleRecompute}
            disabled={isRecomputing}
            className="inline-flex items-center justify-center space-x-1.5 px-3 py-1.5 bg-[#FF3D00] hover:bg-[#e03600] disabled:bg-neutral-400 text-white font-bold uppercase tracking-wider shrink-0 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRecomputing ? "animate-spin" : ""}`} />
            <span>{isRecomputing ? "RECOMPUTING..." : "RECOMPUTE NOW"}</span>
          </button>
        </div>
      )}
      {recomputeError && (
        <div className="p-2 bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 text-xs font-mono text-rose-600">
          {recomputeError}
        </div>
      )}

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
                <ScoreDisplay
                  score={overview.security_posture.score}
                  coverage={overview.security_posture.evidence_coverage}
                  riskTier={overview.security_posture.aggregate_risk_tier}
                  status={overview.security_posture.status}
                  size="sm"
                />
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
