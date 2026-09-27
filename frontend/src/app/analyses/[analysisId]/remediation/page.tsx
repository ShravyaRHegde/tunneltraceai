"use client";

import React, { use, useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  ProjectedFindingDTO,
  RemediationRunStepDTO,
  SemanticDiffItemDTO,
  VerificationClaimDTO,
} from "@/lib/api/types";
import { Card } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/badge";
import {
  SlidersHorizontal,
  AlertTriangle,
  ShieldCheck,
  Play,
  ArrowRight,
  CheckCircle2,
  XCircle,
  HelpCircle,
  RotateCcw,
  Terminal,
  FileCode,
  Layers,
  Activity,
  Lock,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  RefreshCw,
} from "lucide-react";

export default function RemediationTwinPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<"twin" | "semantic_diff" | "text_diff" | "audit" | "claims">("twin");
  const [activeViewMode, setActiveViewMode] = useState<"side_by_side" | "diff_first">("side_by_side");
  const [editedConfig, setEditedConfig] = useState<string>("");
  const [isConfirmModalOpen, setIsConfirmModalOpen] = useState(false);
  const [confirmControlledLab, setConfirmControlledLab] = useState(false);
  const [operatorId, setOperatorId] = useState<string>("analyst-local");
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [expandedClaimId, setExpandedClaimId] = useState<string | null>(null);

  // 1. Fetch Twin
  const {
    data: twin,
    isLoading: isTwinLoading,
    refetch: refetchTwin,
  } = useQuery({
    queryKey: ["remediation-twin", analysisId],
    queryFn: () => api.remediation.getTwin(analysisId),
  });

  // Sync edited config once twin loads
  useEffect(() => {
    if (twin?.rendered_proposed_config && !editedConfig) {
      setEditedConfig(twin.rendered_proposed_config);
    }
  }, [twin, editedConfig]);

  // 2. Fetch Latest Verification
  const { data: latestVerification, refetch: refetchVerification } = useQuery({
    queryKey: ["latest-verification", analysisId],
    queryFn: () => api.remediation.getLatestVerification(analysisId),
    refetchInterval: activeRunId ? 2500 : false,
  });

  // 3. Poll Run if active
  const { data: activeRun } = useQuery({
    queryKey: ["remediation-run", analysisId, activeRunId],
    queryFn: () => api.remediation.getRun(analysisId, activeRunId!),
    enabled: !!activeRunId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (data && (data.status === "COMPLETED" || data.status === "FAILED" || data.status === "ROLLED_BACK" || data.status === "ROLLBACK_FAILED")) {
        return false;
      }
      return 1500;
    },
  });

  // 4. Preflight query
  const { data: preflight, refetch: refetchPreflight } = useQuery({
    queryKey: ["remediation-preflight", analysisId, twin?.twin_id, twin?.proposal_hash],
    queryFn: () => api.remediation.runPreflight(analysisId, twin!.twin_id, twin!.proposal_hash),
    enabled: !!twin?.twin_id && !!twin?.proposal_hash,
  });

  // 5. Update proposal mutation
  const updateProposalMutation = useMutation({
    mutationFn: (text: string) => api.remediation.updateProposal(analysisId, text),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["remediation-twin", analysisId] });
      refetchPreflight();
    },
  });

  // 6. Apply remediation mutation
  const applyMutation = useMutation({
    mutationFn: () =>
      api.remediation.apply(analysisId, {
        twin_id: twin!.twin_id,
        proposal_hash: twin!.proposal_hash,
        lab_instance_id: "strongswan-lab-default",
        operator_id: operatorId || "analyst-local",
        confirm_controlled_lab_only: true,
      }),
    onSuccess: (data) => {
      setActiveRunId(data.run_id);
      setIsConfirmModalOpen(false);
      setConfirmControlledLab(false);
    },
  });

  const isExecuting = activeRun && !["COMPLETED", "FAILED", "ROLLED_BACK", "ROLLBACK_FAILED"].includes(activeRun.status);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <SlidersHorizontal className="w-5 h-5 text-[#FF3D00]" />
            <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
              Configuration Security Twin & Closed-Loop Remediation
            </h1>
          </div>
          <p className="text-xs text-neutral-500 mt-1 font-mono">
            Deterministic Counterfactual Policy Projection → Isolated strongSwan Lab Apply → Fresh Wire Verification.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-3">
          <button
            onClick={() => {
              refetchTwin();
              refetchVerification();
              refetchPreflight();
            }}
            className="px-3 py-1.5 bg-neutral-100 dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-700 text-xs font-mono uppercase hover:bg-neutral-200 dark:hover:bg-neutral-800 flex items-center space-x-1"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>

          <button
            disabled={!preflight?.is_ready || isExecuting}
            onClick={() => setIsConfirmModalOpen(true)}
            className={`px-4 py-1.5 text-xs font-mono font-bold uppercase flex items-center space-x-2 border transition-colors ${
              preflight?.is_ready && !isExecuting
                ? "bg-[#FF3D00] text-white border-[#FF3D00] hover:bg-[#E03600]"
                : "bg-neutral-200 dark:bg-neutral-800 text-neutral-400 border-neutral-300 dark:border-neutral-700 cursor-not-allowed"
            }`}
          >
            <Play className="w-4 h-4 fill-current" />
            <span>Validate in Controlled Lab</span>
          </button>
        </div>
      </div>

      {/* Epistemic Principle & Disclaimer Banner */}
      <div className="p-4 bg-neutral-900 text-neutral-200 border-l-4 border-[#FF3D00] text-xs font-mono space-y-1">
        <div className="flex items-center space-x-2 text-white font-bold uppercase tracking-wider">
          <Activity className="w-4 h-4 text-[#FF3D00]" />
          <span>Closed-Loop Verification Philosophy</span>
        </div>
        <p className="text-neutral-300">
          The <strong>Configuration Security Twin is a counterfactual projection</strong>, not proof.
          Only applying the proposed configuration to our controlled Linux namespace strongSwan lab, establishing a fresh Security Association, generating synthetic traffic, and re-analyzing fresh packet capture creates <strong>VERIFIED</strong> remediation claims.
        </p>
      </div>

      {/* Live Remediation Run Execution Banner (if active or recently finished) */}
      {(activeRun || isExecuting) && (
        <div className="p-4 bg-neutral-50 dark:bg-neutral-900 border-2 border-neutral-300 dark:border-neutral-700 font-mono text-xs space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className={`w-2.5 h-2.5 rounded-full ${isExecuting ? "bg-amber-500 animate-ping" : "bg-emerald-500"}`} />
              <span className="font-bold text-neutral-900 dark:text-white uppercase">
                Closed-Loop Remediation Run #{activeRun?.run_id?.slice(0, 8)}
              </span>
              <span className="px-2 py-0.5 bg-neutral-200 dark:bg-neutral-800 text-neutral-800 dark:text-neutral-200 text-[10px] font-bold">
                {activeRun?.status}
              </span>
            </div>
            <span className="text-neutral-500 text-[11px]">Lab Target: {activeRun?.lab_instance_id}</span>
          </div>

          {/* SAGA Step Progress Bar */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-2 pt-2 border-t border-neutral-200 dark:border-neutral-800">
            {activeRun?.steps?.map((step: RemediationRunStepDTO) => (
              <div
                key={step.sequence}
                className={`p-2 border text-[10px] ${
                  step.status === "SUCCESS"
                    ? "border-emerald-600 bg-emerald-50/50 dark:bg-emerald-950/20 text-emerald-800 dark:text-emerald-300"
                    : step.status === "FAILED"
                    ? "border-rose-600 bg-rose-50/50 dark:bg-rose-950/20 text-rose-800 dark:text-rose-300"
                    : "border-neutral-300 dark:border-neutral-700 text-neutral-500"
                }`}
              >
                <div className="font-bold uppercase truncate">{step.action_type}</div>
                <div className="text-[9px] mt-0.5 opacity-80">{step.status}</div>
              </div>
            ))}
          </div>

          {activeRun?.status === "ROLLBACK_FAILED" ? (
            <div className="p-3 bg-rose-50 dark:bg-rose-950/40 border-2 border-rose-600 text-rose-900 dark:text-rose-200 text-xs space-y-1">
              <div className="flex items-center space-x-2 font-bold uppercase tracking-wider text-rose-700 dark:text-rose-400">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>Critical: Rollback Verification Failed</span>
              </div>
              <p className="text-[11px]">
                Automatic restoration could not be fully verified against baseline configuration digests. <strong>Manual lab testbed intervention required.</strong>
              </p>
              {activeRun?.error_message && <p className="text-[10px] text-rose-600 dark:text-rose-300 font-mono">{activeRun.error_message}</p>}
            </div>
          ) : activeRun?.rollback_state !== "NONE" ? (
            <div className="p-2.5 bg-amber-50 dark:bg-amber-950/30 border border-amber-500 text-amber-900 dark:text-amber-200 text-xs">
              <span className="font-bold uppercase">Automatic Rollback State:</span> {activeRun?.rollback_state}
              {activeRun?.rollback_reason && <p className="text-[11px] mt-0.5">{activeRun?.rollback_reason}</p>}
            </div>
          ) : null}

          {activeRun?.post_capture_hash && (
            <div className="flex flex-wrap items-center justify-between text-[11px] text-neutral-500 pt-1 border-t border-neutral-200 dark:border-neutral-800">
              <span>Verified PCAP Digest: <code className="text-neutral-700 dark:text-neutral-300 font-bold">{activeRun.post_capture_hash.slice(0, 16)}...</code></span>
              {activeRun.pre_apply_spis && <span>Pre-Apply SAs: {activeRun.pre_apply_spis.length} observed</span>}
            </div>
          )}
        </div>
      )}

      {/* Tabs Navigation */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 flex space-x-2 font-mono text-xs overflow-x-auto">
        {[
          { id: "twin", label: "Twin Workbench (3-Column)", icon: Layers },
          { id: "semantic_diff", label: "Security Semantic Diff", icon: SlidersHorizontal },
          { id: "text_diff", label: "swanctl.conf Text Diff", icon: FileCode },
          { id: "audit", label: "Projected Regression Audit", icon: AlertTriangle },
          { id: "claims", label: "Verification Claim Ledger", icon: ShieldCheck },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4 py-2 border-b-2 font-bold uppercase transition-colors flex items-center space-x-1.5 whitespace-nowrap ${
                activeTab === tab.id
                  ? "border-[#FF3D00] text-[#FF3D00]"
                  : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab 1: Twin Workbench (3-Column Progression: Current -> Projected -> Verified) */}
      {activeTab === "twin" && (
        <div className="space-y-6">
          {/* Baseline Linkage Status Notice */}
          {twin && !twin.has_linked_baseline && (
            <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-500 text-amber-900 dark:text-amber-200 text-xs font-mono space-y-1">
              <div className="flex items-center space-x-2 font-bold uppercase tracking-wider text-amber-800 dark:text-amber-300">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>No Linked Configuration Baseline</span>
              </div>
              <p>
                This capture analysis is not linked to an approved configuration file in Configuration &amp; Certificate Inventory. 
                The observable properties and baseline score below were derived solely from observed PCAP wire metadata. Counterfactual configuration projections represent synthetic models until an authoritative gateway configuration file is imported.
              </p>
            </div>
          )}
          {twin && twin.has_linked_baseline && twin.baseline_provenance && (
            <div className="p-3 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-500 text-emerald-900 dark:text-emerald-200 text-xs font-mono flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              <span>Linked Configuration Baseline: <strong>{twin.baseline_provenance}</strong></span>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 font-mono text-xs">
            {/* COLUMN 1: CURRENT OBSERVED */}
            <div className="border border-neutral-300 dark:border-neutral-800 p-4 space-y-4 bg-white dark:bg-neutral-950">
              <div className="border-b border-neutral-200 dark:border-neutral-800 pb-2 flex items-center justify-between">
                <div>
                  <span className="px-2 py-0.5 bg-neutral-200 dark:bg-neutral-800 text-neutral-800 dark:text-neutral-200 text-[10px] font-bold uppercase">
                    {twin?.has_linked_baseline ? "Approved Gateway Baseline" : "Wire-Observed PCAP Facts"}
                  </span>
                  <h3 className="font-bold text-sm text-neutral-900 dark:text-white mt-1 uppercase">
                    1. Observed Model
                  </h3>
                </div>
                <div className="text-right">
                  <div className="text-[10px] text-neutral-400">Baseline Score</div>
                  <div className="text-base font-bold text-neutral-800 dark:text-neutral-200">
                    {twin?.projected_regression_audit?.baseline_score != null
                      ? twin.projected_regression_audit.baseline_score
                      : "UNKNOWN"}
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-[11px] font-bold text-neutral-400 uppercase">
                  {twin?.has_linked_baseline ? "Configured Properties" : "Observable Wire Properties"}
                </div>
                {twin?.semantic_diff?.map((prop: SemanticDiffItemDTO) => (
                  <div key={prop.field} className="p-2 border border-neutral-200 dark:border-neutral-800 space-y-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-neutral-500">{prop.label}:</span>
                      <span className="font-bold text-neutral-900 dark:text-white">{String(prop.current_value)}</span>
                    </div>
                    <div className="text-[10px] text-neutral-400 flex items-center justify-between">
                      <span>Evidence State:</span>
                      <span className="font-semibold text-emerald-600 dark:text-emerald-400">{prop.current_evidence_state}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* COLUMN 2: PROJECTED PROPOSED */}
            <div className="border-2 border-[#FF3D00] p-4 space-y-4 bg-neutral-50/50 dark:bg-neutral-900/40">
              <div className="border-b border-neutral-200 dark:border-neutral-800 pb-2 flex items-center justify-between">
                <div>
                  <span className="px-2 py-0.5 bg-[#FF3D00] text-white text-[10px] font-bold uppercase">
                    PROJECTED (Counterfactual)
                  </span>
                  <h3 className="font-bold text-sm text-neutral-900 dark:text-white mt-1 uppercase">
                    2. Security Twin Proposal
                  </h3>
                </div>
                <div className="text-right">
                  <div className="text-[10px] text-neutral-400">Projected Delta</div>
                  <div className="text-base font-bold text-emerald-600 dark:text-emerald-400">
                    {twin?.projected_score_delta != null
                      ? (twin.projected_score_delta > 0
                          ? `+${twin.projected_score_delta}`
                          : twin.projected_score_delta === 0
                          ? "0 (No Deficiencies)"
                          : `${twin.projected_score_delta}`)
                      : "—"}
                  </div>
                </div>
              </div>

              {/* Proposal Hash Lineage */}
              <div className="p-2 bg-neutral-200 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-[10px] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-neutral-500 uppercase">Immutable Hash:</span>
                  <span className="font-bold text-neutral-900 dark:text-white truncate max-w-[180px]">
                    {twin?.proposal_hash}
                  </span>
                </div>
              </div>

              {/* Editable Configuration Buffer */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px] text-neutral-500 font-bold uppercase">
                  <span>swanctl.conf proposal template</span>
                  <button
                    onClick={() => updateProposalMutation.mutate(editedConfig)}
                    disabled={updateProposalMutation.isPending || editedConfig === twin?.rendered_proposed_config}
                    className="text-[#FF3D00] hover:underline disabled:text-neutral-400"
                  >
                    {updateProposalMutation.isPending ? "Re-projecting..." : "Re-project Changes"}
                  </button>
                </div>
                <textarea
                  value={editedConfig}
                  onChange={(e) => setEditedConfig(e.target.value)}
                  rows={14}
                  className="w-full p-2.5 font-mono text-[11px] bg-white dark:bg-neutral-950 border border-neutral-300 dark:border-neutral-700 focus:outline-none focus:border-[#FF3D00] text-neutral-900 dark:text-neutral-100 resize-none leading-relaxed"
                />
              </div>
            </div>

            {/* COLUMN 3: VERIFIED POST-REMEDIATION */}
            <div className="border border-neutral-300 dark:border-neutral-800 p-4 space-y-4 bg-white dark:bg-neutral-950">
              <div className="border-b border-neutral-200 dark:border-neutral-800 pb-2 flex items-center justify-between">
                <div>
                  <span className="px-2 py-0.5 bg-emerald-600 text-white text-[10px] font-bold uppercase">
                    VERIFIED (Empirical Wire Evidence)
                  </span>
                  <h3 className="font-bold text-sm text-neutral-900 dark:text-white mt-1 uppercase">
                    3. Lab Verification
                  </h3>
                </div>
                <div className="text-right">
                  <div className="text-[10px] text-neutral-400">Verified Score</div>
                  <div className="text-base font-bold text-emerald-600 dark:text-emerald-400">
                    {latestVerification?.verified_score ?? "Pending Run"}
                  </div>
                </div>
              </div>

              {latestVerification ? (
                <div className="space-y-3 font-mono">
                  {/* Dual-Axis Result */}
                  <div className="grid grid-cols-2 gap-2 text-center">
                    <div className="p-2 border border-emerald-600 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-800 dark:text-emerald-300">
                      <div className="text-[9px] uppercase font-bold text-neutral-500">Security Outcome</div>
                      <div className="font-bold text-xs">{latestVerification.security_result}</div>
                    </div>
                    <div className="p-2 border border-emerald-600 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-800 dark:text-emerald-300">
                      <div className="text-[9px] uppercase font-bold text-neutral-500">Operational Transit</div>
                      <div className="font-bold text-xs">{latestVerification.operational_result}</div>
                    </div>
                  </div>

                  {/* Summary */}
                  <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-[11px] space-y-1">
                    <div className="text-neutral-500 uppercase text-[10px] font-bold">Verification Overview</div>
                    <div className="text-neutral-800 dark:text-neutral-200">
                      {latestVerification.verification_result}
                    </div>
                    <div className="text-neutral-400 text-[10px]">
                      Verified at: {new Date(latestVerification.verified_at).toLocaleTimeString()}
                    </div>
                  </div>

                  {/* Claims quick summary */}
                  <div className="space-y-1.5">
                    <div className="text-[10px] font-bold text-neutral-400 uppercase">Itemized Claims ({latestVerification.claims.length})</div>
                    {latestVerification.claims.map((claim: VerificationClaimDTO) => (
                      <div
                        key={claim.claim_id}
                        className="p-2 border border-neutral-200 dark:border-neutral-800 flex items-center justify-between text-[11px]"
                      >
                        <span className="font-bold truncate max-w-[150px]">{claim.rule_id}</span>
                        <span className="px-2 py-0.5 bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 font-bold text-[10px]">
                          {claim.claim_result}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="py-16 text-center text-neutral-400 space-y-2">
                  <Lock className="w-8 h-8 mx-auto text-neutral-300 dark:text-neutral-700" />
                  <p className="text-xs uppercase font-bold">No Verified Run Yet</p>
                  <p className="text-[11px] text-neutral-500 max-w-xs mx-auto">
                    Click &quot;Validate in Controlled Lab&quot; above to execute the closed-loop apply → fresh packet capture cycle.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Security Semantic Diff */}
      {activeTab === "semantic_diff" && (
        <Card title="Security Semantic Diff (Configuration IR Changes)">
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-neutral-100 dark:bg-neutral-900 border-b border-neutral-200 dark:border-neutral-800 text-[11px] uppercase text-neutral-500">
                <tr>
                  <th className="p-3">Property</th>
                  <th className="p-3">Baseline Observed</th>
                  <th className="p-3">Evidence State</th>
                  <th className="p-3">Proposed (Hardened)</th>
                  <th className="p-3">Policy Rationale & Impact</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800">
                {twin?.semantic_diff?.map((diff: SemanticDiffItemDTO) => (
                  <tr
                    key={diff.field}
                    className={diff.is_changed ? "bg-amber-50/40 dark:bg-amber-950/10" : ""}
                  >
                    <td className="p-3 font-bold text-neutral-900 dark:text-white">{diff.label}</td>
                    <td className="p-3 text-neutral-600 dark:text-neutral-400">{String(diff.current_value)}</td>
                    <td className="p-3 font-semibold text-emerald-600">{diff.current_evidence_state}</td>
                    <td className="p-3 font-bold text-[#FF3D00]">{String(diff.proposed_value)}</td>
                    <td className="p-3 text-neutral-500 text-[11px] leading-relaxed">{diff.policy_impact}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Tab 3: swanctl.conf Unified Text Diff */}
      {activeTab === "text_diff" && (
        <Card title="Unified Text Diff (strongSwan swanctl.conf)">
          <pre className="p-4 bg-neutral-900 text-neutral-100 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed border border-neutral-800">
            {twin?.text_diff || "No textual differences detected."}
          </pre>
        </Card>
      )}

      {/* Tab 4: Projected Regression Audit */}
      {activeTab === "audit" && (
        <div className="space-y-4">
          <Card title="Projected Regression Audit (Whole-Policy Evaluation)">
            <div className="space-y-4 font-mono text-xs">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-3 border border-emerald-500 bg-emerald-50/40 dark:bg-emerald-950/10 text-emerald-900 dark:text-emerald-300">
                  <div className="text-[10px] font-bold uppercase">Projected Resolved Findings</div>
                  <div className="text-xl font-bold mt-1">
                    {twin?.projected_regression_audit?.projected_resolved_findings?.length || 0}
                  </div>
                </div>
                <div className="p-3 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-900">
                  <div className="text-[10px] font-bold uppercase text-neutral-500">Unaddressed Findings</div>
                  <div className="text-xl font-bold text-neutral-800 dark:text-neutral-200 mt-1">
                    {twin?.projected_regression_audit?.projected_remaining_findings?.length || 0}
                  </div>
                </div>
                <div className="p-3 border border-rose-500 bg-rose-50/40 dark:bg-rose-950/10 text-rose-900 dark:text-rose-300">
                  <div className="text-[10px] font-bold uppercase">New Projected Regressions</div>
                  <div className="text-xl font-bold mt-1">
                    {twin?.projected_regression_audit?.projected_new_regressions?.length || 0}
                  </div>
                </div>
              </div>

              {/* Resolved Items */}
              <div className="space-y-2 pt-2">
                <h4 className="text-[11px] font-bold uppercase text-emerald-600">Targeted Findings Projected Resolved</h4>
                {twin?.projected_regression_audit?.projected_resolved_findings?.map((item: ProjectedFindingDTO) => (
                  <div key={item.finding_id} className="p-2.5 border border-emerald-300 dark:border-emerald-800 bg-emerald-50/20 dark:bg-emerald-950/10 flex items-center justify-between">
                    <div>
                      <span className="font-bold">{item.rule_id}</span> — {item.title}
                      <p className="text-[10px] text-neutral-500 mt-0.5">{item.rationale}</p>
                    </div>
                    <span className="px-2 py-0.5 bg-emerald-600 text-white font-bold text-[10px] uppercase">
                      {item.projected_state}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Tab 5: Verification Claim Ledger */}
      {activeTab === "claims" && (
        <Card title="Verification Claim Ledger (Finding-Level Proof Audit)">
          {latestVerification?.claims?.length ? (
            <div className="space-y-3 font-mono text-xs">
              {latestVerification.claims.map((claim: VerificationClaimDTO) => {
                const isExpanded = expandedClaimId === claim.claim_id;
                return (
                  <div
                    key={claim.claim_id}
                    className="border border-neutral-300 dark:border-neutral-800 overflow-hidden"
                  >
                    <button
                      onClick={() => setExpandedClaimId(isExpanded ? null : claim.claim_id)}
                      className="w-full p-3 bg-neutral-50 dark:bg-neutral-900/60 flex items-center justify-between text-left hover:bg-neutral-100 dark:hover:bg-neutral-900 transition-colors"
                    >
                      <div className="flex items-center space-x-2">
                        {isExpanded ? <ChevronDown className="w-4 h-4 text-[#FF3D00]" /> : <ChevronRight className="w-4 h-4 text-neutral-400" />}
                        <span className="font-bold text-neutral-900 dark:text-white uppercase">{claim.rule_id}</span>
                        <span className="text-neutral-500 text-[11px]">({claim.root_cause_key})</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 bg-emerald-600 text-white font-bold text-[10px] uppercase">
                          {claim.claim_result}
                        </span>
                      </div>
                    </button>

                    {isExpanded && (
                      <div className="p-4 bg-white dark:bg-neutral-950 border-t border-neutral-200 dark:border-neutral-800 space-y-3 text-[11px]">
                        <div>
                          <span className="font-bold uppercase text-neutral-400">Formal Verification Criterion:</span>
                          <p className="text-neutral-700 dark:text-neutral-300 mt-0.5">{claim.expected_condition}</p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-neutral-100 dark:border-neutral-900">
                          <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800">
                            <span className="font-bold uppercase text-neutral-500 text-[10px]">Baseline Wire Evidence</span>
                            <pre className="mt-1 text-[10px] overflow-x-auto text-neutral-800 dark:text-neutral-200">
                              {JSON.stringify(claim.baseline_evidence, null, 2)}
                            </pre>
                          </div>
                          <div className="p-2.5 bg-emerald-50/40 dark:bg-emerald-950/20 border border-emerald-300 dark:border-emerald-800">
                            <span className="font-bold uppercase text-emerald-600 text-[10px]">Post-Remediation Evidence Frame</span>
                            <pre className="mt-1 text-[10px] overflow-x-auto text-emerald-900 dark:text-emerald-200">
                              {JSON.stringify(claim.post_evidence, null, 2)}
                            </pre>
                          </div>
                        </div>

                        <div className="text-[10px] text-neutral-400">
                          Reason Code: <strong>{claim.reason_code}</strong>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="py-12 text-center text-neutral-400 font-mono text-xs">
              No claim ledger entries found. Verification claims are populated upon lab execution.
            </div>
          )}
        </Card>
      )}

      {/* Explicit Hash-Bound Approval Modal */}
      {isConfirmModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4 font-mono text-xs">
          <div className="bg-white dark:bg-neutral-950 border-2 border-[#FF3D00] max-w-xl w-full p-6 space-y-4">
            <div className="flex items-center space-x-2 text-[#FF3D00] font-bold text-sm uppercase">
              <AlertTriangle className="w-5 h-5 shrink-0" />
              <span>Operator Authorization Gate — Controlled Lab Apply</span>
            </div>

            <p className="text-neutral-700 dark:text-neutral-300 leading-relaxed text-xs">
              You are about to deploy configuration proposal <strong>{twin?.proposal_hash.slice(0, 16)}...</strong> to the isolated strongSwan testbed. This action will:
            </p>

            <ul className="list-disc pl-5 space-y-1 text-neutral-600 dark:text-neutral-400 text-[11px]">
              <li>Acquire exclusive testbed lock (`lab.lock`).</li>
              <li>Create an immutable pre-remediation backup of the active daemon configuration.</li>
              <li>Atomically overwrite `swanctl.conf` inside the Linux namespace.</li>
              <li>Reload strongSwan and renegotiate a fresh Security Association.</li>
              <li>Execute synthetic traffic to verify data plane packet transit.</li>
              <li>Capture a fresh verification PCAP and run full Stages 3–8 analysis.</li>
              <li>Automatically rollback if the tunnel negotiation or daemon crashes.</li>
            </ul>

            <div className="p-3 bg-neutral-100 dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-700 text-[11px] space-y-2">
              <div className="grid grid-cols-2 gap-2 text-[10px]">
                <div>
                  <span className="text-neutral-500 uppercase block">Proposal Digest (SHA-256):</span>
                  <code className="text-neutral-900 dark:text-white font-bold">{twin?.proposal_hash.slice(0, 20)}...</code>
                </div>
                <div>
                  <span className="text-neutral-500 uppercase block">Lab Sandbox Target:</span>
                  <code className="text-neutral-900 dark:text-white font-bold">strongswan-lab-default</code>
                </div>
              </div>

              <div>
                <label className="block text-neutral-500 uppercase text-[10px] mb-1">Authorizing Operator Identifier:</label>
                <input
                  type="text"
                  value={operatorId}
                  onChange={(e) => setOperatorId(e.target.value)}
                  placeholder="e.g. security-engineer-1"
                  className="w-full px-2 py-1 bg-white dark:bg-neutral-950 border border-neutral-300 dark:border-neutral-700 font-mono text-xs text-neutral-900 dark:text-white focus:outline-none focus:border-[#FF3D00]"
                />
              </div>

              <label className="flex items-start space-x-2 cursor-pointer pt-1 border-t border-neutral-200 dark:border-neutral-800">
                <input
                  type="checkbox"
                  checked={confirmControlledLab}
                  onChange={(e) => setConfirmControlledLab(e.target.checked)}
                  className="mt-0.5 rounded-none border-neutral-400 text-[#FF3D00] focus:ring-0"
                />
                <span className="font-bold text-neutral-900 dark:text-white uppercase">
                  I confirm this action targets the controlled strongSwan testbed only. No external production or vendor device will be mutated.
                </span>
              </label>
            </div>

            <p className="text-[10px] text-neutral-400">
              * Approval is bound cryptographically to this exact proposal hash, diff hash, and fresh authorization timestamp. Any subsequent edit immediately revokes authorization.
            </p>

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                onClick={() => {
                  setIsConfirmModalOpen(false);
                  setConfirmControlledLab(false);
                }}
                className="px-4 py-2 bg-neutral-200 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 uppercase font-bold"
              >
                Cancel
              </button>
              <button
                disabled={!confirmControlledLab || applyMutation.isPending}
                onClick={() => applyMutation.mutate()}
                className={`px-5 py-2 font-bold uppercase transition-colors ${
                  confirmControlledLab && !applyMutation.isPending
                    ? "bg-[#FF3D00] text-white hover:bg-[#E03600]"
                    : "bg-neutral-300 dark:bg-neutral-800 text-neutral-400 cursor-not-allowed"
                }`}
              >
                {applyMutation.isPending ? "Applying..." : "Authorize & Execute"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
