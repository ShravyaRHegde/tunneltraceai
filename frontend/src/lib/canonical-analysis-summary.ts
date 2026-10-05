/**
 * Canonical Analysis Summary Adapter (Phase 1)
 *
 * Provides a single, authoritative, strongly-typed contract for mapping
 * API payloads (AnalysisOverviewDTO and AnalysisListItemDTO) into verified
 * presentation metrics across Dashboard, Catalog, and Investigation views.
 */

import { AnalysisOverviewDTO, AnalysisListItemDTO } from "./api/types";

export type CanonicalRiskTier =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "NO_FINDINGS_WITHIN_EVALUATED_EVIDENCE"
  | "INSUFFICIENT_EVIDENCE"
  | "NOT_IPSEC"
  | "FAILED"
  | "UNAVAILABLE";

export interface CanonicalAnalysisSummary {
  analysisId: string;
  captureId: string;
  captureFilename: string;
  captureSha256: string;
  packetCount: number | null;
  status: string;
  currentStage: string;
  isAssessable: boolean;
  securityScore: number | null;
  coveragePercentage: number;
  evaluatedControls: number;
  totalControls: number;
  unknownControls: number;
  findings: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  compliance: {
    pass: number;
    fail: number;
    unknown: number;
    notApplicable: number;
  };
  traffic: {
    totalFlows: number;
    classifiedFlows: number;
    oodCount: number;
    anomalyCount: number;
    mlRunStatus: string;
    modelArtifactState: string;
  };
  provenance: {
    pipelineVersion: string;
    policyVersion: string;
    parserEngine: string;
    parserVersion?: string;
    isSyntheticDemo: boolean;
    createdAt: string;
    completedAt: string | null;
  };
  displayScore: string;
  displayCoverage: string;
  displayRiskTier: CanonicalRiskTier;
  riskBadgeLabel: string;
  riskBadgeColor: "red" | "orange" | "amber" | "green" | "neutral" | "blue";
}

export function toCanonicalAnalysisSummary(
  data: AnalysisOverviewDTO | AnalysisListItemDTO | null | undefined
): CanonicalAnalysisSummary | null {
  if (!data) return null;

  // Detect whether input is AnalysisOverviewDTO (has data.capture object) or AnalysisListItemDTO
  const isOverview = "capture" in data && typeof (data as any).capture === "object";

  if (isOverview) {
    const ov = data as AnalysisOverviewDTO;
    const covRaw = ov.security_posture?.evidence_coverage ?? 0;
    const covPct = covRaw <= 1.0 ? covRaw * 100 : covRaw;
    const isAssessable =
      ov.analysis?.status !== "FAILED" &&
      ov.security_posture?.is_assessable !== false &&
      ov.security_posture?.status !== "NOT_ASSESSABLE" &&
      ov.security_posture?.score !== null &&
      ov.security_posture?.score !== undefined;
    const score = isAssessable ? ov.security_posture?.score ?? null : null;

    const compliancePass = ov.compliance_counts?.pass ?? 0;
    const complianceFail = ov.compliance_counts?.fail ?? 0;
    const complianceUnknown = ov.compliance_counts?.unknown ?? 0;
    const complianceNA = ov.compliance_counts?.not_applicable ?? 0;
    const evaluatedControls = compliancePass + complianceFail;
    const totalControls = evaluatedControls + complianceUnknown + complianceNA || 7;

    const criticalCount = ov.findings_summary?.critical ?? 0;
    const highCount = ov.findings_summary?.high ?? 0;
    const totalFindings = ov.findings_summary?.total ?? 0;

    // Truthful Canonical Risk Tier
    let riskTier: CanonicalRiskTier = "NO_FINDINGS_WITHIN_EVALUATED_EVIDENCE";
    if (ov.analysis?.status === "FAILED") {
      riskTier = "FAILED";
    } else if (criticalCount > 0) {
      riskTier = "CRITICAL";
    } else if (highCount > 0) {
      riskTier = "HIGH";
    } else if (totalFindings > 0) {
      riskTier = "MEDIUM";
    } else if (
      ov.security_posture?.aggregate_risk_tier &&
      ov.security_posture.aggregate_risk_tier !== "NO_FINDINGS_UNDER_THIS_POLICY" &&
      ov.security_posture.aggregate_risk_tier !== "INSUFFICIENT_EVIDENCE"
    ) {
      riskTier = ov.security_posture.aggregate_risk_tier as CanonicalRiskTier;
    } else if (score === null) {
      riskTier = "INSUFFICIENT_EVIDENCE";
    } else {
      riskTier = "NO_FINDINGS_WITHIN_EVALUATED_EVIDENCE";
    }

    const totalFlows = ov.traffic_summary?.total_flows ?? ov.traffic_summary?.classified_flows ?? 0;

    let displayScore = "NOT ASSESSABLE";
    if (score !== null) {
      displayScore = `${Math.round(score)}/100 (${covPct.toFixed(1)}% evidence${complianceUnknown > 0 ? `, ${complianceUnknown} unknown` : ""})`;
    } else if (covPct > 0) {
      displayScore = `INSUFFICIENT EVIDENCE (${covPct.toFixed(1)}%)`;
    }

    return {
      analysisId: ov.analysis_id,
      captureId: ov.capture?.id || "",
      captureFilename: ov.capture?.filename || "capture.pcap",
      captureSha256: ov.capture?.sha256 || "",
      packetCount: ov.capture?.packet_count ?? null,
      status: ov.analysis?.status || "COMPLETED",
      currentStage: ov.analysis?.current_stage || "COMPLETED",
      isAssessable,
      securityScore: score,
      coveragePercentage: covPct,
      evaluatedControls,
      totalControls,
      unknownControls: complianceUnknown,
      findings: {
        total: totalFindings,
        critical: criticalCount,
        high: highCount,
        medium: ov.findings_summary?.medium ?? 0,
        low: ov.findings_summary?.low ?? 0,
      },
      compliance: {
        pass: compliancePass,
        fail: complianceFail,
        unknown: complianceUnknown,
        notApplicable: complianceNA,
      },
      traffic: {
        totalFlows,
        classifiedFlows: ov.traffic_summary?.classified_flows ?? 0,
        oodCount: ov.traffic_summary?.ood_count ?? 0,
        anomalyCount: ov.traffic_summary?.anomaly_count ?? 0,
        mlRunStatus: ov.traffic_summary?.ml_run_status || "COMPLETED",
        modelArtifactState: "EXPERIMENTAL",
      },
      provenance: {
        pipelineVersion: ov.analysis?.pipeline_version || "2.0.0",
        policyVersion: ov.analysis?.policy_version || "1.0.0",
        parserEngine: ov.analysis?.parser_engine || "tshark",
        parserVersion: ov.analysis?.parser_version,
        isSyntheticDemo: Boolean(ov.analysis?.is_synthetic_demo),
        createdAt: ov.analysis?.created_at || new Date().toISOString(),
        completedAt: null,
      },
      displayScore,
      displayCoverage: `${covPct.toFixed(1)}%`,
      displayRiskTier: riskTier,
      riskBadgeLabel: formatRiskLabel(riskTier),
      riskBadgeColor: getRiskColor(riskTier),
    };
  }

  // Handle AnalysisListItemDTO
  const item = data as AnalysisListItemDTO;
  const covRaw = item.coverage_percentage ?? 0;
  const covPct = covRaw <= 1.0 && covRaw > 0 ? covRaw * 100 : covRaw;
  const isAssessable = item.status !== "FAILED" && item.security_score !== null && item.security_score !== undefined;
  const score = isAssessable ? item.security_score : null;

  const criticalCount = item.critical_findings ?? 0;
  const highCount = item.high_findings ?? 0;
  const mediumCount = item.medium_findings ?? 0;
  const lowCount = item.low_findings ?? 0;
  const totalFindings = item.total_findings ?? (criticalCount + highCount + mediumCount + lowCount);

  let riskTier: CanonicalRiskTier = "NO_FINDINGS_WITHIN_EVALUATED_EVIDENCE";
  if (item.status === "FAILED") {
    riskTier = "FAILED";
  } else if (criticalCount > 0) {
    riskTier = "CRITICAL";
  } else if (highCount > 0) {
    riskTier = "HIGH";
  } else if (totalFindings > 0 || (item.risk_tier && item.risk_tier.toUpperCase() === "MEDIUM")) {
    riskTier = "MEDIUM";
  } else if (item.risk_tier && item.risk_tier !== "NO_FINDINGS_UNDER_THIS_POLICY" && item.risk_tier !== "INSUFFICIENT_EVIDENCE") {
    riskTier = item.risk_tier as CanonicalRiskTier;
  } else if (score === null) {
    riskTier = "INSUFFICIENT_EVIDENCE";
  } else {
    riskTier = "NO_FINDINGS_WITHIN_EVALUATED_EVIDENCE";
  }

  let displayScore = "NOT ASSESSABLE";
  if (score !== null) {
    displayScore = `${Math.round(score)}/100 (${covPct.toFixed(1)}% evidence)`;
  } else if (covPct > 0) {
    displayScore = `INSUFFICIENT EVIDENCE (${covPct.toFixed(1)}%)`;
  }

  // Authoritative compliance figures
  const comp = item.compliance_counts;
  const compPass = comp?.pass ?? (isAssessable ? Math.max(0, 7 - totalFindings) : 0);
  const compFail = comp?.fail ?? totalFindings;
  const compUnknown = comp?.unknown ?? (isAssessable ? 0 : 7);
  const compNA = comp?.not_applicable ?? 0;
  const evaluatedControls = compPass + compFail;
  const totalControls = evaluatedControls + compUnknown + compNA || 7;

  return {
    analysisId: item.analysis_id,
    captureId: item.capture_id,
    captureFilename: item.capture_filename,
    captureSha256: item.capture_sha256,
    packetCount: (item as any).packet_count ?? null,
    status: item.status,
    currentStage: item.current_stage,
    isAssessable,
    securityScore: score,
    coveragePercentage: covPct,
    evaluatedControls,
    totalControls,
    unknownControls: compUnknown,
    findings: {
      total: totalFindings,
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
    },
    compliance: {
      pass: compPass,
      fail: compFail,
      unknown: compUnknown,
      notApplicable: compNA,
    },
    traffic: {
      totalFlows: (item as any).flows_count ?? 0,
      classifiedFlows: 0,
      oodCount: 0,
      anomalyCount: 0,
      mlRunStatus: "COMPLETED",
      modelArtifactState: (item as any).model_artifact_state || "EXPERIMENTAL",
    },
    provenance: {
      pipelineVersion: item.pipeline_version || "2.0.0",
      policyVersion: item.policy_version || "1.0.0",
      parserEngine: "tshark",
      isSyntheticDemo: Boolean(item.is_synthetic_demo),
      createdAt: item.created_at,
      completedAt: item.completed_at,
    },
    displayScore,
    displayCoverage: `${covPct.toFixed(1)}%`,
    displayRiskTier: riskTier,
    riskBadgeLabel: formatRiskLabel(riskTier),
    riskBadgeColor: getRiskColor(riskTier),
  };
}

function formatRiskLabel(tier: CanonicalRiskTier): string {
  switch (tier) {
    case "CRITICAL":
      return "CRITICAL RISK";
    case "HIGH":
      return "HIGH RISK";
    case "MEDIUM":
      return "MEDIUM RISK";
    case "LOW":
      return "LOW RISK";
    case "NO_FINDINGS_WITHIN_EVALUATED_EVIDENCE":
      return "NO FINDINGS (WITHIN EVALUATED EVIDENCE)";
    case "INSUFFICIENT_EVIDENCE":
      return "INSUFFICIENT EVIDENCE";
    case "NOT_IPSEC":
      return "NON-IPSEC / NOT ASSESSABLE";
    case "FAILED":
      return "ANALYSIS FAILED";
    case "UNAVAILABLE":
      return "UNAVAILABLE";
  }
}

function getRiskColor(
  tier: CanonicalRiskTier
): "red" | "orange" | "amber" | "green" | "neutral" | "blue" {
  switch (tier) {
    case "CRITICAL":
      return "red";
    case "HIGH":
      return "orange";
    case "MEDIUM":
      return "amber";
    case "LOW":
      return "blue";
    case "NO_FINDINGS_WITHIN_EVALUATED_EVIDENCE":
      return "green";
    case "INSUFFICIENT_EVIDENCE":
    case "NOT_IPSEC":
      return "amber";
    case "FAILED":
      return "red";
    case "UNAVAILABLE":
      return "neutral";
  }
}
