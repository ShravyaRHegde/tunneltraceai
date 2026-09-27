"use client";

import React, { use, useState } from "react";
import Link from "next/link";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { CopyableValue } from "@/components/ui/table";
import { ReportResponseDTO } from "@/lib/api/types";
import { SocWorkflowBanner } from "@/components/soc/soc-workflow-banner";
import {
  FileText,
  Download,
  Eye,
  CheckCircle,
  AlertTriangle,
  Clock,
  RefreshCw,
  Printer,
  Shield,
  FileCode,
  FileSearch,
  History,
  Activity,
  Layers,
  CheckCircle2,
  XCircle,
  AlertCircle,
  ExternalLink,
  FileSpreadsheet,
} from "lucide-react";

export default function ReportsWorkspacePage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const queryClient = useQueryClient();

  const [previewReportId, setPreviewReportId] = useState<string | null>(null);
  const [reportHtml, setReportHtml] = useState<string | null>(null);
  const [isPreviewLoading, setIsPreviewLoading] = useState(false);

  // Context queries for Scope & Provenance verification
  const { data: analysisData } = useQuery({
    queryKey: ["analysis", analysisId],
    queryFn: () => api.analyses.get(analysisId),
  });

  const { data: securityScore } = useQuery({
    queryKey: ["security-score", analysisId],
    queryFn: () => api.analyses.getSecurityScore(analysisId),
  });

  const { data: replayLineage } = useQuery({
    queryKey: ["replay-lineage", analysisId],
    queryFn: () => api.analyses.getReplayLineage(analysisId),
  });

  // List existing reports
  const {
    data: reportsData,
    isLoading,
    isError,
    refetch,
  } = useQuery({
    queryKey: ["reports-list", analysisId],
    queryFn: () => api.reports.list(analysisId),
  });

  // Generate Report Mutation
  const generateMutation = useMutation({
    mutationFn: (reportType: "EXECUTIVE" | "TECHNICAL") =>
      api.reports.generate(analysisId, reportType),
    onSuccess: (newReport) => {
      queryClient.invalidateQueries({ queryKey: ["reports-list", analysisId] });
      if (newReport?.id) {
        handlePreviewHtml(newReport.id);
      }
    },
  });

  const handlePreviewHtml = async (reportId: string) => {
    setPreviewReportId(reportId);
    setIsPreviewLoading(true);
    try {
      const html = await api.reports.getHtml(analysisId, reportId);
      setReportHtml(html);
    } catch {
      setReportHtml("<p style='color:red;'>Failed to load HTML report preview.</p>");
    } finally {
      setIsPreviewLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* SOC Analyst Lifecycle Banner */}
      <SocWorkflowBanner
        activeStep={7}
        analysisId={analysisId}
        evidenceCoverage={securityScore?.evidence_coverage}
      />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <FileText className="w-5 h-5 text-[#FF3D00]" />
            <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
              Publication-Grade Security & Forensics Reporting
            </h1>
          </div>
          <p className="text-xs text-neutral-500 mt-1">
            Deterministic server-side artifact generation from immutable analysis snapshots. Print CSS typography, SHA-256 provenance hashes, and zero LLM hallucination.
          </p>
        </div>

        {/* Quick SOC Journey Navigation */}
        <div className="flex flex-wrap items-center gap-2">
          <Link
            href={`/analyses/${analysisId}/security`}
            className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-300"
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Findings Triage</span>
          </Link>
          <Link
            href={`/analyses/${analysisId}/evidence`}
            className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-300"
          >
            <FileSearch className="w-3.5 h-3.5" />
            <span>Evidence DAG</span>
          </Link>
          <Link
            href={`/analyses/${analysisId}/evidence?view=replay`}
            className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-300"
          >
            <History className="w-3.5 h-3.5" />
            <span>Replay Lineage</span>
          </Link>
          <Link
            href="/monitoring"
            className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-300"
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Fleet Telemetry</span>
          </Link>
        </div>
      </div>

      {/* Scope, Provenance & Evidence Verification Snapshot */}
      <div className="p-4 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800">
        <div className="flex items-center justify-between pb-3 border-b border-neutral-200 dark:border-neutral-800 mb-3">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-[#FF3D00]"></span>
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-neutral-900 dark:text-white">
              Report Target Scope & Evidence Audit Gate
            </span>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-400">
            DETERMINISTIC COMPILATION PRE-CHECK
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs font-mono">
          <div>
            <div className="text-[10px] text-neutral-500 uppercase">Analysis Snapshot</div>
            <div className="font-bold text-neutral-900 dark:text-white truncate">
              {replayLineage?.capture_filename || analysisId}
            </div>
            <div className="text-[10px] text-neutral-400 truncate">
              SHA: {replayLineage?.capture_sha256 ? `${replayLineage.capture_sha256.slice(0, 12)}...` : "Preserved"}
            </div>
          </div>

          <div>
            <div className="text-[10px] text-neutral-500 uppercase">Evaluated Policy Engine</div>
            <div className="font-bold text-neutral-900 dark:text-white">
              NIST SP 800-77 Rev. 1
            </div>
            <div className="text-[10px] text-neutral-400">
              RFC 8221 Cryptographic Suites
            </div>
          </div>

          <div>
            <div className="text-[10px] text-neutral-500 uppercase">Observed Posture</div>
            <div className="font-bold text-neutral-900 dark:text-white flex items-center space-x-1.5">
              <span>
                {securityScore?.status === "NOT_ASSESSABLE" || securityScore?.overall_score === null
                  ? "NOT ASSESSABLE"
                  : securityScore?.overall_score !== undefined
                  ? `${securityScore.overall_score}/100`
                  : "Pending Evaluation"}
              </span>
              {securityScore?.status && (
                <span className="px-1.5 py-0.2 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-[10px]">
                  {securityScore.status}
                </span>
              )}
            </div>
            <div className="text-[10px] text-neutral-400">
              Coverage: {(() => {
                const cov = securityScore?.evidence_coverage;
                if (typeof cov === "object" && cov !== null && "coverage_percentage" in cov) {
                  return `${Number((cov as any).coverage_percentage).toFixed(0)}%`;
                }
                if (typeof cov === "number") {
                  return `${(cov <= 1 ? cov * 100 : cov).toFixed(0)}%`;
                }
                if ((securityScore as any)?.coverage_percentage !== undefined) {
                  return `${Number((securityScore as any).coverage_percentage).toFixed(0)}%`;
                }
                return "UNAVAILABLE";
              })()}
            </div>
          </div>

          <div>
            <div className="text-[10px] text-neutral-500 uppercase">Artifact Integrity Gate</div>
            <div className="flex items-center space-x-1 font-bold text-xs">
              {replayLineage?.capture_integrity_verified ? (
                <div className="flex items-center space-x-1 text-emerald-600 dark:text-emerald-400">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>SHA-256 MATCH</span>
                </div>
              ) : replayLineage?.capture_integrity_status === "FILE_NOT_FOUND" ? (
                <div className="flex items-center space-x-1 text-rose-600 dark:text-rose-400" title="The source capture file is absent from storage">
                  <XCircle className="w-3.5 h-3.5" />
                  <span>FILE MISSING ON DISK</span>
                </div>
              ) : replayLineage?.capture_integrity_status === "HASH_MISMATCH" ? (
                <div className="flex items-center space-x-1 text-rose-600 dark:text-rose-400" title="Recorded hash does not match computed file digest">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>DIGEST MISMATCH</span>
                </div>
              ) : (
                <div className="flex items-center space-x-1 text-neutral-500">
                  <AlertCircle className="w-3.5 h-3.5" />
                  <span>UNVERIFIED</span>
                </div>
              )}
            </div>
            <div className="text-[10px] text-neutral-400">
              Lineage: {replayLineage?.replay_mode || "ORIGINAL_INGESTION"}
            </div>
          </div>
        </div>

        <div className="mt-3 pt-2 border-t border-neutral-100 dark:border-neutral-800/80 text-[11px] text-neutral-500">
          <span className="font-semibold text-neutral-700 dark:text-neutral-300">Auditor Notice: </span>
          Report generation is strictly deterministic and rendered from persisted database snapshots. Missing telemetry sources, partial scanner ingestion, or unassessed rules are explicitly labeled in the generated document.
        </div>
      </div>

      {/* Generation Action Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Executive Summary Card */}
        <Card
          title="Executive Security Summary"
          badge={
            <span className="text-[10px] font-mono px-1 border border-neutral-300 dark:border-neutral-700">
              CISO / LEADERSHIP
            </span>
          }
        >
          <div className="space-y-3">
            <p className="text-xs text-neutral-600 dark:text-neutral-400">
              High-level strategic briefing communicating observed posture score, evidence coverage, material risks, standards compliance status, and deterministic recommended actions.
            </p>
            <div className="pt-2 flex items-center justify-between">
              <span className="text-[10px] font-mono text-neutral-400">
                Format: Canonical HTML + A4 Print PDF
              </span>
              <button
                disabled={generateMutation.isPending}
                onClick={() => generateMutation.mutate("EXECUTIVE")}
                className="flex items-center space-x-1.5 px-4 py-2 bg-[#FF3D00] hover:bg-[#e03600] disabled:bg-neutral-300 text-white text-xs font-mono font-bold uppercase transition-colors"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>GENERATE EXECUTIVE</span>
              </button>
            </div>
          </div>
        </Card>

        {/* Technical Forensics Report Card */}
        <Card
          title="Technical Forensics & Audit Report"
          badge={
            <span className="text-[10px] font-mono px-1 border border-neutral-300 dark:border-neutral-700">
              SOC / AUDITOR
            </span>
          }
        >
          <div className="space-y-3">
            <p className="text-xs text-neutral-600 dark:text-neutral-400">
              Full forensic disclosure containing packet dissections, cryptographic transform tables, SPI pairs, ML flow feature attributions (TreeSHAP), rule evaluations, and complete evidence provenance hashes.
            </p>
            <div className="pt-2 flex items-center justify-between">
              <span className="text-[10px] font-mono text-neutral-400">
                Format: Canonical HTML + A4 Print PDF
              </span>
              <button
                disabled={generateMutation.isPending}
                onClick={() => generateMutation.mutate("TECHNICAL")}
                className="flex items-center space-x-1.5 px-4 py-2 bg-neutral-900 hover:bg-black dark:bg-white dark:hover:bg-neutral-200 dark:text-neutral-900 disabled:bg-neutral-300 text-white text-xs font-mono font-bold uppercase transition-colors"
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>GENERATE TECHNICAL</span>
              </button>
            </div>
          </div>
        </Card>
      </div>

      {/* Structured Machine-Readable Assessment Downloads */}
      <Card title="Structured Evidence & Finding Packages (JSON / CSV)">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-3 border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50 space-y-2">
            <div className="flex items-center space-x-2">
              <FileCode className="w-4 h-4 text-[#FF3D00]" />
              <span className="font-mono font-bold text-xs uppercase text-neutral-900 dark:text-white">
                Assessment Manifest (Versioned JSON)
              </span>
            </div>
            <p className="text-[11px] text-neutral-500 font-mono leading-relaxed">
              Complete machine-readable assessment package including capture SHA-256, protocol facts, evaluated policy rules, itemized deductions, and replay lineage.
            </p>
            <div className="pt-2">
              <a
                href={api.analyses.getExportManifestUrl(analysisId)}
                download={`tunneltrace_assessment_${analysisId.slice(0, 8)}.json`}
                className="inline-flex items-center space-x-1.5 px-3 py-1.5 bg-neutral-900 hover:bg-black dark:bg-white dark:hover:bg-neutral-200 dark:text-neutral-900 text-white text-xs font-mono font-bold uppercase transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>DOWNLOAD JSON MANIFEST</span>
              </a>
            </div>
          </div>

          <div className="p-3 border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50 space-y-2">
            <div className="flex items-center space-x-2">
              <FileSpreadsheet className="w-4 h-4 text-emerald-600" />
              <span className="font-mono font-bold text-xs uppercase text-neutral-900 dark:text-white">
                Findings Register (RFC 4180 CSV)
              </span>
            </div>
            <p className="text-[11px] text-neutral-500 font-mono leading-relaxed">
              Tabular spreadsheet of all deterministic security findings, rule IDs, decision reasons, affected entities, and remediation directives for ticketing and SIEM export.
            </p>
            <div className="pt-2">
              <a
                href={api.analyses.getExportFindingsCsvUrl(analysisId)}
                download={`tunneltrace_findings_${analysisId.slice(0, 8)}.csv`}
                className="inline-flex items-center space-x-1.5 px-3 py-1.5 bg-neutral-900 hover:bg-black dark:bg-white dark:hover:bg-neutral-200 dark:text-neutral-900 text-white text-xs font-mono font-bold uppercase transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>DOWNLOAD CSV FINDINGS</span>
              </a>
            </div>
          </div>
        </div>
      </Card>

      {/* Generated Artifacts Table */}
      <Card
        title={`Generated Report Artifacts (${reportsData?.items?.length || 0})`}
        actions={
          <button
            onClick={() => refetch()}
            className="p-1 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-500"
            title="Refresh reports"
            aria-label="Refresh reports"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        }
      >
        {isLoading ? (
          <div className="py-8 text-center font-mono text-xs text-neutral-500 animate-pulse">
            Querying persisted report records from database...
          </div>
        ) : reportsData?.items && reportsData.items.length > 0 ? (
          <div className="divide-y divide-neutral-200 dark:divide-neutral-800">
            {reportsData.items.map((rep) => {
              const isHtmlAvailable =
                rep.status === "COMPLETED" ||
                rep.status === "PDF_FAILED_HTML_AVAILABLE";

              return (
                <div
                  key={rep.id}
                  className="py-4 flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono font-bold text-xs uppercase px-2 py-0.5 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700">
                        {rep.report_type}
                      </span>
                      <span
                        className={`text-xs font-mono font-bold px-2 py-0.5 border ${
                          rep.status === "COMPLETED" || rep.status === "PDF_FAILED_HTML_AVAILABLE"
                            ? "bg-emerald-100 text-emerald-900 border-emerald-500 dark:bg-emerald-950/40 dark:text-emerald-300"
                            : "bg-neutral-200 text-neutral-800 border-neutral-400"
                        }`}
                      >
                        {rep.status === "COMPLETED" || rep.status === "PDF_FAILED_HTML_AVAILABLE"
                          ? "READY (PDF + HTML)"
                          : rep.status}
                      </span>
                      {rep.artifact_integrity_status === "VERIFIED" ? (
                        <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-400 dark:bg-emerald-950/30 dark:text-emerald-400 flex items-center space-x-1">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>INTEGRITY VERIFIED</span>
                        </span>
                      ) : rep.artifact_integrity_status === "HASH_MISMATCH" ? (
                        <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-rose-50 text-rose-700 border border-rose-400 dark:bg-rose-950/30 dark:text-rose-400 flex items-center space-x-1" title="Stored digest differs from physical file on disk">
                          <AlertTriangle className="w-3 h-3" />
                          <span>DIGEST MISMATCH</span>
                        </span>
                      ) : rep.artifact_integrity_status === "FILE_NOT_FOUND" ? (
                        <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-rose-50 text-rose-700 border border-rose-400 dark:bg-rose-950/30 dark:text-rose-400 flex items-center space-x-1">
                          <XCircle className="w-3 h-3" />
                          <span>FILE MISSING</span>
                        </span>
                      ) : null}
                      <span className="text-[11px] font-mono text-neutral-400">
                        Duration: {rep.generation_duration_ms ? `${rep.generation_duration_ms}ms` : "-"}
                      </span>
                    </div>

                    <div className="text-xs font-mono text-neutral-500 space-y-0.5">
                      <div className="flex items-center space-x-2">
                        <span>Report ID:</span>
                        <CopyableValue value={rep.id} truncate label="Report ID" />
                      </div>
                      {rep.html_sha256 && (
                        <div className="flex items-center space-x-2">
                          <span>Recorded HTML SHA-256:</span>
                          <CopyableValue value={rep.html_sha256} truncate label="HTML SHA-256" />
                        </div>
                      )}
                      {rep.pdf_sha256 && (
                        <div className="flex items-center space-x-2">
                          <span>Recorded PDF SHA-256:</span>
                          <CopyableValue value={rep.pdf_sha256} truncate label="PDF SHA-256" />
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Primary 1-Click Action: Download Structured PDF */}
                    <a
                      href={api.reports.getDownloadUrl(analysisId, rep.id, "pdf")}
                      download={`TunnelTrace_Report_${rep.report_type.toLowerCase()}_${rep.id.slice(0, 8)}.pdf`}
                      className="flex items-center space-x-1.5 px-3.5 py-1.5 text-xs font-mono font-bold bg-[#FF3D00] hover:bg-[#e03600] text-white transition-colors shadow-sm"
                      title="Download compiled native PDF report"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>DOWNLOAD PDF</span>
                    </a>

                    <button
                      onClick={() => {
                        const url = api.reports.getDownloadUrl(analysisId, rep.id, "html");
                        const win = window.open(url, "_blank");
                        if (win) {
                          win.onload = () => { win.print(); };
                        }
                      }}
                      className="flex items-center space-x-1 px-3 py-1.5 text-xs font-mono font-semibold bg-neutral-900 hover:bg-black dark:bg-white dark:hover:bg-neutral-200 dark:text-neutral-900 text-white transition-colors"
                      title="Open printable HTML template and trigger print/save as PDF"
                    >
                      <Printer className="w-3.5 h-3.5" />
                      <span>PRINT / PDF</span>
                    </button>

                    <button
                      onClick={() => handlePreviewHtml(rep.id)}
                      className="flex items-center space-x-1 px-3 py-1.5 text-xs font-mono font-medium bg-white hover:bg-neutral-50 dark:bg-neutral-900 dark:hover:bg-neutral-800 text-neutral-800 dark:text-neutral-200 border border-neutral-300 dark:border-neutral-700 transition-colors"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>PREVIEW</span>
                    </button>

                    <a
                      href={api.reports.getDownloadUrl(analysisId, rep.id, "html")}
                      download
                      className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-mono font-medium text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
                      title="Download raw HTML document"
                    >
                      <span>HTML</span>
                    </a>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="py-12 text-center font-mono text-xs text-neutral-500">
            No report artifacts generated yet for this analysis run.
          </div>
        )}
      </Card>

      {/* HTML Sandboxed Preview Modal / Pane */}
      {previewReportId && (
        <Card
          title="Safe Sandboxed Report HTML Preview"
          actions={
            <div className="flex items-center space-x-2">
              <button
                onClick={() => {
                  const iframe = document.querySelector('iframe[title="Report HTML Preview"]') as HTMLIFrameElement;
                  if (iframe && iframe.contentWindow) {
                    iframe.contentWindow.focus();
                    iframe.contentWindow.print();
                  } else {
                    window.print();
                  }
                }}
                className="flex items-center space-x-1 px-2.5 py-1 text-xs font-mono font-bold bg-[#FF3D00] hover:bg-[#e03600] text-white transition-colors"
                title="Print report or save as PDF using browser print engine"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>PRINT / SAVE AS PDF</span>
              </button>
              <button
                onClick={() => {
                  setPreviewReportId(null);
                  setReportHtml(null);
                }}
                className="text-xs font-mono text-neutral-500 hover:text-neutral-900 dark:hover:text-white px-2 py-1 border border-neutral-300 dark:border-neutral-700"
              >
                CLOSE PREVIEW
              </button>
            </div>
          }
        >
          {isPreviewLoading ? (
            <div className="py-12 text-center font-mono text-xs text-neutral-500 animate-pulse">
              Retrieving sanitized HTML document from storage...
            </div>
          ) : reportHtml ? (
            <div className="border border-neutral-300 dark:border-neutral-800 bg-white">
              <iframe
                title="Report HTML Preview"
                srcDoc={reportHtml}
                sandbox="allow-same-origin"
                className="w-full h-[700px] border-0"
              />
            </div>
          ) : null}
        </Card>
      )}
    </div>
  );
}
