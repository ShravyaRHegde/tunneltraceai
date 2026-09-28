"use client";

import React, { use, useState } from "react";
import Link from "next/link";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { CopyableValue } from "@/components/ui/table";
import { ScoreDisplay } from "@/components/ui/score-display";
import {
  FileText,
  Download,
  Eye,
  RefreshCw,
  Printer,
  Shield,
  FileCode,
  FileSearch,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileSpreadsheet,
  ArrowRight,
  ExternalLink,
  Layers,
  X,
  History,
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
  const [generatingType, setGeneratingType] = useState<"EXECUTIVE" | "TECHNICAL" | null>(null);

  // Context queries
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
    refetch,
  } = useQuery({
    queryKey: ["reports-list", analysisId],
    queryFn: () => api.reports.list(analysisId),
  });

  // Generate Report Mutation
  const generateMutation = useMutation({
    mutationFn: (reportType: "EXECUTIVE" | "TECHNICAL") => {
      setGeneratingType(reportType);
      return api.reports.generate(analysisId, reportType);
    },
    onSuccess: (newReport) => {
      setGeneratingType(null);
      queryClient.invalidateQueries({ queryKey: ["reports-list", analysisId] });
      if (newReport?.id) {
        handlePreviewHtml(newReport.id);
      }
    },
    onError: () => {
      setGeneratingType(null);
    },
  });

  const handlePreviewHtml = async (reportId: string) => {
    setPreviewReportId(reportId);
    setIsPreviewLoading(true);
    try {
      const html = await api.reports.getHtml(analysisId, reportId);
      setReportHtml(html);
    } catch {
      setReportHtml("<p style='color:red; padding: 20px; font-family: monospace;'>Failed to load HTML report preview.</p>");
    } finally {
      setIsPreviewLoading(false);
    }
  };

  const reports = reportsData?.items || [];
  const latestExecutive = reports.find((r) => r.report_type === "EXECUTIVE");
  const latestTechnical = reports.find((r) => r.report_type === "TECHNICAL");

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <FileText className="w-5 h-5 text-[#FF3D00]" />
            <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
              Security & Forensics Reports
            </h1>
          </div>
          <p className="text-xs text-neutral-500 mt-1">
            <strong className="text-neutral-700 dark:text-neutral-300">What this shows:</strong> Publication-grade defense audit reports generated server-side. Includes executive summaries, cryptographic scorecards, and verifiable JSON/CSV exports.
          </p>
        </div>

        {/* Quick Context Links */}
        <div className="flex flex-wrap items-center gap-2">
          <Link
            href={`/analyses/${analysisId}/security`}
            className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-300"
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Findings</span>
          </Link>
          <Link
            href={`/analyses/${analysisId}/evidence`}
            className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-300"
          >
            <FileSearch className="w-3.5 h-3.5" />
            <span>Evidence DAG</span>
          </Link>
          <Link
            href={`/analyses/${analysisId}/ai-analyst`}
            className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-300"
          >
            <Layers className="w-3.5 h-3.5" />
            <span>AI Analyst</span>
          </Link>
        </div>
      </div>

      {/* Target Scope & Verification Ribbon */}
      <div className="p-3.5 bg-neutral-50 dark:bg-[#111113] border border-neutral-300 dark:border-neutral-800 flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <span className="text-[10px] text-neutral-400 uppercase block">Capture File</span>
            <span className="font-bold text-neutral-900 dark:text-white">
              {replayLineage?.capture_filename || analysisData?.capture_filename || analysisId.slice(0, 13)}
            </span>
          </div>
          <div className="h-6 w-px bg-neutral-300 dark:bg-neutral-800 hidden sm:block" />
          <div>
            <span className="text-[10px] text-neutral-400 uppercase block">Security Posture</span>
            <ScoreDisplay
              score={securityScore?.overall_score}
              coverage={
                typeof securityScore?.evidence_coverage === "object" && securityScore?.evidence_coverage !== null && "coverage_percentage" in securityScore.evidence_coverage
                  ? (securityScore.evidence_coverage as any).coverage_percentage
                  : typeof securityScore?.evidence_coverage === "number"
                  ? securityScore.evidence_coverage
                  : (securityScore as any)?.coverage_percentage
              }
              status={securityScore?.status}
              size="sm"
            />
          </div>
          <div className="h-6 w-px bg-neutral-300 dark:bg-neutral-800 hidden sm:block" />
          <div>
            <span className="text-[10px] text-neutral-400 uppercase block">Evidence Integrity</span>
            {replayLineage?.capture_integrity_verified ? (
              <span className="text-emerald-600 dark:text-emerald-400 font-bold flex items-center space-x-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>SHA-256 VERIFIED</span>
              </span>
            ) : (
              <span className="text-neutral-500 font-bold">PRESERVED SNAPSHOT</span>
            )}
          </div>
        </div>

        <div className="text-[10px] text-neutral-400">
          Standards: NIST SP 800-77 Rev. 1 &bull; RFC 8247 &bull; RFC 8221
        </div>
      </div>

      {/* Primary Report Generation Hub: 3 Clean Focused Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Card 1: Executive Security Summary */}
        <div className="p-5 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <FileText className="w-4 h-4 text-[#FF3D00]" />
                <h3 className="font-mono font-bold text-sm text-neutral-900 dark:text-white uppercase">
                  Executive Summary
                </h3>
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-400">
                LEADERSHIP / CISO
              </span>
            </div>
            <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
              Strategic briefing with observed posture score, evidence coverage, compliance status against NIST/RFC standards, and prioritized remediation actions.
            </p>
          </div>

          <div className="space-y-2 pt-2 border-t border-neutral-100 dark:border-neutral-800">
            <button
              disabled={generateMutation.isPending}
              onClick={() => generateMutation.mutate("EXECUTIVE")}
              className="w-full flex items-center justify-center space-x-2 py-2 px-3 bg-[#FF3D00] hover:bg-[#e03600] disabled:bg-neutral-300 dark:disabled:bg-neutral-800 text-white text-xs font-mono font-bold uppercase transition-colors shadow-xs"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>
                {generatingType === "EXECUTIVE" ? "COMPILING EXECUTIVE PDF..." : "GENERATE EXECUTIVE PDF"}
              </span>
            </button>

            {latestExecutive && (
              <div className="flex items-center justify-between text-[11px] font-mono text-neutral-500 pt-1">
                <span className="truncate">Latest: {new Date(latestExecutive.created_at).toLocaleTimeString()}</span>
                <a
                  href={api.reports.getDownloadUrl(analysisId, latestExecutive.id, "pdf")}
                  download={`TunnelTrace_Executive_${analysisId.slice(0, 8)}.pdf`}
                  className="text-[#FF3D00] hover:underline font-bold"
                >
                  Download PDF &rarr;
                </a>
              </div>
            )}
          </div>
        </div>

        {/* Card 2: Technical Forensics & Audit Report */}
        <div className="p-5 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <FileCode className="w-4 h-4 text-neutral-700 dark:text-neutral-300" />
                <h3 className="font-mono font-bold text-sm text-neutral-900 dark:text-white uppercase">
                  Technical Forensics
                </h3>
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-400">
                SOC / AUDITOR
              </span>
            </div>
            <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
              Full forensic disclosure: packet dissections, cryptographic transform tables, SPI pairs, ML flow feature attributions, and evidence provenance hashes.
            </p>
          </div>

          <div className="space-y-2 pt-2 border-t border-neutral-100 dark:border-neutral-800">
            <button
              disabled={generateMutation.isPending}
              onClick={() => generateMutation.mutate("TECHNICAL")}
              className="w-full flex items-center justify-center space-x-2 py-2 px-3 bg-neutral-900 hover:bg-black dark:bg-white dark:hover:bg-neutral-200 dark:text-neutral-900 disabled:bg-neutral-300 text-white text-xs font-mono font-bold uppercase transition-colors shadow-xs"
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>
                {generatingType === "TECHNICAL" ? "COMPILING TECHNICAL PDF..." : "GENERATE TECHNICAL PDF"}
              </span>
            </button>

            {latestTechnical && (
              <div className="flex items-center justify-between text-[11px] font-mono text-neutral-500 pt-1">
                <span className="truncate">Latest: {new Date(latestTechnical.created_at).toLocaleTimeString()}</span>
                <a
                  href={api.reports.getDownloadUrl(analysisId, latestTechnical.id, "pdf")}
                  download={`TunnelTrace_Technical_${analysisId.slice(0, 8)}.pdf`}
                  className="text-neutral-800 dark:text-neutral-200 hover:underline font-bold"
                >
                  Download PDF &rarr;
                </a>
              </div>
            )}
          </div>
        </div>

        {/* Card 3: Machine-Readable Data Exports */}
        <div className="p-5 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Download className="w-4 h-4 text-emerald-600" />
                <h3 className="font-mono font-bold text-sm text-neutral-900 dark:text-white uppercase">
                  Data Exports
                </h3>
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-400">
                SIEM / JSON / CSV
              </span>
            </div>
            <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
              Direct exports for SIEM ingestion, compliance records, and automated security ticketing workflows.
            </p>
          </div>

          <div className="space-y-2 pt-2 border-t border-neutral-100 dark:border-neutral-800">
            <a
              href={api.analyses.getExportManifestUrl(analysisId)}
              download={`tunneltrace_manifest_${analysisId.slice(0, 8)}.json`}
              className="w-full flex items-center justify-between py-2 px-3 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-800 dark:text-neutral-200 text-xs font-mono font-bold uppercase transition-colors"
            >
              <div className="flex items-center space-x-2">
                <FileCode className="w-3.5 h-3.5 text-[#FF3D00]" />
                <span>JSON MANIFEST</span>
              </div>
              <Download className="w-3.5 h-3.5" />
            </a>

            <a
              href={api.analyses.getExportFindingsCsvUrl(analysisId)}
              download={`tunneltrace_findings_${analysisId.slice(0, 8)}.csv`}
              className="w-full flex items-center justify-between py-2 px-3 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-800 dark:text-neutral-200 text-xs font-mono font-bold uppercase transition-colors"
            >
              <div className="flex items-center space-x-2">
                <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />
                <span>CSV FINDINGS</span>
              </div>
              <Download className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </div>

      {/* Generated Report Artifacts History */}
      <Card
        title={`Report History (${reports.length})`}
        actions={
          <button
            onClick={() => refetch()}
            className="p-1 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-500 rounded"
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
        ) : reports.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-neutral-200 dark:border-neutral-800 text-neutral-500 uppercase text-[10px]">
                  <th className="py-2.5 px-3">Report Type</th>
                  <th className="py-2.5 px-3">Generated</th>
                  <th className="py-2.5 px-3">Duration</th>
                  <th className="py-2.5 px-3">SHA-256 Digest</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800">
                {reports.map((rep) => (
                  <tr key={rep.id} className="hover:bg-neutral-50 dark:hover:bg-neutral-900/50 transition-colors">
                    <td className="py-3 px-3">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-neutral-900 dark:text-white uppercase">
                          {rep.report_type}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800">
                          READY
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-3 text-neutral-500 whitespace-nowrap">
                      {new Date(rep.created_at).toLocaleDateString()} {new Date(rep.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </td>
                    <td className="py-3 px-3 text-neutral-500 whitespace-nowrap">
                      {rep.generation_duration_ms ? `${rep.generation_duration_ms}ms` : "-"}
                    </td>
                    <td className="py-3 px-3 text-neutral-500">
                      {rep.pdf_sha256 ? (
                        <CopyableValue value={rep.pdf_sha256} truncate label="PDF Digest" />
                      ) : rep.html_sha256 ? (
                        <CopyableValue value={rep.html_sha256} truncate label="HTML Digest" />
                      ) : (
                        "-"
                      )}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <div className="flex items-center justify-end space-x-2">
                        <a
                          href={api.reports.getDownloadUrl(analysisId, rep.id, "pdf")}
                          download={`TunnelTrace_Report_${rep.report_type.toLowerCase()}_${rep.id.slice(0, 8)}.pdf`}
                          className="flex items-center space-x-1 px-2.5 py-1 text-xs font-bold bg-[#FF3D00] hover:bg-[#e03600] text-white rounded-xs transition-colors"
                          title="Download native PDF file"
                        >
                          <Download className="w-3 h-3" />
                          <span>PDF</span>
                        </a>

                        <button
                          onClick={() => {
                            const url = api.reports.getDownloadUrl(analysisId, rep.id, "html");
                            const win = window.open(url, "_blank");
                            if (win) {
                              win.onload = () => { win.print(); };
                            }
                          }}
                          className="flex items-center space-x-1 px-2 py-1 text-xs border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-800 dark:text-neutral-200 transition-colors"
                          title="Open printable HTML template"
                        >
                          <Printer className="w-3 h-3" />
                          <span>PRINT</span>
                        </button>

                        <button
                          onClick={() => handlePreviewHtml(rep.id)}
                          className="flex items-center space-x-1 px-2 py-1 text-xs border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-800 dark:text-neutral-200 transition-colors"
                          title="Preview HTML in browser"
                        >
                          <Eye className="w-3 h-3" />
                          <span>PREVIEW</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 text-center font-mono text-xs text-neutral-500">
            No report artifacts generated yet. Click &quot;GENERATE EXECUTIVE PDF&quot; or &quot;GENERATE TECHNICAL PDF&quot; above to create a sealed report.
          </div>
        )}
      </Card>

      {/* HTML Sandboxed Preview Modal */}
      {previewReportId && (
        <Card
          title="Sandboxed Report Preview"
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
                className="flex items-center space-x-1 text-xs font-mono text-neutral-500 hover:text-neutral-900 dark:hover:text-white px-2 py-1 border border-neutral-300 dark:border-neutral-700"
              >
                <X className="w-3.5 h-3.5" />
                <span>CLOSE</span>
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
