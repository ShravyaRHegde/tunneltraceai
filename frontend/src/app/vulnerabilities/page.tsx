"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  VulnerabilityReportPreviewResponseDTO,
  VulnerabilityFindingDTO,
} from "@/lib/api/types";
import { Card } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  UploadCloud,
  CheckCircle2,
  XCircle,
  Eye,
  Server,
  Layers,
  Search,
} from "lucide-react";

export default function VulnerabilityReportsPage() {
  const queryClient = useQueryClient();

  // Tab State
  const [activeTab, setActiveTab] = useState<"import" | "reports" | "findings">("import");

  // Form State for Import
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [operatorId, setOperatorId] = useState("operator-admin");
  const [authRef, setAuthRef] = useState("CHG-2026-VULN-01");
  const [engagementScope, setEngagementScope] = useState("198.51.100.0/24, 10.0.0.0/16");
  const [authAttestation, setAuthAttestation] = useState(
    "I attest that this Greenbone/OpenVAS vulnerability report is authorized for import into TunnelTrace AI as supplemental evidence."
  );
  const [hasConfirmedAttestation, setHasConfirmedAttestation] = useState(false);
  const [authorizedTargetsText, setAuthorizedTargetsText] = useState("198.51.100.0/24");
  const [formError, setFormError] = useState<string | null>(null);
  const [previewData, setPreviewData] = useState<VulnerabilityReportPreviewResponseDTO | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFindingDTO | null>(null);
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);

  // Queries
  const { data: reportsData, isLoading: isReportsLoading } = useQuery({
    queryKey: ["vulnerability-reports"],
    queryFn: () => api.vulnerabilities.listReports(0, 50),
  });

  const { data: findingsData, isLoading: isFindingsLoading } = useQuery({
    queryKey: ["vulnerability-findings", selectedReportId],
    queryFn: () => api.vulnerabilities.listFindings(selectedReportId || undefined, { limit: 100 }),
  });

  // Mutations
  const previewMutation = useMutation({
    mutationFn: async () => {
      if (!selectedFile) throw new Error("Please select an XML report file.");
      return api.vulnerabilities.previewReport(selectedFile, authorizedTargetsText);
    },
    onSuccess: (data) => {
      setPreviewData(data);
      setFormError(null);
    },
    onError: (err: Error) => {
      setFormError(err.message || "Failed to preview report.");
      setPreviewData(null);
    },
  });

  const importMutation = useMutation({
    mutationFn: async () => {
      if (!selectedFile) throw new Error("Please select an XML report file.");
      if (!hasConfirmedAttestation) {
        throw new Error("Operator attestation confirmation is required.");
      }
      return api.vulnerabilities.importReport(selectedFile, {
        operator_id: operatorId,
        authorization_reference: authRef,
        operator_attestation: authAttestation,
        engagement_scope: engagementScope,
        authorized_targets: authorizedTargetsText,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vulnerability-reports"] });
      queryClient.invalidateQueries({ queryKey: ["vulnerability-findings"] });
      setSelectedFile(null);
      setPreviewData(null);
      setActiveTab("reports");
    },
    onError: (err: Error) => {
      setFormError(err.message || "Failed to import report.");
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
      setPreviewData(null);
      setFormError(null);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 text-neutral-900 dark:text-neutral-100">
      {/* Top Header & Context Badges */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-neutral-300 dark:border-neutral-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-[#FF3D00]" />
              <span>External Vulnerability Assessment</span>
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 uppercase">
              Greenbone / OpenVAS XML
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 border border-emerald-300 dark:border-emerald-700/60 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 uppercase">
              Supplemental Evidence
            </span>
          </div>
          <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-1 max-w-2xl leading-relaxed">
            <strong className="text-neutral-700 dark:text-neutral-300">Purpose & Data Boundary:</strong> Ingests external Greenbone / OpenVAS XML vulnerability reports as supplemental observational context. Correlates CVEs with observed VPN gateways without altering deterministic packet-derived policy scores.
          </p>
        </div>

        {/* Cross-Flow Navigation */}
        <div className="flex items-center gap-2">
          <Link
            href="/discovery"
            className="flex items-center gap-2 px-3 py-1.5 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-xs font-mono text-neutral-700 dark:text-neutral-300 transition-colors uppercase"
          >
            <Server className="h-3.5 w-3.5 text-emerald-600" />
            <span>Nmap Discovery</span>
          </Link>
        </div>
      </div>

      {/* Epistemic Boundary Notice */}
      <div className="p-4 bg-amber-50 dark:bg-amber-950/20 border border-amber-300 dark:border-amber-800 text-xs font-mono text-amber-900 dark:text-amber-200 space-y-1.5">
        <div className="flex items-center space-x-2 font-bold text-amber-800 dark:text-amber-300 uppercase">
          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
          <span>Epistemic Boundary: Scanner Assertions Are Supplemental Evidence, Not Ground Truth</span>
        </div>
        <p className="leading-relaxed text-amber-800/90 dark:text-amber-300/90 text-[11px]">
          Greenbone/OpenVAS results represent scanner-reported claims (typically based on unauthenticated banners or remote heuristics).
          TunnelTrace strictly preserves uncertainty: unauthenticated banner detections are marked{" "}
          <strong className="text-amber-700 dark:text-amber-300">POTENTIAL</strong> or <strong className="text-neutral-700 dark:text-neutral-300">UNKNOWN</strong>.
          They are never upgraded to confirmed vulnerabilities, and never silently deduct from your deterministic Security Score.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-neutral-300 dark:border-neutral-800">
        <button
          onClick={() => setActiveTab("import")}
          className={`px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider border-b-2 transition-colors ${
            activeTab === "import"
              ? "border-[#FF3D00] text-neutral-900 dark:text-white bg-white dark:bg-[#141416]"
              : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
          }`}
        >
          Import & Preview
        </button>
        <button
          onClick={() => setActiveTab("reports")}
          className={`px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider border-b-2 transition-colors ${
            activeTab === "reports"
              ? "border-[#FF3D00] text-neutral-900 dark:text-white bg-white dark:bg-[#141416]"
              : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
          }`}
        >
          Imported Reports ({reportsData?.total || 0})
        </button>
        <button
          onClick={() => setActiveTab("findings")}
          className={`px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider border-b-2 transition-colors ${
            activeTab === "findings"
              ? "border-[#FF3D00] text-neutral-900 dark:text-white bg-white dark:bg-[#141416]"
              : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
          }`}
        >
          Findings Explorer
        </button>
      </div>

      {/* TAB 1: IMPORT & PREVIEW */}
      {activeTab === "import" && (
        <div className="space-y-6">
          {/* 4-Step Ingestion & Correlation Sequence */}
          <div className="p-4 bg-neutral-50/80 dark:bg-[#141416] border border-neutral-200 dark:border-neutral-800">
            <div className="text-[11px] font-mono font-bold uppercase text-neutral-500 mb-2">
              Vulnerability Ingestion & Correlation Sequence:
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-2.5 bg-white dark:bg-[#19191c] border border-neutral-200 dark:border-neutral-800 rounded">
                <span className="font-bold text-[#FF3D00] mr-1.5">1.</span>
                <span className="font-bold text-neutral-800 dark:text-neutral-200">Load XML File:</span>
                <div className="text-[10px] text-neutral-500 mt-1">Select an exported Greenbone/OpenVAS XML file or sample report.</div>
              </div>
              <div className="p-2.5 bg-white dark:bg-[#19191c] border border-neutral-200 dark:border-neutral-800 rounded">
                <span className="font-bold text-[#FF3D00] mr-1.5">2.</span>
                <span className="font-bold text-neutral-800 dark:text-neutral-200">Preview & Attest:</span>
                <div className="text-[10px] text-neutral-500 mt-1">Generate deterministic preview, parse target hosts, and confirm operator authorization.</div>
              </div>
              <div className="p-2.5 bg-white dark:bg-[#19191c] border border-neutral-200 dark:border-neutral-800 rounded">
                <span className="font-bold text-[#FF3D00] mr-1.5">3.</span>
                <span className="font-bold text-neutral-800 dark:text-neutral-200">Ingest to DB:</span>
                <div className="text-[10px] text-neutral-500 mt-1">Persist findings to local operational database with parsed CVEs and QoD ratings.</div>
              </div>
              <div className="p-2.5 bg-white dark:bg-[#19191c] border border-neutral-200 dark:border-neutral-800 rounded">
                <span className="font-bold text-[#FF3D00] mr-1.5">4.</span>
                <span className="font-bold text-neutral-800 dark:text-neutral-200">Correlate Context:</span>
                <div className="text-[10px] text-neutral-500 mt-1">View correlated findings alongside packet evidence without modifying policy scores.</div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Upload & Attestation Form */}
          <div className="lg:col-span-6 space-y-4">
            <Card title="Upload Greenbone XML Report">
              <div className="space-y-4">
                {formError && (
                  <div className="p-3 bg-rose-50 dark:bg-rose-950/20 border border-rose-300 dark:border-rose-800 text-rose-700 dark:text-rose-400 text-xs flex items-center gap-2 font-mono">
                    <XCircle className="h-4 w-4 shrink-0" />
                    <span>{formError}</span>
                  </div>
                )}

                {/* File Select */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label htmlFor="openvas-xml-file" className="text-xs font-mono font-bold uppercase text-neutral-700 dark:text-neutral-300">
                      Report Artifact (.xml)
                    </label>
                    <button
                      type="button"
                      onClick={() => {
                        const sampleXml = `<?xml version="1.0" encoding="UTF-8"?>
<report id="d1a8c880-9943-41dc-b114-1e03c27e4e11" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" type="scan" version="2.0">
  <task id="t-9921-prod-ike">
    <name>Weekly IPsec Gateway Vulnerability Audit</name>
  </task>
  <scan_run_status>done</scan_run_status>
  <scan_start>2026-09-24T18:00:00Z</scan_start>
  <scan_end>2026-09-24T18:15:30Z</scan_end>
  <ports max="1000" start="1"/>
  <results>
    <result id="res-001">
      <name>strongSwan IKE Daemon Buffer Overflow</name>
      <host>198.51.100.1<asset asset_id="ast-01"/></host>
      <port>500/udp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.108001">
        <name>strongSwan IKE Daemon Buffer Overflow</name>
        <family>Buffer overflow</family>
        <cvss_base>7.5</cvss_base>
        <cve>CVE-2023-41913</cve>
        <cpe>cpe:/a:strongswan:strongswan:5.9.8</cpe>
        <solution type="VendorFix">Upgrade strongSwan to 5.9.11 or later.</solution>
        <qod>
          <value>80</value>
          <type>remote_banner</type>
        </qod>
      </nvt>
      <threat>High</threat>
      <severity>7.5</severity>
      <description>The remote strongSwan IKE daemon is vulnerable to denial of service.</description>
    </result>
    <result id="res-002">
      <name>IKE Weak Transform Proposal Accepted</name>
      <host>198.51.100.1</host>
      <port>4500/udp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.108002">
        <name>IKE Weak Transform Proposal Accepted</name>
        <family>General</family>
        <cvss_base>4.3</cvss_base>
        <cve>CVE-2021-39900</cve>
        <solution type="Workaround">Disable 3DES cipher suites in ipsec.conf.</solution>
        <qod>
          <value>70</value>
          <type>remote_probe</type>
        </qod>
      </nvt>
      <threat>Medium</threat>
      <severity>4.3</severity>
      <description>The remote gateway accepts legacy 3DES encryption transforms.</description>
    </result>
  </results>
</report>`;
                        const blob = new Blob([sampleXml], { type: "text/xml" });
                        const file = new File([blob], "sample_greenbone_audit.xml", { type: "text/xml" });
                        setSelectedFile(file);
                        setHasConfirmedAttestation(true);
                      }}
                      className="text-[10px] font-mono text-[#FF3D00] hover:underline cursor-pointer"
                    >
                      Load Sample OpenVAS XML
                    </button>
                  </div>
                  <input
                    id="openvas-xml-file"
                    name="openvas-xml-file"
                    aria-label="Upload OpenVAS or Greenbone XML Report"
                    type="file"
                    accept=".xml"
                    onChange={handleFileChange}
                    className="block w-full text-xs text-neutral-500 file:mr-4 file:py-1.5 file:px-3 file:border file:border-neutral-300 dark:file:border-neutral-700 file:text-xs file:font-mono file:bg-neutral-100 dark:file:bg-neutral-800 file:text-neutral-800 dark:file:text-neutral-200 cursor-pointer bg-white dark:bg-[#111113] border border-neutral-300 dark:border-neutral-700 p-2 font-mono"
                  />
                  {selectedFile && (
                    <div className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400">
                      Selected: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
                    </div>
                  )}
                  <p className="text-[11px] text-neutral-500 font-mono">
                    Accepts Greenbone/OpenVAS XML report export or GMP &lt;get_reports_response&gt; envelope.
                  </p>
                </div>

                {/* Operator Attestation */}
                <div className="p-4 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-3 font-mono">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-emerald-600" />
                    <span className="text-xs font-bold uppercase tracking-wider text-neutral-900 dark:text-white">
                      Operator Authorization Attestation
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label htmlFor="vuln-operator-id" className="text-[11px] font-medium text-neutral-500">Operator ID</label>
                      <input
                        id="vuln-operator-id"
                        name="vuln-operator-id"
                        type="text"
                        value={operatorId}
                        onChange={(e) => setOperatorId(e.target.value)}
                        className="w-full bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-700 px-2.5 py-1.5 text-xs text-neutral-900 dark:text-white"
                      />
                    </div>
                    <div className="space-y-1">
                      <label htmlFor="vuln-auth-ref" className="text-[11px] font-medium text-neutral-500">Auth Reference</label>
                      <input
                        id="vuln-auth-ref"
                        name="vuln-auth-ref"
                        type="text"
                        value={authRef}
                        onChange={(e) => setAuthRef(e.target.value)}
                        className="w-full bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-700 px-2.5 py-1.5 text-xs text-neutral-900 dark:text-white"
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label htmlFor="vuln-auth-targets" className="text-[11px] font-medium text-neutral-500">Authorized Targets / Boundary</label>
                    <input
                      id="vuln-auth-targets"
                      name="vuln-auth-targets"
                      type="text"
                      value={authorizedTargetsText}
                      onChange={(e) => setAuthorizedTargetsText(e.target.value)}
                      placeholder="198.51.100.0/24, 10.0.0.1"
                      className="w-full bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-700 px-2.5 py-1.5 text-xs text-neutral-900 dark:text-white"
                    />
                    <p className="text-[10px] text-neutral-400">
                      Candidate mapping checks report host IPs against this boundary.
                    </p>
                  </div>

                  <div className="space-y-1">
                    <label htmlFor="vuln-engagement-scope" className="text-[11px] font-medium text-neutral-500">Engagement Scope Title</label>
                    <input
                      id="vuln-engagement-scope"
                      name="vuln-engagement-scope"
                      type="text"
                      value={engagementScope}
                      onChange={(e) => setEngagementScope(e.target.value)}
                      className="w-full bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-700 px-2.5 py-1.5 text-xs text-neutral-900 dark:text-white"
                    />
                  </div>

                  <div className="space-y-1">
                    <label htmlFor="vuln-auth-attestation" className="text-[11px] font-medium text-neutral-500">Written Attestation</label>
                    <textarea
                      id="vuln-auth-attestation"
                      name="vuln-auth-attestation"
                      aria-label="Written Authorization Attestation Statement"
                      rows={2}
                      value={authAttestation}
                      onChange={(e) => setAuthAttestation(e.target.value)}
                      className="w-full bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-700 px-2.5 py-1.5 text-xs text-neutral-900 dark:text-white"
                    />
                  </div>

                  <label htmlFor="vuln-attestation-confirmed" className="flex items-center gap-2 cursor-pointer pt-1">
                    <input
                      id="vuln-attestation-confirmed"
                      name="vuln-attestation-confirmed"
                      type="checkbox"
                      checked={hasConfirmedAttestation}
                      onChange={(e) => setHasConfirmedAttestation(e.target.checked)}
                      className="rounded border-neutral-300 dark:border-neutral-700"
                    />
                    <span className="text-xs text-neutral-700 dark:text-neutral-300">
                      I confirm written authorization exists for importing this assessment evidence.
                    </span>
                  </label>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => previewMutation.mutate()}
                    disabled={!selectedFile || previewMutation.isPending}
                    className="flex-1 px-4 py-2 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 disabled:opacity-50 text-neutral-800 dark:text-neutral-200 text-xs font-mono font-bold flex items-center justify-center gap-2 transition-colors uppercase"
                  >
                    <Eye className="h-3.5 w-3.5 text-neutral-500" />
                    <span>{previewMutation.isPending ? "Parsing XML..." : "Preflight Preview"}</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => importMutation.mutate()}
                    disabled={!selectedFile || !hasConfirmedAttestation || importMutation.isPending}
                    className="flex-1 px-4 py-2 bg-[#FF3D00] hover:bg-[#e03600] disabled:opacity-50 text-white text-xs font-mono font-bold flex items-center justify-center gap-2 transition-colors uppercase"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    <span>{importMutation.isPending ? "Importing..." : "Confirm & Import"}</span>
                  </button>
                </div>
              </div>
            </Card>
          </div>

          {/* Preflight Preview Output */}
          <div className="lg:col-span-6 space-y-4">
            {previewData ? (
              <Card title={`Preflight Preview: ${previewData.task_name || previewData.report_id}`}>
                <div className="space-y-4 font-mono">
                  <div className="text-[11px] text-neutral-500">
                    SHA-256: {previewData.raw_sha256.substring(0, 16)}...
                  </div>

                  {/* Metrics Grid */}
                  <div className="grid grid-cols-4 gap-2 text-center text-xs">
                    <div className="border border-neutral-200 dark:border-neutral-800 p-2 bg-neutral-50 dark:bg-neutral-900">
                      <div className="text-[10px] text-neutral-400 uppercase">Findings</div>
                      <div className="font-bold text-neutral-900 dark:text-white mt-0.5">
                        {previewData.total_findings_count}
                      </div>
                    </div>
                    <div className="border border-neutral-200 dark:border-neutral-800 p-2 bg-neutral-50 dark:bg-neutral-900">
                      <div className="text-[10px] text-neutral-400 uppercase">Hosts</div>
                      <div className="font-bold text-neutral-900 dark:text-white mt-0.5">
                        {previewData.unique_hosts_count}
                      </div>
                    </div>
                    <div className="border border-neutral-200 dark:border-neutral-800 p-2 bg-neutral-50 dark:bg-neutral-900">
                      <div className="text-[10px] text-neutral-400 uppercase">Exact Match</div>
                      <div className="font-bold text-emerald-600 mt-0.5">
                        {previewData.host_mapping_summary.mapped_exact_ip}
                      </div>
                    </div>
                    <div className="border border-neutral-200 dark:border-neutral-800 p-2 bg-neutral-50 dark:bg-neutral-900">
                      <div className="text-[10px] text-neutral-400 uppercase">Feed State</div>
                      <div className="font-semibold text-neutral-700 dark:text-neutral-300 mt-0.5 truncate">
                        {previewData.feed_status}
                      </div>
                    </div>
                  </div>

                  {/* Asset Mapping Breakdown */}
                  <div className="space-y-1.5">
                    <div className="text-xs font-bold uppercase text-neutral-700 dark:text-neutral-300 flex items-center gap-1.5">
                      <Layers className="h-3.5 w-3.5 text-[#FF3D00]" />
                      <span>Host Mapping Verification</span>
                    </div>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {previewData.host_mapping_details.map((h, idx) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between p-2 border border-neutral-200 dark:border-neutral-800 text-xs bg-white dark:bg-[#141416]"
                        >
                          <span className="font-bold">{h.host_ip}</span>
                          <span
                            className={`px-2 py-0.5 text-[10px] font-semibold border ${
                              h.asset_link_state === "MAPPED_EXACT_IP"
                                ? "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-300"
                                : h.asset_link_state === "OUT_OF_SCOPE"
                                ? "bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400 border-rose-300"
                                : "bg-neutral-100 dark:bg-neutral-800 text-neutral-600 border-neutral-300"
                            }`}
                          >
                            {h.asset_link_state}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </Card>
            ) : (
              <div className="p-12 border border-dashed border-neutral-300 dark:border-neutral-800 text-center flex flex-col items-center justify-center space-y-2 font-mono">
                <FileText className="h-8 w-8 text-neutral-400" />
                <h3 className="text-xs font-bold text-neutral-600 dark:text-neutral-400 uppercase">
                  No Preflight Preview Active
                </h3>
                <p className="text-[11px] text-neutral-500 max-w-sm">
                  Select a Greenbone XML report file and click Preflight Preview to inspect metadata and target coordinates before ingestion.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
      )}

      {/* TAB 2: REPORTS LIST */}
      {activeTab === "reports" && (
        <Card title="Imported Greenbone Report Artifacts">
          <div className="space-y-3 font-mono">
            {isReportsLoading ? (
              <div className="p-8 text-center text-xs text-neutral-500">Loading reports...</div>
            ) : reportsData?.reports && reportsData.reports.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Task Name / ID</TableHead>
                    <TableHead>Scope & Attestation</TableHead>
                    <TableHead>Scan Window</TableHead>
                    <TableHead>Findings / Hosts</TableHead>
                    <TableHead>Artifact SHA-256</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reportsData.reports.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell>
                        <div className="font-semibold text-xs text-neutral-900 dark:text-white">
                          {r.task_name || r.report_source_id}
                        </div>
                        <div className="text-[10px] text-neutral-400">
                          {r.report_source_id}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-xs truncate max-w-[180px]">
                          {r.engagement_scope}
                        </div>
                        <div className="text-[10px] text-neutral-400">
                          Op: {r.operator_id}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-xs">
                          {r.scan_started_at ? new Date(r.scan_started_at).toLocaleDateString() : "Unknown"}
                        </div>
                        <div className="text-[10px] text-neutral-400">
                          Feed: {r.feed_status}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="font-bold text-[#FF3D00]">
                          {r.results_count} findings
                        </span>
                        <span className="text-neutral-400"> on {r.hosts_count} hosts</span>
                      </TableCell>
                      <TableCell>
                        <CopyableValue value={r.raw_artifact_sha256} truncate />
                      </TableCell>
                      <TableCell>
                        <span className="text-[10px] px-1.5 py-0.5 border border-neutral-300 dark:border-neutral-700 uppercase">
                          {r.status}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">
                        <button
                          onClick={() => {
                            setSelectedReportId(r.id);
                            setActiveTab("findings");
                          }}
                          className="px-2.5 py-1 text-xs font-bold text-[#FF3D00] hover:underline uppercase"
                        >
                          View Findings
                        </button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="p-8 text-center text-xs text-neutral-500">
                No Greenbone reports imported yet. Go to the Import & Preview tab to upload an XML report.
              </div>
            )}
          </div>
        </Card>
      )}

      {/* TAB 3: FINDINGS EXPLORER */}
      {activeTab === "findings" && (
        <Card title="Vulnerability Findings Explorer">
          <div className="space-y-4 font-mono">
            <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-2">
              <span className="text-xs text-neutral-500">
                {selectedReportId
                  ? `Filtering findings for report ID: ${selectedReportId}`
                  : "Displaying findings across all imported reports."}
              </span>
              {selectedReportId && (
                <button
                  onClick={() => setSelectedReportId(null)}
                  className="text-xs text-[#FF3D00] hover:underline"
                >
                  Clear Filter (Show All)
                </button>
              )}
            </div>

            {isFindingsLoading ? (
              <div className="p-8 text-center text-xs text-neutral-500">Loading findings...</div>
            ) : findingsData?.findings && findingsData.findings.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Host & Port</TableHead>
                    <TableHead>Vulnerability (NVT)</TableHead>
                    <TableHead>Severity / QoD</TableHead>
                    <TableHead>CVEs</TableHead>
                    <TableHead>Asset Link</TableHead>
                    <TableHead>Correlation</TableHead>
                    <TableHead className="text-right">Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findingsData.findings.map((f) => (
                    <TableRow
                      key={f.id}
                      className="cursor-pointer hover:bg-neutral-50 dark:hover:bg-neutral-900/60"
                      onClick={() => setSelectedFinding(f)}
                    >
                      <TableCell>
                        <div className="font-bold text-xs">{f.host_ip}</div>
                        <div className="text-[10px] text-neutral-400">
                          {f.port ? `${f.port}/${f.protocol || "any"}` : "General"}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="font-medium text-xs truncate max-w-[260px]">
                          {f.nvt_name}
                        </div>
                        <div className="text-[10px] text-neutral-400">
                          OID: {f.nvt_oid}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className={`text-[10px] px-1.5 py-0.5 border font-bold uppercase ${
                          f.source_severity === "Critical" || f.source_severity === "High"
                            ? "text-rose-600 border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/40"
                            : "text-amber-600 border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40"
                        }`}>
                          {f.source_severity}
                        </span>
                        {f.qod_value && (
                          <span className="text-[10px] text-neutral-400 ml-1">
                            ({f.qod_value}%)
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1 max-w-[160px]">
                          {f.reported_cves && f.reported_cves.length > 0 ? (
                            f.reported_cves.slice(0, 2).map((cve, i) => (
                              <span
                                key={i}
                                className="text-[10px] px-1 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700"
                              >
                                {cve}
                              </span>
                            ))
                          ) : (
                            <span className="text-neutral-400">—</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="text-[10px] px-1.5 py-0.5 border border-neutral-300 dark:border-neutral-700 uppercase">
                          {f.asset_link_state}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-[10px] px-1.5 py-0.5 border border-amber-300 dark:border-amber-700 text-amber-700 dark:text-amber-400 uppercase font-semibold">
                          {f.correlation_status}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedFinding(f);
                          }}
                          className="px-2 py-1 text-xs text-[#FF3D00] hover:underline uppercase font-bold"
                        >
                          Inspect
                        </button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="p-8 text-center text-xs text-neutral-500">
                No findings found for the selected view.
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Finding Detail Inspector Drawer */}
      {selectedFinding && (
        <InspectorDrawer
          isOpen={!!selectedFinding}
          onClose={() => setSelectedFinding(null)}
          title="Vulnerability Finding Evidence"
        >
          <div className="p-6 space-y-5 font-mono text-xs text-neutral-800 dark:text-neutral-200">
            <div className="space-y-1">
              <span className="text-[10px] text-neutral-400 uppercase font-bold">
                Scanner Assertion
              </span>
              <h2 className="text-base font-bold text-neutral-900 dark:text-white">
                {selectedFinding.nvt_name}
              </h2>
              <div className="text-[11px] text-neutral-500">OID: {selectedFinding.nvt_oid}</div>
            </div>

            <div className="grid grid-cols-3 gap-2 p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-center">
              <div>
                <div className="text-[10px] text-neutral-400 uppercase">Severity</div>
                <div className="font-bold text-rose-600 mt-0.5">
                  {selectedFinding.source_severity}
                </div>
              </div>
              <div>
                <div className="text-[10px] text-neutral-400 uppercase">CVSS Base</div>
                <div className="font-bold text-neutral-900 dark:text-white mt-0.5">
                  {selectedFinding.cvss_base_score ?? "None"}
                </div>
              </div>
              <div>
                <div className="text-[10px] text-neutral-400 uppercase">QoD</div>
                <div className="font-bold text-amber-600 mt-0.5">
                  {selectedFinding.qod_value ? `${selectedFinding.qod_value}%` : "Unknown"}
                </div>
              </div>
            </div>

            <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-1.5">
              <div>
                <span className="text-neutral-500">Host IP:</span>{" "}
                <span className="font-bold">{selectedFinding.host_ip}</span>
              </div>
              <div>
                <span className="text-neutral-500">Port / Protocol:</span>{" "}
                <span>{selectedFinding.port ? `${selectedFinding.port}/${selectedFinding.protocol}` : "General Host"}</span>
              </div>
              <div>
                <span className="text-neutral-500">Asset Link State:</span>{" "}
                <span className="font-bold">{selectedFinding.asset_link_state}</span>
              </div>
              <div className="text-[10px] text-neutral-500 italic">
                {selectedFinding.asset_link_rationale}
              </div>
            </div>

            {selectedFinding.description && (
              <div className="space-y-1">
                <span className="font-bold text-neutral-700 dark:text-neutral-300 uppercase text-[10px]">
                  Description
                </span>
                <p className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-[11px] leading-relaxed">
                  {selectedFinding.description}
                </p>
              </div>
            )}

            {selectedFinding.solution && (
              <div className="space-y-1">
                <span className="font-bold text-neutral-700 dark:text-neutral-300 uppercase text-[10px]">
                  Scanner Solution Guidance
                </span>
                <p className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-[11px] leading-relaxed">
                  {selectedFinding.solution}
                </p>
              </div>
            )}
          </div>
        </InspectorDrawer>
      )}
    </div>
  );
}
