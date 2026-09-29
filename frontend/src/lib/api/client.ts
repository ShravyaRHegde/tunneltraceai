/**
 * Canonical typed API client for TunnelTrace AI.
 * Communicates with FastAPI backend exclusively; zero browser-calculated security logic.
 */

import {
  AnalysisListItemDTO,
  AnalysisOverviewDTO,
  AnalysisRunResponseDTO,
  CaptureResponseDTO,
  ChildSecurityAssociationDTO,
  ComplianceSummaryDTO,
  EvidenceGraphDTO,
  FingerprintabilityDTO,
  InterfaceMetadataDTO,
  PreflightResponseDTO,
  ProtocolSummaryDTO,
  RemediationRunResponseDTO,
  ReportListResponseDTO,
  ReportResponseDTO,
  RiskAssessmentDTO,
  SAGraphResponseDTO,
  SecurityFindingDTO,
  SecurityScoreDTO,
  ThreatInstanceDTO,
  ThreatIntelResponseDTO,
  TrafficSummaryResponseDTO,
  MLModelCardDTO,
  TwinResponseDTO,
  VerificationResponseDTO,
  AIChatQueryResponseDTO,
  AIChatSessionHistoryDTO,
  EvidenceSearchResponseDTO,
  AIHealthResponseDTO,
  ReplayExecutionResponseDTO,
  ReplayLineageDTO,
  SampleCaptureDTO,
  SystemReadinessDTO,
} from "./types";


export function getApiBaseUrl(): string {
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL.replace(/\/$/, "");
  }
  if (typeof window !== "undefined") {
    const host = window.location.hostname;
    if (host !== "localhost" && host !== "127.0.0.1") {
      return "https://tunneltraceai.onrender.com/api/v1";
    }
  }
  return "http://127.0.0.1:8002/api/v1";
}

export const API_BASE_URL = getApiBaseUrl();

export class ApiError extends Error {
  constructor(
    public status: number,
    public message: string,
    public detail?: any
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const base = getApiBaseUrl();
  const url = `${base}${path}`;
  const headers = new Headers(options.headers || {});

  if (!headers.has("Content-Type") && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(url, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let errorDetail: any = null;
    try {
      errorDetail = await res.json();
    } catch {
      errorDetail = await res.text();
    }
    const message =
      typeof errorDetail === "object" && errorDetail?.detail
        ? errorDetail.detail
        : `Request failed with status ${res.status}`;
    throw new ApiError(res.status, message, errorDetail);
  }

  // Handle empty bodies
  if (res.status === 204) {
    return {} as T;
  }

  const contentType = res.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    return res.json();
  }
  return res.text() as unknown as T;
}

export const api = {
  captures: {
    upload: async (file: File, forceRerun: boolean = false): Promise<CaptureResponseDTO> => {
      const formData = new FormData();
      formData.append("file", file);
      const url = forceRerun ? "/captures?force_rerun=true" : "/captures";
      return request<CaptureResponseDTO>(url, {
        method: "POST",
        body: formData,
      });
    },
    get: async (id: string): Promise<CaptureResponseDTO> => {
      return request<CaptureResponseDTO>(`/captures/${id}`);
    },
    listInterfaces: async (): Promise<InterfaceMetadataDTO[]> => {
      return request<InterfaceMetadataDTO[]>("/live-captures/interfaces");
    },
    startLive: async (data: {
      interface_id: string;
      duration_sec?: number;
      capture_profile?: string;
      bpf_filter?: string;
    }): Promise<any> => {
      return request("/live-captures/start", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    stopLive: async (sessionId: string): Promise<any> => {
      return request(`/live-captures/stop/${sessionId}`, {
        method: "POST",
      });
    },
    getSamples: async (): Promise<SampleCaptureDTO[]> => {
      return request<SampleCaptureDTO[]>("/captures/samples");
    },
    ingestSample: async (sampleId: string): Promise<CaptureResponseDTO> => {
      return request<CaptureResponseDTO>(`/captures/samples/${sampleId}/ingest`, {
        method: "POST",
      });
    },
  },

  analyses: {
    list: async (includeArchived: boolean = false): Promise<AnalysisListItemDTO[]> => {
      const query = includeArchived ? "?include_archived=true" : "";
      return request<AnalysisListItemDTO[]>(`/analyses${query}`);
    },
    get: async (id: string): Promise<AnalysisRunResponseDTO> => {
      return request<AnalysisRunResponseDTO>(`/analyses/${id}`);
    },
    create: async (captureId: string, forceRerun: boolean = false): Promise<AnalysisRunResponseDTO> => {
      const query = forceRerun ? "?force_rerun=true" : "";
      return request<AnalysisRunResponseDTO>(`/analyses${query}`, {
        method: "POST",
        body: JSON.stringify({ capture_id: captureId }),
      });
    },
    getOverview: async (id: string): Promise<AnalysisOverviewDTO> => {
      return request<AnalysisOverviewDTO>(`/analyses/${id}/overview`);
    },
    getProtocol: async (id: string): Promise<ProtocolSummaryDTO> => {
      return request<ProtocolSummaryDTO>(`/analyses/${id}/protocol`);
    },
    getSas: async (id: string): Promise<ChildSecurityAssociationDTO[]> => {
      return request<ChildSecurityAssociationDTO[]>(
        `/analyses/${id}/security-associations`
      );
    },
    getSaGraph: async (id: string): Promise<SAGraphResponseDTO> => {
      return request<SAGraphResponseDTO>(
        `/analyses/${id}/security-associations/graph`
      );
    },
    getTraffic: async (id: string): Promise<TrafficSummaryResponseDTO> => {
      return request<TrafficSummaryResponseDTO>(`/analyses/${id}/traffic`);
    },
    getTrafficModelCard: async (id?: string): Promise<MLModelCardDTO> => {
      return request<MLModelCardDTO>(`/analyses/${id || "default"}/traffic/model-card`);
    },
    getFindings: async (id: string): Promise<SecurityFindingDTO[]> => {
      return request<SecurityFindingDTO[]>(`/analyses/${id}/findings`);
    },
    getCompliance: async (id: string): Promise<ComplianceSummaryDTO> => {
      return request<ComplianceSummaryDTO>(`/analyses/${id}/compliance`);
    },
    getSecurityScore: async (id: string): Promise<SecurityScoreDTO> => {
      return request<SecurityScoreDTO>(`/analyses/${id}/security-score`);
    },
    getRisk: async (id: string): Promise<RiskAssessmentDTO> => {
      return request<RiskAssessmentDTO>(`/analyses/${id}/risk`);
    },
    getThreats: async (id: string): Promise<ThreatInstanceDTO[]> => {
      return request<ThreatInstanceDTO[]>(`/analyses/${id}/threat-matrix`);
    },
    getThreatIntelligence: async (id: string): Promise<ThreatIntelResponseDTO> => {
      return request<ThreatIntelResponseDTO>(`/analyses/${id}/threat-intelligence`);
    },
    getFingerprintability: async (id: string): Promise<FingerprintabilityDTO> => {
      return request<FingerprintabilityDTO>(
        `/analyses/${id}/metadata-fingerprintability`
      );
    },
    getEvidenceGraph: async (id: string): Promise<EvidenceGraphDTO> => {
      return request<EvidenceGraphDTO>(`/analyses/${id}/evidence-graph`);
    },
    reAnalyze: async (
      id: string,
      options?: {
        pinned_parser_engine?: string;
        pinned_parser_version?: string;
        pinned_policy_bundle_version?: string;
        pinned_model_bundle_id?: string;
      }
    ): Promise<ReplayExecutionResponseDTO> => {
      return request<ReplayExecutionResponseDTO>(`/analyses/${id}/re-analyze`, {
        method: "POST",
        body: JSON.stringify(options || {}),
      });
    },
    getReplayLineage: async (id: string): Promise<ReplayLineageDTO> => {
      return request<ReplayLineageDTO>(`/analyses/${id}/replay-lineage`);
    },
    getExportManifestUrl: (id: string): string => {
      return `${getApiBaseUrl()}/analyses/${id}/export/manifest`;
    },
    getExportFindingsCsvUrl: (id: string): string => {
      return `${getApiBaseUrl()}/analyses/${id}/export/findings.csv`;
    },
    recompute: async (id: string): Promise<AnalysisRunResponseDTO> => {
      return request<AnalysisRunResponseDTO>(`/analyses/${id}/recompute`, {
        method: "POST",
      });
    },
    archive: async (id: string): Promise<{ success: boolean; analysis_id: string; is_archived: boolean }> => {
      return request<{ success: boolean; analysis_id: string; is_archived: boolean }>(`/analyses/${id}/archive`, {
        method: "POST",
      });
    },
    delete: async (id: string): Promise<{ success: boolean; analysis_id: string }> => {
      return request<{ success: boolean; analysis_id: string }>(`/analyses/${id}`, {
        method: "DELETE",
      });
    },
  },

  reports: {
    generate: async (
      analysisId: string,
      reportType: "EXECUTIVE" | "TECHNICAL"
    ): Promise<ReportResponseDTO> => {
      return request<ReportResponseDTO>(`/analyses/${analysisId}/reports`, {
        method: "POST",
        body: JSON.stringify({ report_type: reportType }),
      });
    },
    list: async (analysisId: string): Promise<ReportListResponseDTO> => {
      return request<ReportListResponseDTO>(`/analyses/${analysisId}/reports`);
    },
    get: async (
      analysisId: string,
      reportId: string
    ): Promise<ReportResponseDTO> => {
      return request<ReportResponseDTO>(
        `/analyses/${analysisId}/reports/${reportId}`
      );
    },
    getHtml: async (
      analysisId: string,
      reportId: string
    ): Promise<string> => {
      return request<string>(
        `/analyses/${analysisId}/reports/${reportId}/html`
      );
    },
    getDownloadUrl: (
      analysisId: string,
      reportId: string,
      format: "pdf" | "html"
    ): string => {
      return `${getApiBaseUrl()}/analyses/${analysisId}/reports/${reportId}/download?format=${format}`;
    },
  },

  remediation: {
    getTwin: async (analysisId: string): Promise<TwinResponseDTO> => {
      return request<TwinResponseDTO>(`/analyses/${analysisId}/remediation/twin`);
    },
    updateProposal: async (
      analysisId: string,
      proposalText: string
    ): Promise<TwinResponseDTO> => {
      return request<TwinResponseDTO>(`/analyses/${analysisId}/remediation/twin/proposals`, {
        method: "POST",
        body: JSON.stringify({ proposal_swanctl_text: proposalText }),
      });
    },
    runPreflight: async (
      analysisId: string,
      twinId: string,
      proposalHash: string
    ): Promise<PreflightResponseDTO> => {
      return request<PreflightResponseDTO>(
        `/analyses/${analysisId}/remediation/twin/preflight?twin_id=${twinId}&proposal_hash=${proposalHash}`,
        { method: "POST" }
      );
    },
    apply: async (
      analysisId: string,
      data: {
        twin_id: string;
        proposal_hash: string;
        lab_instance_id: string;
        operator_id: string;
        confirm_controlled_lab_only: boolean;
      }
    ): Promise<RemediationRunResponseDTO> => {
      return request<RemediationRunResponseDTO>(`/analyses/${analysisId}/remediation/apply`, {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    getRun: async (
      analysisId: string,
      runId: string
    ): Promise<RemediationRunResponseDTO> => {
      return request<RemediationRunResponseDTO>(`/analyses/${analysisId}/remediation/runs/${runId}`);
    },
    getVerification: async (
      analysisId: string,
      verificationId: string
    ): Promise<VerificationResponseDTO> => {
      return request<VerificationResponseDTO>(
        `/analyses/${analysisId}/remediation/verifications/${verificationId}`
      );
    },
    getLatestVerification: async (
      analysisId: string
    ): Promise<VerificationResponseDTO | null> => {
      return request<VerificationResponseDTO | null>(`/analyses/${analysisId}/remediation/latest-verification`);
    },
  },

  ai: {
    chat: async (
      analysisId: string,
      data: {
        question: string;
        session_id?: string;
        model_override?: string;
      }
    ): Promise<AIChatQueryResponseDTO> => {
      return request<AIChatQueryResponseDTO>(`/analyses/${analysisId}/ai/chat`, {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    getHistory: async (
      analysisId: string,
      sessionId: string
    ): Promise<AIChatSessionHistoryDTO> => {
      return request<AIChatSessionHistoryDTO>(`/analyses/${analysisId}/ai/chat/${sessionId}`);
    },
    searchEvidenceOnly: async (
      analysisId: string,
      query: string
    ): Promise<EvidenceSearchResponseDTO> => {
      return request<EvidenceSearchResponseDTO>(`/analyses/${analysisId}/ai/search?q=${encodeURIComponent(query)}`);
    },
    getHealth: async (): Promise<AIHealthResponseDTO> => {
      return request<AIHealthResponseDTO>("/ai/health");
    },
    getKnowledgeStatus: async (): Promise<any> => {
      return request("/ai/knowledge/status");
    },
    ingestKnowledge: async (): Promise<any> => {
      return request("/ai/knowledge/ingest", { method: "POST" });
    },
  },

  discovery: {
    getStatus: async (): Promise<import("./types").DiscoveryStatusDTO> => {
      return request<import("./types").DiscoveryStatusDTO>("/discovery/status");
    },
    listJobs: async (operatorId?: string): Promise<import("./types").DiscoveryJobDTO[]> => {
      const q = operatorId ? `?operator_id=${encodeURIComponent(operatorId)}` : "";
      return request<import("./types").DiscoveryJobDTO[]>(`/discovery/jobs${q}`);
    },
    getJob: async (jobId: string): Promise<import("./types").DiscoveryJobDTO> => {
      return request<import("./types").DiscoveryJobDTO>(`/discovery/jobs/${jobId}`);
    },
    createJob: async (
      data: import("./types").DiscoveryJobCreateRequestDTO
    ): Promise<import("./types").DiscoveryJobDTO> => {
      return request<import("./types").DiscoveryJobDTO>("/discovery/jobs", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    cancelJob: async (jobId: string): Promise<import("./types").DiscoveryJobDTO> => {
      return request<import("./types").DiscoveryJobDTO>(`/discovery/jobs/${jobId}/cancel`, {
        method: "POST",
      });
    },
  },

  ikeAssessment: {
    getStatus: async (): Promise<import("./types").IkeAssessmentStatusDTO> => {
      return request<import("./types").IkeAssessmentStatusDTO>("/ike-assessment/status");
    },
    getConcordance: async (analysisId: string): Promise<import("./types").IkeConcordanceDTO[]> => {
      return request<import("./types").IkeConcordanceDTO[]>(
        `/ike-assessment/analyses/${analysisId}/concordance`
      );
    },
    listJobs: async (limit = 50, offset = 0): Promise<import("./types").IkeJobResponseDTO[]> => {
      return request<import("./types").IkeJobResponseDTO[]>(
        `/ike-assessment/jobs?limit=${limit}&offset=${offset}`
      );
    },
    getJob: async (jobId: string): Promise<import("./types").IkeJobResponseDTO> => {
      return request<import("./types").IkeJobResponseDTO>(`/ike-assessment/jobs/${jobId}`);
    },
    createJob: async (
      data: import("./types").IkeJobCreateRequestDTO
    ): Promise<import("./types").IkeJobResponseDTO> => {
      return request<import("./types").IkeJobResponseDTO>("/ike-assessment/jobs", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
  },

  vulnerabilities: {
    previewReport: async (file: File, authorizedTargets?: string): Promise<import("./types").VulnerabilityReportPreviewResponseDTO> => {
      const formData = new FormData();
      formData.append("file", file);
      if (authorizedTargets) {
        formData.append("authorized_targets", authorizedTargets);
      }
      return request<import("./types").VulnerabilityReportPreviewResponseDTO>("/vulnerabilities/reports/preview", {
        method: "POST",
        body: formData,
      });
    },
    importReport: async (
      file: File,
      data: {
        operator_id: string;
        authorization_reference: string;
        operator_attestation: string;
        engagement_scope: string;
        authorized_targets?: string;
      }
    ): Promise<import("./types").VulnerabilityReportDTO> => {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("operator_id", data.operator_id);
      formData.append("authorization_reference", data.authorization_reference);
      formData.append("operator_attestation", data.operator_attestation);
      formData.append("engagement_scope", data.engagement_scope);
      if (data.authorized_targets) {
        formData.append("authorized_targets", data.authorized_targets);
      }
      return request<import("./types").VulnerabilityReportDTO>("/vulnerabilities/reports/import", {
        method: "POST",
        body: formData,
      });
    },
    listReports: async (skip = 0, limit = 50, status?: string): Promise<import("./types").VulnerabilityReportListResponseDTO> => {
      const params = new URLSearchParams({ skip: String(skip), limit: String(limit) });
      if (status) params.append("status", status);
      return request<import("./types").VulnerabilityReportListResponseDTO>(`/vulnerabilities/reports?${params.toString()}`);
    },
    getReport: async (reportId: string): Promise<import("./types").VulnerabilityReportDTO> => {
      return request<import("./types").VulnerabilityReportDTO>(`/vulnerabilities/reports/${reportId}`);
    },
    listFindings: async (
      reportId?: string,
      params?: {
        skip?: number;
        limit?: number;
        host_ip?: string;
        severity?: string;
        correlation_status?: string;
        asset_link_state?: string;
      }
    ): Promise<import("./types").VulnerabilityFindingListResponseDTO> => {
      const sp = new URLSearchParams();
      if (params?.skip !== undefined) sp.append("skip", String(params.skip));
      if (params?.limit !== undefined) sp.append("limit", String(params.limit));
      if (params?.host_ip) sp.append("host_ip", params.host_ip);
      if (params?.severity) sp.append("severity", params.severity);
      if (params?.correlation_status) sp.append("correlation_status", params.correlation_status);
      if (params?.asset_link_state) sp.append("asset_link_state", params.asset_link_state);
      const url = reportId
        ? `/vulnerabilities/reports/${reportId}/findings?${sp.toString()}`
        : `/vulnerabilities/findings?${sp.toString()}`;
      return request<import("./types").VulnerabilityFindingListResponseDTO>(url);
    },
    getFinding: async (reportId: string, findingId: string): Promise<import("./types").VulnerabilityFindingDTO> => {
      return request<import("./types").VulnerabilityFindingDTO>(`/vulnerabilities/reports/${reportId}/findings/${findingId}`);
    },
  },

  monitoring: {
    registerGateway: async (data: {
      name: string;
      gateway_ip: string;
      authorized_scope: string;
      operator_id: string;
      authorization_reference: string;
    }): Promise<import("./types").GatewayResponseDTO> => {
      return request<import("./types").GatewayResponseDTO>("/monitoring/gateways", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    listGateways: async (): Promise<import("./types").GatewayResponseDTO[]> => {
      return request<import("./types").GatewayResponseDTO[]>("/monitoring/gateways");
    },
    registerSensor: async (data: {
      sensor_name: string;
      sensor_type: "GATEWAY_COLLECTOR" | "CAPTURE_SENSOR";
      gateway_id: string;
      authorized_scope: string;
      freshness_window_seconds?: number;
      reporting_interval_seconds?: number;
    }): Promise<import("./types").RegisterSensorResponseDTO> => {
      return request<import("./types").RegisterSensorResponseDTO>("/monitoring/sensors", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    listSensors: async (gatewayId?: string): Promise<import("./types").SensorResponseDTO[]> => {
      const url = gatewayId ? `/monitoring/sensors?gateway_id=${gatewayId}` : "/monitoring/sensors";
      return request<import("./types").SensorResponseDTO[]>(url);
    },
    revokeSensor: async (sensorId: string): Promise<import("./types").SensorResponseDTO> => {
      return request<import("./types").SensorResponseDTO>(`/monitoring/sensors/${sensorId}/revoke`, {
        method: "POST",
      });
    },
    getHealth: async (): Promise<import("./types").SensorHealthDTO[]> => {
      return request<import("./types").SensorHealthDTO[]>("/monitoring/health");
    },
    getSAStates: async (gatewayId?: string): Promise<import("./types").MonitoredSAStateDTO[]> => {
      const url = gatewayId ? `/monitoring/sa-states?gateway_id=${gatewayId}` : "/monitoring/sa-states";
      return request<import("./types").MonitoredSAStateDTO[]>(url);
    },
    getTimeline: async (params?: {
      gateway_id?: string;
      sensor_id?: string;
      event_kind?: string;
      limit?: number;
      offset?: number;
    }): Promise<import("./types").MonitoringTimelineResponseDTO> => {
      const sp = new URLSearchParams();
      if (params?.gateway_id) sp.append("gateway_id", params.gateway_id);
      if (params?.sensor_id) sp.append("sensor_id", params.sensor_id);
      if (params?.event_kind) sp.append("event_kind", params.event_kind);
      if (params?.limit !== undefined) sp.append("limit", String(params.limit));
      if (params?.offset !== undefined) sp.append("offset", String(params.offset));
      return request<import("./types").MonitoringTimelineResponseDTO>(`/monitoring/timeline?${sp.toString()}`);
    },
    triggerPulse: async (): Promise<{ status: string; accepted_count: number }> => {
      return request<{ status: string; accepted_count: number }>("/monitoring/pulse", {
        method: "POST",
      });
    },
  },

  inventory: {
    importConfiguration: async (
      data: import("./types").ConfigurationImportRequestDTO
    ): Promise<import("./types").ConfigurationSnapshotDTO> => {
      return request<import("./types").ConfigurationSnapshotDTO>("/inventory/configurations/import", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    designateBaseline: async (
      snapshotId: string,
      data: import("./types").BaselineDesignateRequestDTO
    ): Promise<import("./types").ConfigurationSnapshotDTO> => {
      return request<import("./types").ConfigurationSnapshotDTO>(`/inventory/configurations/${snapshotId}/baseline`, {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    listSnapshots: async (params?: {
      gateway_identity?: string;
      is_baseline?: boolean;
      limit?: number;
    }): Promise<import("./types").ConfigurationSnapshotDTO[]> => {
      const sp = new URLSearchParams();
      if (params?.gateway_identity) sp.append("gateway_identity", params.gateway_identity);
      if (params?.is_baseline !== undefined) sp.append("is_baseline", String(params.is_baseline));
      if (params?.limit !== undefined) sp.append("limit", String(params.limit));
      const qs = sp.toString();
      return request<import("./types").ConfigurationSnapshotDTO[]>(`/inventory/configurations/snapshots${qs ? `?${qs}` : ""}`);
    },
    getSnapshot: async (
      snapshotId: string
    ): Promise<import("./types").ConfigurationSnapshotDTO> => {
      return request<import("./types").ConfigurationSnapshotDTO>(`/inventory/configurations/snapshots/${snapshotId}`);
    },
    compareDrift: async (
      data: import("./types").DriftCompareRequestDTO
    ): Promise<import("./types").ConfigurationDriftDTO> => {
      return request<import("./types").ConfigurationDriftDTO>("/inventory/configurations/drift", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    getDriftHistory: async (params?: {
      gateway_identity?: string;
      limit?: number;
    }): Promise<import("./types").ConfigurationDriftDTO[]> => {
      const sp = new URLSearchParams();
      if (params?.gateway_identity) sp.append("gateway_identity", params.gateway_identity);
      if (params?.limit !== undefined) sp.append("limit", String(params.limit));
      const qs = sp.toString();
      return request<import("./types").ConfigurationDriftDTO[]>(`/inventory/configurations/drifts${qs ? `?${qs}` : ""}`);
    },
    importCertificate: async (
      data: import("./types").CertificateImportRequestDTO
    ): Promise<import("./types").GatewayCertificateDTO[]> => {
      return request<import("./types").GatewayCertificateDTO[]>("/inventory/certificates/import", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    listCertificates: async (params?: {
      gateway_identity?: string;
      validity_status?: string;
      snapshot_id?: string;
      limit?: number;
    }): Promise<import("./types").GatewayCertificateDTO[]> => {
      const sp = new URLSearchParams();
      if (params?.gateway_identity) sp.append("gateway_identity", params.gateway_identity);
      if (params?.validity_status) sp.append("validity_status", params.validity_status);
      if (params?.snapshot_id) sp.append("snapshot_id", params.snapshot_id);
      if (params?.limit !== undefined) sp.append("limit", String(params.limit));
      const qs = sp.toString();
      return request<import("./types").GatewayCertificateDTO[]>(`/inventory/certificates${qs ? `?${qs}` : ""}`);
    },
    getCertificate: async (
      certId: string
    ): Promise<import("./types").GatewayCertificateDTO> => {
      return request<import("./types").GatewayCertificateDTO>(`/inventory/certificates/${certId}`);
    },
    getGatewaySummary: async (
      gatewayIdentity: string
    ): Promise<import("./types").GatewayInventorySummaryDTO> => {
      return request<import("./types").GatewayInventorySummaryDTO>(`/inventory/gateways/${encodeURIComponent(gatewayIdentity)}/summary`);
    },
  },

  system: {
    getLiveness: async (): Promise<{ status: string; timestamp: string; service: string }> => {
      return request("/system/health/live");
    },
    getReadiness: async (): Promise<SystemReadinessDTO> => {
      try {
        return await request<SystemReadinessDTO>("/system/health/ready");
      } catch (err: any) {
        if (err instanceof ApiError && err.status === 503 && err.detail) {
          return err.detail as SystemReadinessDTO;
        }
        throw err;
      }
    },
    getHealth: async (): Promise<SystemReadinessDTO> => {
      try {
        return await request<SystemReadinessDTO>("/system/health/ready");
      } catch (err: any) {
        if (err instanceof ApiError && err.status === 503 && err.detail) {
          return err.detail as SystemReadinessDTO;
        }
        throw err;
      }
    },
  },
};

export const apiClient = api;


