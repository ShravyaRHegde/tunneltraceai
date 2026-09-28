/**
 * Strongly typed domain data contracts mirroring FastAPI schemas exactly.
 * Zero-hallucination policy: no mock fallbacks, unknown is preserved.
 */

export interface CaptureResponseDTO {
  capture_id: string;
  capture_source: string;
  capture_format: string;
  original_filename: string | null;
  file_size_bytes: number;
  sha256: string;
  packet_count: number | null;
  duration_sec: number | null;
  first_packet_at: string | null;
  last_packet_at: string | null;
  link_layer_type: string | null;
  validation_state: string;
  created_at: string;
  already_analyzed?: boolean;
  existing_analysis_id?: string | null;
  existing_pipeline_version?: string | null;
}

export interface SampleCaptureDTO {
  sample_id: string;
  filename: string;
  title: string;
  description: string;
  packet_count: number;
  format: string;
  sha256: string;
  provenance: string;
}

export interface AnalysisRunResponseDTO {
  analysis_id: string;
  capture_id: string;
  capture_filename?: string | null;
  capture_sha256?: string | null;
  status: "QUEUED" | "RUNNING" | "PARTIAL" | "COMPLETED" | "FAILED" | "CANCELLED" | "NO_IPSEC";
  current_stage: string;
  parser_engine: string;
  parser_version: string;
  schema_version: string;
  started_at: string | null;
  completed_at: string | null;
  error_code: string | null;
  error_message: string | null;
  parent_analysis_id?: string | null;
  replay_mode?: string | null;
  provenance_metadata?: Record<string, any> | null;
  pipeline_version?: string;
  policy_version?: string;
  is_outdated_version?: boolean;
  is_archived?: boolean;
  is_synthetic_demo?: boolean;
  created_at: string;
}

export interface AnalysisListItemDTO {
  analysis_id: string;
  capture_id: string;
  capture_filename: string;
  capture_sha256: string;
  status: string;
  current_stage: string;
  created_at: string;
  completed_at: string | null;
  security_score: number | null;
  coverage_percentage?: number | null;
  risk_tier?: string | null;
  critical_findings: number;
  high_findings: number;
  parent_analysis_id?: string | null;
  replay_mode?: string | null;
  provenance_metadata?: Record<string, any> | null;
  pipeline_version?: string;
  policy_version?: string;
  is_outdated_version?: boolean;
  is_archived?: boolean;
  is_synthetic_demo?: boolean;
}

export interface ReplayComparisonDTO {
  comparison_id: string;
  replay_mode: string;
  parent_run_id: string;
  child_run_id: string;
  comparison_status: "EXACT_MATCH" | "SEMANTIC_MATCH" | "DISCREPANCY_DETECTED" | "ENVIRONMENT_MISMATCH" | "FAILED";
  artifact_integrity: "VERIFIED" | "MISMATCH" | "UNAVAILABLE";
  differences: Record<string, any> | null;
  summary: string;
  metrics: Record<string, any> | null;
  created_at: string;
}

export interface ReplayLineageDTO {
  analysis_id: string;
  parent_analysis_id: string | null;
  replay_mode: string | null;
  capture_id: string;
  capture_filename: string;
  capture_sha256: string;
  capture_integrity_verified: boolean;
  capture_integrity_status?: "VERIFIED" | "HASH_MISMATCH" | "FILE_NOT_FOUND" | "UNAVAILABLE" | "NOT_CHECKED";
  actual_capture_sha256?: string | null;
  child_runs: Array<{
    analysis_id: string;
    replay_mode: string | null;
    status: string;
    created_at: string;
    completed_at: string | null;
  }>;
  version_pins: Record<string, any>;
  latest_comparison: ReplayComparisonDTO | null;
}

export interface ReplayExecutionResponseDTO {
  child_analysis_id: string;
  parent_analysis_id: string;
  replay_mode: string;
  status: string;
  artifact_integrity: string;
  comparison_status: string;
  summary: string;
  differences: Record<string, any> | null;
  metrics: Record<string, any> | null;
  created_at: string;
}

export interface ProtocolSummaryDTO {
  analysis_id: string;
  ipsec_detected: boolean;
  total_packets_inspected: number;
  ipsec_packet_count: number;
  ikev1_packet_count: number;
  ikev2_packet_count: number;
  esp_packet_count: number;
  ah_packet_count: number;
  nat_t_detected: boolean;
  observed_initiator_spis: string[];
  observed_responder_spis: string[];
  observed_cipher_suites: string[];
  observed_dh_groups: string[];
  observed_exchange_types: string[];
  evidence_states: Record<string, "VERIFIED" | "INFERRED" | "UNKNOWN" | "MISCONFIGURATION_OBSERVED">;
}

export interface ChildSecurityAssociationDTO {
  id: string;
  analysis_id: string;
  ike_sa_id: string | null;
  protocol: string;
  inbound_spi: string;
  outbound_spi: string;
  src_ip: string | null;
  dst_ip: string | null;
  mode: "TUNNEL" | "TRANSPORT" | "BEET" | "UNKNOWN";
  mode_evidence_state: string;
  encryption_algorithm: string | null;
  integrity_algorithm: string | null;
  pfs_status: "ENABLED" | "DISABLED" | "UNKNOWN";
  pfs_dh_group: string | null;
  pfs_evidence_state: string;
  first_observed_at: string | null;
  last_observed_at: string | null;
  lifecycle_state: string;
  evidence_state: string;
}

export interface SAGraphNodeDTO {
  id: string;
  type: string;
  label: string;
  data: Record<string, any>;
}

export interface SAGraphEdgeDTO {
  id: string;
  source: string;
  target: string;
  label?: string;
}

export interface SAGraphResponseDTO {
  analysis_id: string;
  nodes: SAGraphNodeDTO[];
  edges: SAGraphEdgeDTO[];
}

export interface TrafficFlowItemDTO {
  flow_id: string;
  spi: string;
  reverse_spi: string | null;
  src_ip: string;
  dst_ip: string;
  duration_seconds: number;
  packet_count: number;
  byte_count: number;
  association_state: string;
  input_status?: "VALID" | "INSUFFICIENT_INPUT" | string | null;
  supervised_hypothesis?: string | null;
  known_class: string | null;
  final_class: string | null;
  accepted_prediction?: string | null;
  calibrated_confidence: number | null;
  calibration_status?: "CALIBRATED" | "DEGRADED" | "UNAVAILABLE" | string | null;
  normalized_entropy: number | null;
  ood_status: "KNOWN_ACCEPTED" | "ENTROPY_REJECTED" | "OUTLIER_REJECTED" | "INSUFFICIENT_LENGTH" | "UNKNOWN_UNSEEN" | "OUT_OF_DISTRIBUTION" | "INSUFFICIENT_INPUT" | string | null;
  behavioral_anomaly_status: "NORMAL_BEHAVIOR" | "STATISTICAL_BEHAVIORAL_ANOMALY" | "ANOMALOUS_BEHAVIOR" | "NOT_EVALUATED" | string | null;
  anomaly_score?: number | null;
  is_degraded?: boolean | null;
  degraded_reason?: string | null;
  top_shap_features: Array<{ feature: string; importance: number }> | null;
}

export interface TrafficSummaryResponseDTO {
  analysis_id: string;
  total_flows: number;
  classified_flows: number;
  classes_detected: string[];
  ood_count: number;
  anomaly_count: number;
  ml_run_status?: "NOT_CONFIGURED" | "BUNDLE_INVALID" | "RUNNING" | "COMPLETED" | "PARTIAL" | "NO_FLOWS" | "INSUFFICIENT_INPUT" | "FAILED" | string;
  model_version?: string | null;
  model_bundle_id?: string | null;
  flows: TrafficFlowItemDTO[];
}

export interface MLModelCardDTO {
  model_name: string;
  version: string;
  status: string;
  architecture: {
    backbone: string;
    fusion_strategy: string;
    sequence_window_packets: number;
    sequence_features: string[];
    tabular_feature_count: number;
    tabular_features: string[];
    tree_method: string;
    max_depth: number;
    learning_rate: number;
  };
  training_corpus: {
    total_experimental_sessions: number;
    collection_testbed: string;
    ipsec_gateways_evaluated: string[];
    negative_controls: string[];
    dataset_splits: Record<string, number>;
    leakage_audit_status: string;
    privacy_compliance: string;
  };
  evaluation_metrics: {
    macro_f1: number;
    weighted_f1: number;
    accuracy: number;
    balanced_accuracy: number;
    precision_macro: number;
    recall_macro: number;
    classes: string[];
    per_class: Record<string, { precision: number; recall: number; f1_score: number; support: number }>;
    confusion_matrix: {
      classes: string[];
      matrix: number[][];
    };
  };
  calibration_and_ood: {
    calibration_method: string;
    expected_calibration_error: number;
    brier_score: number;
    ood_rejection_policy: string;
    ood_rejection_accuracy: number;
    entropy_threshold: number;
  };
  four_prediction_states: Record<string, string>;
  limitations: string[];
}

export interface ComplianceEvaluationDTO {
  rule_id: string;
  rule_title: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  standard: string;
  compliance_state: "PASS" | "FAIL" | "UNKNOWN" | "NOT_APPLICABLE";
  evidence_state: string;
  observed_value: any;
  expected_value: any;
  rationale: string;
}

export interface ComplianceSummaryDTO {
  analysis_id: string;
  profile_id: string;
  profile_name: string;
  policy_bundle_hash: string;
  total_evaluations: number;
  pass_count: number;
  fail_count: number;
  unknown_count: number;
  not_applicable_count: number;
  evaluations: ComplianceEvaluationDTO[];
}

export interface SecurityFindingDTO {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  category: string;
  score_deduction: number;
  affected_entity: string;
  technical_description: string;
  remediation_guidance: string;
  evidence_references: string[];
  evidence_state: string;
  root_cause_key: string;
}

export interface SecurityScoreDTO {
  analysis_id: string;
  overall_score: number;
  evidence_coverage: number;
  methodology_version: string;
  score_policy_hash: string;
  itemized_deductions: Record<string, number>;
  status: string;
}

export type RiskTierType =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "NO_FINDINGS_UNDER_THIS_POLICY"
  | "INSUFFICIENT_EVIDENCE"
  | "UNKNOWN";

export interface RiskFactorDetailDTO {
  factor_name: string;
  factor_value: string;
  scale: string;
  evidence_state: string;
  source: string;
  source_time: string;
  contributes_to_aggregate: boolean;
  aggregation_role: string;
  rationale: string;
}

export interface RiskItemDTO {
  finding_id: string;
  rule_id: string;
  severity: string;
  likelihood: string;
  impact: string;
  risk_tier: RiskTierType;
  evidence_state: string;
  threat_mapped: boolean;
  rationale: string;
  factors: RiskFactorDetailDTO[];
  contributes_to_aggregate: boolean;
  aggregation_role: string;
  root_cause_key: string;
  policy_version: string;
  policy_hash: string;
  methodology_type: string;
}

export interface RiskAssessmentDTO {
  analysis_id: string;
  risk_policy_id: string;
  risk_policy_version: string;
  risk_policy_hash: string;
  overall_risk_tier: RiskTierType;
  items: RiskItemDTO[];
  evidence_coverage?: number | null;
  evidence_gaps_count?: number;
  methodology_type?: string;
  disclaimer?: string;
  // Backward compatibility
  aggregate_risk_tier?: RiskTierType;
  risk_score?: number;
  rationale?: string;
}

export interface ThreatInstanceDTO {
  finding_id?: string;
  threat_id: string;
  title?: string;
  threat_name?: string;
  category?: string;
  attack_vector?: string;
  likelihood: string;
  impact: string;
  risk_tier: RiskTierType;
  mitre_technique_id?: string;
  mitre_attack_id?: string | null;
  mitre_attack_name?: string | null;
  mitre_attack_url?: string | null;
  mitre_attack_rationale?: string | null;
  catalog_hash?: string | null;
  nist_control?: string;
  evidence_state?: string;
}

export interface ThreatIntelItemDTO {
  cve_id: string;
  cisa_kev_status: "PRESENT" | "NOT_PRESENT_IN_THIS_SNAPSHOT" | "NOT_CHECKED" | "STALE" | "UNAVAILABLE";
  cisa_kev_record?: {
    cve_id: string;
    vendor_project: string;
    product: string;
    vulnerability_name: string;
    date_added: string;
    short_description: string;
    required_action: string;
    due_date: string;
    known_ransomware_campaign_use?: string;
    notes?: string;
  } | null;
  cisa_kev_as_of?: string | null;
  cisa_kev_digest?: string | null;
  epss_status: "PRESENT" | "NOT_PRESENT_IN_THIS_SNAPSHOT" | "NOT_CHECKED" | "STALE" | "UNAVAILABLE";
  epss_record?: {
    cve_id: string;
    epss_score: number;
    epss_percentile: number;
    model_version: string;
    date: string;
  } | null;
  epss_as_of?: string | null;
  epss_digest?: string | null;
  disclaimer: string;
}

export interface ThreatIntelResponseDTO {
  analysis_id: string;
  intel_items: ThreatIntelItemDTO[];
  source_freshness: string;
  disclaimer: string;
}

export interface FingerprintabilityDTO {
  analysis_id: string;
  overall_index: number;
  is_experimental: boolean;
  component_metrics: Record<string, number>;
  disclaimer: string;
}

export interface EvidenceGraphNodeDTO {
  id: string;
  node_type: string;
  label: string;
  entity_id: string;
  properties: Record<string, any>;
}

export interface EvidenceGraphEdgeDTO {
  source_id: string;
  target_id: string;
  relation_type: string;
}

export interface EvidenceGraphDTO {
  analysis_id: string;
  nodes: EvidenceGraphNodeDTO[];
  edges: EvidenceGraphEdgeDTO[];
  evidence_gaps?: Array<{ fact_name: string; rationale: string }>;
}

export interface AnalysisOverviewDTO {
  analysis_id: string;
  capture: {
    id: string | null;
    filename: string;
    sha256: string;
    file_size_bytes: number;
    packet_count: number;
  };
  analysis: {
    status: string;
    current_stage: string;
    parser_engine: string;
    parser_version: string;
    created_at: string | null;
    is_synthetic_demo?: boolean;
    evidence_note?: string;
    status_note?: string;
    pipeline_version?: string;
    policy_version?: string;
    is_outdated_version?: boolean;
    is_archived?: boolean;
  };
  security_posture: {
    score: number | null;
    status?: string;
    is_assessable?: boolean;
    evidence_coverage: number;
    aggregate_risk_tier: string;
    itemized_deductions: Record<string, number>;
    methodology_version: string;
  };
  compliance_counts: {
    pass: number;
    fail: number;
    unknown: number;
    not_applicable: number;
  };
  findings_summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    top_findings: SecurityFindingDTO[];
  };
  traffic_summary: {
    total_flows?: number;
    classified_flows: number;
    classes_detected: string[];
    avg_calibrated_confidence: number | null;
    ood_count: number;
    anomaly_count: number;
    ml_run_status?: string;
    model_bundle_id?: string | null;
  };
  fingerprintability: {
    overall_index: number;
    is_experimental: boolean;
    disclaimer: string;
  };
  protocol_summary: {
    total_observations: number;
    ike_versions: string[];
    protocols_detected: string[];
    nat_detected: boolean;
    transforms_observed: string[];
    dh_groups: string[];
  };
}

export interface ReportResponseDTO {
  id: string;
  analysis_id: string;
  report_type: "EXECUTIVE" | "TECHNICAL";
  status: "QUEUED" | "GENERATING" | "COMPLETED" | "PDF_FAILED_HTML_AVAILABLE" | "FAILED";
  format: "HTML" | "PDF" | "BOTH";
  template_version: string;
  engine_version: string;
  html_sha256: string | null;
  pdf_sha256: string | null;
  snapshot_manifest_sha256: string | null;
  generation_duration_ms: number | null;
  created_at: string;
  completed_at: string | null;
  error_message: string | null;
  artifact_integrity_status?: "VERIFIED" | "HASH_MISMATCH" | "FILE_NOT_FOUND" | "UNAVAILABLE" | null;
  actual_html_sha256?: string | null;
}

export interface ReportListResponseDTO {
  analysis_id: string;
  total_reports: number;
  items: ReportResponseDTO[];
}

export interface InterfaceMetadataDTO {
  interface_id: string;
  display_name: string;
  type: string;
  capture_allowed: boolean;
  lab_owned: boolean;
  operstate: string;
}

export interface SemanticDiffItemDTO {
  field: string;
  label: string;
  current_value: any;
  current_evidence_state: string;
  proposed_value: any;
  is_changed: boolean;
  policy_impact: string;
}

export interface ProjectedFindingDTO {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: string;
  root_cause_key: string;
  projected_state: string;
  rationale: string;
}

export interface ProjectedRegressionAuditDTO {
  targeted_finding_ids: string[];
  targeted_rule_ids: string[];
  projected_resolved_findings: ProjectedFindingDTO[];
  projected_remaining_findings: ProjectedFindingDTO[];
  projected_new_regressions: ProjectedFindingDTO[];
  baseline_score: number | null;
  projected_score: number | null;
  projected_score_delta: number | null;
  baseline_risk_score: number | null;
  projected_risk_score: number | null;
  projected_risk_delta: number | null;
  has_blocking_regressions: boolean;
  proof_obligations: any[];
  disclaimer: string;
}

export interface TwinResponseDTO {
  twin_id: string;
  analysis_id: string;
  status: string;
  proposal_hash: string;
  current_snapshot: Record<string, any>;
  proposed_ir: Record<string, any>;
  rendered_proposed_config: string;
  semantic_diff: SemanticDiffItemDTO[];
  text_diff: string;
  projected_regression_audit: ProjectedRegressionAuditDTO;
  projected_score: number | null;
  projected_score_delta: number | null;
  disclaimer: string;
  has_linked_baseline?: boolean;
  baseline_provenance?: string | null;
}

export interface PreflightCheckDTO {
  code: string;
  status: "PASS" | "FAIL" | "WARN";
  message: string;
}

export interface PreflightResponseDTO {
  status: "READY" | "BLOCKED" | "WARNING";
  is_ready: boolean;
  checks: PreflightCheckDTO[];
  blocking_reasons: string[];
}

export interface RemediationRunStepDTO {
  sequence: number;
  action_type: string;
  status: "PENDING" | "RUNNING" | "SUCCESS" | "FAILED" | "SKIPPED";
  safe_output: Record<string, any> | null;
  error_code: string | null;
  created_at: string;
}

export interface RemediationRunResponseDTO {
  run_id: string;
  twin_id: string;
  status: string;
  proposal_hash: string;
  lab_instance_id: string;
  operator_id: string;
  rollback_state: string;
  rollback_reason: string | null;
  error_message: string | null;
  approval_metadata?: Record<string, any> | null;
  pre_apply_spis?: string[] | null;
  post_capture_hash?: string | null;
  steps: RemediationRunStepDTO[];
  executed_at: string;
  completed_at: string | null;
}

export interface VerificationClaimDTO {
  claim_id: string;
  rule_id: string;
  rule_version: string;
  root_cause_key: string;
  claim_result: "VERIFIED_RESOLVED" | "VERIFIED_NOT_RESOLVED" | "PARTIALLY_VERIFIED" | "UNKNOWN" | "NOT_APPLICABLE";
  reason_code: string;
  expected_condition: string | null;
  baseline_evidence: Record<string, any> | null;
  post_evidence: Record<string, any> | null;
}

export interface VerificationResponseDTO {
  verification_id: string;
  remediation_run_id: string;
  baseline_analysis_id: string;
  post_analysis_id: string | null;
  post_capture_id: string | null;
  verification_result: "VERIFIED_RESOLVED" | "VERIFIED_NOT_RESOLVED" | "PARTIALLY_VERIFIED" | "VERIFICATION_FAILED" | "UNKNOWN";
  security_result: "RESOLVED" | "NOT_RESOLVED" | "PARTIAL" | "UNKNOWN" | "FAILED";
  operational_result: "HEALTHY" | "DEGRADED" | "FAILED";
  baseline_score: number | null;
  verified_score: number | null;
  score_delta: number | null;
  claims: VerificationClaimDTO[];
  finding_diff_summary: Record<string, any> | null;
  regression_summary: Record<string, any> | null;
  verified_at: string;
}

// -----------------------------------------------------------------------------
// Stage 11: Grounded AI Analyst & Local RAG Types
// -----------------------------------------------------------------------------

export interface AIChatClaimDTO {
  claim_id: string;
  text: string;
  claim_type: "PROTOCOL_FACT" | "POLICY_FINDING" | "SECURITY_SCORE" | "ML_INFERENCE" | "STANDARD_REQUIREMENT" | "REMEDIATION_STATUS";
  epistemic_state: "VERIFIED" | "INFERRED" | "UNKNOWN" | "PROJECTED" | "VERIFIED_POST_REMEDIATION";
  citation_ids: string[];
}

export interface AIChatCitationDTO {
  source_id: string;
  source_type: "fact" | "finding" | "rule" | "score" | "flow" | "standard" | "twin" | "verification" | "claim";
  locator: string;
  title: string;
  excerpt?: string;
}

export interface AIChatQueryResponseDTO {
  query_run_id: string;
  session_id: string;
  analysis_id: string;
  status: "ANSWERED" | "INSUFFICIENT_EVIDENCE" | "OUT_OF_SCOPE" | "MODEL_UNAVAILABLE" | "FAILED";
  answer: string;
  claims: AIChatClaimDTO[];
  citations: AIChatCitationDTO[];
  limitations: string[];
  provenance: {
    answer_hash: string;
    fact_lock_hash: string;
    prompt_template_version: string;
    model_name: string;
    verified_at: string;
  } | null;
  metrics: {
    generation_ms?: number;
    total_ms: number;
    citation_validity_rate?: number;
    prompt_eval_count?: number;
    eval_count?: number;
  };
}

export interface AIChatMessageDTO {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  status: string;
  claims: AIChatClaimDTO[] | null;
  citations: AIChatCitationDTO[] | null;
  limitations: string[] | null;
  created_at: string;
}

export interface AIChatSessionHistoryDTO {
  session_id: string;
  analysis_id: string | null;
  title: string;
  model_name: string;
  is_active: boolean;
  messages: AIChatMessageDTO[];
}

export interface EvidenceSearchResponseDTO {
  analysis_id: string;
  query: string;
  intent: string;
  fact_lock_hash: string;
  matched_facts: Array<{
    source_id: string;
    fact_type: string;
    name: string;
    value: any;
    epistemic_state: string;
    entity: string;
  }>;
  matched_standards: Array<{
    source_id: string;
    document_code: string;
    section_reference: string;
    section_title: string;
    authority: string;
    similarity: number;
    excerpt: string;
  }>;
}

export interface AIHealthResponseDTO {
  status: "healthy" | "degraded" | "offline";
  runtime: string;
  base_url: string;
  primary_model: string;
  primary_model_available: boolean;
  fallback_model: string;
  fallback_model_available: boolean;
  embedding_model: string;
  embedding_model_available: boolean;
  embedding_dimension: number;
  knowledge_index_ready: boolean;
  total_documents_indexed: number;
  total_chunks_indexed: number;
  installed_models: string[];
}

export interface DiscoveredServiceDTO {
  id: string;
  protocol: string;
  port: number;
  state: string;
  state_reason: string | null;
  service_name: string | null;
  product: string | null;
  version: string | null;
  extra_info: string | null;
  confidence: number | null;
}

export interface DiscoveredHostDTO {
  id: string;
  ip_address: string;
  ip_version: string;
  state: string;
  hostnames: string[] | null;
  services: DiscoveredServiceDTO[];
}

export interface DiscoveryJobDTO {
  id: string;
  job_name: string;
  operator_id: string;
  authorization_reference: string;
  authorization_attestation: string;
  authorized_at: string;
  profile: string;
  requested_targets: string[];
  canonical_targets: string[];
  exclusions: string[];
  permitted_ports: number[];
  status:
    | "QUEUED"
    | "VALIDATING"
    | "RUNNING"
    | "COMPLETED"
    | "COMPLETED_WITH_AMBIGUITY"
    | "CANCELLED"
    | "FAILED"
    | "REJECTED"
    | "TOOL_UNAVAILABLE";
  failure_reason: string | null;
  raw_output_sha256: string | null;
  output_bytes_count: number | null;
  tool_version: string | null;
  target_count: number;
  hosts_up_count: number;
  services_discovered_count: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  hosts: DiscoveredHostDTO[];
}

export interface DiscoveryStatusDTO {
  enabled: boolean;
  nmap_available: boolean;
  nmap_version: string | null;
  nmap_path: string | null;
  max_targets: number;
  max_ports: number;
  timeout_sec: number;
  rate_limit_pps: number;
  available_profiles: Array<{ name: string; description: string; protocol: string }>;
}

export interface DiscoveryJobCreateRequestDTO {
  job_name: string;
  operator_id: string;
  authorization_reference: string;
  authorization_attestation: string;
  profile: string;
  requested_targets: string[];
  exclusions?: string[];
  permitted_ports?: number[];
  simulate_demo?: boolean;
}

export interface IkeAssessmentStatusDTO {
  enabled: boolean;
  ike_scan_available: boolean;
  ike_scan_version: string | null;
  ike_scan_path: string | null;
  timeout_sec: number;
  allow_experimental_v2: boolean;
  available_profiles: Array<{
    name: string;
    description: string;
    ike_version: string;
    is_experimental: boolean;
    default_port: number;
    permitted_ports: number[];
    retries: number;
    timeout_ms: number;
  }>;
}

export interface IkeProbeResultDTO {
  id: string;
  target_ip: string;
  target_port: number;
  response_category: string;
  ike_version: string;
  handshake_type: string | null;
  notify_code: number | null;
  notify_message: string | null;
  vendor_ids: string[] | null;
  transforms_returned: Array<Record<string, any>> | null;
  rtt_ms: number | null;
  is_experimental: boolean;
  created_at: string;
}

export interface IkeJobResponseDTO {
  id: string;
  job_name: string;
  operator_id: string;
  authorization_reference: string;
  target_ip: string;
  target_port: number;
  profile: string;
  ike_version_requested: string;
  status:
    | "QUEUED"
    | "VALIDATING"
    | "RUNNING"
    | "COMPLETED"
    | "CANCELLED"
    | "FAILED"
    | "TOOL_UNAVAILABLE";
  failure_reason: string | null;
  raw_output_sha256: string | null;
  output_bytes_count: number | null;
  tool_version: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  results: IkeProbeResultDTO[];
}

export interface IkeJobCreateRequestDTO {
  job_name: string;
  operator_id: string;
  authorization_reference: string;
  authorization_attestation: string;
  profile_name: string;
  target: string;
  port?: number;
  analysis_id?: string;
}

export interface IkeConcordanceDTO {
  id: string;
  analysis_id: string;
  ike_job_id: string | null;
  target_ip: string;
  concordance_status:
    | "CONSISTENT"
    | "CONFLICT"
    | "INSUFFICIENT_EVIDENCE"
    | "NOT_COMPARABLE";
  passive_ike_versions: string[];
  active_ike_versions: string[];
  passive_selected_cipher: string | null;
  active_accepted_cipher: string | null;
  concordance_details: {
    passive_lane?: {
      ike_versions: string[];
      selected_cipher: string | null;
      associated_frames: number[];
      has_initial_negotiation: boolean;
    };
    active_lane?: {
      ike_versions: string[];
      accepted_cipher: string | null;
      response_categories: string[];
      is_experimental: boolean;
      rtt_ms: number | null;
    };
    lab_ground_truth_lane?: any;
  };
  evaluated_at: string;
}

export interface VulnerabilityReportPreviewResponseDTO {
  report_id: string;
  format_id: string | null;
  format_version: string | null;
  task_id: string | null;
  task_name: string | null;
  scan_config: string | null;
  scanner_name: string | null;
  scanner_version: string | null;
  feed_status: string;
  feed_type: string | null;
  scan_started_at: string | null;
  scan_ended_at: string | null;
  raw_sha256: string;
  raw_bytes_count: number;
  total_findings_count: number;
  unique_hosts_count: number;
  host_mapping_summary: {
    mapped_exact_ip: number;
    ambiguous_multiple_matches: number;
    unlinked_no_discovery_record: number;
    out_of_scope: number;
    total_unique_hosts: number;
  };
  host_mapping_details: Array<{
    host_ip: string;
    asset_link_state: string;
    asset_link_rationale: string;
    mapped_host_id: string | null;
  }>;
  severity_breakdown: Record<string, number>;
  correlation_breakdown: Record<string, number>;
  findings_sample: Array<{
    source_result_id: string;
    host_ip: string;
    port: number | null;
    protocol: string | null;
    nvt_oid: string;
    nvt_name: string;
    source_severity: string;
    cvss_base_score: number | null;
    qod_value: number | null;
    qod_type: string | null;
    cves: string[];
    cpes: string[];
    asset_link_state: string;
    correlation_status: string;
    cve_applicability_state: string;
    correlation_rationale: string;
  }>;
}

export interface VulnerabilityReportDTO {
  id: string;
  report_source_id: string;
  source_system: string;
  report_format: string;
  report_format_version: string | null;
  task_id: string | null;
  task_name: string | null;
  scan_config: string | null;
  port_list: string | null;
  scanner_name: string | null;
  scanner_version: string | null;
  feed_type: string | null;
  feed_version: string | null;
  feed_status: string;
  engagement_scope: string;
  authorization_reference: string;
  operator_id: string;
  operator_attestation: string;
  is_local_attestation: boolean;
  status: string;
  failure_reason: string | null;
  raw_artifact_sha256: string;
  raw_artifact_bytes: number;
  storage_path: string | null;
  duplicate_of_id: string | null;
  scan_started_at: string | null;
  scan_ended_at: string | null;
  imported_at: string;
  hosts_count: number;
  results_count: number;
}

export interface VulnerabilityFindingDTO {
  id: string;
  report_id: string;
  source_result_id: string;
  host_ip: string;
  host_name: string | null;
  ip_version: string;
  port: number | null;
  protocol: string | null;
  service_name: string | null;
  nvt_oid: string;
  nvt_name: string;
  nvt_family: string | null;
  cvss_version: string | null;
  cvss_base_score: number | null;
  cvss_vector: string | null;
  source_severity: string;
  qod_value: number | null;
  qod_type: string | null;
  detection_method: string | null;
  reported_cves: string[];
  reported_cpes: string[];
  source_product_claim: string | null;
  source_version_claim: string | null;
  description: string | null;
  summary: string | null;
  solution: string | null;
  solution_type: string | null;
  source_timestamp: string | null;
  status: string;
  mapped_discovered_host_id: string | null;
  asset_link_state: string;
  asset_link_rationale: string;
  correlation_status: string;
  correlation_method: string;
  cve_applicability_state: string;
  correlation_rationale: string;
  created_at: string;
}

export interface VulnerabilityReportListResponseDTO {
  reports: VulnerabilityReportDTO[];
  total: number;
  skip: number;
  limit: number;
}

export interface VulnerabilityFindingListResponseDTO {
  findings: VulnerabilityFindingDTO[];
  total: number;
  skip: number;
  limit: number;
}

// -----------------------------------------------------------------------------
// Continuous Monitoring Domain Types
// -----------------------------------------------------------------------------

export interface GatewayResponseDTO {
  id: string;
  name: string;
  gateway_ip: string;
  authorized_scope: string;
  operator_id: string;
  authorization_reference: string;
  status: "ACTIVE" | "INACTIVE" | "REVOKED";
  created_at: string;
  updated_at: string;
}

export interface SensorResponseDTO {
  id: string;
  sensor_name: string;
  sensor_type: "GATEWAY_COLLECTOR" | "CAPTURE_SENSOR";
  gateway_id: string;
  authorized_scope: string;
  token_prefix: string;
  freshness_window_seconds: number;
  reporting_interval_seconds: number;
  status: "ACTIVE" | "REVOKED" | "DISABLED";
  created_at: string;
  revoked_at: string | null;
  last_heartbeat_at: string | null;
}

export interface RegisterSensorResponseDTO extends SensorResponseDTO {
  raw_token: string;
}

export interface SensorHealthDTO {
  sensor_id: string;
  sensor_name: string;
  sensor_type: "GATEWAY_COLLECTOR" | "CAPTURE_SENSOR";
  gateway_id: string;
  gateway_name: string;
  authorized_scope: string;
  current_health: "HEALTHY" | "DEGRADED" | "STALE" | "UNAVAILABLE" | "UNKNOWN" | "DISABLED";
  health_reason: string;
  last_source_timestamp: string | null;
  last_received_at: string | null;
  freshness_window_seconds: number;
  reporting_interval_seconds: number;
  total_events_received: number;
  total_drops_reported: number;
  sequence_gaps_count: number;
  clock_skew_seconds: number;
  active_quality_warnings: string[];
  is_stale: boolean;
}

export interface MonitoredSAStateDTO {
  id: string;
  gateway_id: string;
  gateway_name: string;
  sensor_id: string;
  sa_type: "IKE_SA" | "CHILD_SA";
  initiator_spi: string;
  responder_spi: string | null;
  child_spi_in: string | null;
  child_spi_out: string | null;
  state: "INITIATING" | "ESTABLISHED" | "REKEYED" | "FAILED" | "EXPIRED" | "DELETED" | "STALE";
  local_endpoint: string | null;
  remote_endpoint: string | null;
  cipher_suite: string | null;
  established_at: string | null;
  last_event_at: string;
  is_stale: boolean;
  staleness_reason: string | null;
  evidence_grade: "OBSERVED" | "INFERRED" | "UNKNOWN" | "UNAVAILABLE";
}

export interface MonitoringEventItemDTO {
  id: string;
  event_id: string;
  schema_version: string;
  sensor_id: string;
  gateway_id: string;
  authorized_scope: string;
  event_kind: string;
  source_timestamp: string;
  received_at: string;
  clock_skew_seconds: number;
  sequence_number: number | null;
  evidence_grade: string;
  raw_source_status: string | null;
  ike_version: string | null;
  local_endpoint: string | null;
  remote_endpoint: string | null;
  initiator_spi: string | null;
  responder_spi: string | null;
  child_spi_in: string | null;
  child_spi_out: string | null;
  cipher_suite: string | null;
  failure_reason: string | null;
  interface_name: string | null;
  packet_count: number | null;
  drop_count: number | null;
  byte_count: number | null;
  artifact_hash: string | null;
}

export interface MonitoringTimelineResponseDTO {
  total_count: number;
  offset: number;
  limit: number;
  items: MonitoringEventItemDTO[];
}

// ============================================================================
// Configuration & Certificate Inventory Types
// ============================================================================

export type InventorySourceType =
  | "CONFIGURED_FILE"
  | "RUNTIME_ACTIVE"
  | "PACKET_OBSERVED"
  | "LAB_CONTROLLED";

export type CertificateValidityStatus =
  | "VALID"
  | "EXPIRED"
  | "NOT_YET_VALID"
  | "EXPIRING_SOON";

export type IdentityAssociationStatus =
  | "MATCHED"
  | "AMBIGUOUS"
  | "UNASSOCIATED";

export type ChainValidationStatus =
  | "VALIDATED"
  | "FAILED"
  | "UNCHECKED";

export type RevocationStatus =
  | "REVOKED"
  | "GOOD"
  | "UNCHECKED";

export type ComparisonStatus =
  | "MATCHED"
  | "DRIFT_DETECTED"
  | "INCOMPARABLE";

export type FieldDriftStatus =
  | "MATCHED"
  | "CHANGED"
  | "MISSING_IN_OBSERVED"
  | "NEW_IN_OBSERVED"
  | "NOT_COMPARABLE"
  | "UNKNOWN"
  | "UNSUPPORTED";

export interface FieldDriftItemDTO {
  field_path: string;
  baseline_value: any;
  observed_value: any;
  status: FieldDriftStatus;
  description: string;
}

export interface ConfigurationSnapshotDTO {
  id: string;
  gateway_id: string | null;
  gateway_identity: string;
  authorized_scope: string;
  source_type: InventorySourceType;
  collection_method: string;
  collector_version: string;
  parser_version: string;
  schema_version: string;
  canonical_digest: string;
  normalized_ir: {
    format: string;
    version: string;
    connections: Record<string, any>;
    secrets: Record<string, any>;
  };
  unsupported_directives: Array<{ path: string; value: string }>;
  is_baseline: boolean;
  baseline_version: number | null;
  approved_by: string | null;
  approval_reference: string | null;
  source_observed_at: string | null;
  provenance: Record<string, any>;
  created_at: string;
}

export interface ConfigurationDriftDTO {
  id: string;
  gateway_identity: string;
  baseline_snapshot_id: string;
  observed_snapshot_id: string;
  comparison_status: ComparisonStatus;
  drift_summary: {
    total_fields: number;
    matched_count: number;
    changed_count: number;
    missing_count: number;
    new_count: number;
    not_comparable_count: number;
    reason?: string;
  };
  field_drifts: FieldDriftItemDTO[];
  created_at: string;
}

export interface GatewayCertificateDTO {
  id: string;
  gateway_id: string | null;
  gateway_identity: string;
  snapshot_id: string | null;
  sha256_fingerprint: string;
  serial_number: string;
  subject_dn: string;
  issuer_dn: string;
  subject_alt_names: {
    dns?: string[];
    ip?: string[];
    email?: string[];
    directory_name?: string[];
  };
  not_valid_before: string;
  not_valid_after: string;
  validity_status: CertificateValidityStatus;
  days_until_expiry: number;
  public_key_algorithm: string;
  public_key_bits: number;
  signature_algorithm: string;
  is_ca: boolean;
  key_usages: string[];
  extended_key_usages: string[];
  associated_connection: string | null;
  identity_association_status: IdentityAssociationStatus;
  chain_validation_status: ChainValidationStatus;
  trust_store_identifier: string | null;
  trust_store_digest: string | null;
  revocation_status: RevocationStatus;
  source_alias: string;
  epistemic_status: string;
  created_at: string;
}

export interface GatewayInventorySummaryDTO {
  gateway_identity: string;
  authorized_scope: string;
  has_baseline: boolean;
  baseline_snapshot_id: string | null;
  baseline_version: number | null;
  latest_snapshot_id: string | null;
  latest_snapshot_digest: string | null;
  latest_snapshot_created_at: string | null;
  latest_drift_status: string | null;
  certificate_count: number;
  expiring_soon_certificates: number;
  expired_certificates: number;
}

export interface ConfigurationImportRequestDTO {
  gateway_identity: string;
  authorized_scope?: string;
  source_type?: InventorySourceType;
  config_text: string;
  collection_method?: string;
  operator_id: string;
  authorization_reference: string;
  source_observed_at?: string;
}

export interface BaselineDesignateRequestDTO {
  operator_id: string;
  approval_reference: string;
  baseline_version?: number;
}

export interface DriftCompareRequestDTO {
  baseline_snapshot_id: string;
  observed_snapshot_id: string;
}

export interface CertificateImportRequestDTO {
  gateway_identity: string;
  snapshot_id?: string;
  certificate_pem: string;
  trust_store_pem?: string;
  source_alias?: string;
  epistemic_status?: string;
  operator_id: string;
  authorization_reference: string;
}

export interface SystemReadinessDTO {
  status: "READY" | "NOT_READY" | string;
  timestamp: string;
  stage: string;
  dependencies: {
    database?: { status: string; engine?: string; error?: string; latency_ms?: number };
    redis?: { status: string; connected_clients?: number; error?: string; latency_ms?: number };
    storage?: { status: string; writable?: boolean; free_space_bytes?: number; root_path?: string; error?: string; latency_ms?: number };
    tshark?: { status: string; version?: string; engine?: string; stage?: string };
    live_capture?: { status: string; stage?: string };
    privileged_agent?: { available: boolean; daemon_running?: boolean; error?: string };
    ml_engine?: { status: string; stage?: string; reason?: string };
    policy_engine?: { status: string; stage?: string };
    [key: string]: any;
  };
}
