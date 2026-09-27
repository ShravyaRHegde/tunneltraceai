"use client";

import React, { use, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import { EChartWrapper } from "@/components/charts/echart-wrapper";
import * as echarts from "echarts";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { TrafficFlowItemDTO } from "@/lib/api/types";
import {
  Radio,
  AlertCircle,
  HelpCircle,
  AlertTriangle,
  Info,
  CheckCircle2,
  TrendingUp,
} from "lucide-react";

export default function TrafficIntelligencePage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [selectedFlow, setSelectedFlow] = useState<TrafficFlowItemDTO | null>(null);

  const {
    data: traffic,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["traffic-summary", analysisId],
    queryFn: () => api.analyses.getTraffic(analysisId),
  });

  if (isLoading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
        Extracting flow feature vectors and computing 1D-CNN + XGBoost + Calibration + TreeSHAP...
      </div>
    );
  }

  if (isError || !traffic) {
    return (
      <div className="p-6 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 text-center space-y-2 font-mono text-xs text-rose-600">
        <AlertCircle className="w-6 h-6 mx-auto" />
        <p>Failed to load traffic intelligence: {(error as any)?.message || "Unknown error"}</p>
      </div>
    );
  }

  // Aggregate class counts for ECharts
  const classCounts: Record<string, number> = {};
  traffic.flows.forEach((flow) => {
    const cls = flow.final_class || flow.known_class || "UNKNOWN_OOD";
    classCounts[cls] = (classCounts[cls] || 0) + 1;
  });

  const chartOptions: echarts.EChartsOption = {
    tooltip: { trigger: "item" },
    grid: { top: 20, right: 20, bottom: 30, left: 60 },
    xAxis: {
      type: "category",
      data: Object.keys(classCounts),
      axisLabel: { color: "#888", fontSize: 10, rotate: 15 },
    },
    yAxis: {
      type: "value",
      axisLabel: { color: "#888", fontSize: 10 },
      splitLine: { lineStyle: { color: "#333", type: "dashed" } },
    },
    series: [
      {
        name: "Flow Count",
        type: "bar",
        data: Object.values(classCounts),
        itemStyle: { color: "#FF3D00" },
      },
    ],
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <Radio className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            Encrypted Traffic Intelligence & Workload Inference
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          Stage-7 1D-CNN + XGBoost fusion, temperature/Platt calibrated confidence, out-of-distribution (OOD) rejection, TreeSHAP feature attributions, and statistical behavioral anomalies.
        </p>
      </div>

      {/* Persistent Non-Decryption Disclaimer */}
      <div className="p-3 bg-neutral-100 dark:bg-neutral-900/80 border border-neutral-300 dark:border-neutral-800 flex items-start space-x-2.5 text-xs text-neutral-600 dark:text-neutral-400">
        <Info className="w-4 h-4 text-neutral-500 shrink-0 mt-0.5" />
        <p>
          <strong className="font-semibold text-neutral-800 dark:text-neutral-200 uppercase font-mono">
            Encrypted Metadata Inference Notice:
          </strong>{" "}
          Application class inferred from encrypted packet timing, size, and direction metadata. Payload is not decrypted.
        </p>
      </div>

      {/* Model Deployment & Runtime Status Banner */}
      {traffic.ml_run_status === "NOT_CONFIGURED" ? (
        <div className="p-3 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 text-xs text-amber-800 dark:text-amber-300 font-mono space-y-1">
          <div className="flex items-center space-x-2 font-bold uppercase">
            <AlertCircle className="w-4 h-4 text-amber-600 shrink-0" />
            <span>ML Inference Inactive: Model Bundle Not Deployed (STATUS: NOT_CONFIGURED)</span>
          </div>
          <p className="text-[11px] text-amber-700 dark:text-amber-400">
            No validated production model bundle is deployed in <code>models/active/</code>. Flow classifications are unavailable to prevent ungrounded predictions. Deterministic protocol forensics and policy evaluations remain fully operational.
          </p>
        </div>
      ) : traffic.ml_run_status === "BUNDLE_INVALID" ? (
        <div className="p-3 bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 text-xs text-rose-800 dark:text-rose-300 font-mono space-y-1">
          <div className="flex items-center space-x-2 font-bold uppercase">
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
            <span>ML Inference Error: Model Bundle Corrupted or Verification Failed (STATUS: BUNDLE_INVALID)</span>
          </div>
          <p className="text-[11px] text-rose-700 dark:text-rose-400">
            Active model bundle failed cryptographic integrity or schema checks. Inference was halted safely.
          </p>
        </div>
      ) : null}

      {/* KPI Cards */}
      {(() => {
        const isModelActive =
          traffic.ml_run_status === "COMPLETED" && traffic.classified_flows > 0;

        return (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card title="Encrypted Flow Inference">
              <div className="space-y-1 font-mono">
                <div className="text-2xl font-bold text-neutral-900 dark:text-white">
                  {traffic.classified_flows} / {traffic.total_flows}
                </div>
                <p className="text-[11px] text-neutral-500">
                  Run Status:{" "}
                  <span className="font-semibold text-neutral-800 dark:text-neutral-200">
                    {traffic.ml_run_status || "NOT_CONFIGURED"}
                  </span>
                </p>
              </div>
            </Card>

            <Card title="Workload Classes Detected">
              <div className="space-y-1 font-mono">
                <div className={`text-2xl font-bold ${isModelActive ? "text-neutral-900 dark:text-white" : "text-neutral-500 text-lg"}`}>
                  {isModelActive ? (traffic.classes_detected?.length || 0) : "UNAVAILABLE"}
                </div>
                <p className="text-[11px] text-neutral-500 truncate">
                  {isModelActive
                    ? traffic.classes_detected?.join(", ") || "None"
                    : "Active model bundle not deployed"}
                </p>
              </div>
            </Card>

            <Card title="OOD / Rejected Flows">
              <div className="space-y-1 font-mono">
                <div className={`text-2xl font-bold ${isModelActive ? "text-amber-600" : "text-neutral-500 text-lg"}`}>
                  {isModelActive ? traffic.ood_count : "UNAVAILABLE"}
                </div>
                <p className="text-[11px] text-neutral-500">
                  {isModelActive
                    ? "Outside supported model distribution (Not an attack signal)."
                    : "Inference has not executed; OOD unavailable."}
                </p>
              </div>
            </Card>

            <Card title="Behavioral Anomalies">
              <div className="space-y-1 font-mono">
                <div className={`text-2xl font-bold ${isModelActive ? "text-rose-600" : "text-neutral-500 text-lg"}`}>
                  {isModelActive ? traffic.anomaly_count : "UNAVAILABLE"}
                </div>
                <p className="text-[11px] text-neutral-500">
                  {isModelActive
                    ? "Statistical behavioral outliers (Not an attack signal)."
                    : "Inference has not executed; anomaly scoring unavailable."}
                </p>
              </div>
            </Card>
          </div>
        );
      })()}

      {/* Main Workspace (12 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Table & Chart Column */}
        <div className={selectedFlow ? "lg:col-span-8" : "lg:col-span-12"} space-y-6>
          {/* Class Distribution Chart */}
          <Card title="Inferred Traffic Class Distribution">
            {traffic.classified_flows > 0 ? (
              <EChartWrapper
                options={chartOptions}
                height="200px"
                accessibleSummary="Bar chart showing distribution of inferred traffic classes"
              />
            ) : (
              <div className="py-10 text-center font-mono text-xs text-neutral-500">
                {traffic.ml_run_status === "NOT_CONFIGURED"
                  ? "No distribution chart: active model bundle not deployed in models/active/."
                  : "No classified flows available for distribution plotting."}
              </div>
            )}
          </Card>

          {/* Flows Table */}
          <Card title={`Directional Encrypted Flows (${traffic.flows.length})`}>
            {traffic.flows.length > 0 ? (
              <Table>
                <TableHeader>
                  <tr>
                    <TableHead>SPI</TableHead>
                    <TableHead>Supervised Hyp.</TableHead>
                    <TableHead>Accepted Prediction</TableHead>
                    <TableHead>Calibrated Conf.</TableHead>
                    <TableHead>OOD State</TableHead>
                    <TableHead>Behavioral Anomaly</TableHead>
                    <TableHead>Runtime / Input</TableHead>
                    <TableHead>Pkts / Bytes</TableHead>
                  </tr>
                </TableHeader>
                <TableBody>
                  {traffic.flows.map((flow) => {
                    const isOOD =
                      flow.ood_status &&
                      flow.ood_status !== "KNOWN_ACCEPTED" &&
                      flow.ood_status !== "NOT_EVALUATED";
                    const isAnomaly =
                      flow.behavioral_anomaly_status === "STATISTICAL_BEHAVIORAL_ANOMALY" ||
                      flow.behavioral_anomaly_status === "ANOMALOUS_BEHAVIOR";

                    return (
                      <TableRow
                        key={flow.flow_id}
                        onClick={() => setSelectedFlow(flow)}
                        isSelected={selectedFlow?.flow_id === flow.flow_id}
                      >
                        <TableCell mono>
                          <CopyableValue value={flow.spi} label="Flow SPI" />
                        </TableCell>
                        <TableCell mono className="text-neutral-600 dark:text-neutral-400 text-xs">
                          {flow.supervised_hypothesis || flow.known_class || (
                            <span className="text-neutral-400 dark:text-neutral-600">UNAVAILABLE</span>
                          )}
                        </TableCell>
                        <TableCell mono>
                          <span
                            className={`font-bold ${
                              isOOD
                                ? "text-amber-600 dark:text-amber-400"
                                : flow.final_class && flow.final_class !== "UNAVAILABLE"
                                ? "text-neutral-900 dark:text-white"
                                : "text-neutral-400 dark:text-neutral-600"
                            }`}
                          >
                            {flow.accepted_prediction || flow.final_class || "UNAVAILABLE"}
                          </span>
                        </TableCell>
                        <TableCell mono>
                          {flow.calibrated_confidence !== null &&
                          flow.calibrated_confidence !== undefined &&
                          flow.calibrated_confidence > 0 ? (
                            <span>
                              {(flow.calibrated_confidence * 100).toFixed(1)}%
                            </span>
                          ) : (
                            <span className="text-neutral-400 dark:text-neutral-600">UNAVAILABLE</span>
                          )}
                        </TableCell>
                        <TableCell mono>
                          {flow.ood_status ? (
                            isOOD ? (
                              <span className="px-1.5 py-0.5 bg-amber-100 dark:bg-amber-950/40 text-amber-800 dark:text-amber-400 border border-amber-300 dark:border-amber-700 text-[10px] font-bold">
                                {flow.ood_status}
                              </span>
                            ) : (
                              <span className="text-neutral-500 text-[11px]">{flow.ood_status}</span>
                            )
                          ) : (
                            <span className="text-neutral-400 dark:text-neutral-600 text-[11px]">NOT_RUN</span>
                          )}
                        </TableCell>
                        <TableCell mono>
                          {flow.behavioral_anomaly_status ? (
                            isAnomaly ? (
                              <span className="px-1.5 py-0.5 bg-rose-100 dark:bg-rose-950/40 text-rose-800 dark:text-rose-400 border border-rose-300 dark:border-rose-700 text-[10px] font-bold">
                                ANOMALOUS
                              </span>
                            ) : flow.behavioral_anomaly_status === "NORMAL_BEHAVIOR" ? (
                              <span className="text-neutral-500 text-[11px]">NORMAL</span>
                            ) : (
                              <span className="text-neutral-400 text-[11px]">{flow.behavioral_anomaly_status}</span>
                            )
                          ) : (
                            <span className="text-neutral-400 dark:text-neutral-600 text-[11px]">NOT_RUN</span>
                          )}
                        </TableCell>
                        <TableCell mono className="text-[11px]">
                          {flow.input_status === "INSUFFICIENT_INPUT" ? (
                            <span className="text-amber-600 dark:text-amber-400">INSUFFICIENT_INPUT</span>
                          ) : flow.is_degraded ? (
                            <span className="text-amber-500">DEGRADED_SHORT</span>
                          ) : flow.calibrated_confidence ? (
                            <span className="text-emerald-600 dark:text-emerald-400">STANDARD</span>
                          ) : (
                            <span className="text-neutral-400 dark:text-neutral-600">NOT_RUN</span>
                          )}
                        </TableCell>
                        <TableCell mono className="text-neutral-500 text-[11px]">
                          {flow.packet_count} pkts / {(flow.byte_count / 1024).toFixed(1)} KB
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            ) : (
              <div className="py-12 text-center font-mono text-xs text-neutral-500">
                No encrypted flows reconstructed for this capture.
              </div>
            )}
          </Card>
        </div>

        {/* Right Contextual Inspector */}
        {selectedFlow && (
          <div className="lg:col-span-4">
            <InspectorDrawer
              isOpen={!!selectedFlow}
              onClose={() => setSelectedFlow(null)}
              title={`Flow: ${selectedFlow.spi}`}
              subtitle={`Duration: ${selectedFlow.duration_seconds.toFixed(2)}s`}
              badge={
                <span className="px-1.5 py-0.5 font-mono text-[10px] bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700">
                  {selectedFlow.accepted_prediction || selectedFlow.final_class || "UNAVAILABLE"}
                </span>
              }
            >
              <div className="space-y-4">
                {/* Inference Details */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    ML Model Predictions & Provenance
                  </span>
                  <div className="space-y-1.5 font-mono text-xs bg-neutral-50 dark:bg-neutral-900 p-2.5 border border-neutral-200 dark:border-neutral-800">
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Supervised Hypothesis:</span>
                      <span className="font-bold text-neutral-900 dark:text-white">
                        {selectedFlow.supervised_hypothesis || selectedFlow.known_class || "UNAVAILABLE"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Final Accepted Class:</span>
                      <span className="font-bold text-neutral-900 dark:text-white">
                        {selectedFlow.accepted_prediction || selectedFlow.final_class || "UNAVAILABLE"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Calibrated Confidence:</span>
                      <span className="font-bold">
                        {selectedFlow.calibrated_confidence !== null && selectedFlow.calibrated_confidence > 0
                          ? `${(selectedFlow.calibrated_confidence * 100).toFixed(2)}%`
                          : "Unavailable"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Calibration Status:</span>
                      <span>{selectedFlow.calibration_status || "UNAVAILABLE"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Normalized Entropy:</span>
                      <span>
                        {selectedFlow.normalized_entropy !== null
                          ? selectedFlow.normalized_entropy.toFixed(4)
                          : "N/A"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">OOD Evaluation:</span>
                      <span>{selectedFlow.ood_status || "NOT_EVALUATED"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Behavioral Outlier:</span>
                      <span>{selectedFlow.behavioral_anomaly_status || "NOT_EVALUATED"}</span>
                    </div>
                    {selectedFlow.anomaly_score !== null && selectedFlow.anomaly_score !== undefined && (
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Anomaly Score:</span>
                        <span>{selectedFlow.anomaly_score.toFixed(4)}</span>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Runtime Pipeline:</span>
                      <span>
                        {selectedFlow.input_status === "INSUFFICIENT_INPUT"
                          ? "Insufficient input"
                          : selectedFlow.is_degraded
                          ? `Degraded (${selectedFlow.degraded_reason || "Short flow"})`
                          : "Standard Fusion"}
                      </span>
                    </div>
                  </div>
                  <p className="mt-1 text-[9px] font-mono text-neutral-400">
                    Notice: Calibration applies to validation population only. OOD and Behavioral Anomaly indicate statistical divergence, not malicious attacks or system compromise.
                  </p>
                </div>

                {/* XGBoost TreeSHAP Feature Attributions */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] font-mono uppercase text-neutral-400">
                      XGBoost Feature Attribution (SHAP)
                    </span>
                    <span className="text-[9px] font-mono text-neutral-500">
                      TreeSHAP Scope
                    </span>
                  </div>
                  {selectedFlow.top_shap_features &&
                  selectedFlow.top_shap_features.length > 0 ? (
                    <div className="space-y-1.5 font-mono text-xs bg-neutral-50 dark:bg-neutral-900 p-2.5 border border-neutral-200 dark:border-neutral-800">
                      {selectedFlow.top_shap_features.map((feat, idx) => (
                        <div key={idx} className="flex justify-between items-center text-[11px]">
                          <span className="text-neutral-600 dark:text-neutral-400 truncate max-w-[160px]">
                            {feat.feature}
                          </span>
                          <span
                            className={`font-bold ${
                              feat.importance >= 0
                                ? "text-emerald-600 dark:text-emerald-400"
                                : "text-rose-600 dark:text-rose-400"
                            }`}
                          >
                            {feat.importance >= 0 ? "+" : ""}
                            {feat.importance.toFixed(3)}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-[11px] font-mono text-neutral-500">
                      SHAP feature attributions not computed for this flow or OOD rejected.
                    </div>
                  )}
                  <p className="mt-1 text-[9px] font-mono text-neutral-400">
                    Feature attributions apply strictly to the tabular XGBoost classifier branch.
                  </p>
                </div>

                {/* Flow Network Attributes */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    Observed Flow Metadata
                  </span>
                  <div className="space-y-1 font-mono text-xs bg-neutral-50 dark:bg-neutral-900 p-2.5 border border-neutral-200 dark:border-neutral-800">
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Source IP:</span>
                      <span>{selectedFlow.src_ip}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Destination IP:</span>
                      <span>{selectedFlow.dst_ip}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Packets:</span>
                      <span>{selectedFlow.packet_count}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Bytes:</span>
                      <span>{selectedFlow.byte_count}</span>
                    </div>
                  </div>
                </div>
              </div>
            </InspectorDrawer>
          </div>
        )}
      </div>
    </div>
  );
}
