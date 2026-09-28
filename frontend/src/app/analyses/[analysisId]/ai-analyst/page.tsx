"use client";

import React, { use, useEffect, useState, useRef } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  BookOpen,
  Bot,
  Check,
  CheckCircle2,
  Copy,
  Cpu,
  ExternalLink,
  FileText,
  Layers,
  Lock,
  RefreshCw,
  Search,
  Send,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";

import { Card } from "@/components/ui/card";
import { useAnalysis } from "@/lib/analysis-context";
import { StatusBadge, SeverityBadge } from "@/components/ui/badge";
import { apiClient } from "@/lib/api/client";
import {
  AIChatClaimDTO,
  AIChatCitationDTO,
  AIChatMessageDTO,
  AIChatQueryResponseDTO,
  EvidenceSearchResponseDTO,
  AIHealthResponseDTO,
} from "@/lib/api/types";

interface MessageItem {
  id: string;
  role: "user" | "assistant";
  content: string;
  status?: string;
  claims?: AIChatClaimDTO[];
  citations?: AIChatCitationDTO[];
  limitations?: string[];
  provenance?: {
    answer_hash: string;
    fact_lock_hash: string;
    model_name: string;
    verified_at: string;
  } | null;
  metrics?: {
    total_ms: number;
    generation_ms?: number;
  };
}


export default function AIAnalystPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const { overview } = useAnalysis();

  const failCount = overview?.compliance_counts?.fail ?? 0;
  const score = overview?.security_posture?.score ?? 100;
  const topFinding = overview?.findings_summary?.top_findings?.[0];

  const quickPrompts = React.useMemo(() => {
    const prompts: string[] = [];
    if (failCount > 0 || score < 100) {
      prompts.push("Why did this tunnel fail compliance?");
      if (topFinding) {
        prompts.push(`What evidence supports finding ${topFinding.rule_id || topFinding.finding_id}?`);
      }
    } else {
      prompts.push("Summarize verified cryptographic transforms in this tunnel");
      prompts.push("Explain why this tunnel received a 100/100 score");
    }
    prompts.push("Is Perfect Forward Secrecy (PFS) enabled for Child SAs?");
    prompts.push("What does RFC 8247 require for IKEv2 encryption algorithms?");
    if (overview?.traffic_summary?.total_flows && overview.traffic_summary.total_flows > 0) {
      prompts.push("Explain how encrypted flow timing and metadata were analyzed");
    }
    prompts.push("List the observed Diffie-Hellman groups and key lengths");
    return prompts.slice(0, 5);
  }, [failCount, score, topFinding, overview]);

  // Subsystem state
  const [health, setHealth] = useState<AIHealthResponseDTO | null>(null);
  const [messages, setMessages] = useState<MessageItem[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [inputQuery, setInputQuery] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationStep, setGenerationStep] = useState<string>("");
  const [selectedModel, setSelectedModel] = useState<string>("qwen3:4b-instruct-2507-q4_K_M");
  const [evidenceOnlyMode, setEvidenceOnlyMode] = useState(false);
  const [evidenceSearchResults, setEvidenceSearchResults] = useState<EvidenceSearchResponseDTO | null>(null);
  const [isIngestingKnowledge, setIsIngestingKnowledge] = useState(false);

  // Selected source for highlight in right panel
  const [selectedSourceId, setSelectedSourceId] = useState<string | null>(null);
  const [sourceFilter, setSourceFilter] = useState<"ALL" | "FINDINGS" | "STANDARDS" | "FACTS">("ALL");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Load health & index status on mount
  useEffect(() => {
    async function loadSubsystemStatus() {
      try {
        const h = await apiClient.ai.getHealth();
        setHealth(h);
        if (h.primary_model) {
          setSelectedModel(h.primary_model);
        }
      } catch (err) {
        console.error("Failed to load AI health:", err);
      }
    }
    loadSubsystemStatus();
  }, []);

  // Auto-scroll messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, generationStep]);

  // Handle Query Submission
  const handleSend = async (queryText?: string) => {
    const q = (queryText || inputQuery).trim();
    if (!q || isGenerating) return;

    setInputQuery("");

    // Add user message
    const userMsg: MessageItem = {
      id: `user-${Date.now()}`,
      role: "user",
      content: q,
    };
    setMessages((prev) => [...prev, userMsg]);

    if (evidenceOnlyMode) {
      // Deterministic evidence search fallback
      setIsGenerating(true);
      setGenerationStep("Querying authoritative evidence graph...");
      try {
        const res = await apiClient.ai.searchEvidenceOnly(analysisId, q);
        setEvidenceSearchResults(res);

        const fallbackAnswer: MessageItem = {
          id: `assistant-${Date.now()}`,
          role: "assistant",
          content: `Evidence Search Mode: Retrieved ${res.matched_facts.length} structured fact(s) and ${res.matched_standards.length} standard chunk(s) matching your query without generative AI.`,
          status: "ANSWERED",
          claims: [],
          citations: res.matched_standards.map((s) => ({
            source_id: s.source_id,
            source_type: "standard",
            locator: s.section_reference,
            title: `${s.document_code} ${s.section_reference}`,
            excerpt: s.excerpt,
          })),
          limitations: ["Generated in deterministic Evidence-Search mode (LLM bypassed)."],
        };
        setMessages((prev) => [...prev, fallbackAnswer]);
      } catch (err: any) {
        setMessages((prev) => [
          ...prev,
          {
            id: `assistant-${Date.now()}`,
            role: "assistant",
            content: `Evidence search failed: ${err.message || err}`,
            status: "FAILED",
          },
        ]);
      } finally {
        setIsGenerating(false);
        setGenerationStep("");
      }
      return;
    }

    // Full Grounded RAG Flow
    setIsGenerating(true);
    setGenerationStep("Retrieving forensic analysis facts...");

    try {
      setTimeout(() => {
        setGenerationStep("Assembling FactLock & normative standards context...");
      }, 600);

      setTimeout(() => {
        setGenerationStep(`Generating grounded response via ${selectedModel.split(":")[0]}...`);
      }, 1500);

      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(
          () =>
            reject(
              new Error(
                "The AI assistant request timed out (20-second bounded limit). This may be due to complex evidence aggregation or local model latency. You can still inspect raw forensic findings directly in the Protocol, SA Explorer, or Evidence tabs."
              )
            ),
          20000
        )
      );

      const resp = await Promise.race([
        apiClient.ai.chat(analysisId, {
          question: q,
          session_id: sessionId || undefined,
          model_override: selectedModel,
        }),
        timeoutPromise,
      ]);

      setGenerationStep("Validating citation integrity & fact grounding...");

      if (!sessionId && resp.session_id) {
        setSessionId(resp.session_id);
      }

      const assistantMsg: MessageItem = {
        id: resp.query_run_id,
        role: "assistant",
        content: resp.answer,
        status: resp.status,
        claims: resp.claims,
        citations: resp.citations,
        limitations: resp.limitations,
        provenance: resp.provenance,
        metrics: resp.metrics,
      };

      setMessages((prev) => [...prev, assistantMsg]);

      // If citations returned, select first citation to show in right panel
      if (resp.citations && resp.citations.length > 0) {
        setSelectedSourceId(resp.citations[0].source_id);
      }
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          id: `assistant-${Date.now()}`,
          role: "assistant",
          content: `${err.message || "Model query timed out or runtime offline."}\n\nDeterministic cryptographic facts, compliance decisions, and threat findings remain 100% authoritative and accessible across the Protocol Forensics, SA Explorer, and Evidence tabs.`,
          status: "MODEL_TIMEOUT",
          limitations: [
            "20-second bounded timeout reached before local model completed token generation.",
            "Deterministic facts in database remain 100% accessible and unimpacted.",
          ],
        },
      ]);
    } finally {
      setIsGenerating(false);
      setGenerationStep("");
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Extract all citations from active messages
  const lastAssistantMsg = [...messages].reverse().find((m) => m.role === "assistant");
  const activeCitations = lastAssistantMsg?.citations || [];

  // Filter sources for right panel
  const filteredCitations = activeCitations.filter((cit) => {
    if (sourceFilter === "ALL") return true;
    if (sourceFilter === "FINDINGS") return cit.source_type === "finding" || cit.source_id.includes("finding");
    if (sourceFilter === "STANDARDS") return cit.source_type === "standard" || cit.source_id.includes("standard");
    if (sourceFilter === "FACTS") return ["fact", "sa", "flow", "score", "claim", "verification"].includes(cit.source_type);
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between border-b border-neutral-300 dark:border-neutral-800 pb-4 gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Bot className="w-5 h-5 text-[#FF3D00]" />
            <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
              AI Security Assistant
            </h1>
            <span className="px-2 py-0.5 text-xs font-mono font-bold bg-neutral-900 text-white dark:bg-white dark:text-black">
              EVIDENCE-GROUNDED ADVISOR
            </span>
          </div>
          <p className="text-xs text-neutral-500 mt-1">
            <strong className="text-neutral-700 dark:text-neutral-300">What this shows:</strong> Natural-language explanation of findings strictly grounded in verified packet evidence and cited standards. Cannot hallucinate unobserved facts or override deterministic security scores.
          </p>
        </div>

        {/* Runtime Controls & 4 Independent Status Chips */}
        <div className="flex items-center flex-wrap gap-2 text-xs font-mono">
          {/* Chip 1: Provider Connected */}
          <div
            className="flex items-center px-2 py-1 border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-900"
            title={`Local Ollama Base URL: ${health?.base_url || "http://localhost:11434"}`}
          >
            <span
              className={`w-2 h-2 mr-1.5 rounded-full ${
                health?.status === "healthy"
                  ? "bg-emerald-500"
                  : health?.status === "degraded"
                  ? "bg-amber-500"
                  : "bg-rose-500"
              }`}
            />
            <span className="uppercase text-[10px] text-neutral-600 dark:text-neutral-400 font-bold">
              Provider: {health?.runtime || "OLLAMA"} ({health?.status || "PROBING"})
            </span>
          </div>

          {/* Chip 2: Model Selector / Loaded Status */}
          <div className="flex items-center border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-900 px-2 py-1">
            <Cpu className="w-3.5 h-3.5 text-neutral-500 mr-1.5" />
            <span className="text-neutral-500 mr-1 text-[10px] uppercase font-bold">Model:</span>
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              disabled={isGenerating}
              className="bg-transparent font-bold text-neutral-800 dark:text-neutral-200 outline-none cursor-pointer text-xs"
            >
              <option value="gemma3:4b">Gemma 3 4B (Local)</option>
              <option value="qwen3:4b-instruct-2507-q4_K_M">Qwen 3 4B (Local)</option>
            </select>
          </div>

          {/* Chip 3: Knowledge Chunks Count */}
          <div
            className="flex items-center px-2 py-1 border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-900"
            title={`${health?.total_documents_indexed || 0} standards documents indexed into vector corpus`}
          >
            <BookOpen className="w-3 h-3 text-neutral-500 mr-1.5" />
            <span className="text-[10px] text-neutral-600 dark:text-neutral-400 font-bold uppercase">
              RAG: {health?.total_chunks_indexed ?? 0} Chunks
            </span>
          </div>

          {/* Chip 4: Packet Evidence Linked */}
          <div
            className="flex items-center px-2 py-1 border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-900"
            title="Fact-locked packet observations and rule violations from current analysis"
          >
            <ShieldCheck className="w-3 h-3 text-neutral-500 mr-1.5" />
            <span className="text-[10px] text-neutral-600 dark:text-neutral-400 font-bold uppercase">
              Evidence: {overview?.protocol_summary?.total_observations ?? 0} Facts · {overview?.findings_summary?.total ?? 0} Findings
            </span>
          </div>

          {/* Evidence Only Toggle */}
          <button
            onClick={() => setEvidenceOnlyMode(!evidenceOnlyMode)}
            className={`flex items-center px-2 py-1 border transition-colors ${
              evidenceOnlyMode
                ? "bg-amber-100 border-amber-500 text-amber-900 dark:bg-amber-950 dark:border-amber-700 dark:text-amber-200 font-bold"
                : "bg-white dark:bg-neutral-900 border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-400"
            }`}
            title="Bypass LLM generation and directly query evidence graphs and standards"
          >
            <Search className="w-3.5 h-3.5 mr-1" />
            Evidence Search {evidenceOnlyMode ? "ON" : "OFF"}
          </button>
        </div>
      </div>

      {/* Unindexed Knowledge Warning Banner with Ingest Trigger */}
      {health && health.total_chunks_indexed === 0 && (
        <div className="p-3 bg-amber-50 dark:bg-amber-950/40 border-l-4 border-amber-500 text-xs font-mono text-amber-900 dark:text-amber-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-2 font-bold uppercase">
            <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
            <span>Knowledge base unindexed (0 chunks) — RAG search unavailable</span>
          </div>
          <button
            disabled={isIngestingKnowledge}
            onClick={async () => {
              setIsIngestingKnowledge(true);
              try {
                await apiClient.ai.ingestKnowledge();
                const h = await apiClient.ai.getHealth();
                setHealth(h);
              } catch (e) {
                console.error("Failed to ingest knowledge:", e);
              } finally {
                setIsIngestingKnowledge(false);
              }
            }}
            className="px-3 py-1 bg-amber-600 text-white font-bold hover:bg-amber-700 text-xs uppercase transition-colors shrink-0 disabled:opacity-50"
          >
            {isIngestingKnowledge ? "INDEXING STANDARDS..." : "INDEX STANDARDS NOW"}
          </button>
        </div>
      )}

      {/* Explicit Explanatory Role & Grounding Philosophy Banner */}
      <div className="p-4 bg-neutral-100 dark:bg-neutral-900 border-l-4 border-blue-500 text-xs font-mono space-y-1 text-neutral-800 dark:text-neutral-200">
        <div className="flex items-center space-x-2 font-bold uppercase tracking-wider text-blue-700 dark:text-blue-400">
          <Sparkles className="w-4 h-4 shrink-0" />
          <span>Local Explanatory AI Analyst · Grounded In Evidence</span>
        </div>
        <p className="text-[11px] leading-relaxed text-neutral-600 dark:text-neutral-400">
          This local assistant (<code className="font-bold text-neutral-900 dark:text-white">{selectedModel}</code>) operates strictly as an <strong>explanatory analyst</strong> grounded in persisted packet facts and cited IETF/NIST standards. 
          It is <strong>separate from the Stage 7 encrypted traffic ML classifier</strong> and <strong>cannot create security findings, alter posture scores, or validate configuration fixes</strong>. All assertions require cited evidence hashes or published standard clauses.
        </p>
      </div>

      {/* Main Workspace Layout (8 cols chat + 4 cols sources) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Grounded Conversation Canvas (8 cols) */}
        <div className="lg:col-span-8 space-y-4">
          <Card
            title="Grounded Conversation Canvas"
            actions={
              <div className="flex items-center space-x-2 text-xs font-mono">
                {sessionId && (
                  <span className="text-neutral-400 text-[10px]">
                    Session: {sessionId.slice(0, 8)}
                  </span>
                )}
                <button
                  onClick={() => {
                    setMessages([]);
                    setSessionId(null);
                    setEvidenceSearchResults(null);
                  }}
                  className="px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-600 dark:text-neutral-400"
                >
                  Clear Thread
                </button>
              </div>
            }
          >
            <div className="flex flex-col h-[580px]">
              {/* Message Feed Area */}
              <div className="flex-1 overflow-y-auto space-y-4 p-4 font-mono text-xs">
                {messages.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-center p-6 space-y-4 text-neutral-500">
                    <div className="w-12 h-12 border-2 border-dashed border-neutral-400 dark:border-neutral-700 flex items-center justify-center">
                      <Terminal className="w-6 h-6 text-neutral-400" />
                    </div>
                    <div className="space-y-1">
                      <p className="font-bold text-neutral-800 dark:text-neutral-200 text-sm">
                        TunnelTrace AI Analyst Ready
                      </p>
                      <p className="max-w-md text-xs text-neutral-500">
                        Ask questions about cryptographic compliance, IKE negotiations,
                        Security Posture Score deductions, or Stage 10 closed-loop fixes.
                      </p>
                    </div>

                    {/* Quick suggestion prompt chips */}
                    <div className="pt-2 w-full max-w-lg space-y-2">
                      <p className="text-[10px] text-neutral-400 uppercase tracking-wider">
                        Suggested Forensic Inquiries (Run-Specific)
                      </p>
                      <div className="flex flex-wrap justify-center gap-1.5">
                        {quickPrompts.map((prompt, idx) => (
                          <button
                            key={idx}
                            onClick={() => handleSend(prompt)}
                            disabled={isGenerating}
                            className="px-2.5 py-1 text-left bg-neutral-100 dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-800 hover:border-[#FF3D00] text-neutral-700 dark:text-neutral-300 transition-colors"
                          >
                            {prompt}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  messages.map((msg) => (
                    <div
                      key={msg.id}
                      className={`space-y-2 ${
                        msg.role === "user" ? "pl-8" : "pr-2"
                      }`}
                    >
                      {/* Message Header */}
                      <div className="flex items-center justify-between text-[11px] text-neutral-400">
                        <span className="flex items-center space-x-1.5 font-bold">
                          {msg.role === "user" ? (
                            <>
                              <span className="w-2 h-2 bg-blue-500" />
                              <span className="text-blue-900 dark:text-blue-300">ANALYST QUERY</span>
                            </>
                          ) : (
                            <>
                              <span className="w-2 h-2 bg-[#FF3D00]" />
                              <span className="text-neutral-900 dark:text-white">
                                GROUNDED AI ANALYST ({selectedModel.split(":")[0]})
                              </span>
                            </>
                          )}
                        </span>
                        {msg.status && (
                          <span
                            className={`px-1.5 py-0.2 text-[10px] font-bold border ${
                              msg.status === "ANSWERED"
                                ? "bg-emerald-50 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300"
                                : msg.status === "INSUFFICIENT_EVIDENCE"
                                ? "bg-amber-50 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300"
                                : "bg-neutral-100 text-neutral-800 border-neutral-300 dark:bg-neutral-800 dark:text-neutral-200"
                            }`}
                          >
                            {msg.status}
                          </span>
                        )}
                      </div>

                      {/* Message Body Card */}
                      <div
                        className={`p-3.5 border text-xs leading-relaxed ${
                          msg.role === "user"
                            ? "bg-neutral-50 dark:bg-neutral-900/60 border-neutral-300 dark:border-neutral-800 text-neutral-900 dark:text-neutral-100"
                            : "bg-white dark:bg-neutral-950 border-neutral-400 dark:border-neutral-700 text-neutral-900 dark:text-neutral-100 space-y-3"
                        }`}
                      >
                        {/* Text */}
                        <div className="whitespace-pre-wrap font-sans text-sm">
                          {msg.content}
                        </div>

                        {/* Citation Chips in Answer */}
                        {msg.citations && msg.citations.length > 0 && (
                          <div className="pt-2 border-t border-neutral-200 dark:border-neutral-800 flex flex-wrap gap-1.5 items-center">
                            <span className="text-[10px] text-neutral-500 uppercase tracking-wider mr-1">
                              Cited Sources:
                            </span>
                            {msg.citations.map((c, i) => (
                              <button
                                key={i}
                                onClick={() => setSelectedSourceId(c.source_id)}
                                className={`px-2 py-0.5 text-[11px] font-mono border transition-colors flex items-center space-x-1 ${
                                  selectedSourceId === c.source_id
                                    ? "bg-[#FF3D00] text-white border-[#FF3D00] font-bold"
                                    : "bg-neutral-100 dark:bg-neutral-900 border-neutral-300 dark:border-neutral-700 hover:border-neutral-500"
                                }`}
                              >
                                <span>[{c.source_id.split(":")[0]}: {c.locator || c.title}]</span>
                              </button>
                            ))}
                          </div>
                        )}

                        {/* Itemized Claims with Epistemic State Badges */}
                        {msg.claims && msg.claims.length > 0 && (
                          <div className="pt-2 border-t border-neutral-200 dark:border-neutral-800 space-y-1">
                            <p className="text-[10px] text-neutral-500 uppercase tracking-wider">
                              Verified Epistemic Claims:
                            </p>
                            <div className="space-y-1">
                              {msg.claims.map((claim, ci) => (
                                <div
                                  key={ci}
                                  className="flex items-start justify-between text-[11px] bg-neutral-50 dark:bg-neutral-900 p-1.5 border border-neutral-200 dark:border-neutral-800"
                                >
                                  <span className="text-neutral-800 dark:text-neutral-200 pr-2">
                                    • {claim.text}
                                  </span>
                                  <span
                                    className={`px-1.5 py-0.2 text-[9px] font-mono font-bold uppercase shrink-0 border ${
                                      claim.epistemic_state === "VERIFIED"
                                        ? "bg-emerald-100 text-emerald-900 border-emerald-400"
                                        : claim.epistemic_state === "INFERRED"
                                        ? "bg-blue-100 text-blue-900 border-blue-400"
                                        : claim.epistemic_state === "PROJECTED"
                                        ? "bg-purple-100 text-purple-900 border-purple-400"
                                        : claim.epistemic_state === "VERIFIED_POST_REMEDIATION"
                                        ? "bg-teal-100 text-teal-900 border-teal-400"
                                        : "bg-amber-100 text-amber-900 border-amber-400"
                                    }`}
                                  >
                                    {claim.epistemic_state}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Provenance & Action Footer */}
                        {msg.role === "assistant" && (
                          <div className="pt-2 border-t border-neutral-200 dark:border-neutral-800 flex items-center justify-between text-[10px] text-neutral-400 font-mono">
                            <div className="flex items-center space-x-3">
                              {msg.provenance && (
                                <>
                                  <span title="SHA-256 hash of answer text">
                                    ANS: {msg.provenance.answer_hash.slice(0, 8)}...
                                  </span>
                                  <span title="SHA-256 hash of FactLock context">
                                    FACTS: {msg.provenance.fact_lock_hash.slice(0, 8)}...
                                  </span>
                                </>
                              )}
                              {msg.metrics?.total_ms && (
                                <span>{msg.metrics.total_ms}ms</span>
                              )}
                            </div>

                            <button
                              onClick={() => handleCopy(msg.content, msg.id)}
                              className="flex items-center space-x-1 hover:text-neutral-700 dark:hover:text-neutral-200"
                            >
                              {copiedId === msg.id ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-500" />
                                  <span className="text-emerald-500">COPIED</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span>COPY</span>
                                </>
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  ))
                )}

                {/* Live Grounding State Indicator */}
                {isGenerating && (
                  <div className="p-3 border border-amber-400 dark:border-amber-600 bg-amber-50 dark:bg-amber-950/40 text-amber-900 dark:text-amber-200 space-y-1 animate-pulse">
                    <div className="flex items-center space-x-2 text-xs font-bold">
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>{generationStep || "Processing..."}</span>
                    </div>
                    <p className="text-[11px] text-amber-700 dark:text-amber-400">
                      Enforcing FactLock, standards cross-referencing, and zero-hallucination integrity gates.
                    </p>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>

              {/* Input Control Area */}
              <div className="border-t border-neutral-300 dark:border-neutral-800 p-3 bg-neutral-50 dark:bg-neutral-900/40">
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    handleSend();
                  }}
                  className="flex space-x-2"
                >
                  <input
                    type="text"
                    value={inputQuery}
                    onChange={(e) => setInputQuery(e.target.value)}
                    disabled={isGenerating}
                    placeholder={
                      evidenceOnlyMode
                        ? "Search findings and standards without generative AI..."
                        : "Ask a grounded question about IKE negotiation, findings, or RFCs..."
                    }
                    className="flex-1 px-3 py-2 text-xs font-mono bg-white dark:bg-neutral-950 border border-neutral-300 dark:border-neutral-700 text-neutral-900 dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-[#FF3D00]"
                  />
                  <button
                    type="submit"
                    disabled={!inputQuery.trim() || isGenerating}
                    className="px-4 py-2 bg-[#FF3D00] text-white text-xs font-mono font-bold uppercase tracking-wider flex items-center space-x-1.5 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-[#E63700] transition-colors"
                  >
                    <span>{evidenceOnlyMode ? "SEARCH" : "ASK"}</span>
                    <Send className="w-3.5 h-3.5" />
                  </button>
                </form>
              </div>
            </div>
          </Card>
        </div>

        {/* Right Column: Persistent Sources & Evidence Panel (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          <Card
            title="Forensic Evidence & Standards"
            actions={
              <div className="flex space-x-1 text-[10px] font-mono">
                {(["ALL", "STANDARDS", "FINDINGS", "FACTS"] as const).map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setSourceFilter(cat)}
                    className={`px-1.5 py-0.5 border ${
                      sourceFilter === cat
                        ? "bg-neutral-900 text-white dark:bg-white dark:text-black border-transparent font-bold"
                        : "border-neutral-300 dark:border-neutral-700 text-neutral-500 hover:bg-neutral-100 dark:hover:bg-neutral-800"
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            }
          >
            <div className="space-y-3 text-xs font-mono max-h-[580px] overflow-y-auto pr-1">
              {filteredCitations.length === 0 ? (
                <div className="p-6 text-center text-neutral-400 space-y-2">
                  <BookOpen className="w-6 h-6 mx-auto text-neutral-400" />
                  <p>No sources cited in the current response.</p>
                  <p className="text-[11px] text-neutral-500">
                    When the AI Analyst answers, all verified findings, SA transforms, and RFC normative chunks appear here.
                  </p>
                </div>
              ) : (
                filteredCitations.map((cit, idx) => {
                  const isSelected = selectedSourceId === cit.source_id;
                  const isStandard = cit.source_type === "standard" || cit.source_id.startsWith("standard:");
                  const isFinding = cit.source_type === "finding" || cit.source_id.startsWith("finding:");

                  return (
                    <div
                      key={idx}
                      onClick={() => setSelectedSourceId(cit.source_id)}
                      className={`p-3 border cursor-pointer transition-all ${
                        isSelected
                          ? "bg-neutral-100 dark:bg-neutral-900 border-[#FF3D00] shadow-sm"
                          : "bg-white dark:bg-neutral-950 border-neutral-300 dark:border-neutral-800 hover:border-neutral-400"
                      }`}
                    >
                      <div className="flex items-center justify-between pb-1 border-b border-neutral-200 dark:border-neutral-800">
                        <span className="text-[10px] font-bold text-neutral-500 uppercase tracking-wider">
                          {cit.source_type}
                        </span>
                        <span className="text-[10px] text-neutral-400">
                          {cit.source_id}
                        </span>
                      </div>

                      <div className="pt-2 space-y-1.5">
                        <p className="font-bold text-neutral-900 dark:text-white">
                          {cit.title || cit.locator}
                        </p>
                        {cit.excerpt && (
                          <p className="text-[11px] text-neutral-600 dark:text-neutral-400 leading-normal bg-neutral-50 dark:bg-neutral-900 p-2 border border-neutral-200 dark:border-neutral-800">
                            {cit.excerpt}
                          </p>
                        )}

                        {/* Deep link action button */}
                        <div className="pt-1 flex justify-end">
                          {isFinding ? (
                            <Link
                              href={`/analyses/${analysisId}/security#findings`}
                              className="text-[10px] text-blue-600 dark:text-blue-400 hover:underline flex items-center space-x-1"
                            >
                              <span>Open Finding Inspector</span>
                              <ExternalLink className="w-3 h-3" />
                            </Link>
                          ) : isStandard ? (
                            <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-bold">
                              AUTHORITATIVE LOCAL STANDARD
                            </span>
                          ) : (
                            <Link
                              href={`/analyses/${analysisId}/protocol`}
                              className="text-[10px] text-neutral-500 hover:underline flex items-center space-x-1"
                            >
                              <span>Inspect SA Protocol</span>
                              <ExternalLink className="w-3 h-3" />
                            </Link>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </Card>

          {/* Subsystem Isolation Notice */}
          <div className="p-3 bg-neutral-100 dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-800 text-[11px] font-mono text-neutral-600 dark:text-neutral-400 space-y-1">
            <div className="flex items-center space-x-1.5 font-bold text-neutral-800 dark:text-neutral-200">
              <Lock className="w-3.5 h-3.5 text-[#FF3D00]" />
              <span>Read-Only Explanatory Boundary</span>
            </div>
            <p>
              The AI Analyst is strictly explanatory. It cannot alter Security Scores,
              modify Policy-as-Code rules, or execute strongSwan remediations.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
