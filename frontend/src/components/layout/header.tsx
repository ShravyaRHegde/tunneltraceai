"use client";

import React, { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Menu, Plus, Radio, Sun, Moon, ChevronRight, ChevronDown, Check, X, Layers } from "lucide-react";
import { useAnalysis } from "@/lib/analysis-context";
import { api } from "@/lib/api/client";
import { StatusBadge } from "../ui/badge";

interface HeaderProps {
  onToggleSidebar?: () => void;
}

export function Header({ onToggleSidebar }: HeaderProps) {
  const router = useRouter();
  const { activeAnalysisId, setActiveAnalysisId, analysis, overview, recentRuns, wsConnected } = useAnalysis();
  const [theme, setTheme] = useState<"light" | "dark">("light");
  const [isRunPickerOpen, setIsRunPickerOpen] = useState(false);
  const pickerRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (pickerRef.current && !pickerRef.current.contains(event.target as Node)) {
        setIsRunPickerOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // System readiness probe for connection status
  const { data: readiness, isError: isReadinessError } = useQuery({
    queryKey: ["system-readiness"],
    queryFn: () => api.system.getReadiness(),
    refetchInterval: 30000,
  });

  useEffect(() => {
    if (localStorage.theme === "dark") {
      document.documentElement.classList.add("dark");
      setTheme("dark");
    } else {
      document.documentElement.classList.remove("dark");
      setTheme("light");
    }
  }, []);

  const toggleTheme = () => {
    if (theme === "light") {
      document.documentElement.classList.add("dark");
      localStorage.theme = "dark";
      setTheme("dark");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.theme = "light";
      setTheme("light");
    }
  };

  const handleSelectRun = (runId: string) => {
    setActiveAnalysisId(runId);
    setIsRunPickerOpen(false);
    router.push(`/analyses/${runId}/overview`);
  };

  const handleClearRun = (e: React.MouseEvent) => {
    e.stopPropagation();
    setActiveAnalysisId(null);
    setIsRunPickerOpen(false);
  };

  return (
    <header className="h-14 bg-white dark:bg-[#111113] border-b border-neutral-300 dark:border-neutral-800 px-4 flex items-center justify-between z-30 relative">
      {/* Left: Mobile Toggle & Active Run Selector */}
      <div className="flex items-center space-x-3">
        <button
          onClick={onToggleSidebar}
          className="lg:hidden p-1.5 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-300"
          aria-label="Toggle navigation menu"
        >
          <Menu className="w-4 h-4" />
        </button>

        {/* Persistent Active Run Selector */}
        <div className="relative" ref={pickerRef}>
          {activeAnalysisId ? (
            <div className="flex items-center space-x-1 sm:space-x-2">
              <button
                onClick={() => setIsRunPickerOpen((prev) => !prev)}
                className="flex items-center space-x-1.5 text-xs py-1 px-1.5 sm:px-2 border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-900 hover:border-[#FF3D00] transition-colors max-w-[145px] xs:max-w-[210px] sm:max-w-none"
                title="Switch active investigation run"
              >
                <span className="font-mono text-neutral-400 uppercase font-bold text-[10px] sm:text-xs">RUN:</span>
                <span className="font-mono font-bold text-neutral-900 dark:text-white truncate">
                  {activeAnalysisId.slice(0, 8)}...
                </span>
                {overview?.capture?.filename && (
                  <span className="hidden md:inline font-mono text-neutral-600 dark:text-neutral-300 truncate max-w-[120px] lg:max-w-[180px]">
                    • {overview.capture.filename}
                  </span>
                )}
                {analysis?.status && (
                  <div className="hidden sm:block">
                    <StatusBadge status={analysis.status} />
                  </div>
                )}
                <ChevronDown className="w-3 h-3 text-neutral-400 shrink-0" />
              </button>

              <button
                onClick={handleClearRun}
                className="p-1 text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200 border border-neutral-200 dark:border-neutral-800 hover:bg-neutral-100 dark:hover:bg-neutral-800 shrink-0"
                title="Deselect active run"
              >
                <X className="w-3 h-3" />
              </button>
            </div>
          ) : (
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setIsRunPickerOpen((prev) => !prev)}
                className="flex items-center space-x-1.5 text-xs font-mono py-1 px-2.5 border border-dashed border-neutral-300 dark:border-neutral-700 hover:border-[#FF3D00] text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white transition-colors"
              >
                <span className="text-[#FF3D00] font-bold">●</span>
                <span>CHOOSE RUN</span>
                <ChevronDown className="w-3 h-3 text-neutral-400" />
              </button>
              <span className="hidden sm:inline text-[11px] font-mono text-neutral-400">
                (or ingest a new PCAP)
              </span>
            </div>
          )}

          {/* Run Picker Dropdown Menu */}
          {isRunPickerOpen && (
            <div className="absolute left-0 top-full mt-1.5 w-72 xs:w-80 sm:w-96 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 shadow-lg p-2 z-50 space-y-2">
              <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-1.5 px-1">
                <span className="text-[10px] font-mono font-bold uppercase text-neutral-500">
                  Select Active Investigation Run
                </span>
                <Link
                  href="/analyses"
                  onClick={() => setIsRunPickerOpen(false)}
                  className="text-[10px] font-mono text-[#FF3D00] hover:underline flex items-center space-x-0.5"
                >
                  <span>Catalog</span>
                  <ChevronRight className="w-3 h-3" />
                </Link>
              </div>

              {recentRuns.length === 0 ? (
                <div className="p-3 text-center text-xs font-mono text-neutral-400">
                  No investigation runs found.
                </div>
              ) : (
                <div className="max-h-60 overflow-y-auto space-y-1">
                  {recentRuns.slice(0, 8).map((r) => {
                    const isSelected = r.analysis_id === activeAnalysisId;
                    return (
                      <button
                        key={r.analysis_id}
                        onClick={() => handleSelectRun(r.analysis_id)}
                        className={`w-full text-left p-2 border transition-colors flex items-center justify-between text-xs font-mono ${
                          isSelected
                            ? "bg-neutral-100 dark:bg-neutral-800 border-[#FF3D00] text-neutral-900 dark:text-white"
                            : "border-neutral-200 dark:border-neutral-800/80 hover:bg-neutral-50 dark:hover:bg-neutral-900 text-neutral-700 dark:text-neutral-300"
                        }`}
                      >
                        <div className="space-y-0.5 truncate pr-2">
                          <div className="flex items-center space-x-1.5">
                            <span className="font-bold truncate max-w-[180px]">
                              {r.capture_filename || "Capture"}
                            </span>
                            {r.is_synthetic_demo && (
                              <span className="text-[9px] px-1 bg-amber-100 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border border-amber-300 dark:border-amber-700/60">
                                DEMO
                              </span>
                            )}
                          </div>
                          <div className="text-[10px] text-neutral-400">
                            ID: {r.analysis_id.slice(0, 8)}... • Score:{" "}
                            {r.security_score !== null && r.security_score !== undefined
                              ? `${r.security_score}/100`
                              : "N/A"}
                          </div>
                        </div>

                        {isSelected && (
                          <Check className="w-4 h-4 text-[#FF3D00] shrink-0" />
                        )}
                      </button>
                    );
                  })}
                </div>
              )}

              <div className="pt-1.5 border-t border-neutral-200 dark:border-neutral-800 flex justify-between items-center text-[10px] font-mono">
                <Link
                  href="/analyses/new"
                  onClick={() => setIsRunPickerOpen(false)}
                  className="text-neutral-600 dark:text-neutral-400 hover:text-[#FF3D00] flex items-center space-x-1"
                >
                  <Plus className="w-3 h-3" />
                  <span>New Ingestion</span>
                </Link>
                {activeAnalysisId && (
                  <button
                    onClick={handleClearRun}
                    className="text-neutral-400 hover:text-rose-500"
                  >
                    Clear selection
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Right: Truthful Connection Status & Quick CTA */}
      <div className="flex items-center space-x-4">
        {/* Realtime Connection Indicator */}
        <div className="flex items-center space-x-1.5 text-[11px] font-mono">
          {wsConnected ? (
            <>
              <Radio className="w-3.5 h-3.5 text-emerald-500 animate-pulse" />
              <span className="hidden sm:inline text-emerald-600 dark:text-emerald-400 font-semibold" title="Browser WebSocket connection to backend event stream is active">
                APP CONNECTION ACTIVE
              </span>
            </>
          ) : !isReadinessError && readiness?.dependencies?.database?.status === "UP" ? (
            <>
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span className="hidden sm:inline text-neutral-600 dark:text-neutral-400">
                POLLING (REST)
              </span>
            </>
          ) : (
            <>
              <span className="w-2 h-2 rounded-full bg-rose-500" />
              <span className="hidden sm:inline text-rose-500 font-semibold">
                OFFLINE
              </span>
            </>
          )}
        </div>

        {/* New Ingest CTA */}
        <Link
          href="/analyses/new"
          className="flex items-center space-x-1 bg-[#FF3D00] hover:bg-[#e03600] text-white text-xs font-mono font-bold px-3 py-1.5 border border-[#FF3D00] transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          <span className="hidden md:inline uppercase">New Ingest</span>
        </Link>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-1.5 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-300 hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
          title={`Switch to ${theme === "light" ? "Dark" : "Light"} theme`}
          aria-label={`Switch to ${theme === "light" ? "Dark" : "Light"} theme`}
        >
          {theme === "light" ? (
            <Moon className="w-4 h-4" />
          ) : (
            <Sun className="w-4 h-4" />
          )}
        </button>
      </div>
    </header>
  );
}
