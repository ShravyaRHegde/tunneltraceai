"use client";

import React from "react";
import { formatCoverage } from "@/lib/format";
import { AlertTriangle } from "lucide-react";

export interface ScoreDisplayProps {
  score: number | null | undefined;
  coverage?: number | null | undefined;
  riskTier?: string | null | undefined;
  status?: string | null | undefined;
  size?: "sm" | "md" | "lg";
  showCoverage?: boolean;
  className?: string;
}

export function isScoreAssessable(
  score: number | null | undefined,
  coverage?: number | null | undefined,
  status?: string | null | undefined,
  riskTier?: string | null | undefined
): boolean {
  if (score === null || score === undefined) return false;
  if (status === "INSUFFICIENT_EVIDENCE" || status === "NOT_ASSESSABLE") return false;
  if (riskTier === "INSUFFICIENT_EVIDENCE") return false;

  if (coverage !== null && coverage !== undefined) {
    const covPct = coverage <= 1.0 ? coverage * 100 : coverage;
    if (covPct < 60.0) return false;
  }

  return true;
}

export function ScoreDisplay({
  score,
  coverage,
  riskTier,
  status,
  size = "md",
  showCoverage = false,
  className = "",
}: ScoreDisplayProps) {
  const assessable = isScoreAssessable(score, coverage, status, riskTier);
  const covPct = coverage !== null && coverage !== undefined
    ? (coverage <= 1.0 ? coverage * 100 : coverage)
    : null;

  if (!assessable) {
    if (size === "sm") {
      return (
        <div className={`inline-flex flex-col ${className}`}>
          <span className="font-mono font-bold text-amber-500 text-xs tracking-tight flex items-center space-x-1">
            <AlertTriangle className="w-3 h-3 text-amber-500 shrink-0 inline" />
            <span>{covPct && covPct > 0 ? "PARTIAL" : "NOT ASSESSABLE"}</span>
          </span>
          {covPct !== null && (
            <span className="text-[10px] font-mono text-neutral-400">
              {formatCoverage(coverage)} evidence
            </span>
          )}
        </div>
      );
    }

    if (size === "lg") {
      return (
        <div className={`space-y-1 ${className}`}>
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-amber-500" />
            <span className="text-2xl font-mono font-bold text-amber-500">
              NOT ASSESSABLE
            </span>
          </div>
          <p className="text-xs text-amber-600 dark:text-amber-400 font-mono">
            {covPct === 0 || covPct === null
              ? "Zero observable IPsec packet evidence found in capture. Score withheld."
              : `Insufficient evidence (${formatCoverage(coverage)} coverage < 60% threshold). Authoritative score withheld.`}
          </p>
        </div>
      );
    }

    // Default 'md'
    return (
      <div className={`inline-flex items-center space-x-1.5 ${className}`}>
        <span className="px-2 py-0.5 text-xs font-mono font-bold bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800 inline-flex items-center space-x-1">
          <AlertTriangle className="w-3 h-3 text-amber-500 shrink-0" />
          <span>{covPct && covPct > 0 ? `PARTIAL (${formatCoverage(coverage)})` : "NOT ASSESSABLE"}</span>
        </span>
      </div>
    );
  }

  // Assessable score
  const numericScore = Number(score);
  const colorClass =
    numericScore >= 80
      ? "text-emerald-600 dark:text-emerald-400"
      : numericScore >= 60
      ? "text-amber-500 dark:text-amber-400"
      : "text-rose-600 dark:text-rose-400";

  if (size === "sm") {
    const isPartialCoverage = covPct !== null && covPct < 95.0;
    return (
      <span className={`font-mono text-xs inline-flex items-center gap-1 ${className}`}>
        <span className={`font-bold ${colorClass}`}>{numericScore}</span>
        <span className="text-neutral-400 font-normal">/100</span>
        {covPct !== null && (
          <span
            className={`text-[10px] font-mono ${
              isPartialCoverage ? "text-amber-600 dark:text-amber-400" : "text-neutral-400"
            }`}
            title={`Assessed under ${formatCoverage(coverage)} evidence coverage`}
          >
            ({formatCoverage(coverage)})
          </span>
        )}
      </span>
    );
  }

  if (size === "lg") {
    return (
      <div className={`space-y-1 ${className}`}>
        <div className="flex items-baseline space-x-2">
          <span className={`text-3xl font-mono font-bold ${colorClass}`}>
            {numericScore}
          </span>
          <span className="text-sm font-mono text-neutral-400">/ 100</span>
        </div>
        {covPct !== null && (
          <p className="text-[11px] text-neutral-500 font-mono">
            Evaluated on {formatCoverage(coverage)} evidence coverage.
          </p>
        )}
        {covPct !== null && covPct < 95.0 && (
          <div className="mt-1.5 flex items-center space-x-1.5 px-2 py-1 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300 text-[10px] font-mono font-bold uppercase">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
            <span>ASSESSED EVIDENCE ONLY · PARTIAL COVERAGE ({formatCoverage(coverage)})</span>
          </div>
        )}
      </div>
    );
  }

  // Default 'md'
  const isPartialCoverage = covPct !== null && covPct < 95.0;
  return (
    <div className={`inline-flex items-center space-x-1 font-mono ${className}`}>
      <span className={`text-base font-bold ${colorClass}`}>{numericScore}</span>
      <span className="text-neutral-400 text-xs">/100</span>
      {covPct !== null && (
        <span
          className={`text-xs ${
            isPartialCoverage ? "text-amber-600 dark:text-amber-400 font-medium" : "text-neutral-400"
          }`}
          title={`Assessed under ${formatCoverage(coverage)} evidence coverage`}
        >
          ({formatCoverage(coverage)})
        </span>
      )}
    </div>
  );
}

/**
 * Universal helper function returning ScoreDisplay element.
 */
export function renderScore(
  score: number | null | undefined,
  coverage?: number | null | undefined,
  riskTier?: string | null | undefined,
  size: "sm" | "md" | "lg" = "md"
) {
  return <ScoreDisplay score={score} coverage={coverage} riskTier={riskTier} size={size} />;
}
