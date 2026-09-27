/**
 * Formatting utilities for metrics and evidence displays.
 */

export function formatCoverage(val: number | null | undefined): string {
  if (val == null) return "N/A";
  const num = Number(val);
  if (isNaN(num)) return "N/A";
  const pct = num <= 1.0 ? num * 100 : num;
  return `${pct.toFixed(1)}%`;
}

export function formatPercent(val: number | null | undefined, decimals: number = 1): string {
  if (val == null) return "N/A";
  const num = Number(val);
  if (isNaN(num)) return "N/A";
  const pct = num <= 1.0 ? num * 100 : num;
  return `${pct.toFixed(decimals)}%`;
}

export function formatRelativeTime(dateStr: string | null | undefined): string {
  if (!dateStr) return "N/A";
  try {
    const date = new Date(dateStr);
    const now = new Date();
    const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);
    if (diffSec < 60) return "Just now";
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return `${Math.floor(diffSec / 86400)}d ago`;
  } catch {
    return "Unknown";
  }
}

