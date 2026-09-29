import React from "react";

export interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  compact?: boolean;
  fill?: boolean;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  compact = false,
  fill = false,
}: EmptyStateProps) {
  return (
    <div
      className={`flex flex-col items-center justify-center border-y border-line px-4 text-center ${
        compact ? "py-8" : "py-12"
      } ${fill ? "flex-1" : ""}`}
    >
      {icon && <div className="mb-3 text-ink-3 [&>svg]:h-5 [&>svg]:w-5">{icon}</div>}
      <p className="editorial-title text-2xl">{title}</p>
      {description && (
        <p className="mt-2 max-w-[62ch] text-sm leading-6 text-ink-2">{description}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
