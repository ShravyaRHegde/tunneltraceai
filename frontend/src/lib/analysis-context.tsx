"use client";

import React, { createContext, useContext, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api/client";
import { usePathname } from "next/navigation";
import { AnalysisListItemDTO, AnalysisOverviewDTO, AnalysisRunResponseDTO } from "./api/types";
import { useAnalysisWebSocket } from "./use-analysis-websocket";

interface AnalysisContextType {
  activeAnalysisId: string | null;
  setActiveAnalysisId: (id: string | null) => void;
  analysis: AnalysisRunResponseDTO | undefined;
  overview: AnalysisOverviewDTO | undefined;
  recentRuns: AnalysisListItemDTO[];
  isLoading: boolean;
  isError: boolean;
  wsConnected: boolean;
  refetch: () => void;
}

const AnalysisContext = createContext<AnalysisContextType>({
  activeAnalysisId: null,
  setActiveAnalysisId: () => {},
  analysis: undefined,
  overview: undefined,
  recentRuns: [],
  isLoading: false,
  isError: false,
  wsConnected: false,
  refetch: () => {},
});

export function AnalysisProvider({
  children,
  initialAnalysisId,
}: {
  children: React.ReactNode;
  initialAnalysisId?: string;
}) {
  const pathname = usePathname();
  // Synchronously extract analysisId from pathname if route is /analyses/:id/...
  const pathMatch = pathname ? pathname.match(/^\/analyses\/([^/]+)/) : null;
  const pathAnalysisId = pathMatch && pathMatch[1] !== "new" ? pathMatch[1] : null;

  const [storedAnalysisId, setStoredAnalysisId] = useState<string | null>(() => {
    if (typeof window !== "undefined") {
      try {
        return localStorage.getItem("tunneltrace_active_analysis_id");
      } catch {
        return null;
      }
    }
    return null;
  });

  // Effective ID prioritizes initial prop, current URL path, or last stored ID
  const activeAnalysisId = initialAnalysisId ?? pathAnalysisId ?? storedAnalysisId;

  // Sync back to localStorage if activeAnalysisId is determined from path
  React.useEffect(() => {
    if (pathAnalysisId && pathAnalysisId !== storedAnalysisId) {
      setStoredAnalysisId(pathAnalysisId);
      try {
        localStorage.setItem("tunneltrace_active_analysis_id", pathAnalysisId);
      } catch {}
    }
  }, [pathAnalysisId, storedAnalysisId]);

  const setActiveAnalysisId = (id: string | null) => {
    setStoredAnalysisId(id);
    if (typeof window !== "undefined") {
      try {
        if (id) {
          localStorage.setItem("tunneltrace_active_analysis_id", id);
        } else {
          localStorage.removeItem("tunneltrace_active_analysis_id");
        }
      } catch {}
    }
  };

  const {
    data: recentRunsData,
  } = useQuery({
    queryKey: ["analyses-list"],
    queryFn: () => api.analyses.list(),
    staleTime: 30000,
  });

  const {
    data: analysis,
    isLoading: isAnalysisLoading,
    isError: isAnalysisError,
    refetch: refetchAnalysis,
  } = useQuery({
    queryKey: ["analysis", activeAnalysisId],
    queryFn: () => (activeAnalysisId ? api.analyses.get(activeAnalysisId) : null),
    enabled: !!activeAnalysisId,
  });

  const {
    data: overview,
    isLoading: isOverviewLoading,
    isError: isOverviewError,
    refetch: refetchOverview,
  } = useQuery({
    queryKey: ["analysis-overview", activeAnalysisId],
    queryFn: () =>
      activeAnalysisId ? api.analyses.getOverview(activeAnalysisId) : null,
    enabled: !!activeAnalysisId,
  });

  const { isConnected: wsConnected } = useAnalysisWebSocket(activeAnalysisId);

  const refetch = () => {
    refetchAnalysis();
    refetchOverview();
  };

  return (
    <AnalysisContext.Provider
      value={{
        activeAnalysisId,
        setActiveAnalysisId,
        analysis: analysis || undefined,
        overview: overview || undefined,
        recentRuns: recentRunsData || [],
        isLoading: isAnalysisLoading || isOverviewLoading,
        isError: isAnalysisError || isOverviewError,
        wsConnected,
        refetch,
      }}
    >
      {children}
    </AnalysisContext.Provider>
  );
}

export function useAnalysis() {
  return useContext(AnalysisContext);
}
