"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";

interface WebSocketMessage {
  type: string;
  analysis_id?: string;
  status?: string;
  current_stage?: string;
  timestamp?: string;
  data?: unknown;
}

export function useAnalysisWebSocket(analysisId: string | null) {
  const queryClient = useQueryClient();
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const currentUrlRef = useRef<string | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttemptRef = useRef(0);
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const connectRef = useRef<() => void>(() => {});

  const safeClose = useCallback((socket: WebSocket | null) => {
    if (!socket) return;
    socket.onopen = null;
    socket.onmessage = null;
    socket.onerror = null;
    socket.onclose = null;
    if (socket.readyState === WebSocket.OPEN) {
      socket.close();
    } else if (socket.readyState === WebSocket.CONNECTING) {
      socket.onopen = () => {
        try {
          socket.close();
        } catch {}
      };
    }
  }, []);

  const connect = useCallback(() => {
    const wsEnv = process.env.NEXT_PUBLIC_WS_URL;
    let wsUrl: string;
    if (wsEnv) {
      const base = wsEnv.replace(/\/$/, "");
      wsUrl = analysisId ? `${base}/analyses/${analysisId}` : base;
    } else {
      const apiEnv = process.env.NEXT_PUBLIC_API_URL;
      let host = "127.0.0.1:8002";
      let protocol = "ws:";
      if (typeof window !== "undefined") {
        protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        if (apiEnv) {
          try {
            const u = new URL(apiEnv);
            host = u.host;
          } catch {
            host = window.location.hostname + ":8002";
          }
        } else {
          host = window.location.hostname + ":8002";
        }
      }
      wsUrl = analysisId
        ? `${protocol}//${host}/api/v1/ws/analyses/${analysisId}`
        : `${protocol}//${host}/api/v1/ws`;
    }

    if (
      wsRef.current &&
      (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING) &&
      currentUrlRef.current === wsUrl
    ) {
      return;
    }

    if (wsRef.current) {
      safeClose(wsRef.current);
      wsRef.current = null;
    }

    currentUrlRef.current = wsUrl;

    try {
      const socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => {
        setIsConnected(true);
        setConnectionError(null);
        reconnectAttemptRef.current = 0;

        // Keep-alive ping every 25 seconds
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: "PING" }));
          }
        }, 25000);
      };

      socket.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          if (parsed.type === "PONG") return;

          setLastMessage(parsed);

          // If analysis state changed, trigger query invalidation for authoritative REST sync
          if (
            parsed.type === "ANALYSIS_STATE" ||
            parsed.type === "STAGE_COMPLETED" ||
            parsed.type === "ANALYSIS_COMPLETED"
          ) {
            queryClient.invalidateQueries({
              queryKey: ["analysis", analysisId],
            });
            queryClient.invalidateQueries({
              queryKey: ["analysis-overview", analysisId],
            });
          }
        } catch {
          // ignore malformed frame
        }
      };

      socket.onerror = () => {
        setConnectionError("WebSocket connection error");
      };

      socket.onclose = () => {
        setIsConnected(false);
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);

        // Exponential backoff reconnect: max 30s
        const backoff = Math.min(
          1000 * Math.pow(1.5, reconnectAttemptRef.current),
          30000
        );
        reconnectAttemptRef.current += 1;

        reconnectTimeoutRef.current = setTimeout(() => {
          connectRef.current();
        }, backoff);
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to initialize WebSocket";
      setConnectionError(msg);
    }
  }, [analysisId, queryClient, safeClose]);

  useEffect(() => {
    connectRef.current = connect;
    connect();

    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
      if (wsRef.current) {
        safeClose(wsRef.current);
        wsRef.current = null;
      }
      setIsConnected(false);
    };
  }, [connect, safeClose]);

  return {
    isConnected,
    lastMessage,
    connectionError,
  };
}
