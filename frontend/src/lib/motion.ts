"use client";

import { useEffect, useLayoutEffect, useRef, useState } from "react";

const useHydratedEffect =
  typeof window === "undefined" ? useEffect : useLayoutEffect;

export const EASE = "cubic-bezier(0.16, 1, 0.3, 1)";

export function easeOutExpo(t: number): number {
  return t === 1 ? 1 : 1 - Math.pow(2, -10 * t);
}

export function prefersReducedMotion(): boolean {
  if (typeof window === "undefined") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export interface CountUpOptions {
  duration?: number;
  delay?: number;
  decimals?: number;
}

export function useCountUp(
  target: number | null | undefined,
  options: CountUpOptions = {}
): string {
  const { duration = 800, delay = 0, decimals = 0 } = options;
  const numeric =
    target === null || target === undefined || !Number.isFinite(Number(target))
      ? null
      : Number(target);

  const [value, setValue] = useState(numeric ?? 0);
  const frameRef = useRef<number | null>(null);
  const timerRef = useRef<number | null>(null);
  const previousRef = useRef<number | null>(null);

  useHydratedEffect(() => {
    const from = previousRef.current ?? 0;
    previousRef.current = numeric;

    if (numeric === null) {
      setValue(0);
      return;
    }

    if (prefersReducedMotion() || from === numeric) {
      setValue(numeric);
      return;
    }

    setValue(from);

    const startAt = performance.now() + delay;
    const tick = (now: number) => {
      const elapsed = now - startAt;
      if (elapsed < 0) {
        frameRef.current = requestAnimationFrame(tick);
        return;
      }
      const progress = Math.min(elapsed / duration, 1);
      setValue(from + (numeric - from) * easeOutExpo(progress));
      frameRef.current =
        progress < 1 ? requestAnimationFrame(tick) : null;
      if (progress >= 1) setValue(numeric);
    };

    timerRef.current = window.setTimeout(() => {
      timerRef.current = null;
      frameRef.current = requestAnimationFrame(tick);
    }, delay);

    return () => {
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
      if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
      timerRef.current = null;
      frameRef.current = null;
    };
  }, [numeric, duration, delay]);

  return (numeric === null ? 0 : value).toFixed(decimals);
}
