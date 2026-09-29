"use client";

import React, { useEffect, useId, useRef, useState } from "react";
import { ArrowDown, ArrowLeft, ArrowRight } from "lucide-react";
import { prefersReducedMotion } from "@/lib/motion";

const steps = [
  { title: "PCAP ingestion", tag: ".PCAP · .PCAPNG", detail: "Start with an authorized capture. TunnelTrace keeps the original file hash attached to the run." },
  { title: "Protocol analysis", tag: "IKE · IKEV2 · UDP", detail: "Reconstruct negotiations and security associations from the packets that were observed." },
  { title: "Traffic analysis", tag: "CHILD SA · ESP", detail: "Follow endpoint pairs and encrypted flows through the established tunnel." },
  { title: "Detection", tag: "POLICY · CRYPTOGRAPHY", detail: "Evaluate protocol and cryptographic posture against the evidence available in the capture." },
  { title: "Findings", tag: "SEVERITY · STATUS", detail: "Review each result with its severity and evidence state. Missing evidence stays unknown." },
  { title: "Evidence", tag: "FRAMES · HASH · LINEAGE", detail: "Trace conclusions back to packet frames, source hashes, and reproducible analysis runs." },
  { title: "Investigation", tag: "RUN · REPORT · REPLAY", detail: "Keep the capture, analysis, findings, and exported report together as one investigation." },
];

const points = [
  { x: 66, y: 270, title: "PCAP" },
  { x: 166, y: 270, title: "PROTOCOL" },
  { x: 266, y: 158, title: "TRAFFIC" },
  { x: 366, y: 270, title: "DETECTION" },
  { x: 466, y: 158, title: "FINDINGS" },
  { x: 566, y: 270, title: "EVIDENCE" },
  { x: 666, y: 158, title: "INVESTIGATION" },
];

function InvestigationGraph({ activeStep }: { activeStep: number }) {
  const gridId = useId().replaceAll(":", "");
  const progress = steps.length < 2 ? 0 : (activeStep / (steps.length - 1)) * 100;
  return (
    <div className="trace-graph relative" role="img" aria-label={`Illustrative TunnelTrace workflow map. Current step: ${steps[activeStep].title}. This is not capture data.`}>
      <div className="absolute left-4 top-4 z-10 flex items-center gap-2 micro-label text-ink-3">
        <span className="h-1.5 w-1.5 rounded-full bg-accent-press" />SCHEMATIC · NOT CAPTURE DATA
      </div>
      <svg viewBox="0 0 740 440" className="h-full min-h-[17rem] w-full" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
        <defs>
          <pattern id={gridId} width="34" height="34" patternUnits="userSpaceOnUse">
            <path d="M34 0H0V34" fill="none" stroke="var(--color-line)" strokeWidth=".7" />
          </pattern>
        </defs>
        <rect width="740" height="440" fill={`url(#${gridId})`} />
        <g fill="none" stroke="var(--color-line-strong)" strokeWidth="2">
          <path d="M36 270H166L266 158L366 270L466 158L566 270L706 270" />
          <path d="M66 270V105H200M266 158V80H370M366 270V372H500M466 158V86H610M566 270V360H700" strokeDasharray="4 8" />
          <path d="M166 270L220 340M366 270L420 190M566 270L620 205" />
        </g>
        <path d="M36 270H166L266 158L366 270L466 158L566 270L706 270" fill="none" stroke="var(--color-ink)" strokeWidth="8" pathLength="100" strokeDasharray="100" strokeDashoffset={100 - progress} className="trace-progress-line" />
        <path d="M36 270H166L266 158L366 270L466 158L566 270L706 270" fill="none" stroke="var(--color-accent)" strokeWidth="4" pathLength="100" strokeDasharray="100" strokeDashoffset={100 - progress} className="trace-progress-line" />
        <g fill="var(--color-ink-3)" fontFamily="var(--font-mono)" fontSize="9" letterSpacing="1">
          <text x="69" y="93">SOURCE FILE</text>
          <text x="276" y="68">IKE EXCHANGE</text>
          <text x="425" y="383">PACKET REFERENCES</text>
          <text x="610" y="73">RUN LINEAGE</text>
          <text x="177" y="363">ENDPOINT PAIR</text>
          <text x="613" y="195">RULE STATE</text>
        </g>
        {points.map((point, index) => {
          const complete = index < activeStep;
          const active = index === activeStep;
          const color = complete || active ? "var(--color-ink)" : "var(--color-ink-3)";
          const nodeFill = complete || active ? "var(--color-accent)" : "var(--color-ground)";
          return (
            <g key={point.title} className={`trace-node ${active ? "is-active" : ""}`}>
              {active && <circle cx={point.x} cy={point.y} r="19" fill="none" stroke="var(--color-accent-border)" strokeWidth="1" className="trace-node-ring" />}
              <circle cx={point.x} cy={point.y} r="11" fill="var(--color-ground)" stroke={color} strokeWidth="2" />
              <circle cx={point.x} cy={point.y} r="5" fill={nodeFill} />
              <text x={point.x} y={point.y + 32} textAnchor="middle" fill={color} fontFamily="var(--font-mono)" fontSize="9" fontWeight={active ? "700" : "500"} letterSpacing=".4">{point.title}</text>
            </g>
          );
        })}
      </svg>
      <div className="absolute bottom-4 left-4 right-4 flex items-center justify-between border-t border-line pt-2 font-mono text-[.62rem] uppercase tracking-[.08em] text-ink-3">
        <span>Step {String(activeStep + 1).padStart(2, "0")} / {String(steps.length).padStart(2, "0")}</span>
        <span>{steps[activeStep].tag}</span>
      </div>
    </div>
  );
}

export function InvestigationPath() {
  const [activeStep, setActiveStep] = useState(0);
  const chapters = useRef<(HTMLElement | null)[]>([]);

  useEffect(() => {
    if (!("IntersectionObserver" in window)) return;
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      const index = visible ? Number((visible.target as HTMLElement).dataset.stepIndex) : NaN;
      if (Number.isInteger(index)) setActiveStep(index);
    }, { rootMargin: "-42% 0px -42% 0px", threshold: [0, .25, .5, .75, 1] });
    chapters.current.forEach((chapter) => chapter && observer.observe(chapter));
    return () => observer.disconnect();
  }, []);

  const goToStep = (index: number) => {
    setActiveStep(index);
    chapters.current[index]?.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "center" });
  };

  return (
    <section id="path" className="border-y border-line bg-panel-2/50">
      <div className="page-wrap py-14 sm:py-20">
        <div className="mb-9 grid gap-5 border-b border-line pb-6 sm:grid-cols-[.75fr_1.25fr] sm:items-end sm:gap-10">
          <div>
            <span className="micro-label text-ink-3">The investigation path</span>
            <h2 className="mt-3 max-w-[12ch] font-sans text-4xl font-bold leading-[.98] tracking-[-.055em] sm:text-6xl">One capture.<br />A traceable path.</h2>
          </div>
          <p className="max-w-[54ch] text-sm leading-6 text-ink-2">Move through the evidence in sequence. Scroll naturally to advance; use the step controls to jump directly. The diagram is illustrative until you open a capture.</p>
        </div>

        <div className="grid gap-8 lg:grid-cols-[.8fr_1.2fr] lg:gap-12">
          <div className="path-chapters">
            {steps.map((step, index) => (
              <article key={step.title} id={`path-step-${index + 1}`} ref={(node) => { chapters.current[index] = node; }} data-step-index={index} data-active={activeStep === index} data-complete={index < activeStep} aria-current={activeStep === index ? "step" : undefined} aria-labelledby={`path-step-heading-${index + 1}`} className="path-chapter flex min-h-[51svh] flex-col justify-center border-b border-line py-10 transition-colors duration-500 lg:min-h-[68svh]">
                <div className="flex items-center gap-3 font-mono text-[.68rem] uppercase tracking-[.1em] text-ink-3">
                  <span className={`grid h-9 w-9 place-items-center border ${index <= activeStep ? "border-accent-border text-ink" : "border-line-strong text-ink-3"}`}>{String(index + 1).padStart(2, "0")}</span>
                  <span>{step.tag}</span>
                  <span className="ml-auto">{index < activeStep ? "Complete" : index === activeStep ? "Current step" : "Upcoming"}</span>
                </div>
                <h3 id={`path-step-heading-${index + 1}`} className="mt-6 max-w-[13ch] font-sans text-4xl font-bold leading-[.98] tracking-[-.055em] sm:text-5xl">{step.title}</h3>
                <p className="mt-4 max-w-[48ch] text-sm leading-6 text-ink-2">{step.detail}</p>
                <button type="button" onClick={() => goToStep(Math.min(index + 1, steps.length - 1))} disabled={index === steps.length - 1} className="mt-8 inline-flex min-h-11 w-fit items-center gap-2 border-b border-line-strong text-sm font-medium transition-colors hover:border-ink hover:text-ink disabled:hidden cursor-pointer">Continue to next step <ArrowDown className="h-4 w-4" /></button>
              </article>
            ))}
          </div>

          <aside className="hidden lg:block">
            <div className="sticky top-28 space-y-4">
              <InvestigationGraph activeStep={activeStep} />
              <nav aria-label="Investigation path steps" className="grid grid-cols-7 gap-1">
                {steps.map((step, index) => (
                  <button key={step.title} type="button" onClick={() => goToStep(index)} aria-label={`Go to step ${index + 1}: ${step.title}`} aria-current={activeStep === index ? "step" : undefined} className={`h-10 border-t-2 text-[.6rem] font-mono transition-colors cursor-pointer ${activeStep === index ? "border-accent-press text-ink" : index < activeStep ? "border-line-strong text-ink-2" : "border-line text-ink-3 hover:text-ink"}`}>{String(index + 1).padStart(2, "0")}</button>
                ))}
              </nav>
              <div className="flex items-center justify-between border-t border-line pt-3">
                <button type="button" onClick={() => goToStep(Math.max(0, activeStep - 1))} disabled={activeStep === 0} className="inline-flex min-h-10 items-center gap-2 text-xs text-ink-2 transition-colors hover:text-ink disabled:opacity-40 cursor-pointer"><ArrowLeft className="h-4 w-4" />Previous</button>
                <span className="font-mono text-[.65rem] text-ink-3">{steps[activeStep].title}</span>
                <button type="button" onClick={() => goToStep(Math.min(steps.length - 1, activeStep + 1))} disabled={activeStep === steps.length - 1} className="inline-flex min-h-10 items-center gap-2 text-xs text-ink-2 transition-colors hover:text-ink disabled:opacity-40 cursor-pointer">Next<ArrowRight className="h-4 w-4" /></button>
              </div>
            </div>
          </aside>
        </div>
      </div>
    </section>
  );
}

export { InvestigationGraph };
