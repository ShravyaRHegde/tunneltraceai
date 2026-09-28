"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";
import Link from "next/link";
import "./landing.css";

interface Pillar {
  eyebrow: string;
  title: string;
  body: string;
}

const pillars: Pillar[] = [
  {
    eyebrow: "01 / FORENSICS",
    title: "Reconstruct the tunnel from the capture.",
    body: "Parse IKE_SA_INIT, IKE_AUTH and CREATE_CHILD_SA exchanges from PCAP files. Recover negotiated transforms, tunnel endpoints and packet-level evidence for every frame.",
  },
  {
    eyebrow: "02 / TRAFFIC INTELLIGENCE",
    title: "Classify encrypted traffic without payload access.",
    body: "Infer application behavior across 24 statistical flow features (packet size, inter-arrival timing, burst dynamics, directionality). Zero decryption required — payload stays fully encrypted.",
  },
  {
    eyebrow: "03 / POLICY",
    title: "Compare observed transforms against expected policy.",
    body: "Trace negotiated parameters against NIST SP 800-77 Rev. 1 & RFC compliance rules. Identify cipher suite vulnerabilities, weak DH groups, and policy deviations. Score posture 0–100.",
  },
  {
    eyebrow: "04 / REMEDIATION",
    title: "Harden the config, test it, verify the fix.",
    body: "Generate corrected strongSwan / swanctl configuration patches. Deploy in an isolated twin, capture fresh traffic and verify the security posture improves.",
  },
];

export default function LandingPage() {
  const [demoOpen, setDemoOpen] = useState(false);
  const [active, setActive] = useState("Overview");
  const activeTransitionRef = useRef<string | null>(null);
  const [capRun, setCapRun] = useState(0);
  const progressRef = useRef<HTMLDivElement>(null);
  const programmaticScrollRef = useRef(false);
  const scrollAnimationRef = useRef<number | null>(null);
  const railRef = useRef<HTMLElement>(null);
  const railPathRef = useRef<SVGPathElement>(null);
  const railDotRef = useRef<SVGCircleElement>(null);
  const railStopsRef = useRef<(HTMLSpanElement | null)[]>([]);

  useEffect(() => {
    const navSections = Array.from(document.querySelectorAll<HTMLElement>("[data-nav]"));
    const sectionObserver = new IntersectionObserver(
      (entries) => {
        if (activeTransitionRef.current) return;
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (visible && visible.target instanceof HTMLElement && visible.target.dataset.nav) {
          setActive(visible.target.dataset.nav);
        }
      },
      { threshold: [0.2, 0.45, 0.7] }
    );
    navSections.forEach((section) => sectionObserver.observe(section));

    const revealObserver = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) entry.target.classList.add("in-view");
          else if (!entry.target.classList.contains("feature-card")) entry.target.classList.remove("in-view");
        });
      },
      { threshold: 0.18 }
    );
    document.querySelectorAll(".reveal").forEach((element) => revealObserver.observe(element));

    const capabilitiesSection = document.querySelector("#capabilities");
    let wasCapabilitiesInView = false;
    const capabilityObserver = capabilitiesSection
      ? new IntersectionObserver(
          (entries) => {
            entries.forEach((entry) => {
              if (entry.isIntersecting && !wasCapabilitiesInView) {
                wasCapabilitiesInView = true;
                setCapRun((value) => value + 1);
              }
              if (!entry.isIntersecting) {
                wasCapabilitiesInView = false;
              }
            });
          },
          { threshold: 0.28 }
        )
      : null;
    if (capabilitiesSection && capabilityObserver) capabilityObserver.observe(capabilitiesSection);

    const chapters = navSections;

    const updateScrollUI = () => {
      const max = document.documentElement.scrollHeight - window.innerHeight;
      const pct = max ? (window.scrollY / max) * 100 : 0;
      if (progressRef.current) progressRef.current.style.width = `${pct}%`;

      if (railRef.current && railPathRef.current && railDotRef.current && chapters.length) {
        const tops = chapters.map((section) => section.offsetTop);
        const y = window.scrollY;
        let railProgress = 0;
        if (y <= tops[0]) {
          railProgress = 0;
        } else if (y >= tops[tops.length - 1]) {
          railProgress = 1;
        } else {
          for (let i = 0; i < tops.length - 1; i += 1) {
            if (y >= tops[i] && y <= tops[i + 1]) {
              const span = Math.max(1, tops[i + 1] - tops[i]);
              const local = (y - tops[i]) / span;
              railProgress = (i + local) / (tops.length - 1);
              break;
            }
          }
        }

        const pathLength = 600;
        const pathOffset = pathLength * (1 - railProgress);
        railPathRef.current.style.strokeDashoffset = `${pathOffset}`;
        const dotY = 60 + railProgress * 600;
        railDotRef.current.setAttribute("cy", `${dotY}`);
        const halo = railRef.current.querySelector(".rail-dot-halo");
        if (halo) halo.setAttribute("cy", `${dotY}`);
        railDotRef.current.style.setProperty("--rail-progress", railProgress.toFixed(4));
        railRef.current.style.setProperty("--rail-progress", railProgress.toFixed(4));

        const activeIndex = Math.min(
          chapters.length - 1,
          Math.max(0, Math.round(railProgress * (chapters.length - 1)))
        );
        railStopsRef.current.forEach((stop, index) => {
          if (!stop) return;
          stop.classList.toggle("is-active", index === activeIndex);
          stop.classList.toggle("is-passed", index < activeIndex);
        });
      }
    };

    let scrollRAF: number | null = null;
    const onScroll = () => {
      if (scrollRAF) return;
      scrollRAF = requestAnimationFrame(() => {
        scrollRAF = null;
        updateScrollUI();
      });
    };

    const wheelBusyRef = { current: false };
    let settleTimer: number | null = null;

    const easeInOut = (t: number) =>
      t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;

    const getCurrentChapterIndex = () => {
      if (!chapters.length) return 0;
      const currentY = window.scrollY;
      let bestIndex = 0;
      let bestDistance = Infinity;

      chapters.forEach((section, index) => {
        const distance = Math.abs(section.offsetTop - currentY);
        if (distance < bestDistance) {
          bestDistance = distance;
          bestIndex = index;
        }
      });

      return bestIndex;
    };

    const stopAnimation = () => {
      if (scrollAnimationRef.current) {
        cancelAnimationFrame(scrollAnimationRef.current);
        scrollAnimationRef.current = null;
      }
    };

    const animateScrollTo = (targetY: number, duration = 1150, done?: () => void) => {
      stopAnimation();
      const startY = window.scrollY;
      const distance = targetY - startY;

      if (Math.abs(distance) < 1) {
        window.scrollTo(0, targetY);
        done?.();
        return;
      }

      const startTime = performance.now();
      const tick = (now: number) => {
        const progress = Math.min(1, (now - startTime) / duration);
        window.scrollTo(0, startY + distance * easeInOut(progress));

        if (progress < 1) {
          scrollAnimationRef.current = requestAnimationFrame(tick);
        } else {
          scrollAnimationRef.current = null;
          done?.();
        }
      };

      scrollAnimationRef.current = requestAnimationFrame(tick);
    };

    const goToChapter = (index: number) => {
      const section = chapters[index];
      if (!section) return;

      const targetY = Math.max(0, section.offsetTop);

      wheelBusyRef.current = true;
      activeTransitionRef.current = section.dataset.nav || null;
      animateScrollTo(targetY, 1150, () => {
        if (activeTransitionRef.current === section.dataset.nav) {
          setActive(section.dataset.nav);
          activeTransitionRef.current = null;
        }
        if (settleTimer) window.clearTimeout(settleTimer);
        settleTimer = window.setTimeout(() => {
          wheelBusyRef.current = false;
        }, 160);
      });
    };

    const onWheel = (event: WheelEvent) => {
      if (window.innerWidth < 1021) return;
      if (event.ctrlKey || event.metaKey) return;
      if (document.body.classList.contains("modal-is-open")) return;
      if (Math.abs(event.deltaY) <= Math.abs(event.deltaX) || event.deltaY === 0) return;

      event.preventDefault();

      if (wheelBusyRef.current || programmaticScrollRef.current) return;

      const currentIndex = getCurrentChapterIndex();
      const nextIndex =
        event.deltaY > 0
          ? Math.min(chapters.length - 1, currentIndex + 1)
          : Math.max(0, currentIndex - 1);

      if (nextIndex === currentIndex) return;
      goToChapter(nextIndex);
    };

    window.addEventListener("wheel", onWheel, { passive: false, capture: true });
    window.addEventListener("scroll", onScroll, { passive: true });
    updateScrollUI();

    return () => {
      sectionObserver.disconnect();
      revealObserver.disconnect();
      capabilityObserver?.disconnect();
      window.removeEventListener("wheel", onWheel, { capture: true });
      window.removeEventListener("scroll", onScroll);
      if (scrollRAF) cancelAnimationFrame(scrollRAF);
      if (settleTimer) window.clearTimeout(settleTimer);
    };
  }, []);

  const go = (id: string, nav: string) => {
    const target = document.getElementById(id);
    if (!target) return;

    const targetY = Math.max(0, target.offsetTop);
    const startY = window.scrollY;
    const distance = targetY - startY;
    const startTime = performance.now();
    const duration = 1150;
    const ease = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);

    programmaticScrollRef.current = true;
    activeTransitionRef.current = nav;

    const tick = (now: number) => {
      const progress = Math.min(1, (now - startTime) / duration);
      window.scrollTo(0, startY + distance * ease(progress));
      if (progress < 1) {
        requestAnimationFrame(tick);
      } else {
        if (activeTransitionRef.current === nav) {
          setActive(nav);
          activeTransitionRef.current = null;
        }
        window.setTimeout(() => {
          programmaticScrollRef.current = false;
        }, 160);
      }
    };

    requestAnimationFrame(tick);
  };

  useEffect(() => {
    document.body.classList.toggle("modal-is-open", demoOpen);
    return () => document.body.classList.remove("modal-is-open");
  }, [demoOpen]);

  return (
    <div className="site-shell">
      <div className="scroll-progress" ref={progressRef} />
      <ScrollRail railRef={railRef} pathRef={railPathRef} dotRef={railDotRef} stopsRef={railStopsRef} />
      
      {/* Side Bottom Toast Pop-up: Only on first scroll of landing page */}
      <SihTeamToast />

      <header className="nav-wrap">
        <nav className="nav">
          <button className="brand" onClick={() => go("top", "Overview")} aria-label="TunnelTrace home">
            <span className="brand-mark"><span /></span>
            <span>TunnelTrace</span>
          </button>
          <div className="nav-links">
            {[
              ["Overview", "top"],
              ["Capabilities", "capabilities"],
              ["Platform", "platform"],
              ["Workflow", "workflow"],
            ].map(([label, id]) => (
              <button
                key={label}
                className={active === label ? "nav-link active" : "nav-link"}
                onClick={() => go(id, label)}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="nav-actions">
            <a className="nav-text" href="https://github.com/sharancode3/TunnelTrace-AI" target="_blank" rel="noreferrer">
              GitHub ↗
            </a>
            <Link href="/dashboard" className="nav-cta">
              View console
            </Link>
          </div>
        </nav>
      </header>

      <main>
        <section id="top" className="hero section-dark chapter" data-nav="Overview">
          <div className="hero-content">
            <h1>
              Reconstruct the tunnel.<br />
              <em>Prove what happened.</em>
            </h1>
            <p className="hero-copy">
              Load a PCAP. TunnelTrace reconstructs IKEv2 and ESP sessions, traces negotiated cryptography, infers encrypted traffic behavior across 24 tabular features and produces evidence — without decrypting payloads.
            </p>
            <div className="hero-actions">
              <Link href="/dashboard" className="primary-btn">
                Open investigation <span>↗</span>
              </Link>
              <button className="ghost-btn" onClick={() => go("capabilities", "Capabilities")}>
                How it works ↓
              </button>
            </div>
          </div>
          <div className="hero-stage" aria-hidden="true">
            <TunnelGraphic />
          </div>
        </section>

        <section id="capabilities" className="section-light capabilities chapter" data-nav="Capabilities">
          <div className="container">
            <div className="section-heading reveal">
              <div>
                <h2>
                  Built for the questions<br />
                  <span>packet sniffers leave unanswered.</span>
                </h2>
              </div>
              <p>
                From the first IKE exchange to a verified hardened tunnel, every conclusion stays connected to its evidence.
              </p>
            </div>
            <div className="feature-grid">
              {pillars.map((pillar, index) => (
                <FeatureCard key={pillar.eyebrow} {...pillar} index={index} replay={capRun} />
              ))}
            </div>
          </div>
        </section>

        <section id="platform" className="section-light platform chapter" data-nav="Platform">
          <div className="container">
            <div className="platform-copy reveal">
              <h2>
                Your team already knows <span>something is wrong.</span>
              </h2>
              <p>
                Load a PCAP. TunnelTrace reconstructs the tunnel, scores the posture, and surfaces every finding with the frame that triggered it — all in one view.
              </p>
              <div className="platform-points">
                <div>
                  <b>38 → 96</b>
                  <span>posture score before and after hardening</span>
                </div>
                <div>
                  <b>3</b>
                  <span>critical findings in sample capture</span>
                </div>
                <div>
                  <b>0</b>
                  <span>payload bytes decrypted</span>
                </div>
              </div>
              <button className="text-btn" onClick={() => setDemoOpen(true)}>
                Open a sample investigation <span>↗</span>
              </button>
            </div>
            <DashboardMock onOpenDemo={() => setDemoOpen(true)} />
          </div>
        </section>

        <section id="workflow" className="section-dark workflow chapter" data-nav="Workflow">
          <div className="container">
            <div className="section-heading light-heading reveal">
              <div>
                <h2>
                  From capture to verified fix<br />
                  <em>in seven steps.</em>
                </h2>
              </div>
              <p>Seven steps from capture to verified hardened tunnel — one continuous analytical loop.</p>
            </div>
            <WorkflowRail />
            <div className="final-cta">
              <div>
                <h3>Build evidence before you build confidence.</h3>
              </div>
              <Link href="/dashboard" className="primary-btn">
                View console <span>↗</span>
              </Link>
            </div>
          </div>
        </section>
      </main>

      <footer className="footer">
        <div className="container footer-inner">
          <span>© 2026 TunnelTrace AI · Smart India Hackathon PS 26160</span>
          <span>IPsec Protocol Forensics & Encrypted Traffic Intelligence</span>
          <a href="https://github.com/sharancode3/TunnelTrace-AI" target="_blank" rel="noreferrer">
            GitHub ↗
          </a>
        </div>
      </footer>

      {demoOpen && <DemoModal onClose={() => setDemoOpen(false)} />}
    </div>
  );
}

/**
 * Side bottom pop-up toast:
 * Shows on first scroll (scrollY > 40 && scrollY < 620)
 * Automatically vanishes after the user scrolls past / next chapter.
 */
function SihTeamToast() {
  const [isVisible, setIsVisible] = useState(false);
  const [isDismissed, setIsDismissed] = useState(false);

  useEffect(() => {
    let ticking = false;

    const handleScroll = () => {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(() => {
        ticking = false;
        if (isDismissed) return;
        const y = window.scrollY;
        // Triggered only during first scroll region, vanishes past chapter 1 or back at top
        if (y > 40 && y < 620) {
          setIsVisible(true);
        } else {
          setIsVisible(false);
        }
      });
    };

    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, [isDismissed]);

  if (isDismissed) return null;

  return (
    <aside
      className={`sih-team-toast${isVisible ? " is-visible" : ""}`}
      aria-label="Smart India Hackathon Team Details"
      role="complementary"
    >
      <div className="sih-toast-header">
        <div className="sih-badge-group">
          <span className="sih-pulse-dot" />
          <span className="sih-toast-title">SIH 2026 · PS 26160</span>
        </div>
        <button
          type="button"
          className="sih-toast-close"
          onClick={() => {
            setIsDismissed(true);
            setIsVisible(false);
          }}
          title="Dismiss banner"
          aria-label="Dismiss banner"
        >
          ✕
        </button>
      </div>

      <div className="sih-toast-body">
        <div className="sih-toast-row">
          <span className="label">Team Name</span>
          <span className="value highlight">Team TunnelTrace AI</span>
        </div>
        <div className="sih-toast-row">
          <span className="label">Team ID</span>
          <span className="value">SIH-26160</span>
        </div>
        <div className="sih-toast-row">
          <span className="label">Ministry / Org</span>
          <span className="value">NTRO</span>
        </div>
        <div className="sih-toast-row">
          <span className="label">Platform</span>
          <span className="value">Explainable IPsec Intelligence</span>
        </div>
      </div>

      <div className="sih-toast-footer">
        <span>Zero Payload Decryption</span>
        <span>RFC 7296 / RFC 4303</span>
      </div>
    </aside>
  );
}

function FeatureCard({
  eyebrow,
  title,
  body,
  index,
  replay,
}: Pillar & { index: number; replay: number }) {
  const visuals = [ForensicsVisual, TrafficVisual, PolicyVisual, TwinVisual];
  const Visual = visuals[index];
  return (
    <article
      className="feature-card"
      style={{ "--delay": `${index * 80}ms` } as React.CSSProperties}
    >
      <div className="feature-visual">
        <Visual key={`${index}-${replay}`} />
      </div>
      <div className="feature-text">
        <div className="eyebrow dark">{eyebrow}</div>
        <h3>{title}</h3>
        <p>{body}</p>
      </div>
    </article>
  );
}

function ScrollRail({
  railRef,
  pathRef,
  dotRef,
  stopsRef,
}: {
  railRef: React.RefObject<HTMLElement | null>;
  pathRef: React.RefObject<SVGPathElement | null>;
  dotRef: React.RefObject<SVGCircleElement | null>;
  stopsRef: React.MutableRefObject<(HTMLSpanElement | null)[]>;
}) {
  const labels = ["01", "02", "03", "04"];
  return (
    <aside className="chapter-rail" ref={railRef} aria-label="Chapter progress">
      <div className="chapter-rail-inner">
        <svg className="chapter-rail-svg" viewBox="0 0 24 720" aria-hidden="true">
          <path className="rail-track" d="M12 60 V660" />
          <path className="rail-progress" ref={pathRef} d="M12 60 V660" pathLength={600} />
          <circle className="rail-dot" ref={dotRef} cx="12" cy="60" r="3.1" />
          <circle className="rail-dot-halo" cx="12" cy="60" r="7" />
        </svg>
        <div className="rail-stops">
          {labels.map((label, index) => (
            <span
              key={label}
              ref={(el) => {
                stopsRef.current[index] = el;
              }}
              className={index === 0 ? "rail-stop is-active" : "rail-stop"}
            >
              <b>{label}</b>
            </span>
          ))}
        </div>
      </div>
    </aside>
  );
}

function TunnelGraphic() {
  return (
    <div className="tunnel-art">
      <div className="orbit o1" />
      <div className="orbit o2" />
      <div className="orbit o3" />
      <div className="node n-a">
        <span>IKEv2</span>
        <b>SA_INIT</b>
      </div>
      <div className="node n-b">
        <span>ESP</span>
        <b>FLOW 24-FEAT</b>
      </div>
      <div className="node n-c">
        <span>NIST SP 800-77</span>
        <b>SCORE 0—100</b>
      </div>
      <div className="core-stack">
        <div className="stack-layer layer-1" />
        <div className="stack-layer layer-2" />
        <div className="stack-layer layer-3" />
        <div className="stack-face">
          TUNNELTRACE
          <br />
          <span>INTELLIGENCE CORE</span>
        </div>
      </div>
      <div className="packet packet-1" />
      <div className="packet packet-2" />
      <div className="packet packet-3" />
    </div>
  );
}

function ForensicsVisual() {
  const layers = Array.from({ length: 7 });
  return (
    <div className="mini-visual forensics-visual">
      <svg viewBox="0 0 220 190" aria-hidden="true" focusable="false">
        <g>
          {layers.map((_, i) => {
            const y = 152 - i * 18;
            return (
              <polygon
                key={i}
                className="f-layer"
                points={`110,${y - 26} 174,${y - 6} 110,${y + 14} 46,${y - 6}`}
                pathLength={1}
                opacity="0"
              >
                <animate
                  attributeName="opacity"
                  from="0"
                  to="1"
                  begin={`${0.1 + i * 0.14}s`}
                  dur="0.48s"
                  fill="freeze"
                />
                <animateTransform
                  attributeName="transform"
                  type="translate"
                  from="0 12"
                  to="0 0"
                  begin={`${0.1 + i * 0.14}s`}
                  dur="0.55s"
                  calcMode="spline"
                  keySplines=".2 .8 .2 1"
                  fill="freeze"
                />
                <animate
                  attributeName="stroke"
                  values="#8d969d;#9aa2aa;#8d969d"
                  begin={`${0.1 + i * 0.14}s`}
                  dur="0.8s"
                  fill="freeze"
                />
              </polygon>
            );
          })}
          <polyline
            className="f-trace t1"
            points="78,101 110,114 142,101"
            pathLength={1}
            fill="none"
            strokeDasharray="1"
            strokeDashoffset="1"
            opacity="0"
          >
            <animate attributeName="opacity" from="0" to="1" begin="1.28s" dur="0.05s" fill="freeze" />
            <animate attributeName="stroke-dashoffset" from="1" to="0" begin="1.28s" dur="0.7s" fill="freeze" />
          </polyline>
          <polyline
            className="f-trace t2"
            points="66,82 110,100 154,82"
            pathLength={1}
            fill="none"
            strokeDasharray="1"
            strokeDashoffset="1"
            opacity="0"
          >
            <animate attributeName="opacity" from="0" to="1" begin="1.48s" dur="0.05s" fill="freeze" />
            <animate attributeName="stroke-dashoffset" from="1" to="0" begin="1.48s" dur="0.72s" fill="freeze" />
          </polyline>
          <polyline
            className="f-trace t3"
            points="89,61 110,69 131,61"
            pathLength={1}
            fill="none"
            strokeDasharray="1"
            strokeDashoffset="1"
            opacity="0"
          >
            <animate attributeName="opacity" from="0" to="1" begin="1.68s" dur="0.62s" fill="freeze" />
            <animate attributeName="stroke-dashoffset" from="1" to="0" begin="1.68s" dur="0.62s" fill="freeze" />
          </polyline>
          <circle
            className="f-core"
            cx="110"
            cy="93"
            r="5"
            fill="#b85c4a"
            opacity="0"
            transform="scale(.3)"
            style={{ transformOrigin: "110px 93px" }}
          >
            <animate attributeName="opacity" from="0" to="1" begin="2.05s" dur="0.28s" fill="freeze" />
            <animateTransform
              attributeName="transform"
              type="scale"
              from=".3"
              to="1"
              begin="2.05s"
              dur="0.38s"
              fill="freeze"
            />
            <animate attributeName="r" values="5;6;5" begin="2.45s" dur="1.6s" repeatCount="indefinite" />
          </circle>
        </g>
      </svg>
    </div>
  );
}

function TrafficVisual() {
  return (
    <div className="mini-visual traffic-visual">
      <svg viewBox="0 0 220 190" aria-hidden="true" focusable="false">
        <g className="traffic-guides" fill="none" stroke="#b3bac0" strokeWidth="1" opacity="0.5">
          <path d="M60 77 V144">
            <animate attributeName="stroke-dasharray" from="0 80" to="80 0" begin="1.65s" dur=".45s" fill="freeze" />
          </path>
          <path d="M135 86 V144">
            <animate attributeName="stroke-dasharray" from="0 70" to="70 0" begin="1.78s" dur=".45s" fill="freeze" />
          </path>
          <path d="M91 110 V146">
            <animate attributeName="stroke-dasharray" from="0 50" to="50 0" begin="1.9s" dur=".4s" fill="freeze" />
          </path>
        </g>
        <g className="traffic-route" fill="none" stroke="#7f8992" strokeWidth="1.15">
          <path
            className="traffic-flow"
            pathLength={1}
            d="M60 77 L91 95 L135 72 L135 111 L102 129 L102 145"
            strokeDasharray="1"
            strokeDashoffset="1"
          >
            <animate attributeName="stroke-dashoffset" from="1" to="0" begin="2.02s" dur="1s" fill="freeze" />
          </path>
          <circle className="traffic-dot d1" cx="60" cy="77" r="2.5" fill="#111" opacity="0">
            <animate attributeName="opacity" from="0" to="1" begin="2.25s" dur=".2s" fill="freeze" />
          </circle>
          <circle className="traffic-dot d2" cx="135" cy="72" r="2.5" fill="#111" opacity="0">
            <animate attributeName="opacity" from="0" to="1" begin="2.55s" dur=".2s" fill="freeze" />
          </circle>
          <circle className="traffic-dot d3" cx="102" cy="145" r="2.5" fill="#111" opacity="0">
            <animate attributeName="opacity" from="0" to="1" begin="2.85s" dur=".2s" fill="freeze" />
          </circle>
        </g>
        {[
          ["node-1", 46, 48, 0],
          ["node-2", 122, 57, 0.18],
          ["node-3", 78, 97, 0.34],
          ["node-4", 88, 130, 0.5],
        ].map(([name, x, y, delay]) => (
          <g
            key={name as string}
            className={`traffic-node ${name}`}
            transform={`translate(${x} ${y})`}
            opacity="0"
          >
            <polygon points="0,12 14,4 28,12 14,20" fill="#f8f8f5" stroke="#8e979f" strokeWidth=".8" />
            <polygon points="0,12 14,20 14,32 0,24" fill="#f1f2ee" stroke="#8e979f" strokeWidth=".8" />
            <polygon points="14,20 28,12 28,24 14,32" fill="#f6f7f4" stroke="#8e979f" strokeWidth=".8" />
            <animate attributeName="opacity" from="0" to="1" begin={`${1.38 + Number(delay)}s`} dur=".35s" fill="freeze" />
            <animateTransform
              attributeName="transform"
              type="translate"
              from={`${x} ${Number(y) - 10}`}
              to={`${x} ${y}`}
              begin={`${1.38 + Number(delay)}s`}
              dur=".45s"
              fill="freeze"
            />
          </g>
        ))}
      </svg>
    </div>
  );
}

function PolicyVisual() {
  const cubes = Array.from({ length: 15 });
  return (
    <div className="mini-visual policy-visual">
      <svg viewBox="0 0 220 190" aria-hidden="true" focusable="false">
        <polygon
          className="p-platform"
          points="47,119 110,88 173,119 110,151"
          fill="#f6f7f4"
          stroke="#9aa2ac"
          strokeWidth="1"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to="1" begin="2.95s" dur=".48s" fill="freeze" />
          <animateTransform
            attributeName="transform"
            type="translate"
            from="0 16"
            to="0 0"
            begin="2.95s"
            dur=".54s"
            fill="freeze"
          />
        </polygon>
        <polygon
          className="p-platform"
          points="47,119 110,151 110,171 47,139"
          fill="#f1f2ee"
          stroke="#9aa2ac"
          strokeWidth="1"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to="1" begin="3.08s" dur=".42s" fill="freeze" />
          <animateTransform
            attributeName="transform"
            type="translate"
            from="0 13"
            to="0 0"
            begin="3.08s"
            dur=".48s"
            fill="freeze"
          />
        </polygon>
        <polygon
          className="p-platform"
          points="110,151 173,119 173,139 110,171"
          fill="#eceee9"
          stroke="#9aa2ac"
          strokeWidth="1"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to="1" begin="3.14s" dur=".42s" fill="freeze" />
          <animateTransform
            attributeName="transform"
            type="translate"
            from="0 13"
            to="0 0"
            begin="3.14s"
            dur=".48s"
            fill="freeze"
          />
        </polygon>
        <ellipse
          className="p-halo"
          cx="110"
          cy="124"
          rx="31"
          ry="12"
          fill="none"
          stroke="#b9c9be"
          strokeWidth="1"
          strokeDasharray="2 4"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to=".85" begin="4.15s" dur=".45s" fill="freeze" />
          <animate attributeName="rx" values="31;35;31" begin="4.6s" dur="1.8s" repeatCount="indefinite" />
        </ellipse>
        <circle className="p-dot" cx="110" cy="124" r="3.5" fill="#7f9586" opacity="0">
          <animate attributeName="opacity" from="0" to="1" begin="4.22s" dur=".25s" fill="freeze" />
          <animate attributeName="r" values="3.5;5;3.5" begin="4.55s" dur="1.3s" repeatCount="indefinite" />
        </circle>
        <g className="p-cubes">
          {cubes.map((_, i) => {
            const col = i % 5;
            const row = Math.floor(i / 5);
            const x = 73 + col * 17 - row * 6;
            const y = 63 + row * 15;
            return (
              <g
                className="p-cube"
                key={i}
                transform={`translate(${x} ${y - 24})`}
                opacity="0"
              >
                <polygon points="0,0 7,-4 14,0 7,4" fill="#f8f8f5" stroke="#9299a2" strokeWidth=".8" />
                <polygon points="0,0 7,4 7,11 0,7" fill="#f1f2ee" stroke="#9299a2" strokeWidth=".8" />
                <polygon points="7,4 14,0 14,7 7,11" fill="#f6f7f4" stroke="#9299a2" strokeWidth=".8" />
                <animate attributeName="opacity" from="0" to="1" begin={`${3.38 + i * 0.07}s`} dur=".3s" fill="freeze" />
                <animateTransform
                  attributeName="transform"
                  type="translate"
                  from={`${x} ${y - 24}`}
                  to={`${x} ${y}`}
                  begin={`${3.38 + i * 0.07}s`}
                  dur=".46s"
                  fill="freeze"
                />
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}

function TwinVisual() {
  return (
    <div className="mini-visual twin-visual">
      <svg viewBox="0 0 220 190" aria-hidden="true" focusable="false">
        <polygon
          className="t-base"
          points="36,121 110,85 184,121 110,158"
          fill="#f5f1e7"
          stroke="#8f8c84"
          strokeWidth="1"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to="1" begin="4.58s" dur=".42s" fill="freeze" />
          <animateTransform
            attributeName="transform"
            type="translate"
            from="0 10"
            to="0 0"
            begin="4.58s"
            dur=".5s"
            fill="freeze"
          />
        </polygon>
        <polygon
          className="t-base"
          points="36,121 110,158 110,173 36,136"
          fill="#eee8d9"
          stroke="#8f8c84"
          strokeWidth="1"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to="1" begin="4.68s" dur=".38s" fill="freeze" />
          <animateTransform
            attributeName="transform"
            type="translate"
            from="0 9"
            to="0 0"
            begin="4.68s"
            dur=".44s"
            fill="freeze"
          />
        </polygon>
        <polygon
          className="t-base"
          points="110,158 184,121 184,136 110,173"
          fill="#e9e3d5"
          stroke="#8f8c84"
          strokeWidth="1"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to="1" begin="4.73s" dur=".38s" fill="freeze" />
          <animateTransform
            attributeName="transform"
            type="translate"
            from="0 9"
            to="0 0"
            begin="4.73s"
            dur=".44s"
            fill="freeze"
          />
        </polygon>
        <polygon
          className="t-mid"
          points="72,105 110,87 148,105 110,124"
          fill="#f6f3eb"
          stroke="#8c8b84"
          strokeWidth="1"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to="1" begin="4.92s" dur=".42s" fill="freeze" />
          <animateTransform
            attributeName="transform"
            type="translate"
            from="0 8"
            to="0 0"
            begin="4.92s"
            dur=".46s"
            fill="freeze"
          />
        </polygon>
        <polygon
          className="t-mid-side"
          points="72,105 110,124 110,137 72,118"
          fill="#eee9de"
          stroke="#8c8b84"
          strokeWidth="1"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to="1" begin="5.0s" dur=".4s" fill="freeze" />
          <animateTransform
            attributeName="transform"
            type="translate"
            from="0 7"
            to="0 0"
            begin="5.0s"
            dur=".42s"
            fill="freeze"
          />
        </polygon>
        <polygon
          className="t-mid-side"
          points="110,124 148,105 148,118 110,137"
          fill="#ebe5da"
          stroke="#8c8b84"
          strokeWidth="1"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to="1" begin="5.04s" dur=".4s" fill="freeze" />
          <animateTransform
            attributeName="transform"
            type="translate"
            from="0 7"
            to="0 0"
            begin="5.04s"
            dur=".42s"
            fill="freeze"
          />
        </polygon>
        <g className="t-top-group">
          <polygon
            className="t-top"
            points="82,59 110,46 138,59 110,73"
            fill="#faf8f3"
            stroke="#8c8b84"
            strokeWidth="1"
            opacity="0"
          >
            <animate attributeName="opacity" from="0" to="1" begin="5.24s" dur=".42s" fill="freeze" />
            <animateTransform
              attributeName="transform"
              type="translate"
              from="0 10"
              to="0 0"
              begin="5.24s"
              dur=".48s"
              fill="freeze"
            />
          </polygon>
          <polygon
            className="t-top-side"
            points="82,59 110,73 110,84 82,70"
            fill="#f0ebdf"
            stroke="#8c8b84"
            strokeWidth="1"
            opacity="0"
          >
            <animate attributeName="opacity" from="0" to="1" begin="5.30s" dur=".42s" fill="freeze" />
            <animateTransform
              attributeName="transform"
              type="translate"
              from="0 9"
              to="0 0"
              begin="5.30s"
              dur=".45s"
              fill="freeze"
            />
          </polygon>
          <polygon
            className="t-top-side"
            points="110,73 138,59 138,70 110,84"
            fill="#ebe5d7"
            stroke="#8c8b84"
            strokeWidth="1"
            opacity="0"
          >
            <animate attributeName="opacity" from="0" to="1" begin="5.34s" dur=".42s" fill="freeze" />
            <animateTransform
              attributeName="transform"
              type="translate"
              from="0 9"
              to="0 0"
              begin="5.34s"
              dur=".45s"
              fill="freeze"
            />
          </polygon>
        </g>
        <ellipse
          className="t-orbit"
          cx="110"
          cy="110"
          rx="74"
          ry="38"
          fill="none"
          stroke="#b9c9be"
          strokeWidth="1"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to=".75" begin="5.48s" dur=".45s" fill="freeze" />
          <animateTransform
            attributeName="transform"
            type="rotate"
            from="0 110 110"
            to="360 110 110"
            begin="5.48s"
            dur="3.5s"
            repeatCount="indefinite"
          />
        </ellipse>
        <circle className="t-orbit-dot" cx="37" cy="110" r="2.3" fill="#7f9586" opacity="0">
          <animate attributeName="opacity" from="0" to="1" begin="5.68s" dur=".2s" fill="freeze" />
        </circle>
        <circle className="t-orbit-dot" cx="183" cy="110" r="2.3" fill="#7f9586" opacity="0">
          <animate attributeName="opacity" from="0" to="1" begin="5.82s" dur=".2s" fill="freeze" />
        </circle>
        <path
          className="t-signal"
          d="M110 105 L110 46"
          pathLength={1}
          fill="none"
          stroke="#5b7165"
          strokeWidth="1.1"
          strokeDasharray="1"
          strokeDashoffset="1"
          opacity="0"
        >
          <animate attributeName="opacity" from="0" to="1" begin="5.76s" dur=".05s" fill="freeze" />
          <animate attributeName="stroke-dashoffset" from="1" to="0" begin="5.76s" dur=".55s" fill="freeze" />
        </path>
        <path
          className="t-check"
          d="M104 42 L109 47 L118 37"
          pathLength={1}
          fill="none"
          stroke="#5b7165"
          strokeWidth="1.15"
          strokeDasharray="1"
          strokeDashoffset="1"
        >
          <animate attributeName="stroke-dashoffset" from="1" to="0" begin="6.08s" dur=".45s" fill="freeze" />
        </path>
        <circle className="t-pulse" cx="110" cy="45" r="4" fill="#7f9586" opacity="0">
          <animate attributeName="opacity" from="0" to="1" begin="6.02s" dur=".25s" fill="freeze" />
          <animate attributeName="r" values="4;5.5;4" begin="6.25s" dur="1.4s" repeatCount="indefinite" />
        </circle>
      </svg>
    </div>
  );
}

function DashboardMock({ onOpenDemo }: { onOpenDemo: () => void }) {
  const bars = [36, 52, 42, 68, 44, 76, 58, 82, 63, 90, 72, 96];
  return (
    <div className="dashboard-mock reveal">
      <div className="dash-bar">
        <span>TUNNELTRACE / INVESTIGATION</span>
        <b>LIVE</b>
      </div>
      <div className="dash-grid">
        <div className="dash-hero-score">
          <div className="eyebrow dark">SECURITY POSTURE</div>
          <div className="big-score">
            38<span>/100</span>
          </div>
          <div className="critical-tag">CRITICAL NON-COMPLIANCE</div>
          <div className="score-track">
            <span style={{ width: "38%" }} />
          </div>
          <small>Capture v3.2 · weak crypto posture detected</small>
        </div>
        <div className="dash-findings">
          <div className="dash-head">
            <span>CRITICAL FINDINGS</span>
            <b>03</b>
          </div>
          <Finding name="Deprecated cipher suite" meta="Frame 14 · ENCR_3DES_CBC" />
          <Finding name="Weak DH group" meta="Frame 14 · DH_MODP_1024" />
          <Finding name="Perfect Forward Secrecy" meta="Policy · missing" />
        </div>
        <div className="dash-chart">
          <div className="dash-head">
            <span>TRAFFIC PATTERN</span>
            <b>MATCH</b>
          </div>
          <div className="chart-bars">
            {bars.map((height, i) => (
              <i key={i} style={{ height: `${height}%` }} />
            ))}
          </div>
          <div className="chart-foot">
            <span>VoIP/RTP</span>
            <b>detected</b>
          </div>
        </div>
        <div className="dash-twin">
          <div className="dash-head">
            <span>CONFIGURATION TWIN</span>
            <b>READY</b>
          </div>
          <div className="twin-scores">
            <span>38</span>
            <i>→</i>
            <strong>96</strong>
          </div>
          <p>AES-256-GCM · DH19 · PFS</p>
          <button type="button" onClick={onOpenDemo}>
            GENERATE PATCH
          </button>
        </div>
      </div>
    </div>
  );
}

function Finding({ name, meta }: { name: string; meta: string }) {
  return (
    <div className="finding">
      <span className="finding-dot" />
      <div>
        <b>{name}</b>
        <small>{meta}</small>
      </div>
      <span className="chev">↗</span>
    </div>
  );
}

interface StepItem {
  num: string;
  title: string;
  sub: string;
  card: string;
  label: string;
}

const WORKFLOW_STEPS: StepItem[] = [
  {
    num: "01",
    title: "CAPTURE",
    sub: "Load PCAP or live stream",
    card: "Load a PCAP or observe a live stream. Preserve packet order, timing, endpoints, and IKE/ESP exchanges as the raw evidence set.",
    label: "PCAP / LIVE TRAFFIC",
  },
  {
    num: "02",
    title: "RECONSTRUCT",
    sub: "IKE and ESP state",
    card: "Rebuild the observed IKE and IPsec state from the capture, including negotiations, CHILD_SA relationships, and tunnel transitions.",
    label: "IKE / ESP STATE",
  },
  {
    num: "03",
    title: "INFER",
    sub: "Encrypted flow behavior",
    card: "Infer encrypted traffic behavior across 24 statistical flow features without decrypting payload contents.",
    label: "ENCRYPTED FLOW",
  },
  {
    num: "04",
    title: "ASSESS",
    sub: "Policy and posture score",
    card: "Evaluate observed cryptographic posture against NIST SP 800-77 Rev. 1. Identify weak transforms, DH groups, PFS settings, and score 0–100.",
    label: "POLICY / POSTURE",
  },
  {
    num: "05",
    title: "EXPLAIN",
    sub: "Trace findings to frames",
    card: "Trace each finding back to the packets, frames, negotiations, and policy evidence that support the conclusion.",
    label: "EVIDENCE TRACE",
  },
  {
    num: "06",
    title: "REMEDIATE",
    sub: "Generate hardened config",
    card: "Project a hardened strongSwan configuration from findings and test the proposed change in an isolated twin before deployment.",
    label: "HARDEN / TEST",
  },
  {
    num: "07",
    title: "VERIFY",
    sub: "Capture and compare",
    card: "Capture the hardened tunnel again and compare the result against the original evidence to verify the improvement.",
    label: "FRESH CAPTURE",
  },
];

function WorkflowRail() {
  const [openedSteps, setOpenedSteps] = useState<Set<number>>(new Set());
  const [isTouchDevice] = useState(() => {
    if (typeof window === "undefined") return false;
    return "ontouchstart" in window || (navigator.maxTouchPoints > 0);
  });
  const [cardPositions, setCardPositions] = useState<Record<number, React.CSSProperties>>({});
  const railRef = useRef<HTMLDivElement>(null);
  const stepRefs = useRef<(HTMLDivElement | null)[]>([]);
  const cardRefs = useRef<(HTMLDivElement | null)[]>([]);
  const positionUpdateScheduled = useRef(false);

  const updateCardPositions = useCallback(() => {
    if (!railRef.current) return;
    const railRect = railRef.current.getBoundingClientRect();
    const viewportHeight = window.innerHeight;

    const newPositions: Record<number, React.CSSProperties> = {};
    WORKFLOW_STEPS.forEach((_, i) => {
      const stepEl = stepRefs.current[i];
      const cardEl = cardRefs.current[i];
      if (!stepEl || !cardEl) return;

      const stepRect = stepEl.getBoundingClientRect();
      const cardRect = cardEl.getBoundingClientRect();

      const cardWidth = cardRect.width || 280;
      const cardHeight = cardRect.height || 160;
      const gap = 16;

      let left = stepRect.left - railRect.left + (stepRect.width - cardWidth) / 2;
      let top = stepRect.bottom - railRect.top + gap;

      if (left < 8) left = 8;
      if (left + cardWidth > railRect.width - 8) left = railRect.width - cardWidth - 8;

      if (top + cardHeight > viewportHeight - 20) {
        top = stepRect.top - railRect.top - cardHeight - gap;
        if (top < 8) top = 8;
      }

      newPositions[i] = {
        left: `${left}px`,
        top: `${top}px`,
        width: `${cardWidth}px`,
      };
    });

    setCardPositions(newPositions);
  }, []);

  const schedulePositionUpdate = useCallback(() => {
    if (positionUpdateScheduled.current) return;
    positionUpdateScheduled.current = true;
    requestAnimationFrame(() => {
      positionUpdateScheduled.current = false;
      updateCardPositions();
    });
  }, [updateCardPositions]);

  useEffect(() => {
    schedulePositionUpdate();
    window.addEventListener("resize", schedulePositionUpdate);
    window.addEventListener("scroll", schedulePositionUpdate, { passive: true });
    return () => {
      window.removeEventListener("resize", schedulePositionUpdate);
      window.removeEventListener("scroll", schedulePositionUpdate);
    };
  }, [schedulePositionUpdate, openedSteps]);

  const handlePointerEnter = useCallback((index: number) => {
    setOpenedSteps((prev) => {
      const next = new Set(prev);
      next.add(index);
      return next;
    });
  }, []);

  const handleRailLeave = useCallback(() => {
    setOpenedSteps(new Set());
  }, []);

  const handleStepClick = useCallback((index: number) => {
    setOpenedSteps((prev) => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  }, []);

  const handleDocumentClick = useCallback((e: MouseEvent) => {
    if (railRef.current && !railRef.current.contains(e.target as Node)) {
      setOpenedSteps(new Set());
    }
  }, []);

  useEffect(() => {
    document.addEventListener("click", handleDocumentClick);
    return () => document.removeEventListener("click", handleDocumentClick);
  }, [handleDocumentClick]);

  return (
    <div ref={railRef} className="workflow-rail" onPointerLeave={handleRailLeave}>
      {WORKFLOW_STEPS.map((step, i) => {
        const isOpened = openedSteps.has(i);
        const handlers = isTouchDevice
          ? { onClick: () => handleStepClick(i) }
          : { onPointerEnter: () => handlePointerEnter(i) };

        return (
          <div
            ref={(el) => {
              stepRefs.current[i] = el;
            }}
            className={`workflow-step${isOpened ? " is-opened" : ""}`}
            key={step.num}
            style={{ "--delay": `${i * 60}ms` } as React.CSSProperties}
            {...handlers}
          >
            <div className="workflow-num">{step.num}</div>
            <div className="workflow-dot" />
            <h4>{step.title}</h4>
            <p>{step.sub}</p>
            {i < WORKFLOW_STEPS.length - 1 && <span className="workflow-connector" />}
          </div>
        );
      })}
      {WORKFLOW_STEPS.map((step, i) => {
        const isOpened = openedSteps.has(i);
        if (!isOpened) return null;

        const pos = cardPositions[i] || {};

        return (
          <div
            ref={(el) => {
              cardRefs.current[i] = el;
            }}
            key={`card-${step.num}`}
            className="workflow-card is-visible"
            style={pos}
          >
            <div className="workflow-card-label">{step.label}</div>
            <h5>{step.title}</h5>
            <p>{step.card}</p>
          </div>
        );
      })}
    </div>
  );
}

function DemoModal({ onClose }: { onClose: () => void }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="modal-backdrop demo-open"
      onMouseDown={(event) => event.target === event.currentTarget && onClose()}
    >
      <div className="modal">
        <div className="modal-top">
          <span style={{ font: '600 10px "JetBrains Mono"', color: "#777" }}>
            TUNNELTRACE / SAMPLE INVESTIGATION PREVIEW
          </span>
          <button type="button" onClick={onClose}>
            Esc
          </button>
        </div>
        <div className="modal-score">
          <span>Security posture</span>
          <strong>
            38<span>/100</span>
          </strong>
          <em>CRITICAL</em>
        </div>
        <div className="modal-grid">
          <div className="modal-col">
            <div className="modal-label">RECONSTRUCTED FACTS</div>
            <div className="modal-row">
              <b>IKEv2 SA_INIT</b>
              <span>FRAME 14</span>
            </div>
            <div className="modal-row">
              <b>ENCR_3DES_CBC</b>
              <span>0x003A (WEAK)</span>
            </div>
            <div className="modal-row">
              <b>DH Group 2</b>
              <span>MODP_1024</span>
            </div>
          </div>
          <div className="modal-col">
            <div className="modal-label">TRAFFIC PATTERN</div>
            <div className="ml-pill">
              VoIP/RTP <strong>detected</strong>
            </div>
            <p>
              Inferred from 24 statistical flow features (packet size, timing, bursts). Zero payload bytes decrypted.
            </p>
          </div>
          <div className="modal-col">
            <div className="modal-label">HARDENED CONFIG</div>
            <div className="upgrade-line">
              <span>38</span>
              <b>→</b>
              <strong>96</strong>
            </div>
            <p>AES-256-GCM · DH19 (Curve25519) · PFS enabled</p>
          </div>
        </div>
        <div className="modal-footer">
          <span>LOCAL / AIR-GAPPED / EVIDENCE-LINKED</span>
          <div style={{ display: "flex", gap: "10px" }}>
            <Link
              href="/analyses/f57f39ee-cf37-41ec-a5ea-f8891de69a0c/overview"
              className="primary-btn"
              onClick={onClose}
            >
              Open sample investigation ↗
            </Link>
            <Link href="/dashboard" className="ghost-btn" style={{ color: "#111", borderColor: "#bbb" }} onClick={onClose}>
              Dashboard ↗
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
