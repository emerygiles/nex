import { useCallback, useMemo, useState } from "react";
import { resetRun, streamRun } from "../lib/api";
import type { Detection, StepEvent, SurfaceNode } from "../lib/types";

export type GapInfo = { technique: string; hits: number; existing: number } | null;

/**
 * Owns all NEX run state and derives view-model data from the SSE stream.
 * Components consume this hook and stay pure presentation (no business logic in UI).
 */
export function useNexRun(onComplete?: () => void) {
  const [running, setRunning] = useState(false);
  const [events, setEvents] = useState<StepEvent[]>([]);
  const [surface, setSurface] = useState<SurfaceNode[]>([]);
  const [sourcetypes, setSourcetypes] = useState<{ name: string; events: number }[]>([]);
  const [detections, setDetections] = useState<{ name: string; technique: string }[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [gap, setGap] = useState<GapInfo>(null);
  const [detection, setDetection] = useState<Detection | null>(null);
  const [deployed, setDeployed] = useState(false);
  const [verified, setVerified] = useState<string | null>(null);

  const reset = useCallback(() => {
    setEvents([]); setSurface([]); setSourcetypes([]); setDetections([]);
    setActive(null); setGap(null); setDetection(null); setDeployed(false); setVerified(null);
  }, []);

  const run = useCallback(() => {
    reset();
    setRunning(true);
    streamRun(
      (e) => {
        setEvents((prev) => [...prev, e]);
        if (e.kind === "tool" && e.message.startsWith("enumerate")) {
          setSourcetypes(e.data?.sourcetypes ?? []);
          setDetections(e.data?.detections ?? []);
        }
        if (e.kind === "graph") setSurface(e.data ?? []);
        if (e.phase === "attack-think" && e.data?.technique) setActive(e.data.technique);
        if (e.kind === "tool" && e.message.startsWith("test_detection") && e.data) {
          setActive(e.data.technique ?? null);
          setGap({ technique: e.data.technique, hits: e.data.hits, existing: e.data.existing_coverage });
        }
        if (e.kind === "gap") setGap((g) => g ?? { technique: e.data.technique, hits: 0, existing: 0 });
        if (e.kind === "detection") setDetection(e.data);
        if (e.kind === "tool" && e.message.startsWith("deploy")) setDeployed(true);
        if (e.kind === "verified" && e.data?.covered) setVerified(e.data.technique);
      },
      () => { setRunning(false); onComplete?.(); }
    );
  }, [reset, onComplete]);

  const reopen = useCallback(async () => {
    await resetRun().catch(() => undefined);
    reset();
  }, [reset]);

  // Derived KPIs (presentation-ready, no logic in components).
  const stats = useMemo(() => {
    const covered = surface.filter((s) => s.covered || s.technique === verified).length;
    const blind = surface.filter((s) => !s.covered && s.technique !== verified).length;
    const eventsAnalyzed = sourcetypes.reduce((n, s) => n + (s.events || 0), 0);
    return { techniques: surface.length, covered, blind, eventsAnalyzed };
  }, [surface, verified, sourcetypes]);

  const phase = events.length ? events[events.length - 1].phase : null;

  return {
    running, events, surface, sourcetypes, detections,
    active, gap, detection, deployed, verified, stats, phase,
    run, reopen,
  };
}
