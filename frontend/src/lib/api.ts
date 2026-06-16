import type { Health, StepEvent } from "./types";

const BASE = import.meta.env.VITE_API ?? "http://127.0.0.1:8800";

export async function getHealth(): Promise<Health> {
  const r = await fetch(`${BASE}/health`);
  if (!r.ok) throw new Error(`health ${r.status}`);
  return r.json();
}

export interface Coverage {
  sourcetypes: { name: string; events: number }[];
  detections: { name: string; technique: string }[];
  surface: import("./types").SurfaceNode[];
}

/** Current environment + coverage snapshot (no agent run). */
export async function getCoverage(): Promise<Coverage> {
  const r = await fetch(`${BASE}/coverage`);
  if (!r.ok) throw new Error(`coverage ${r.status}`);
  return r.json();
}

/** Data-source (visibility) coverage — high-value techniques with no data source at all. */
export async function getVisibility(): Promise<import("./types").Visibility> {
  const r = await fetch(`${BASE}/visibility`);
  if (!r.ok) throw new Error(`visibility ${r.status}`);
  return r.json();
}

/** Analyst-approved deploy of a proposed detection (human-in-the-loop). */
export async function deployDetection(d: import("./types").Detection): Promise<any> {
  const r = await fetch(`${BASE}/deploy`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: d.name, spl: d.spl, technique: d.technique, tactic: d.tactic }),
  });
  if (!r.ok) throw new Error(`deploy ${r.status}`);
  return r.json();
}

/** Re-open the blind spot (deletes NEX auto-authored detections). REST mode only. */
export async function resetRun(): Promise<{ removed: string[] }> {
  const r = await fetch(`${BASE}/reset`, { method: "POST" });
  if (!r.ok) throw new Error(`reset ${r.status}`);
  return r.json();
}

/**
 * Streams the agent run over SSE. Calls `onEvent` for each step and `onDone`
 * when the stream closes. Returns an abort function.
 */
export function streamRun(
  onEvent: (e: StepEvent) => void,
  onDone: () => void
): () => void {
  const es = new EventSource(`${BASE}/run`);
  es.addEventListener("step", (ev) => {
    try {
      onEvent(JSON.parse((ev as MessageEvent).data));
    } catch {
      /* ignore malformed frame */
    }
  });
  es.onerror = () => {
    es.close();
    onDone();
  };
  return () => es.close();
}
