export type View = "coverage" | "surface" | "visibility" | "detections" | "activity";

export type Phase =
  | "start" | "recon" | "attack-think" | "prove" | "skeptic" | "ship" | "done";

export type Kind =
  | "status" | "tool" | "graph" | "thought" | "gap" | "detection" | "verified"
  | "visibility" | "pending";

export interface VisTechnique {
  technique: string;
  name: string;
  tactic: string;
  data_source: string;
  status: "visible" | "blind";
}

export interface Visibility {
  techniques: VisTechnique[];
  visible: number;
  blind: number;
  present_data_sources: string[];
  missing_data_sources: string[];
}

export interface StepEvent {
  phase: Phase;
  kind: Kind;
  message: string;
  data: any;
  ts: number;
}

export interface SurfaceNode {
  technique: string;
  events: number;
  sourcetype: string;
  covered: boolean;
}

export interface Detection {
  name: string;
  spl: string;
  sigma: any;
  severity: string;
  technique: string;
  tactic: string;
}

export interface Health {
  ok: boolean;
  mode: string;
  brain: string;
  mcp: string;
  mcp_url: string | null;
  auto_deploy: boolean;
}
