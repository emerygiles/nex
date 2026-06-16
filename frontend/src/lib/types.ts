export type View = "coverage" | "surface" | "visibility" | "detections" | "activity";

export type Phase =
  | "start" | "recon" | "attack-think" | "prove" | "skeptic" | "ship" | "done";

export type Kind =
  | "status" | "tool" | "graph" | "thought" | "gap" | "detection" | "verified"
  | "visibility" | "pending";

export type Tier = "good" | "partial" | "none";

export interface ModelPosture {
  model: string;
  label: string;
  present: boolean;
  matched_sourcetype: string | null;
  completeness: number;
  timeliness: number;
  retention: number;
  consistency: number;
  score: number;
  tier: Tier;
}

export interface RequiredModel {
  model: string;
  label: string;
  log_sources: string[];
  present: boolean;
  tier: Tier;
}

export interface Remediation {
  action: string;
  model?: string;
  model_label?: string;
  sourcetype?: string;
  attack_log_sources?: string[];
  splunk: string;
  why: string;
}

export interface VisTechnique {
  technique: string;
  name: string;
  tactics: string[];
  tier: Tier;
  status: "visible" | "blind"; // back-compat
  score: number;
  weight: number;
  priority: number;
  rationale: string;
  required_models: RequiredModel[];
  present_models: string[];
  missing_models: string[];
  remediation: Remediation[];
}

export interface Visibility {
  attack_version: string;
  profile: { name: string; label: string; description: string };
  models: ModelPosture[];
  summary: { good: number; partial: number; blind: number; visible: number };
  techniques: VisTechnique[];
  blind: number;
  visible: number;
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
