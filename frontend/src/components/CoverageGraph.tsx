import { useMemo } from "react";
import ReactFlow, { Background, BackgroundVariant, type Edge, type Node } from "reactflow";
import type { SurfaceNode } from "../lib/types";

interface Props {
  surface: SurfaceNode[];
  activeTechnique: string | null;
  verifiedTechnique: string | null;
}

const C = { blind: "#E11D48", secure: "#059669", brand: "#6D28D9", line: "#E9E9EE", ink: "#101013" };

function techNode(s: SurfaceNode, active: boolean, verified: boolean, i: number): Node {
  const covered = verified || s.covered;
  const edge = verified ? C.secure : active ? C.brand : covered ? C.secure : C.blind;
  return {
    id: s.technique,
    position: { x: 250 + (i % 3) * 196, y: 24 + Math.floor(i / 3) * 116 },
    data: {
      label: (
        <div className="px-1 py-0.5 text-left">
          <div className="font-mono text-[12px] font-semibold text-ink">{s.technique}</div>
          <div className="tabular text-[10px] text-muted">{s.events.toLocaleString()} events</div>
          <div className="mt-1 inline-flex items-center gap-1 text-[10px] font-medium" style={{ color: edge }}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: edge }} />
            {covered ? "covered" : active ? "investigating" : "blind spot"}
          </div>
        </div>
      ),
    },
    style: {
      width: 150, padding: 0, borderRadius: 12, background: "#FFFFFF",
      border: `1.5px solid ${edge}`, fontFamily: "Geist, sans-serif",
      boxShadow: active || verified ? `0 0 0 4px ${edge}1a` : "0 1px 2px rgba(16,16,19,0.04)",
    },
  };
}

export default function CoverageGraph({ surface, activeTechnique, verifiedTechnique }: Props) {
  const { nodes, edges } = useMemo(() => {
    const root: Node = {
      id: "splunk",
      position: { x: 24, y: 140 },
      data: { label: (
        <div className="px-1 text-left">
          <div className="text-[12px] font-semibold text-white">Splunk</div>
          <div className="text-[10px] text-white/60">live telemetry</div>
        </div>
      ) },
      style: { width: 116, padding: 8, borderRadius: 12, background: C.ink, border: "none" },
    };
    const ns = surface.map((s, i) =>
      techNode(s, activeTechnique === s.technique, verifiedTechnique === s.technique, i)
    );
    const es: Edge[] = surface.map((s) => {
      const covered = verifiedTechnique === s.technique || s.covered;
      const active = activeTechnique === s.technique;
      return {
        id: `e-${s.technique}`, source: "splunk", target: s.technique, animated: active,
        style: { stroke: active ? C.brand : covered ? `${C.secure}66` : `${C.blind}66`, strokeWidth: 1.5 },
      };
    });
    return { nodes: [root, ...ns], edges: es };
  }, [surface, activeTechnique, verifiedTechnique]);

  return (
    <section className="panel flex flex-col overflow-hidden">
      <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
        <h2 className="text-sm font-semibold text-ink">ATT&CK coverage map</h2>
        <div className="flex items-center gap-3 text-[11px] text-muted">
          <Legend color={C.secure} label="covered" />
          <Legend color={C.blind} label="blind spot" />
          <Legend color={C.brand} label="investigating" />
        </div>
      </div>
      <div className="relative h-[360px]">
        {surface.length === 0 && (
          <div className="absolute inset-0 grid place-items-center px-6 text-center">
            <p className="max-w-xs text-sm text-muted">
              Run a sweep to map every ATT&amp;CK technique present in your data against current detection coverage.
            </p>
          </div>
        )}
        <ReactFlow
          nodes={nodes} edges={edges} fitView
          proOptions={{ hideAttribution: true }}
          nodesDraggable={false} nodesConnectable={false} zoomOnScroll={false} panOnDrag
        >
          <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#E4E4EA" />
        </ReactFlow>
      </div>
    </section>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="h-2 w-2 rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
}
