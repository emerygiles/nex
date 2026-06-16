/** Minimal, consistent SVG icon primitives (strokeWidth 1.5). No emojis. */
import type { SVGProps } from "react";

const base = (p: SVGProps<SVGSVGElement>) => ({
  width: 18, height: 18, viewBox: "0 0 24 24", fill: "none",
  stroke: "currentColor", strokeWidth: 1.5, strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const, ...p,
});

export const ShieldIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" /></svg>
);
export const CrosshairIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><circle cx="12" cy="12" r="7" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3" /></svg>
);
export const PulseIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><path d="M3 12h4l2-6 4 12 2-6h6" /></svg>
);
export const LayersIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><path d="M12 3l9 5-9 5-9-5 9-5z" /><path d="M3 13l9 5 9-5" /></svg>
);
export const DocIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><path d="M6 3h8l4 4v14H6z" /><path d="M14 3v4h4M9 13h6M9 17h6" /></svg>
);
export const CheckIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><path d="M4 12.5l5 5 11-11" /></svg>
);
export const AlertIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><path d="M12 4l9 16H3l9-16z" /><path d="M12 10v4M12 17.5v.5" /></svg>
);
export const PlayIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><path d="M7 5l12 7-12 7V5z" fill="currentColor" stroke="none" /></svg>
);
export const RefreshIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><path d="M4 9a8 8 0 0114-3l2 2M20 15a8 8 0 01-14 3l-2-2" /><path d="M20 4v4h-4M4 20v-4h4" /></svg>
);
export const DatabaseIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" /></svg>
);
export const SparkIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3z" /></svg>
);
export const EyeOffIcon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}><path d="M3 3l18 18M10.6 10.6a3 3 0 004.2 4.2" /><path d="M9.4 5.2A9.7 9.7 0 0112 5c5 0 9 4.5 9 7-.4 1-1.2 2.2-2.4 3.3M6.1 6.1C3.8 7.5 2.3 9.7 2 12c.6 1.6 2.6 4.6 6 6" /></svg>
);
