import { CrosshairIcon, DatabaseIcon, LayersIcon, PulseIcon, ShieldIcon } from "../lib/icons";
import type { Health } from "../lib/types";
import type { View } from "../lib/types";
import StatusDot from "./ui/StatusDot";

const NAV: { id: View; label: string; icon: typeof ShieldIcon }[] = [
  { id: "coverage", label: "Coverage", icon: ShieldIcon },
  { id: "surface", label: "Surface map", icon: CrosshairIcon },
  { id: "detections", label: "Detections", icon: LayersIcon },
  { id: "activity", label: "Activity", icon: PulseIcon },
];

interface Props {
  health: Health | null;
  view: View;
  onNavigate: (v: View) => void;
}

export default function Sidebar({ health, view, onNavigate }: Props) {
  return (
    <aside className="hidden w-[232px] shrink-0 flex-col border-r border-line bg-surface lg:flex">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="grid h-8 w-8 place-items-center rounded-md bg-brand-700 text-white">
          <ShieldIcon width={17} height={17} />
        </div>
        <div className="leading-tight">
          <div className="text-[15px] font-semibold tracking-tight text-ink">NEX</div>
          <div className="text-[11px] text-faint">Purple-team console</div>
        </div>
      </div>

      <nav className="flex flex-col gap-0.5 px-3 pt-1" aria-label="Primary">
        {NAV.map(({ id, label, icon: Icon }) => {
          const active = view === id;
          return (
            <button
              key={id}
              type="button"
              onClick={() => onNavigate(id)}
              aria-current={active ? "page" : undefined}
              className={`navitem w-full text-left ${active ? "navitem-active" : ""}`}
            >
              <Icon width={17} height={17} className={active ? "text-brand-700" : "text-faint"} />
              {label}
            </button>
          );
        })}
      </nav>

      <div className="mt-auto space-y-2 border-t border-line p-4">
        <div className="eyebrow px-1">Environment</div>
        <Row label={<span className="flex items-center gap-2 text-muted"><DatabaseIcon width={15} height={15} className="text-faint" /> Data plane</span>}>
          <span className="flex items-center gap-1.5 font-medium text-ink"><StatusDot ok={!!health?.ok} /> {health?.mcp ?? "—"}</span>
        </Row>
        <Row label={<span className="text-muted">Brain</span>}>
          <span className="font-medium text-ink">{health?.brain ?? "—"}</span>
        </Row>
        <Row label={<span className="text-muted">Mode</span>}>
          <span className="font-mono text-[11px] text-body">{health?.mode ?? "—"}</span>
        </Row>
      </div>
    </aside>
  );
}

function Row({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between px-1 py-1 text-xs">
      {label}
      {children}
    </div>
  );
}
