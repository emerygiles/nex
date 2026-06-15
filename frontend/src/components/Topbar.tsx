import { PlayIcon, RefreshIcon } from "../lib/icons";
import type { Health } from "../lib/types";
import StatusDot from "./ui/StatusDot";

interface Props {
  health: Health | null;
  running: boolean;
  title: string;
  subtitle: string;
  onRun: () => void;
  onReset: () => void;
}

export default function Topbar({ health, running, title, subtitle, onRun, onReset }: Props) {
  return (
    <header className="sticky top-0 z-10 flex items-center justify-between gap-4 border-b border-line bg-canvas/80 px-6 py-3.5 backdrop-blur">
      <div className="min-w-0">
        <h1 className="text-[15px] font-semibold tracking-tight text-ink">{title}</h1>
        <p className="truncate text-xs text-muted">{subtitle}</p>
      </div>

      <div className="flex items-center gap-2.5">
        <div className="hidden items-center gap-1.5 md:flex">
          <span className="chip">
            <StatusDot ok={!!health?.ok} busy={running} />
            {health?.mcp ?? "offline"}
          </span>
          <span className="chip font-mono text-[11px]">{health?.brain ?? "—"}</span>
        </div>
        <button className="btn-ghost" onClick={onReset} disabled={running} aria-label="Re-open blind spot">
          <RefreshIcon width={16} height={16} /> Reset
        </button>
        <button className="btn-primary" onClick={onRun} disabled={running}>
          <PlayIcon width={15} height={15} />
          {running ? "Sweeping…" : "Run sweep"}
        </button>
      </div>
    </header>
  );
}
