import type { SurfaceNode } from "../lib/types";

interface Props {
  surface: SurfaceNode[];
  verified: string | null;
  active: string | null;
}

/** Sortable-by-impact list of every ATT&CK technique observed in the telemetry. */
export default function TechniqueTable({ surface, verified, active }: Props) {
  const rows = [...surface].sort((a, b) => b.events - a.events);
  return (
    <section className="panel overflow-hidden">
      <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
        <h2 className="text-sm font-semibold text-ink">Observed techniques</h2>
        <span className="tabular text-[11px] text-faint">{rows.length}</span>
      </div>
      {rows.length === 0 ? (
        <p className="px-5 py-8 text-center text-sm text-muted">No telemetry mapped yet — run a sweep.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-line text-left text-[11px] uppercase tracking-wide text-faint">
              <th className="px-5 py-2 font-medium">Technique</th>
              <th className="px-5 py-2 font-medium">Sourcetype</th>
              <th className="px-5 py-2 text-right font-medium">Events</th>
              <th className="px-5 py-2 text-right font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((s) => {
              const covered = s.covered || s.technique === verified;
              const isActive = s.technique === active && !covered;
              return (
                <tr key={s.technique} className="hover:bg-canvas">
                  <td className="px-5 py-2.5 font-mono text-[12.5px] font-medium text-ink">{s.technique}</td>
                  <td className="px-5 py-2.5 font-mono text-[11.5px] text-muted">{s.sourcetype}</td>
                  <td className="px-5 py-2.5 text-right tabular text-body">{s.events.toLocaleString()}</td>
                  <td className="px-5 py-2.5 text-right">
                    <StatusBadge state={covered ? "covered" : isActive ? "active" : "blind"} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}

function StatusBadge({ state }: { state: "covered" | "blind" | "active" }) {
  const map = {
    covered: "border-secure/20 bg-secure-soft text-secure",
    blind: "border-blind/20 bg-blind-soft text-blind",
    active: "border-brand-200 bg-brand-50 text-brand-700",
  } as const;
  const label = { covered: "covered", blind: "blind spot", active: "investigating" }[state];
  return <span className={`inline-flex rounded-md border px-2 py-0.5 text-[11px] font-medium ${map[state]}`}>{label}</span>;
}
