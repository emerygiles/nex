import { CheckIcon } from "../lib/icons";

type Det = { name: string; technique: string };

/** All deployed saved-search detections, split into NEX-authored vs. baseline.
 * Baseline are the three seeded SOC detections; everything else NEX deployed. */
export default function DetectionsTable({ detections }: { detections: Det[] }) {
  const isBaseline = (n: string) => /Fatigue|PowerShell|Console Login/i.test(n);
  const nexAuthored = detections.filter((d) => !isBaseline(d.name));
  const baseline = detections.filter((d) => isBaseline(d.name));

  return (
    <section className="panel overflow-hidden">
      <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
        <h2 className="text-sm font-semibold text-ink">Deployed detections</h2>
        <span className="tabular text-[11px] text-faint">{detections.length}</span>
      </div>
      {detections.length === 0 ? (
        <p className="px-5 py-8 text-center text-sm text-muted">No detections enumerated yet.</p>
      ) : (
        <div className="divide-y divide-line">
          {nexAuthored.length > 0 && <GroupHeader label="Authored by NEX" />}
          {nexAuthored.map((d) => <Row key={d.name} d={d} nex />)}
          {baseline.length > 0 && <GroupHeader label="Baseline SOC detections" />}
          {baseline.map((d) => <Row key={d.name} d={d} />)}
        </div>
      )}
    </section>
  );
}

function GroupHeader({ label }: { label: string }) {
  return <div className="bg-canvas px-5 py-2 text-[11px] font-semibold uppercase tracking-wide text-faint">{label}</div>;
}

function Row({ d, nex }: { d: { name: string; technique: string }; nex?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 px-5 py-3 hover:bg-canvas">
      <div className="flex min-w-0 items-center gap-2.5">
        <span className={`grid h-6 w-6 shrink-0 place-items-center rounded-md ${nex ? "bg-secure/12 text-secure" : "bg-line text-muted"}`}>
          {nex ? <CheckIcon width={13} height={13} /> : <span className="h-1.5 w-1.5 rounded-full bg-muted" />}
        </span>
        <span className="truncate text-[13px] text-body">{d.name}</span>
      </div>
      <span className="chip shrink-0 border-line bg-surface font-mono text-[11px] text-ink">{d.technique}</span>
    </div>
  );
}
