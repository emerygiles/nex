interface Props {
  sourcetypes: { name: string; events: number }[];
  detections: { name: string; technique: string }[];
}

export default function EnvironmentPanel({ sourcetypes, detections }: Props) {
  return (
    <section className="panel flex h-full flex-col overflow-hidden">
      <div className="border-b border-line px-5 py-3.5">
        <h2 className="text-sm font-semibold text-ink">Environment</h2>
      </div>

      <div className="flex-1 space-y-5 overflow-y-auto p-5">
        <Group title="Sourcetypes" count={sourcetypes.length}>
          {sourcetypes.length === 0 ? (
            <Empty />
          ) : (
            <ul className="divide-y divide-line">
              {sourcetypes.map((s) => (
                <li key={s.name} className="flex items-center justify-between gap-3 py-2">
                  <span className="truncate font-mono text-[11.5px] text-body">{s.name}</span>
                  <span className="tabular shrink-0 text-[11px] text-muted">{s.events.toLocaleString()}</span>
                </li>
              ))}
            </ul>
          )}
        </Group>

        <Group title="Existing detections" count={detections.length}>
          {detections.length === 0 ? (
            <Empty />
          ) : (
            <ul className="divide-y divide-line">
              {detections.map((d) => (
                <li key={d.name} className="flex items-center justify-between gap-3 py-2">
                  <span className="truncate text-[12.5px] text-body">{d.name}</span>
                  <span className="chip shrink-0 border-secure/20 bg-secure-soft py-0.5 font-mono text-[10px] text-secure">
                    {d.technique}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Group>
      </div>
    </section>
  );
}

function Group({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <span className="eyebrow">{title}</span>
        <span className="tabular text-[11px] text-faint">{count}</span>
      </div>
      {children}
    </div>
  );
}

function Empty() {
  return <p className="py-1 text-xs text-faint">Awaiting recon —</p>;
}
