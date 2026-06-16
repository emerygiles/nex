import type { Visibility } from "../lib/types";
import { AlertIcon, CheckIcon } from "../lib/icons";

/**
 * Data-source (visibility) coverage — the "gaps under the gaps".
 * Detection coverage = rule coverage x data-source coverage. NEX's gap finder only sees
 * techniques whose telemetry exists; this panel surfaces high-value techniques you have
 * NO data source to even observe. (Credit: Marcus House, on the project's LinkedIn post.)
 */
export default function VisibilityPanel({ data }: { data: Visibility | null }) {
  const blind = data?.techniques.filter((t) => t.status === "blind") ?? [];
  const visible = data?.techniques.filter((t) => t.status === "visible") ?? [];

  return (
    <section className="panel flex h-full flex-col overflow-hidden">
      <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
        <div>
          <h2 className="text-sm font-semibold text-ink">Visibility gaps</h2>
          <p className="text-[11px] text-muted">Techniques with no data source — invisible to any detection</p>
        </div>
        {data && (
          <div className="flex items-center gap-2 text-[11px]">
            <span className="chip border-secure/20 bg-secure-soft text-secure">{data.visible} visible</span>
            <span className="chip border-blind/20 bg-blind-soft text-blind">{data.blind} blind</span>
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-5">
        {!data ? (
          <p className="text-sm text-muted">Loading data-source coverage…</p>
        ) : (
          <>
            <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-blind">
              No data source — you can't see these at all
            </div>
            <ul className="divide-y divide-line">
              {blind.map((t) => (
                <li key={t.technique} className="flex items-start gap-3 py-2.5">
                  <AlertIcon width={15} height={15} className="mt-0.5 shrink-0 text-blind" />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-baseline gap-2">
                      <span className="font-mono text-[12px] font-semibold text-ink">{t.technique}</span>
                      <span className="truncate text-[12.5px] text-body">{t.name}</span>
                    </div>
                    <div className="text-[11px] text-muted">
                      {t.tactic} · needs <span className="text-blind">{t.data_source}</span>
                    </div>
                  </div>
                </li>
              ))}
            </ul>

            <div className="mb-2 mt-5 text-[11px] font-semibold uppercase tracking-wide text-secure">
              Data source present — NEX can reason about these
            </div>
            <ul className="divide-y divide-line">
              {visible.map((t) => (
                <li key={t.technique} className="flex items-center gap-3 py-2">
                  <CheckIcon width={14} height={14} className="shrink-0 text-secure" />
                  <span className="font-mono text-[11.5px] text-ink">{t.technique}</span>
                  <span className="truncate text-[12px] text-muted">{t.name}</span>
                </li>
              ))}
            </ul>

            {data.missing_data_sources.length > 0 && (
              <p className="mt-5 rounded-lg border border-line bg-canvas p-3 text-[12px] leading-relaxed text-muted">
                Detection coverage = rule coverage × data-source coverage. To close these, onboard:{" "}
                <span className="text-ink">{data.missing_data_sources.join(", ")}</span>.
              </p>
            )}
          </>
        )}
      </div>
    </section>
  );
}
