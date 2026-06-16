import type { Tier, Visibility, VisTechnique } from "../lib/types";
import { CheckIcon, AlertIcon, EyeOffIcon } from "../lib/icons";

/**
 * Visibility coverage — the "gaps under the gaps", v2.
 * STIX-derived technique telemetry, scored none/partial/good from measured data quality
 * (volume, freshness, retention, and real CIM data-model membership), ranked by a threat
 * profile, each gap carrying the concrete Splunk input to onboard. Detection coverage =
 * rule coverage × data-source coverage. (Built on Marcus House's review feedback.)
 */

const TIER_STYLE: Record<Tier, { chip: string; dot: string; label: string }> = {
  good: { chip: "border-secure/20 bg-secure-soft text-secure", dot: "bg-secure", label: "Good" },
  partial: { chip: "border-warn/20 bg-warn-soft text-warn", dot: "bg-warn", label: "Partial" },
  none: { chip: "border-blind/20 bg-blind-soft text-blind", dot: "bg-blind", label: "Blind" },
};

function TierChip({ tier }: { tier: Tier }) {
  const s = TIER_STYLE[tier];
  return <span className={`chip ${s.chip}`}>{s.label}</span>;
}

function ScoreBar({ score, tier }: { score: number; tier: Tier }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-line">
      <div className={`h-full rounded-full ${TIER_STYLE[tier].dot}`} style={{ width: `${Math.round(score * 100)}%` }} />
    </div>
  );
}

function ModelStrip({ data }: { data: Visibility }) {
  const present = data.models.filter((m) => m.present);
  const missing = data.models.filter((m) => !m.present);
  return (
    <div className="border-b border-line px-5 py-3">
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
        CIM data-model posture
      </div>
      <div className="flex flex-wrap gap-1.5">
        {present.map((m) => (
          <span
            key={m.model}
            title={`${m.matched_sourcetype} · completeness ${m.completeness} · CIM ${m.consistency} · fresh ${m.timeliness} · retention ${m.retention}`}
            className={`chip ${TIER_STYLE[m.tier].chip}`}
          >
            <span className={`mr-1 inline-block h-1.5 w-1.5 rounded-full ${TIER_STYLE[m.tier].dot}`} />
            {m.label}
          </span>
        ))}
        {missing.map((m) => (
          <span key={m.model} className="chip border-line bg-canvas text-faint" title="No telemetry mapped">
            {m.label}
          </span>
        ))}
      </div>
    </div>
  );
}

function ActionPill({ action }: { action: string }) {
  const map: Record<string, string> = {
    onboard: "Onboard",
    cim_normalize: "CIM-map",
    increase_fidelity: "Tune",
    extend_retention: "Retention",
  };
  return (
    <span className="rounded border border-line bg-canvas px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-muted">
      {map[action] ?? action}
    </span>
  );
}

function TechniqueRow({ t }: { t: VisTechnique }) {
  const Icon = t.tier === "good" ? CheckIcon : t.tier === "partial" ? EyeOffIcon : AlertIcon;
  const accent = TIER_STYLE[t.tier].dot.replace("bg-", "text-");
  return (
    <li className="py-3.5">
      <div className="flex items-start gap-3">
        <Icon width={15} height={15} className={`mt-0.5 shrink-0 ${accent}`} />
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-[12px] font-semibold text-ink">{t.technique}</span>
            <span className="truncate text-[12.5px] text-body">{t.name}</span>
            <span className="ml-auto shrink-0">
              <TierChip tier={t.tier} />
            </span>
          </div>
          {t.rationale && <p className="mt-0.5 text-[11px] leading-snug text-muted">{t.rationale}</p>}

          {/* required CIM models, colored by what the environment actually supplies */}
          <div className="mt-1.5 flex flex-wrap gap-1">
            {t.required_models.map((rm) => (
              <span
                key={rm.model}
                title={rm.log_sources.join(", ")}
                className={`rounded px-1.5 py-0.5 text-[10.5px] ${
                  rm.present
                    ? `${TIER_STYLE[rm.tier].chip} border`
                    : "border border-dashed border-blind/30 bg-blind-soft text-blind"
                }`}
              >
                {rm.label}
                {!rm.present && " ✕"}
              </span>
            ))}
          </div>

          {/* remediation — close the loop */}
          {t.remediation.length > 0 && (
            <ul className="mt-2 space-y-1">
              {t.remediation.map((r, i) => (
                <li key={i} className="flex items-start gap-1.5 text-[11px] leading-snug text-body">
                  <ActionPill action={r.action} />
                  <span className="text-muted">{r.splunk}</span>
                </li>
              ))}
            </ul>
          )}

          <div className="mt-2 flex items-center gap-2">
            <ScoreBar score={t.score} tier={t.tier} />
            <span className="shrink-0 font-mono text-[10px] text-faint">prio {t.priority.toFixed(2)}</span>
          </div>
        </div>
      </div>
    </li>
  );
}

export default function VisibilityPanel({ data }: { data: Visibility | null }) {
  return (
    <section className="panel flex h-full flex-col overflow-hidden">
      <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
        <div>
          <h2 className="text-sm font-semibold text-ink">Visibility gaps</h2>
          <p className="text-[11px] text-muted">
            {data
              ? `Ranked by "${data.profile.label}" · ATT&CK v${data.attack_version} · onboarded + CIM-mapped + in window`
              : "Tiered data-source coverage — the gaps under the gaps"}
          </p>
        </div>
        {data && (
          <div className="flex items-center gap-1.5 text-[11px]">
            <span className="chip border-secure/20 bg-secure-soft text-secure">{data.summary.good} good</span>
            <span className="chip border-warn/20 bg-warn-soft text-warn">{data.summary.partial} partial</span>
            <span className="chip border-blind/20 bg-blind-soft text-blind">{data.summary.blind} blind</span>
          </div>
        )}
      </div>

      {!data ? (
        <div className="p-5 text-sm text-muted">Loading data-source coverage…</div>
      ) : (
        <>
          <ModelStrip data={data} />
          <div className="flex-1 overflow-y-auto px-5">
            <ul className="divide-y divide-line">
              {data.techniques.map((t) => (
                <TechniqueRow key={t.technique} t={t} />
              ))}
            </ul>
            <p className="my-4 rounded-lg border border-line bg-canvas p-3 text-[11.5px] leading-relaxed text-muted">
              Detection coverage = rule coverage × data-source coverage. A source counts as{" "}
              <span className="text-secure">good</span> only when it's onboarded,{" "}
              <span className="text-ink">CIM-normalized</span>, and within the search window — ESCU content
              assumes CIM, so an ingested-but-unmapped feed still won't fire a detection.
            </p>
          </div>
        </>
      )}
    </section>
  );
}
