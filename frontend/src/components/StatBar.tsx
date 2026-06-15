interface Stat {
  label: string;
  value: number | string;
  accent?: "ink" | "brand" | "blind" | "secure";
}

const accentClass: Record<NonNullable<Stat["accent"]>, string> = {
  ink: "text-ink",
  brand: "text-brand-700",
  blind: "text-blind",
  secure: "text-secure",
};

export default function StatBar({ stats }: { stats: Stat[] }) {
  return (
    <div className="grid grid-cols-2 divide-line overflow-hidden rounded-xl border border-line bg-surface shadow-card sm:grid-cols-4 sm:divide-x">
      {stats.map((s) => (
        <div key={s.label} className="px-5 py-4">
          <div className="eyebrow">{s.label}</div>
          <div className={`mt-1.5 text-2xl font-semibold tabular tracking-tight ${accentClass[s.accent ?? "ink"]}`}>
            {s.value}
          </div>
        </div>
      ))}
    </div>
  );
}
