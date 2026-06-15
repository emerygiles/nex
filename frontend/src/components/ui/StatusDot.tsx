export default function StatusDot({ ok, busy }: { ok?: boolean; busy?: boolean }) {
  const color = busy ? "bg-brand-600" : ok ? "bg-secure" : "bg-faint";
  return (
    <span className="relative inline-flex h-2 w-2">
      {busy && <span className="absolute inline-flex h-full w-full rounded-full bg-brand-600/40 animate-breathe" />}
      <span className={`relative inline-flex h-2 w-2 rounded-full ${color}`} />
    </span>
  );
}
