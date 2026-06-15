import { AlertIcon, CheckIcon } from "../lib/icons";
import type { GapInfo } from "../hooks/useNexRun";

export default function GapAlert({ gap, verified }: { gap: GapInfo; verified: boolean }) {
  if (!gap) return null;
  const closed = verified;
  return (
    <div
      role="status"
      className={`flex items-center gap-3 rounded-xl border px-4 py-3 ${
        closed ? "border-secure/30 bg-secure-soft" : "border-blind/30 bg-blind-soft"
      }`}
    >
      <span
        className={`grid h-8 w-8 shrink-0 place-items-center rounded-md ${
          closed ? "bg-secure/12 text-secure" : "bg-blind/12 text-blind"
        }`}
      >
        {closed ? <CheckIcon width={17} height={17} /> : <AlertIcon width={17} height={17} />}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-semibold text-ink">{gap.technique}</span>
          <span className={`text-xs font-medium ${closed ? "text-secure" : "text-blind"}`}>
            {closed ? "Blind spot closed" : "Blind spot confirmed"}
          </span>
        </div>
        <p className="text-xs text-muted">
          <span className="tabular">{gap.hits.toLocaleString()}</span> malicious events ·{" "}
          <span className="tabular">{gap.existing}</span> prior detections
        </p>
      </div>
      <span
        className={`hidden rounded-md px-2 py-1 text-[11px] font-semibold sm:block ${
          closed ? "bg-secure/12 text-secure" : "bg-blind/12 text-blind"
        }`}
      >
        {closed ? "RESOLVED" : "EXPOSED"}
      </span>
    </div>
  );
}
