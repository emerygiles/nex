import { AnimatePresence, motion } from "framer-motion";
import type { StepEvent } from "../lib/types";
import { SparkIcon } from "../lib/icons";

const phaseLabel: Record<string, string> = {
  start: "Init", recon: "Recon", "attack-think": "Hypothesis",
  prove: "Proof", skeptic: "Skeptic", ship: "Remediate", done: "Done",
};
const phaseColor: Record<string, string> = {
  start: "text-faint", recon: "text-brand-700", "attack-think": "text-brand-700",
  prove: "text-blind", skeptic: "text-brand-700", ship: "text-secure", done: "text-secure",
};

export default function ActivityStream({ events, running }: { events: StepEvent[]; running: boolean }) {
  return (
    <section className="panel flex h-full flex-col overflow-hidden">
      <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
        <h2 className="text-sm font-semibold text-ink">Agent activity</h2>
        <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-brand-700">
          <SparkIcon width={13} height={13} /> Foundation-Sec
        </span>
      </div>

      <div className="flex-1 overflow-y-auto px-2 py-2">
        {events.length === 0 ? (
          <div className="grid h-full place-items-center px-6 text-center">
            <p className="text-sm text-muted">
              The agent's reasoning and tool calls stream here during a sweep.
            </p>
          </div>
        ) : (
          <ol className="space-y-px">
            <AnimatePresence initial={false}>
              {events.map((e, i) => (
                <motion.li
                  key={i}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                  className="grid grid-cols-[84px_1fr] gap-3 rounded-md px-3 py-2 hover:bg-canvas"
                >
                  <div className="pt-px">
                    <span className={`text-[10px] font-semibold uppercase tracking-wider ${phaseColor[e.phase] ?? "text-faint"}`}>
                      {phaseLabel[e.phase] ?? e.phase}
                    </span>
                  </div>
                  <div className="min-w-0">
                    <p className="text-[13px] leading-snug text-body">{e.message}</p>
                    {e.kind === "tool" && e.data?.spl && (
                      <pre className="mt-1.5 overflow-x-auto rounded-md bg-term px-2.5 py-2 font-mono text-[11px] leading-relaxed text-[#C9D1E4]">
                        {e.data.spl}
                      </pre>
                    )}
                  </div>
                </motion.li>
              ))}
            </AnimatePresence>
            {running && (
              <li className="grid grid-cols-[84px_1fr] gap-3 px-3 py-2">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-faint">···</span>
                <span className="inline-flex h-3 w-24 animate-breathe rounded bg-line" />
              </li>
            )}
          </ol>
        )}
      </div>
    </section>
  );
}
