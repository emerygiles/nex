import { motion } from "framer-motion";
import type { Detection } from "../lib/types";
import { CheckIcon, DocIcon } from "../lib/icons";

interface Props {
  detection: Detection | null;
  deployed: boolean;
  pending?: boolean;
  deploying?: boolean;
  onApprove?: () => void;
}

export default function DetectionPanel({ detection, deployed, pending, deploying, onApprove }: Props) {
  const status = deployed ? "Deployed" : pending ? "Awaiting approval" : "Ready";
  return (
    <section className="panel flex h-full flex-col overflow-hidden">
      <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
        <h2 className="text-sm font-semibold text-ink">Authored detection</h2>
        {detection && (
          <span
            className={`inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-[11px] font-semibold ${
              deployed ? "bg-secure/12 text-secure" : pending ? "bg-blind-soft text-blind" : "bg-brand-50 text-brand-700"
            }`}
          >
            {deployed && <CheckIcon width={13} height={13} />}
            {status}
          </span>
        )}
      </div>

      {!detection ? (
        <div className="grid flex-1 place-items-center px-6 py-10 text-center">
          <div className="space-y-2">
            <DocIcon width={22} height={22} className="mx-auto text-faint" />
            <p className="text-sm text-muted">A deploy-ready SPL + Sigma rule appears here once a gap is confirmed.</p>
          </div>
        </div>
      ) : (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex-1 space-y-4 overflow-y-auto p-5">
          <div>
            <div className="text-sm font-medium text-ink">{detection.name}</div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <span className="chip border-blind/20 bg-blind-soft text-blind">{detection.technique}</span>
              {detection.tactic && <span className="chip">{detection.tactic}</span>}
              <span className="chip">severity · {detection.severity}</span>
            </div>
          </div>

          <Field label="Splunk SPL">
            <pre className="overflow-x-auto rounded-lg bg-term px-3.5 py-3 font-mono text-[11.5px] leading-relaxed text-[#C9D1E4]">
              {detection.spl}
            </pre>
          </Field>

          <Field label="Sigma rule">
            <pre className="overflow-x-auto rounded-lg border border-line bg-canvas px-3.5 py-3 font-mono text-[11px] leading-relaxed text-body">
              {JSON.stringify(detection.sigma, null, 2)}
            </pre>
          </Field>

          {pending && !deployed && (
            <div className="flex items-center justify-between gap-3 rounded-lg border border-blind/25 bg-blind-soft px-3.5 py-3">
              <p className="text-[12.5px] text-body">
                NEX proposed this detection. <span className="font-medium text-ink">An analyst approves before it deploys.</span>
              </p>
              <button className="btn-primary shrink-0" onClick={onApprove} disabled={deploying}>
                {deploying ? "Deploying…" : "Approve & deploy"}
              </button>
            </div>
          )}
        </motion.div>
      )}
    </section>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="eyebrow mb-1.5">{label}</div>
      {children}
    </div>
  );
}
