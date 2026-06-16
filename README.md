# NEX Autonomous Purple-Team for Splunk

> **NEX finds the detection blind spots in your Splunk deployment that you don't know you have then closes them.**

NEX is an agentic security solution for the **Splunk Agentic Ops Hackathon (Security track)**. It attacks your *own* Splunk data the way a bug-bounty hunter would, **proves** a detection-coverage gap exists (runs the SPL, gets zero hits), runs a self-skeptic pass to suppress false positives, then **writes and deploys the detection** that closes the gap — as both an SPL saved search and a portable Sigma rule.

It's not a chatbot that *describes* problems. It closes the loop: **find → prove → fix → verify.**

---

## Why it matters

Every SOC has detection gaps. Finding them is slow, manual, and depends on an analyst thinking like an attacker. NEX automates exactly that loop using:

- **Splunk MCP Server** — the agent's hands: enumerate knowledge objects, run SPL, deploy saved searches.
- **Splunk Hosted Models** (`Foundation-sec-1.1-8b-instruct`) — the agent's brain: security-tuned reasoning about attacker TTPs and detection logic.
- **MITRE ATT&CK** — the coverage map the agent reasons against.

## The agent loop

1. **Recon** — enumerate indexes, sourcetypes, and existing detections via MCP.
2. **Attack-think** — Foundation-sec picks an ATT&CK technique likely to slip past current coverage.
3. **Prove the gap** — generate + run candidate SPL via MCP; **0 hits = confirmed blind spot**.
4. **Skeptic gate** — a second pass tries to *disprove* the gap (existing rule? missing data?). Kills false positives.
5. **Ship the fix** — emit SPL + Sigma + severity + ATT&CK ID, and deploy the saved search via MCP.

## Visibility coverage — the "gaps under the gaps"

Rule coverage only matters for techniques whose telemetry you actually collect *and can query*.
NEX runs a **tiered visibility check** alongside the rule-gap finder. Detection coverage =
rule coverage × data-source coverage. (`GET /visibility`, the **Visibility** view, and a recon
step in the loop.) It is built directly on Splunk Enterprise Architect **Marcus House**'s review:

- **STIX-driven, not hand-mapped.** Technique → telemetry comes from ATT&CK's own STIX bundle
  (the v17 detection-strategy / analytic model, with concrete log sources like `AWS:CloudTrail`,
  `WinEventLog:Sysmon`, `saas:okta`). It generalizes to ~600 techniques and survives each ATT&CK
  release. Regenerate with `python scripts/build_attack_mapping.py` (uses `mitreattack-python`).
- **Tiered, not boolean.** Each technique scores **good / partial / none** from DeTT&CT-style
  data-quality dimensions — *completeness, timeliness, retention, consistency* — not a single
  visible/blind bit. Having firewall flow logs isn't PCAP; having a feed isn't having the fields.
- **Splunk reality.** "Have the data source" means **onboarded AND CIM-normalized AND within the
  search window**. ESCU content assumes CIM, so a log that's ingested but not mapped into the
  right CIM data model still won't fire a detection — that's the `consistency` dimension, and on
  the live backend it's *measured* with `| tstats` against each CIM data model.
- **Remediation, not just flagging.** Every gap carries the concrete Splunk input to onboard or
  CIM-map to close it — recon is the flag, remediation is the payoff.
- **Priority queue, not flat list.** Techniques are ranked against a configurable **threat
  profile** (`THREAT_PROFILE`, see `backend/threat_profiles.py`; `GET /threat-profiles`), so the
  org's actual exposure floats to the top.

**OR vs AND across data sources:** NEX uses **OR** to decide "can you see it at all" (any one
relevant CIM data model present → some visibility) and then **weights the count and quality** of
the present sources for the tier. A short, documented overlay applies **AND** for the few
techniques with a genuinely *necessary* primary source (e.g. S3 object-exfil needs CloudTrail
*data events* — the management plane can't see it). Pure AND invents blind spots; pure OR throws
away the quality signal. See the note at the top of `backend/threat_profiles.py`.

## Production safety

- **SPL command allowlist** — any agent-run or deployed SPL is rejected if it contains a write/
  exfil/execute command (`delete`, `outputlookup`, `sendemail`, `script`, `collect`, …). A
  detection tool reads telemetry; it never deletes or shells out.
- **Human-in-the-loop deploy** — set `AUTO_DEPLOY=false` and NEX *proposes* the detection and
  waits for analyst approval (`POST /deploy` / the **Approve & deploy** button) instead of
  deploying it itself. The model proposes; the analyst decides.
- **Grounded proof** — a gap is proven by the technique's real telemetry presence, not by the
  model's candidate rule, so a weak SPL can never read as "no gap."

## Two run modes

| Mode | Data plane | Use |
|---|---|---|
| **Sandbox** | built-in mock MCP + bundled APT dataset | Judges run it with **zero Splunk setup** |
| **Live** | official Splunk MCP Server (`:8089/services/mcp`) | Real detection-gap analysis on your instance |

Same agent code; the MCP endpoint is swapped via config.

> **Status:** Sandbox mode is the primary, fully-working path (and the recommended way to evaluate NEX). Live mode is implemented end-to-end; on Splunk Enterprise it additionally requires the KV Store to be healthy so the MCP Server can mint an encrypted token.

---

## Quick start

### Sandbox (no Splunk needed)

```bash
# Backend
cd backend
python -m venv .venv && . .venv/Scripts/activate   # Windows; use bin/activate on *nix
pip install -r requirements.txt
cp .env.example .env          # MODE=sandbox is the default
uvicorn app:app --reload --port 8800

# Frontend (new terminal)
cd frontend
npm install
npm run dev                   # http://localhost:5173
```

### Live (real Splunk via REST) — `MODE=splunk_rest`

This runs the agent against a real Splunk instance: real knowledge-object enumeration,
real SPL searches, and a real deployed saved search.

1. **Ingest the demo attack dataset** (creates the `nex` index data via HEC):
   ```
   python scripts/ingest_demo_data.py --token <HEC_TOKEN>
   ```
2. **Create the baseline 'existing detections'** (covers T1110/T1059.001/T1078.004, not the exfil):
   ```
   python scripts/setup_detections.py --user <admin> --password <pw>
   ```
3. In `backend/.env`:
   ```
   MODE=splunk_rest
   SPLUNK_REST_URL=https://localhost:8089
   SPLUNK_USER=<admin>
   SPLUNK_PASSWORD=<pw>
   SPLUNK_INDEX=nex
   AI_PROVIDER=foundation_sec     # Foundation-Sec-8B via local Ollama; or 'scripted'
   ```
4. Start the backend. `POST /reset` re-opens the blind spot between demo runs.

### Live (Splunk MCP Server) — `MODE=mcp`

Equivalent transport via the official **Splunk MCP Server** (#7931) at `:8089/services/mcp`.
Requires an encrypted MCP token, which needs a healthy KV Store. (On Splunk Enterprise 10.4
the bundled MongoDB/OpenSSL-3 combo can fail to read its TLS key, blocking token creation;
the REST data plane above is functionally equivalent and unaffected.)

### AI brain options

`foundation_sec` (Cisco Foundation-Sec-8B-Instruct, local Ollama), `anthropic` (dev), or
`scripted` (deterministic, zero-dep). Live-model calls have a deterministic safety net and
grounding guards so a small model can't produce an off-target or hallucinated result.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) and [docs/architecture.mmd](docs/architecture.mmd).

## Tech

React + TypeScript + Vite + Tailwind + shadcn/ui + React Flow + Framer Motion · Python + FastAPI · Splunk MCP Server · Foundation-sec-1.1-8b · SPL + Sigma.

## License

[MIT](LICENSE).
