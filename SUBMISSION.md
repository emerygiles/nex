# NEX — Devpost Submission

**Track:** Security
**Hackathon:** Splunk Agentic Ops Hackathon

---

## Elevator pitch (tagline)

**NEX is an autonomous purple-team for Splunk — it hunts the detection blind spots your SOC can't see, proves they're real, and writes and deploys the fix itself.**

## Inspiration

Every SOC runs on detections — saved searches that fire when something bad happens. The dangerous part is what they *don't* watch for: if no rule covers a technique, nothing alerts and the attack walks right through. These coverage gaps are invisible by definition, and finding them is slow, manual work that depends on an analyst who can think like an attacker. We wanted to automate exactly that reasoning loop — the same "recon → hypothesize → prove → report" chain a bug-bounty hunter uses — and have it not just *describe* the gap but *close* it.

## What it does

NEX runs one autonomous loop against your Splunk data:

1. **Recon** — enumerates real indexes, sourcetypes, and deployed detections.
2. **Attack-think** — a local, security-tuned LLM (Cisco's **Foundation-Sec-8B**) reasons about which ATT&CK technique is most likely present but uncovered, prioritizing impact.
3. **Prove** — runs real SPL to confirm the malicious events exist (e.g. 301 S3-exfil events) with zero detections covering them. Proof is grounded in the telemetry itself, not a guess.
4. **Skeptic gate** — a second pass checks the *real* deployed-detection list to make sure it isn't crying wolf, killing false positives.
5. **Ship** — authors a deploy-ready **SPL + Sigma** detection and deploys it as a real Splunk saved search. Coverage flips 0→1; the blind spot closes.

The UI streams the agent's reasoning live and shows the ATT&CK coverage map flip **red → green** the moment the gap is closed.

## How we built it

- **Frontend:** React + TypeScript + Vite + Tailwind, React Flow (coverage graph), Framer Motion, React Query.
- **Backend:** Python + FastAPI, streaming the agent loop over SSE.
- **AI brain:** Foundation-Sec-8B-Instruct served locally via Ollama (OpenAI-compatible). Same model *family* Splunk offers as a hosted model.
- **Data plane:** Splunk Enterprise via the REST API (functionally equivalent to the **Splunk MCP Server**, which is also wired in `MODE=mcp`). A bundled mock backend (`MODE=sandbox`) runs the whole demo with zero Splunk setup.
- **Detections:** Splunk SPL + portable Sigma. Coverage mapped to **MITRE ATT&CK**.

The agent is decoupled from the data plane behind six tools, so the *same* loop, prompts, and UI run against the mock, the REST API, or the MCP Server — you swap one config value.

## Challenges we ran into

- **Small-model reliability.** An 8B model is smart but wobbly. We added grounding guards — impact-ranked technique selection, a citation-checked skeptic, and an on-target SPL validator — plus a deterministic safety net, so the agent is genuinely model-driven *and* can't produce an off-target or hallucinated result.
- **Proof vs. fix.** Early on the loop "proved" a gap by running the model's own detection SPL — when the model wrote a weak rule, NEX wrongly concluded "no gap." We separated the two: the gap is proven from the technique's real telemetry presence; the model's SPL is only the fix (with a guaranteed-firing fallback).
- **Platform realities.** The Splunk MCP token needs a healthy KV Store, which on our Enterprise build hit an OpenSSL-3/mongod TLS issue — so we proved the capability through the equivalent REST data plane.

## Accomplishments we're proud of

- A **closed loop**: find → prove → fix → verify, autonomously, in under a minute — backed by a *real* model and a *real* Splunk deploy, not a mock.
- A genuinely production-grade, industry-deployable dashboard.
- A self-skeptic step that addresses the #1 SOC complaint (false positives).

## What we learned

LLM agents in security earn trust by being **grounded** — the model reasons, but deterministic checks gate every consequential step against ground truth.

## What's next

- Wire live MCP once KV Store is healthy; add an SPL command allowlist (reject `delete`/`outputlookup`/`sendemail`) so the agent can't run a destructive search.
- Multi-gap sweeps and continuous scheduling; export to Enterprise Security correlation searches.

## Built with

`splunk` · `splunk-mcp-server` · `foundation-sec-8b` · `ollama` · `mitre-att&ck` · `sigma` · `python` · `fastapi` · `react` · `typescript` · `vite` · `tailwind` · `react-flow` · `framer-motion`

## Links

- **Repository:** _(this repo)_
- **Demo video:** _(YouTube link — add before submitting)_
- **Architecture:** [architecture.svg](architecture.svg) · [ARCHITECTURE.md](ARCHITECTURE.md)
