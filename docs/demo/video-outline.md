# Video Outline — NEX (Splunk Agentic Ops Hackathon)

**Title:** NEX — an AI agent that finds and closes Splunk detection blind spots itself
**Format:** Use-case demo · **Target length: 3:00** (hard cap) · Single screen-share, voiceover
**The one wow moment:** the red→green flip when NEX deploys a real detection and the blind spot closes.

---

## Section 1 — Hook + Problem (0:00–0:20) · 20s
- **Message:** Every SOC has detection blind spots it can't see; finding them is slow and manual.
- **On screen:** NEX **Coverage** dashboard already loaded with real data (6 techniques, 354 events, ≥1 blind spot).
- **Goal:** establish stakes + show this is live, real data in 2 sentences.

## Section 2 — One click (0:20–0:35) · 15s
- **Message:** NEX is an autonomous purple-team — one click and it attacks your own Splunk data like an attacker.
- **On screen:** Click **Run sweep**. Agent activity panel begins streaming.

## Section 3 — Recon + AI reasoning (0:35–1:20) · 45s — THE AI BEAT
- **Message:** A real security-tuned model (Foundation-Sec-8B, local) reasons about which gap matters most.
- **On screen:** Activity stream: `enumerate_coverage()`, `map_attack_surface()`, then the model's hypothesis naming **T1537** (301 events, highest impact). Coverage graph lights T1537 **red**.
- **Backup:** if a node label is hard to read, cut to the **Surface map** view (table sorted by impact).

## Section 4 — Prove + skeptic (1:20–2:00) · 40s
- **Message:** It doesn't guess — it proves the gap with a real search, then sanity-checks itself.
- **On screen:** `test_detection` → **301 hits, 0 detections**; skeptic confirms no existing rule covers it; red **EXPOSED** banner.

## Section 5 — Author + deploy + FLIP (2:00–2:38) · 38s — THE WOW
- **Message:** It writes the fix — SPL + Sigma — and deploys it as a real Splunk saved search.
- **On screen:** Authored detection panel fills; `deploy_detection()`; **coverage 0→1**; banner turns **green RESOLVED**; T1537 node flips **red→green**. Hold 2s.

## Section 6 — Proof + value + close (2:38–3:00) · 22s
- **Message:** It's real, autonomous, and closes the loop — found, proved, fixed, verified.
- **On screen:** Click **Detections** → the new `NEX-DET – …(T1537)` sits beside the baseline rules. End card with the stack.
- **Stack card:** Splunk · Splunk MCP Server (REST data plane) · Foundation-Sec-8B · MITRE ATT&CK.

---

## Timing ledger
| Section | Dur | Running |
|---|---|---|
| Hook+Problem | 0:20 | 0:20 |
| One click | 0:15 | 0:35 |
| Recon+AI | 0:45 | 1:20 |
| Prove+skeptic | 0:40 | 2:00 |
| Author+deploy+flip | 0:38 | 2:38 |
| Proof+value | 0:22 | 3:00 |

## Editing notes
- The real run is ~35–60s of inference. **Don't speed-ramp the reasoning text** — it's the proof the AI is real. Instead, tighten by trimming dead air between tool calls and using a soft 1.2–1.5× on the longest pauses only.
- One screen-share, 1440-wide, sidebar visible. No talking head needed.
