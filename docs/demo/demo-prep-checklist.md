# Demo Prep Checklist — NEX

## Services (verified ready 2026-06-11)
- [x] **Splunk** mgmt API `:8089` up (NEX uses this). *(Splunk Web `:8000` is flaky — not needed; only for optional B-roll of the saved search in Splunk UI.)*
- [x] **Ollama** running; **Foundation-Sec-8B loaded in VRAM** (warm — first inference won't stall the take).
- [x] **Backend** `:8800` up — `MODE=splunk_rest`, `AI_PROVIDER=foundation_sec`.
- [x] **Frontend** `http://localhost:5173` up.
- [x] **Demo data** present (354 events; T1537 = 301). *Fixed the search-window bug that had aged it out.*
- [x] **Gap open** — T1537 uncovered, ready to close on camera.

## Before you hit record
- [ ] Browser at **1440px wide** (sidebar visible), Coverage view selected, zoom 100%.
- [ ] Close notifications / other tabs. Full-screen the browser.
- [ ] Hard-refresh `localhost:5173` so KPIs show **Blind spots ≥ 1**.
- [ ] Do ONE throwaway sweep + **Reset** right before recording (keeps the model hot; re-opens the gap).
- [ ] Confirm the top-bar chips read **splunk-rest** and **foundation_sec** (proves it's the real path on camera).

## Between takes
- [ ] Click **Reset** (top bar) — re-opens T1537 so you can run the flip again. Wait for it to confirm.
- [ ] If the model feels cold (>60s), run one warm-up sweep first.

## Backup plans
- **Model drifts / slow:** the impact-guard guarantees T1537 is the pick regardless; if inference is too slow for the cut, set `AI_PROVIDER=scripted` in `backend/.env` and restart — instant, deterministic run, still the real Splunk loop (note: reasoning text is templated, not model-written).
- **Run stalls:** `curl -X POST localhost:8800/reset` then refresh and re-run.
- **Splunk hiccup:** the bundled **sandbox** mode (`MODE=sandbox`) runs the whole demo with zero Splunk — fallback for a safe take.

## Reset / restart commands (PowerShell-friendly via the .venv)
```
# reopen the gap
curl -s -X POST http://127.0.0.1:8800/reset
# restart backend if needed (from NEX/backend)
./.venv/Scripts/python -m uvicorn app:app --port 8800
# warm the model
curl -s -N http://127.0.0.1:8800/run > $null ; curl -s -X POST http://127.0.0.1:8800/reset
```
