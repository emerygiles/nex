"""Model client — the agent's brain.

Providers behind one interface:
  - foundation_sec : Cisco Foundation-Sec-8B-Instruct (open weights) served locally via an
                     OpenAI-compatible endpoint (Ollama). The security-tuned brain.
  - anthropic      : dev-time fallback (needs ANTHROPIC_API_KEY)
  - scripted       : deterministic, no network — lets the sandbox run with zero deps

Design note: every live-model method is wrapped by `_guard`, which falls back to the
deterministic result if the model errors or returns unpar_seable output. This makes the
demo genuinely model-driven *and* reliable — a small 8B model can't break the loop.
"""
from __future__ import annotations

import json
import re

import httpx

from config import settings


def _extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model response (handles ```json fences, prose)."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        return json.loads(fence.group(1))
    start = text.find("{")
    if start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return json.loads(text[start:i + 1])
    raise ValueError("no JSON object in model output")


class ModelClient:
    def __init__(self, mcp=None) -> None:
        self.provider = settings.ai_provider
        self._mcp = mcp

    # ---- public API (each tries the live model, falls back if needed) ------
    def pick_uncovered_technique(self, surface: list[dict]) -> dict:
        return self._guard(lambda: self._pick(surface), lambda: self._pick_scripted(surface))

    def write_detection(self, technique: str) -> dict:
        return self._guard(lambda: self._write(technique), lambda: self._write_scripted(technique))

    def grounded_detection(self, technique: str) -> dict:
        """Deterministic, guaranteed-firing detection (the safety-net rule). Public for the loop."""
        return self._write_scripted(technique)

    def skeptic_review(self, technique: str, evidence: dict) -> dict:
        return self._guard(lambda: self._skeptic(technique, evidence),
                           lambda: self._skeptic_scripted(evidence))

    # ---- guard / fallback --------------------------------------------------
    def _guard(self, live, fallback):
        if self.provider == "scripted":
            return fallback()
        try:
            return live()
        except Exception as e:  # noqa: BLE001 - any model/parse failure → safety net
            if settings.ai_safety_net:
                result = fallback()
                result["_fallback"] = f"{type(e).__name__}: {e}"
                return result
            raise

    # ---- deterministic implementations (also the safety net) ---------------
    def _pick_scripted(self, surface):
        gap = [s for s in surface if not s["covered"]]
        if not gap:
            # No blind spots (or empty surface). Never fabricate a gap on a covered technique.
            raise ValueError("no uncovered technique to investigate")
        choice = max(gap, key=lambda s: s["events"])
        return {
            "technique": choice["technique"],
            "rationale": f"{choice['events']} events on {choice['sourcetype']} for "
                         f"{choice['technique']} with no matching detection — likely blind spot.",
        }

    def _write_scripted(self, technique):
        g = self._mcp.planted_gap if self._mcp is not None and hasattr(self._mcp, "planted_gap") else {}
        if g:
            return {
                "name": g.get("name", f"Detection for {technique}") + f" ({technique})",
                "spl": g["candidate_spl"],
                "sigma": g.get("candidate_sigma", {"title": f"{technique} detection", "level": "high"}),
                "severity": "high", "technique": technique, "tactic": g.get("tactic", ""),
            }
        # Real-mode safety net: a valid, index-scoped SPL grounded on the technique's evidence.
        samples = self._mcp.sample_events(technique) if self._mcp and hasattr(self._mcp, "sample_events") else []
        st = samples[0].get("sourcetype", "") if samples else ""
        st_clause = f"sourcetype={st} " if st else ""
        return {
            "name": f"Detection for {technique}",
            "spl": f"search index={settings.splunk_index} {st_clause}technique={technique} "
                   f"| stats count by user sourcetype | where count > 0",
            "sigma": {"title": f"{technique} detection", "level": "high"},
            "severity": "high", "technique": technique, "tactic": "",
        }

    def _skeptic_scripted(self, evidence):
        confirmed = evidence.get("existing_coverage", 0) == 0 and evidence.get("hits", 0) > 0
        return {
            "confirmed": confirmed,
            "reason": "Attack present in data and zero existing detections cover it."
            if confirmed else "Could not confirm: coverage already exists or no events.",
        }

    # ---- live model (Foundation-Sec-8B via OpenAI-compatible endpoint) ------
    def _chat(self, system: str, user: str) -> str:
        if self.provider == "anthropic":
            return self._chat_anthropic(system, user)
        # foundation_sec (Ollama OpenAI-compatible). json_object mode forces syntactically valid JSON.
        r = httpx.post(
            f"{settings.foundation_base_url}/chat/completions",
            json={
                "model": settings.foundation_model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "temperature": 0.2,
                "stream": False,
                "response_format": {"type": "json_object"},
            },
            timeout=120.0,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def _chat_anthropic(self, system: str, user: str) -> str:
        import anthropic
        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        msg = client.messages.create(
            model="claude-3-5-sonnet-latest", max_tokens=1024, system=system,
            messages=[{"role": "user", "content": user}],
        )
        return msg.content[0].text

    def _pick(self, surface):
        from agent.prompts import SYSTEM_ATTACKER, PICK_TEMPLATE
        uncovered = [s for s in surface if not s["covered"]]
        if not uncovered:
            raise ValueError("no uncovered technique to investigate")
        top = max(uncovered, key=lambda s: s["events"])

        # Sort by impact (event volume desc) so the model sees the juiciest blind spot first.
        ordered = sorted(uncovered, key=lambda s: s["events"], reverse=True)
        lines = "\n".join(
            f"- {s['technique']}: {s['events']} events on {s['sourcetype']}, covered=False"
            for s in ordered
        )
        out = _extract_json(self._chat(SYSTEM_ATTACKER, PICK_TEMPLATE.format(surface=lines)))

        by_tech = {s["technique"]: s for s in uncovered}
        picked = by_tech.get(out.get("technique"))

        # Impact guard: NEX closes the highest-impact blind spot. We keep the model's threat
        # reasoning, but if it drifted to a low-volume technique we re-anchor to the top gap so
        # the run reliably resolves the material exposure rather than a 1-event blip.
        if picked is not None and picked["events"] >= 0.5 * top["events"]:
            return {"technique": picked["technique"], "rationale": out.get("rationale", "")}

        model_text = out.get("rationale", "").strip()
        rationale = (
            f"{top['events']} events on {top['sourcetype']} for {top['technique']} with no matching "
            f"detection — the highest-impact blind spot, prioritized for remediation."
        )
        if model_text:
            rationale += f" Model assessment: {model_text}"
        return {"technique": top["technique"], "rationale": rationale}

    def _write(self, technique):
        from agent.prompts import SYSTEM_ATTACKER, WRITE_TEMPLATE
        samples = self._mcp.sample_events(technique) if self._mcp and hasattr(self._mcp, "sample_events") \
            else (self._mcp.run_search(technique).get("sample", []) if self._mcp else [])
        out = _extract_json(self._chat(
            SYSTEM_ATTACKER, WRITE_TEMPLATE.format(technique=technique, samples=json.dumps(samples)[:1500])))
        spl = (out.get("spl") or "").strip()
        if not spl:
            raise ValueError("model SPL missing")
        # Grounding guard: the authored SPL MUST target the same sourcetype as the proven
        # evidence, else it's off-target (8B models often drift to an unrelated log source).
        expected_st = samples[0].get("sourcetype", "") if samples else ""
        expected_ev = samples[0].get("eventName", "") if samples else ""
        st_ok = (not expected_st) or expected_st.lower() in spl.lower()
        ev_ok = (not expected_ev) or expected_ev.lower() in spl.lower()
        if not (st_ok and ev_ok):
            raise ValueError(
                f"model SPL off-target (expected sourcetype={expected_st!r} eventName={expected_ev!r}): {spl!r}")
        # Normalize to NEX's detection shape; build a Sigma stub from the model's title.
        return {
            "name": out.get("name", f"AI detection for {technique}"),
            "spl": spl,
            "sigma": {
                "title": out.get("sigma_title", f"{technique} detection"),
                "level": out.get("severity", "high"),
                "tags": [f"attack.{technique.lower()}"],
                "authored_by": "Foundation-Sec-8B",
            },
            "severity": out.get("severity", "high"),
            "technique": technique,
            "tactic": out.get("tactic", ""),
        }

    def _skeptic(self, technique, evidence):
        from agent.prompts import SYSTEM_ATTACKER, SKEPTIC_TEMPLATE
        detections = self._mcp.enumerate_coverage().get("detections", []) if self._mcp else []
        det_lines = "\n".join(f"- {d['name']} (covers {d['technique']})" for d in detections) or "- (none)"
        out = _extract_json(self._chat(SYSTEM_ATTACKER, SKEPTIC_TEMPLATE.format(
            technique=technique, hits=evidence.get("hits"), detections=det_lines)))

        model_confirmed = bool(out.get("confirmed"))
        cited = out.get("cited_detection")
        # Ground the verdict: a rejection is only valid if it cites a REAL detection that covers
        # this technique. Otherwise the data is authoritative (hits>0 & no real coverage => gap).
        real_names = {d["name"] for d in detections}
        real_cover = {d["name"] for d in detections if d["technique"] == technique}
        data_says_gap = evidence.get("existing_coverage", 0) == 0 and evidence.get("hits", 0) > 0
        if not model_confirmed and (cited not in real_cover):
            return {
                "confirmed": data_says_gap,
                "reason": (out.get("reason", "") +
                           f"  [grounding override: cited '{cited}' is not a real detection covering "
                           f"{technique}; gap stands on the data]") if data_says_gap else out.get("reason", ""),
            }
        if model_confirmed and cited in real_names:
            # Model confirmed but also cited a covering rule — contradictory; trust the data.
            return {"confirmed": data_says_gap, "reason": out.get("reason", "")}
        return {"confirmed": model_confirmed, "reason": out.get("reason", "")}
