"""In-process Mock MCP backend.

Mirrors the subset of the Splunk MCP Server tool surface NEX needs, backed by
the bundled APT scenario, so the full agent loop runs with zero Splunk setup.
"""
from __future__ import annotations

import json
from pathlib import Path

SCENARIO_PATH = Path(__file__).resolve().parents[2] / "data" / "apt_scenario" / "scenario.json"


class MockMCP:
    name = "mock"

    def __init__(self) -> None:
        self._scenario = json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))
        # Existing detections start as the scenario's set; deploys append here.
        self._detections = list(self._scenario["existing_detections"])

    # --- read tools ---------------------------------------------------------
    def enumerate_coverage(self) -> dict:
        return {
            "sourcetypes": self._scenario["sourcetypes"],
            "detections": self._detections,
        }

    def map_attack_surface(self) -> list[dict]:
        covered = {d["technique"] for d in self._detections}
        seen: dict[str, dict] = {}
        for ev in self._scenario["events"]:
            t = ev["technique"]
            node = seen.setdefault(t, {"technique": t, "events": 0, "sourcetype": ev["sourcetype"]})
            node["events"] += ev.get("count", 1)
        for t, node in seen.items():
            node["covered"] = t in covered
        return list(seen.values())

    def run_search(self, spl: str) -> dict:
        """Very small SPL emulator: match events by non-empty eventName / technique tokens.

        NOTE: empty tokens must never match (an empty string is a substring of everything),
        and a bare technique id (e.g. 'T1537') matches by technique only.
        """
        spl_l = spl.lower()

        def matches(ev: dict) -> bool:
            en = ev.get("eventName") or ""
            if en and en.lower() in spl_l:
                return True
            if ev["technique"].lower() in spl_l:
                return True
            # Sourcetype only counts when the query also narrows by a real event field,
            # so a broad 'sourcetype=aws:cloudtrail' doesn't sweep in unrelated events.
            if ev["sourcetype"].lower() in spl_l and (en and en.lower() in spl_l):
                return True
            return False

        hits = [ev for ev in self._scenario["events"] if matches(ev)]
        total = sum(ev.get("count", 1) for ev in hits)
        return {"hits": total, "sample": hits[:3]}

    def coverage_for(self, technique: str) -> int:
        return sum(1 for d in self._detections if d["technique"] == technique)

    def sample_events(self, technique: str) -> list[dict]:
        return [ev for ev in self._scenario["events"] if ev["technique"] == technique][:3]

    def count_technique(self, technique: str) -> int:
        return sum(ev.get("count", 1) for ev in self._scenario["events"] if ev["technique"] == technique)

    # --- write tool ---------------------------------------------------------
    def save_detection(self, name: str, spl: str, technique: str, tactic: str = "") -> dict:
        self._detections.append(
            {"name": name, "technique": technique, "tactic": tactic, "spl": spl, "deployed": True}
        )
        return {"ok": True, "name": name, "coverage_for_technique": self.coverage_for(technique)}

    # --- helper for the scripted brain -------------------------------------
    @property
    def planted_gap(self) -> dict:
        return self._scenario["planted_gap"]
