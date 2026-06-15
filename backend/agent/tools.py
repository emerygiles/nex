"""Tool layer — normalizes the MCP backend (mock or live) into NEX's six tools.

These are the only ways the agent touches Splunk:
  enumerate_coverage, map_attack_surface, test_detection,
  check_existing_coverage, generate_detection (model, not MCP), deploy_detection.
"""
from __future__ import annotations


class Tools:
    def __init__(self, mcp, model) -> None:
        self._mcp = mcp
        self._model = model

    def enumerate_coverage(self) -> dict:
        return self._mcp.enumerate_coverage()

    def map_attack_surface(self) -> list[dict]:
        return self._mcp.map_attack_surface()

    def count_attack_events(self, technique: str) -> int:
        """Grounded proof: how many real events for this technique exist in the data.

        This is what proves a gap — independent of the quality of any candidate detection.
        """
        return self._mcp.count_technique(technique)

    def test_detection(self, spl: str) -> int:
        """Run candidate SPL; return hit count (used to check a detection actually fires)."""
        return self._mcp.run_search(spl).get("hits", 0)

    def check_existing_coverage(self, technique: str) -> int:
        return self._mcp.coverage_for(technique)

    def generate_detection(self, technique: str) -> dict:
        return self._model.write_detection(technique)

    def grounded_detection(self, technique: str) -> dict:
        """Deterministic, guaranteed-firing detection (fallback if the model's SPL is empty)."""
        return self._model.grounded_detection(technique)

    def deploy_detection(self, detection: dict) -> dict:
        return self._mcp.save_detection(
            name=detection["name"],
            spl=detection["spl"],
            technique=detection["technique"],
            tactic=detection.get("tactic", ""),
        )
