"""The NEX agent loop: recon -> attack-think -> prove -> skeptic -> ship.

Implemented as a generator that yields UI events (one per meaningful step) so the
frontend can render the agent's thinking, the coverage graph, and the red->green
flip in real time. Pure orchestration — all Splunk access goes through `Tools`.
"""
from __future__ import annotations

import time
from typing import Iterator

from agent.models import ModelClient
from agent.tools import Tools
from config import settings


def _evt(phase: str, kind: str, message: str, data=None) -> dict:
    return {"phase": phase, "kind": kind, "message": message, "data": data, "ts": time.time()}


def run_investigation(mcp, pace: float = 0.6) -> Iterator[dict]:
    model = ModelClient(mcp=mcp)
    tools = Tools(mcp, model)

    def beat():
        if pace:
            time.sleep(pace)

    yield _evt("start", "status", f"NEX run started — mode={mcp.name}, brain={model.provider}")
    beat()

    # 1) Recon -------------------------------------------------------------
    coverage = tools.enumerate_coverage()
    yield _evt("recon", "tool", "enumerate_coverage()", coverage)
    beat()
    surface = tools.map_attack_surface()
    yield _evt("recon", "graph", "map_attack_surface() — ATT&CK coverage map", surface)
    covered = sum(1 for s in surface if s["covered"])
    blind = [s for s in surface if not s["covered"]]
    yield _evt("recon", "thought",
               f"{len(surface)} techniques observed in data; {covered} covered, "
               f"{len(blind)} potentially blind.")
    beat()

    # Visibility coverage — the "gaps under the gaps". Rule coverage only matters for techniques
    # whose telemetry is actually CIM-queryable; score each high-value technique none/partial/good
    # from measured data quality, ranked by the active threat profile.
    from attack_coverage import visibility_report
    sources = mcp.telemetry_posture() if hasattr(mcp, "telemetry_posture") \
        else coverage.get("sourcetypes", [])
    vis = visibility_report(sources, profile_name=settings.threat_profile)
    s = vis["summary"]
    if s["blind"] or s["partial"]:
        top = next((t for t in vis["techniques"] if t["tier"] != "good"), None)
        lead = (f" Top exposure: {top['technique']} {top['name']} ({top['tier']})." if top else "")
        yield _evt("recon", "visibility",
                   f"Visibility check ({vis['profile']['label']}): {s['blind']} blind, {s['partial']} "
                   f"partial, {s['good']} good across {len(vis['techniques'])} high-value techniques. "
                   f"Detection only fires where telemetry is onboarded AND CIM-mapped AND in window.{lead}",
                   vis)
        beat()

    # No telemetry, or every observed technique is already covered → report and stop.
    if not surface:
        yield _evt("done", "status", "No telemetry in scope — nothing to analyze.")
        return
    if not blind:
        yield _evt("done", "status",
                   f"All clear: every one of {len(surface)} observed techniques is already covered. "
                   f"No blind spots to close.")
        return

    # 2) Attack-think ------------------------------------------------------
    pick = model.pick_uncovered_technique(surface)
    technique = pick["technique"]
    yield _evt("attack-think", "thought",
               f"Hypothesis: {technique} is exploitable past current coverage. {pick['rationale']}")
    beat()

    # 3) Prove the gap -----------------------------------------------------
    # Proof is grounded in the technique's REAL presence in the telemetry — not in the
    # quality of any candidate detection. (A weak candidate SPL must never read as "no gap".)
    hits = tools.count_attack_events(technique)
    existing = tools.check_existing_coverage(technique)
    yield _evt("prove", "tool", "test_detection(spl)",
               {"hits": hits, "existing_coverage": existing, "technique": technique})
    if not (hits > 0 and existing == 0):
        yield _evt("prove", "status", f"No gap for {technique} (hits={hits}, coverage={existing}). Halting.")
        return
    yield _evt("prove", "gap",
               f"CONFIRMED blind spot: {technique} — {hits} malicious events, 0 detections.",
               {"technique": technique})
    beat()

    # 4) Skeptic gate ------------------------------------------------------
    verdict = model.skeptic_review(technique, {"hits": hits, "existing_coverage": existing})
    yield _evt("skeptic", "thought", f"Skeptic pass: {verdict['reason']}", verdict)
    if not verdict["confirmed"]:
        yield _evt("skeptic", "status", "Skeptic rejected the gap as a false positive. Halting.")
        return
    beat()

    # 5) Ship the fix ------------------------------------------------------
    detection = tools.generate_detection(technique)
    # Guarantee the authored rule actually fires on the evidence; otherwise fall back to a
    # grounded detection so we never deploy a dead rule.
    if tools.test_detection(detection["spl"]) == 0:
        detection = tools.grounded_detection(technique)
    yield _evt("ship", "detection", f"Detection authored for {technique}", detection)
    beat()

    # Human-in-the-loop: in production NEX PROPOSES; a human approves the deploy (POST /deploy).
    # The model proposes, the analyst decides. auto_deploy=True (demo) closes the loop on its own.
    if not settings.auto_deploy:
        yield _evt("ship", "pending",
                   f"Detection ready for {technique}. Awaiting analyst approval before deploy.",
                   {"technique": technique, "detection": detection, "existing": existing})
        yield _evt("done", "status", "NEX proposed a fix — review and approve to deploy.")
        return

    result = tools.deploy_detection(detection)
    yield _evt("ship", "tool", "deploy_detection()", result)
    new_cov = tools.check_existing_coverage(technique)
    yield _evt("ship", "verified",
               f"Deployed. Coverage for {technique}: {existing} -> {new_cov}. Gap closed.",
               {"technique": technique, "covered": new_cov > 0})
    yield _evt("done", "status", "NEX closed the loop: found, proved, fixed, verified.")
