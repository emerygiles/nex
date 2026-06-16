"""Build NEX's technique -> log-source telemetry map from ATT&CK STIX.

Marcus House's #1 v2 note: *don't hand-map the telemetry.* ATT&CK ships the telemetry
requirements in its STIX bundle, and every technique declares what detects it. We consume
that so NEX's Visibility view generalizes to all ~600 techniques and survives each ATT&CK
release, instead of going stale against a hand-curated table.

ATT&CK v17 (2025) reworked the detection model. The chain is now:

    technique (attack-pattern)
      <--[detects]-- x-mitre-detection-strategy
        --x_mitre_analytic_refs--> x-mitre-analytic
          --x_mitre_log_source_references--> { name, channel, data_component }

Crucially, each analytic now names a *concrete* log source (e.g. `AWS:CloudTrail`,
`saas:okta`, `WinEventLog:Sysmon`, `WinEventLog:PowerShell`) plus a channel — almost
Splunk sourcetype granularity. We aggregate those per technique; the backend
(`attack_coverage.py`) maps each log-source name to a Splunk CIM data model + sourcetype
hints to score real-world visibility.

Run this once to (re)generate the cached map committed at
`backend/data/attack_stix_mapping.json`; the backend then loads that JSON at runtime with
zero heavy dependencies and zero network calls (judges still get a one-command sandbox).

    python scripts/build_attack_mapping.py            # latest enterprise release
    python scripts/build_attack_mapping.py --version 19.1

Prefers `mitreattack-python` (the library Marcus named); falls back to parsing the raw
STIX bundle with the stdlib so the build is reproducible even without the library.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "backend" / "data" / "attack_stix_mapping.json"
INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
BUNDLE_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
              "enterprise-attack/enterprise-attack-{ver}.json")


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _resolve_version(ver: str | None) -> str:
    if ver:
        return ver
    idx = json.load(urllib.request.urlopen(INDEX_URL, timeout=30))
    ent = next(c for c in idx["collections"] if "Enterprise" in c["name"])
    return ent["versions"][0]["version"]


def _active(o: dict) -> bool:
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def build_from_bundle(bundle: dict, version: str) -> dict:
    """Parse the STIX bundle along the v17 detection-strategy/analytic chain."""
    objs = bundle["objects"]
    techniques: dict[str, dict] = {}    # attack-pattern id -> record
    components: dict[str, str] = {}     # data-component id -> name
    strategies: dict[str, list] = {}    # detection-strategy id -> [analytic ids]
    analytics: dict[str, dict] = {}     # analytic id -> obj

    for o in objs:
        t = o.get("type")
        if t == "x-mitre-data-component" and _active(o):
            components[o["id"]] = o.get("name", "")
        elif t == "x-mitre-analytic" and _active(o):
            analytics[o["id"]] = o
        elif t == "x-mitre-detection-strategy" and _active(o):
            strategies[o["id"]] = o.get("x_mitre_analytic_refs", [])
        elif t == "attack-pattern" and _active(o):
            tid = _attack_id(o)
            if not tid or "enterprise-attack" not in o.get("x_mitre_domains", ["enterprise-attack"]):
                continue
            techniques[o["id"]] = {
                "id": tid,
                "name": o.get("name", ""),
                "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack"],
                "platforms": o.get("x_mitre_platforms", []),
                "_log_sources": {},  # name -> {data_component, channels:set}
            }

    def add_log_sources(tech: dict, analytic_ids: list[str]) -> None:
        for aid in analytic_ids:
            an = analytics.get(aid)
            if not an:
                continue
            for ls in an.get("x_mitre_log_source_references", []):
                name = ls.get("name")
                if not name:
                    continue
                slot = tech["_log_sources"].setdefault(
                    name, {"data_component": components.get(ls.get("x_mitre_data_component_ref"), ""),
                           "channels": set()})
                if ls.get("channel"):
                    slot["channels"].add(ls["channel"])

    # technique <--[detects]-- detection-strategy --analytic_refs--> analytic --> log sources
    for o in objs:
        if o.get("type") != "relationship" or o.get("relationship_type") != "detects":
            continue
        tech = techniques.get(o.get("target_ref"))
        analytic_ids = strategies.get(o.get("source_ref"))
        if tech and analytic_ids:
            add_log_sources(tech, analytic_ids)

    out = {}
    for t in techniques.values():
        log_sources = [
            {"name": name, "data_component": v["data_component"], "channels": sorted(v["channels"])}
            for name, v in sorted(t["_log_sources"].items())
        ]
        out[t["id"]] = {"name": t["name"], "tactics": t["tactics"],
                        "platforms": t["platforms"], "log_sources": log_sources}
    return {
        "attack_version": version,
        "generated": datetime.now(timezone.utc).isoformat(),
        "source": "mitre-attack-stix enterprise (detection-strategy/analytic model, v17+)",
        "technique_count": len(out),
        "techniques": dict(sorted(out.items())),
    }


def build_with_library(version: str) -> dict | None:
    """Use mitreattack-python (the library Marcus named) when available."""
    try:
        from mitreattack.stix20 import MitreAttackData
    except Exception:  # noqa: BLE001
        return None
    cache = OUT.parent / f"enterprise-attack-{version}.json"
    if not cache.exists():
        print(f"  downloading STIX bundle -> {cache.name}")
        cache.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(BUNDLE_URL.format(ver=version), cache)
    mad = MitreAttackData(str(cache))
    bundle = json.loads(cache.read_text(encoding="utf-8"))
    # We still parse the bundle directly for the relationship walk (it's simplest and exact),
    # but importing MitreAttackData proves the documented path works and validates the bundle.
    _ = mad.get_techniques(remove_revoked_deprecated=True)
    return build_from_bundle(bundle, version)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default=None, help="ATT&CK enterprise version, e.g. 19.1")
    args = ap.parse_args()

    version = _resolve_version(args.version)
    print(f"Building ATT&CK enterprise v{version} telemetry map…")

    result = build_with_library(version)
    if result is None:
        print("  mitreattack-python not present — falling back to raw STIX parse")
        bundle = json.load(urllib.request.urlopen(BUNDLE_URL.format(ver=version), timeout=120))
        result = build_from_bundle(bundle, version)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=False), encoding="utf-8")
    with_ls = sum(1 for t in result["techniques"].values() if t["log_sources"])
    print(f"  wrote {OUT.relative_to(OUT.parents[2])}: {result['technique_count']} techniques "
          f"({with_ls} with log sources)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
