"""Tests for the tiered visibility engine (backend/attack_coverage.py).

Runnable with `pytest` or directly: `python tests/test_visibility.py`.
Covers the OR-for-presence / quality-weighted-tier logic, the CIM-consistency gap, the
necessary-primary-source (AND) exception, remediation, and threat-profile ranking.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from attack_coverage import assess_environment, visibility_report  # noqa: E402

NOW = time.time()
FRESH = {"latest": NOW - 1800, "earliest": NOW - 30 * 86400}


def _src(name, events, cim_models, **extra):
    return {"name": name, "events": events, "cim_models": cim_models, **FRESH, **extra}


def test_cim_unmapped_is_partial_not_good():
    """A feed ingested with volume but NOT CIM-mapped scores partial, never good —
    Marcus's 'data presence != detection capability'."""
    env = assess_environment([_src("cisco:asa", 5000, [])])
    nt = env["Network_Traffic"]
    assert nt.present is True
    assert nt.consistency < 0.5          # measured: not in the CIM data model
    assert nt.tier == "partial"

    env2 = assess_environment([_src("aws:cloudtrail", 5000, ["Change", "Authentication"])])
    assert env2["Change"].tier == "good"  # same volume, but CIM-mapped -> good


def test_stale_feed_drops_timeliness():
    """A feed that stopped flowing is a silent outage even though the index 'has' it."""
    stale = {"name": "okta:im2", "events": 2000, "cim_models": ["Authentication"],
             "latest": NOW - 20 * 86400, "earliest": NOW - 40 * 86400}
    env = assess_environment([stale])
    assert env["Authentication"].timeliness < 0.6


def test_or_presence_any_source_gives_visibility():
    """OR semantics: any one relevant CIM data model present => not fully blind."""
    rep = visibility_report([_src("XmlWinEventLog:Sysmon", 9000, ["Endpoint"])])
    # PowerShell (T1059.001) is endpoint-centric — present via Sysmon alone.
    t1059 = next(t for t in rep["techniques"] if t["technique"] == "T1059.001")
    assert t1059["tier"] in ("good", "partial")
    assert t1059["tier"] != "none"


def test_necessary_primary_source_caps_tier_AND_exception():
    """T1537 (S3 object exfil) needs CloudTrail data events (Data_Access). With only the
    management plane, it must NOT read as 'good' even though Change/Auth are healthy."""
    env_sources = [
        _src("aws:cloudtrail", 5000, ["Change", "Authentication"]),  # mgmt plane only
        _src("XmlWinEventLog:Sysmon", 9000, ["Endpoint"]),
    ]
    rep = visibility_report(env_sources)
    t1537 = next(t for t in rep["techniques"] if t["technique"] == "T1537")
    assert "Data_Access" in t1537["missing_models"]
    assert t1537["tier"] == "partial"     # capped by the missing necessary source
    # remediation must name the onboarding fix
    actions = {r["action"] for r in t1537["remediation"]}
    assert "onboard" in actions


def test_blind_when_no_relevant_telemetry():
    """An environment with only DNS logs is blind to a pure cloud-exfil technique."""
    rep = visibility_report([_src("stream:dns", 1000, ["Network_Resolution"])], profile_name="cloud_saas")
    t = next(t for t in rep["techniques"] if t["technique"] == "T1537")
    assert t["tier"] == "none"
    assert t["remediation"]                 # tells you what to onboard


def test_priority_ranking_puts_exposure_first():
    """Ranking = threat weight x exposure; blind/partial high-weight floats above good."""
    rep = visibility_report([
        _src("aws:cloudtrail", 5000, ["Change", "Authentication"]),
        _src("XmlWinEventLog:Sysmon", 9000, ["Endpoint"]),
        _src("cisco:asa", 2600, []),
    ])
    priorities = [t["priority"] for t in rep["techniques"]]
    assert priorities == sorted(priorities, reverse=True)
    # the top item should not be a fully-covered 'good' technique
    assert rep["techniques"][0]["tier"] != "good"


def test_report_shape_and_backcompat():
    rep = visibility_report([_src("okta:im2", 1800, ["Authentication"])])
    for key in ("attack_version", "profile", "models", "summary", "techniques",
                "blind", "visible", "missing_data_sources"):
        assert key in rep
    s = rep["summary"]
    assert s["good"] + s["partial"] + s["blind"] == len(rep["techniques"])


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} passed")
