"""Visibility-vs-detection coverage engine — the "gaps under the gaps", v2.

This supersedes the hand-mapped `attack_datasources.py`. It implements Marcus House's
v2 feedback end-to-end:

1.  **STIX-driven, not hand-mapped.** Technique -> telemetry comes from ATT&CK's own STIX
    bundle (`backend/data/attack_stix_mapping.json`, built by
    `scripts/build_attack_mapping.py`). Generalizes to ~600 techniques and survives
    each ATT&CK release.
2.  **Tiered, not boolean.** Each technique scores `good | partial | none`, from
    DeTT&CT-style data-quality dimensions (completeness, timeliness, retention,
    consistency) rather than a single visible/blind bit.
3.  **Splunk reality.** "Have the data source" means *onboarded AND CIM-normalized AND
    within the search/retention window* — ESCU content assumes CIM compliance, so a log
    that's ingested but not CIM-mapped still won't make a detection fire. That's the
    `consistency` dimension, and it can pull a technique from "good" down to "partial".
4.  **Remediation, not just flagging.** Every gap carries the concrete Splunk input to
    onboard (sourcetype hints + CIM data model) to close it.
5.  **Priority queue, not flat list.** Techniques are ranked against a configurable threat
    profile, so the org's actual exposure floats to the top instead of an alphabetical dump.

The unifying abstraction is the **Splunk CIM data model**. ATT&CK log sources and the
environment's observed sourcetypes are each mapped to CIM data models; a technique is
visible if the environment supplies *any* CIM data model the technique's telemetry needs
(OR across data sources), and its tier is driven by the quality and redundancy of those
present sources. See `coverage_logic` in the module docstring of `threat_profiles` for the
OR-vs-AND rationale.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from threat_profiles import get_profile

_MAPPING_PATH = Path(__file__).resolve().parent / "data" / "attack_stix_mapping.json"

# --- Splunk CIM data models (the unifying layer) ---------------------------------------
# Human labels for the CIM data models we reason over.
CIM_MODELS = {
    "Authentication": "Authentication",
    "Endpoint": "Endpoint (processes/files)",
    "Network_Traffic": "Network Traffic",
    "Network_Resolution": "Network Resolution (DNS)",
    "Web": "Web / Proxy",
    "Email": "Email",
    "Change": "Change / Cloud Audit",
    "Data_Access": "Data Access (cloud object stores)",
    "Infrastructure": "Infrastructure / Hypervisor",
    "External": "External enrichment (threat intel / scan)",
}

# ATT&CK log-source name (or prefix before ':') -> the CIM data model(s) that carry it.
# Keyed first by exact name, then by prefix. Small, stable, data-source-LEVEL (not the
# technique-level hand-mapping Marcus called out).
_ATTACK_LS_EXACT: dict[str, list[str]] = {
    "WinEventLog:Security": ["Authentication", "Endpoint"],
    "AWS:CloudTrail": ["Change", "Authentication", "Data_Access"],
    "AWS:VPCFlowLogs": ["Network_Traffic"],
    "AWS:CloudWatch": ["Change"],
    "Network Traffic": ["Network_Traffic"],
    "Domain Name": ["Network_Resolution"],
    "DNS": ["Network_Resolution"],
    "Internet Scan": ["External"],
    "Malware Repository": ["External"],
    "Persona": ["External"],
    "Application Log": ["Web"],
    "Application:Mail": ["Email"],
}
_ATTACK_LS_PREFIX: dict[str, list[str]] = {
    "WinEventLog": ["Endpoint"],
    "etw": ["Endpoint"],
    "auditd": ["Endpoint"],
    "linux": ["Endpoint"],
    "ebpf": ["Endpoint"],
    "macos": ["Endpoint"],
    "fs": ["Endpoint"],
    "EDR": ["Endpoint"],
    "Windows": ["Endpoint"],
    "NSM": ["Network_Traffic"],
    "networkdevice": ["Network_Traffic"],
    "esxcli": ["Network_Traffic"],
    "ALB": ["Web"],
    "ApplicationLog": ["Web"],
    "azure": ["Change", "Authentication"],
    "gcp": ["Change"],
    "m365": ["Change", "Authentication", "Email"],
    "saas": ["Change", "Authentication"],
    "kubernetes": ["Change"],
    "docker": ["Infrastructure"],
    "containerd": ["Infrastructure"],
    "esxi": ["Infrastructure"],
}

# Special-case ATT&CK log-source names that imply a specific model regardless of prefix.
_ATTACK_LS_OVERRIDE: dict[str, list[str]] = {
    "auditd:USER_LOGIN": ["Authentication"],
    "azure:signinlogs": ["Authentication"],
    "m365:signinlogs": ["Authentication"],
    "m365:exchange": ["Email"],
    "m365:messagetrace": ["Email"],
    "saas:okta": ["Authentication"],
    "saas:auth": ["Authentication"],
    "NSM:Firewall": ["Network_Traffic"],
}


def attack_ls_to_models(name: str) -> list[str]:
    if name in _ATTACK_LS_OVERRIDE:
        return _ATTACK_LS_OVERRIDE[name]
    if name in _ATTACK_LS_EXACT:
        return _ATTACK_LS_EXACT[name]
    prefix = name.split(":", 1)[0]
    return _ATTACK_LS_PREFIX.get(prefix, [])


# Observed Splunk sourcetype substring -> CIM data model(s) it can populate, plus whether a
# CIM-compliant TA normally normalizes it (the `consistency` signal). This is the only place
# real-world sourcetypes meet ATT&CK; it's deliberately a short, auditable table.
@dataclass(frozen=True)
class SourcetypeRule:
    hints: tuple[str, ...]
    models: tuple[str, ...]
    cim_normalized: bool  # does a standard CIM TA map this sourcetype?
    label: str
    quality: float = 1.0  # intrinsic fidelity ceiling — flow/audit-only feeds cap below a full feed


SOURCETYPE_RULES: list[SourcetypeRule] = [
    SourcetypeRule(("okta",), ("Authentication",), True, "Okta identity"),
    SourcetypeRule(("duo",), ("Authentication",), True, "Duo MFA"),
    SourcetypeRule(("wineventlog:security", "windows:security", "xmlwineventlog:security"),
                   ("Authentication", "Endpoint"), True, "Windows Security log"),
    SourcetypeRule(("azure", "azuread", "aad", "signin"), ("Authentication", "Change"), True, "Azure AD / Entra"),
    SourcetypeRule(("sysmon", "xmlwineventlog", "wineventlog"), ("Endpoint",), True, "Windows Sysmon/EventLog"),
    SourcetypeRule(("crowdstrike", "carbonblack", "sentinelone", "edr", "defender"),
                   ("Endpoint",), True, "EDR telemetry"),
    SourcetypeRule(("auditd", "linux:", "linux_secure", "nix", "osquery"), ("Endpoint",), True, "Linux audit"),
    # CloudTrail = control-plane (management) events: identity + config changes, NOT object-level
    # data access. S3 object reads/writes need CloudTrail *data events* (off by default) — see below.
    SourcetypeRule(("aws:cloudtrail", "aws:cloudwatch"), ("Change", "Authentication"), True, "AWS CloudTrail (mgmt)"),
    SourcetypeRule(("cloudtrail:data", "s3:serveraccess", "s3access", "aws:s3:accesslogs"),
                   ("Data_Access",), True, "AWS data events / S3 access"),
    SourcetypeRule(("gcp", "google:gcp"), ("Change",), True, "GCP audit"),
    SourcetypeRule(("o365", "m365", "office365"), ("Change", "Authentication", "Email"), True, "Microsoft 365"),
    SourcetypeRule(("vpcflow", "stream:tcp", "netflow", "zeek", "bro", "conn.log"),
                   ("Network_Traffic",), True, "Network flow (Zeek/NetFlow)"),
    # A firewall is flow/connection telemetry — not full content/PCAP and not a web proxy.
    # (Marcus: "having firewall logs isn't PCAP.") Network_Traffic only, capped fidelity.
    SourcetypeRule(("cisco:asa", "pan:", "fortigate", "firewall", "checkpoint"),
                   ("Network_Traffic",), True, "Firewall / NGFW", quality=0.6),
    SourcetypeRule(("stream:dns", "dns", "named", "bind", "msad:dns"), ("Network_Resolution",), True, "DNS logs"),
    SourcetypeRule(("stream:http", "proxy", "squid", "bluecoat", "websense", "swg"), ("Web",), True, "Web proxy"),
    SourcetypeRule(("apache", "nginx", "iis", ":web", "alb", "modsecurity", "waf"), ("Web",), True, "Web server / WAF"),
    SourcetypeRule(("exchange", "proofpoint", "mimecast", "messagetrace", "ironport"),
                   ("Email",), True, "Email gateway"),
    SourcetypeRule(("esxi", "vmware", "vmkernel"), ("Infrastructure",), False, "ESXi / hypervisor"),
    SourcetypeRule(("kubernetes", "k8s", "containerd", "docker"), ("Change", "Infrastructure"), False, "Container"),
]


# --- environment posture ----------------------------------------------------------------
@dataclass
class ModelPosture:
    """How well one CIM data model is covered by the environment's telemetry."""
    model: str
    present: bool = False
    matched_sourcetype: str | None = None
    label: str = ""
    completeness: float = 0.0   # event volume / field richness
    timeliness: float = 0.0     # freshness of ingest
    retention: float = 0.0      # within search/retention window
    consistency: float = 0.0    # CIM-normalized (the Splunk gap-under-the-gap)
    score: float = 0.0
    tier: str = "none"

    def breakdown(self) -> dict:
        return {
            "model": self.model, "label": CIM_MODELS.get(self.model, self.model),
            "present": self.present, "matched_sourcetype": self.matched_sourcetype,
            "completeness": round(self.completeness, 2), "timeliness": round(self.timeliness, 2),
            "retention": round(self.retention, 2), "consistency": round(self.consistency, 2),
            "score": round(self.score, 2), "tier": self.tier,
        }


# DeTT&CT-style weights. Consistency (CIM) and completeness dominate because, in Splunk,
# a non-CIM or sparse feed is the difference between a detection firing and silently not.
_W = {"completeness": 0.30, "consistency": 0.30, "retention": 0.20, "timeliness": 0.20}


def _tier(score: float, present: bool) -> str:
    if not present:
        return "none"
    return "good" if score >= 0.75 else "partial"


def _volume_completeness(events: int) -> float:
    if events >= 2000:
        return 1.0
    if events >= 500:
        return 0.85
    if events >= 50:
        return 0.6
    return 0.4 if events > 0 else 0.0


def _timeliness(latest_epoch: float | None, now: float) -> float:
    """Freshness of the feed from its last-seen event. A feed that stopped flowing is a
    silent detection outage even though the index still 'has the data source'."""
    if not latest_epoch:
        return 0.5  # unknown last-seen; neither credit nor penalize hard
    age_h = max(0.0, (now - latest_epoch) / 3600.0)
    if age_h <= 24:
        return 1.0
    if age_h <= 72:
        return 0.8
    if age_h <= 24 * 7:
        return 0.55
    return 0.25


def _retention(earliest_epoch: float | None, latest_epoch: float | None, now: float) -> float:
    """How deep the history goes — matters for scheduled look-back and hunting/backfill."""
    if not earliest_epoch:
        return 0.7
    span_days = max(0.0, ((latest_epoch or now) - earliest_epoch) / 86400.0)
    if span_days >= 30:
        return 1.0
    if span_days >= 7:
        return 0.8
    if span_days >= 1:
        return 0.6
    return 0.4


def assess_environment(sources: list[dict], now: float | None = None) -> dict[str, ModelPosture]:
    """Score each CIM data model from *measured* telemetry sources.

    Each source may carry measured signals (the production path fills these from Splunk):
      name        : sourcetype
      events      : event count (-> completeness)
      latest      : epoch of most recent event (-> timeliness)
      earliest    : epoch of oldest event (-> retention)
      cim_models  : list of CIM data models the sourcetype is actually mapped into
                    (-> consistency; this is the Splunk 'gap under the gap' — ingested != CIM).
    Sources with only {name, events} still work (timeliness/retention default to neutral,
    consistency falls back to whether a standard CIM TA would normalize the sourcetype).
    """
    import time as _time
    now = now or _time.time()
    models: dict[str, ModelPosture] = {m: ModelPosture(model=m) for m in CIM_MODELS}

    for st in sources:
        name = (st.get("name") or "").lower()
        events = int(st.get("events") or 0)
        measured_cim = st.get("cim_models")  # None => not measured; [] => measured-and-absent
        for rule in SOURCETYPE_RULES:
            if not any(h in name for h in rule.hints):
                continue
            completeness = _volume_completeness(events) * rule.quality
            timeliness = _timeliness(st.get("latest"), now)
            retention = _retention(st.get("earliest"), st.get("latest"), now)
            for m in rule.models:
                # consistency is PER (sourcetype, data model): is this feed actually mapped into
                # *this* CIM data model? Measured when we have it, else the rule's TA default.
                if measured_cim is not None:
                    consistency = 1.0 if m in measured_cim else 0.35
                else:
                    consistency = 1.0 if rule.cim_normalized else 0.35
                score = (_W["completeness"] * completeness + _W["consistency"] * consistency
                         + _W["retention"] * retention + _W["timeliness"] * timeliness)
                mp = models[m]
                # Keep the strongest backing sourcetype for each data model.
                if score > mp.score or not mp.present:
                    mp.present = True
                    mp.matched_sourcetype = st.get("name")
                    mp.label = rule.label
                    mp.completeness, mp.timeliness = completeness, timeliness
                    mp.retention, mp.consistency = retention, consistency
                    mp.score = score
    for mp in models.values():
        mp.tier = _tier(mp.score, mp.present)
    return models


# --- mapping load -----------------------------------------------------------------------
_MAPPING_CACHE: dict | None = None


def load_mapping() -> dict:
    global _MAPPING_CACHE
    if _MAPPING_CACHE is None:
        _MAPPING_CACHE = json.loads(_MAPPING_PATH.read_text(encoding="utf-8"))
    return _MAPPING_CACHE


# Operational "primary source" overlay — a SMALL, auditable supplement where ATT&CK's data
# model is coarser than Splunk reality. ATT&CK lists CloudTrail generically for cloud exfil, but
# object-level S3 PutObject/GetObject is ONLY visible with CloudTrail *data events* (off by
# default) — the management plane cannot see it. For these techniques the named model is a
# *necessary* detector: if it's absent the tier is capped (you may see adjacent signals like a
# bucket-ACL change, but you're blind to the actual bulk transfer). This is the AND exception to
# the otherwise-OR model; see the OR/AND note in `threat_profiles`. Keep this list short and
# defensible — it is SOC knowledge, not a return to hand-mapping every technique.
PRIMARY_MODEL: dict[str, str] = {
    "T1537": "Data_Access",   # transfer to cloud account: needs object-level data events
    "T1530": "Data_Access",   # data from cloud storage: same
}
_PRIMARY_LS_NOTE = "(operational) CloudTrail data events / S3 server-access logs"


def technique_required_models(tid: str, mapping: dict) -> dict[str, list[str]]:
    """CIM data model -> the ATT&CK log sources (concrete names) that imply it, for one technique."""
    rec = mapping["techniques"].get(tid, {})
    out: dict[str, list[str]] = {}
    for ls in rec.get("log_sources", []):
        for m in attack_ls_to_models(ls["name"]):
            out.setdefault(m, [])
            if ls["name"] not in out[m]:
                out[m].append(ls["name"])
    # Fold in the operational primary source if ATT&CK omitted it.
    primary = PRIMARY_MODEL.get(tid)
    if primary:
        out.setdefault(primary, [])
        if _PRIMARY_LS_NOTE not in out[primary]:
            out[primary].append(_PRIMARY_LS_NOTE)
    return out


# --- per-technique scoring (OR across data sources, quality-weighted) -------------------
@dataclass
class TechniqueCoverage:
    technique: str
    name: str
    tactics: list[str]
    required_models: dict[str, list[str]]
    present_models: list[str]
    missing_models: list[str]
    tier: str
    score: float
    weight: float = 0.0
    priority: float = 0.0
    rationale: str = ""
    remediation: list[dict] = field(default_factory=list)


def _score_technique(tid: str, mapping: dict, env: dict[str, ModelPosture]) -> tuple[str, float, list[str], list[str]]:
    """OR across required CIM models for 'visible at all'; tier = best present model score,
    bumped for redundancy (multiple independent present sources).

    Each present model's contribution is scaled by its *centrality* to the technique
    (how many of the technique's ATT&CK log sources imply that model). An incidental match —
    e.g. an endpoint feed that ATT&CK lists once for a fundamentally network/cloud technique —
    is capped at 'partial' so broad EDR coverage can't paper over a missing primary source.
    """
    required = technique_required_models(tid, mapping)
    # Drop External-only requirements from the visibility math (threat-intel/scan aren't SOC onboarding).
    scoreable = {m: ls for m, ls in required.items() if m != "External"}
    if not scoreable:
        scoreable = required
    total_ls = sum(len(ls) for ls in scoreable.values()) or 1

    present = [m for m in scoreable if env.get(m) and env[m].present]
    missing = [m for m in scoreable if m not in present]
    if not present:
        return "none", 0.0, present, missing

    def effective(m: str) -> float:
        centrality = len(scoreable[m]) / total_ls
        s = env[m].score
        return min(s, 0.65) if centrality < 0.34 else s   # incidental match -> partial ceiling

    best = max(effective(m) for m in present)
    bonus = min(0.12, 0.06 * (len(present) - 1))   # redundancy: more present sources = more robust
    score = min(1.0, best + bonus)

    # AND exception: a missing *necessary* primary source caps the tier — adjacent telemetry
    # can't substitute for it (e.g. you can't see S3 object exfil without data events).
    primary = PRIMARY_MODEL.get(tid)
    if primary and (not env.get(primary) or not env[primary].present):
        score = min(score, 0.6)

    return ("good" if score >= 0.75 else "partial"), score, present, missing


def _remediation(tc: TechniqueCoverage, env: dict[str, ModelPosture]) -> list[dict]:
    recs: list[dict] = []
    # Closing a 'none' gap: onboard one of the missing data models.
    if tc.tier == "none":
        for m in tc.missing_models:
            recs.append({
                "action": "onboard",
                "model": m,
                "model_label": CIM_MODELS.get(m, m),
                "attack_log_sources": tc.required_models.get(m, []),
                "splunk": _onboarding_hint(m),
                "why": f"No telemetry maps to the {CIM_MODELS.get(m, m)} data model, so {tc.technique} "
                       f"is invisible to any detection.",
            })
        return recs[:3]
    # A missing *necessary* primary source is the headline fix for a capped 'partial'.
    primary = PRIMARY_MODEL.get(tc.technique)
    if primary and primary in tc.missing_models:
        recs.append({
            "action": "onboard", "model": primary, "model_label": CIM_MODELS.get(primary, primary),
            "attack_log_sources": tc.required_models.get(primary, []),
            "splunk": _onboarding_hint(primary),
            "why": f"{tc.technique} is capped at partial: the necessary {CIM_MODELS.get(primary, primary)} "
                   f"telemetry is absent, so adjacent logs may show context but not the actual activity.",
        })
    # Lifting a 'partial' gap to 'good': fix the weakest present model's failing dimension.
    weak = sorted((env[m] for m in tc.present_models), key=lambda mp: mp.score)
    for mp in weak[:2]:
        if mp.consistency < 0.6:
            recs.append({"action": "cim_normalize", "model": mp.model, "model_label": CIM_MODELS.get(mp.model),
                         "sourcetype": mp.matched_sourcetype,
                         "why": f"{mp.matched_sourcetype} is ingested but not CIM-normalized; ESCU/data-model "
                                f"detections for {tc.technique} won't fire until it maps to the "
                                f"{CIM_MODELS.get(mp.model)} data model.",
                         "splunk": "Install/align the CIM-compliant TA and tag events into the data model."})
        elif mp.completeness < 0.6:
            recs.append({"action": "increase_fidelity", "model": mp.model, "sourcetype": mp.matched_sourcetype,
                         "why": f"Low event volume/field coverage on {mp.matched_sourcetype} weakens "
                                f"{tc.technique} detection.",
                         "splunk": "Raise log verbosity / enable the required event IDs or fields."})
        elif mp.retention < 0.6:
            recs.append({"action": "extend_retention", "model": mp.model, "sourcetype": mp.matched_sourcetype,
                         "why": f"{mp.matched_sourcetype} ages out before the search window for {tc.technique}.",
                         "splunk": "Extend index retention or the detection's search window."})
    return recs


def _onboarding_hint(model: str) -> str:
    return {
        "Authentication": "Onboard an identity/auth source (Okta, Azure AD sign-ins, or WinEventLog:Security) "
                          "and map to the Authentication data model.",
        "Endpoint": "Onboard Sysmon or an EDR (CrowdStrike/Defender) and map to the Endpoint data model.",
        "Network_Traffic": "Onboard Zeek/Stream or firewall traffic logs and map to the Network_Traffic data model.",
        "Network_Resolution": "Onboard DNS query logging (Splunk Stream stream:dns or Windows DNS analytic logs) "
                              "and map to the Network_Resolution data model.",
        "Web": "Onboard web-server/proxy/WAF logs and map to the Web data model.",
        "Email": "Onboard the email gateway (Exchange/Proofpoint/M365 message trace) and map to the Email data model.",
        "Change": "Onboard the cloud control-plane audit log (CloudTrail/Azure Activity/GCP Audit) and map to "
                  "the Change data model.",
        "Data_Access": "Onboard cloud object-store data events (CloudTrail data events / S3 access logs) and map "
                       "to the Data Access data model.",
        "Infrastructure": "Onboard hypervisor/container platform logs (ESXi, Kubernetes audit).",
        "External": "External enrichment (threat-intel/internet-scan) — integrate a feed rather than onboard a log.",
    }.get(model, f"Onboard a source for the {model} data model.")


# --- top-level report -------------------------------------------------------------------
def visibility_report(sources, profile_name: str = "default") -> dict:
    """Build the tiered, remediation-bearing, threat-ranked visibility report.

    `sources` is the environment's telemetry. Each item may be a bare sourcetype name
    (back-compat) or a measured dict {name, events, latest, earliest, cim_models}. The
    production data plane (`SplunkRest.telemetry_posture`) fills the measured fields from
    the live instance; the sandbox supplies representative measurements.
    """
    observed: list[dict] = []
    for s in sources:
        if isinstance(s, str):
            observed.append({"name": s, "events": 0})
        else:
            observed.append({
                "name": s.get("name", ""), "events": s.get("events", 0),
                "latest": s.get("latest"), "earliest": s.get("earliest"),
                "cim_models": s.get("cim_models"),
            })

    mapping = load_mapping()
    profile = get_profile(profile_name)
    env = assess_environment(observed)

    techs: list[TechniqueCoverage] = []
    for tid, weight in profile["weights"].items():
        rec = mapping["techniques"].get(tid)
        if not rec:
            continue
        required = technique_required_models(tid, mapping)
        tier, score, present, missing = _score_technique(tid, mapping, env)
        tc = TechniqueCoverage(
            technique=tid, name=rec["name"], tactics=rec.get("tactics", []),
            required_models=required, present_models=present, missing_models=missing,
            tier=tier, score=score, weight=weight,
        )
        # Priority = threat weight x exposure (none hurts most, good barely).
        exposure = {"none": 1.0, "partial": 0.5, "good": 0.12}[tier]
        tc.priority = round(weight * exposure, 3)
        tc.rationale = profile["notes"].get(tid, "")
        tc.remediation = _remediation(tc, env)
        techs.append(tc)

    techs.sort(key=lambda t: (-t.priority, {"none": 0, "partial": 1, "good": 2}[t.tier], t.technique))

    counts = {"good": 0, "partial": 0, "none": 0}
    for t in techs:
        counts[t.tier] += 1

    return {
        "attack_version": mapping.get("attack_version"),
        "profile": {"name": profile["name"], "label": profile["label"], "description": profile["description"]},
        "models": [env[m].breakdown() for m in CIM_MODELS],
        "summary": {
            "good": counts["good"], "partial": counts["partial"], "blind": counts["none"],
            # Back-compat fields the old UI/loop read:
            "visible": counts["good"] + counts["partial"],
        },
        "techniques": [
            {
                "technique": t.technique, "name": t.name, "tactics": t.tactics,
                "tier": t.tier, "status": "blind" if t.tier == "none" else "visible",  # back-compat
                "score": round(t.score, 2), "weight": t.weight, "priority": t.priority,
                "rationale": t.rationale,
                "required_models": [
                    {"model": m, "label": CIM_MODELS.get(m, m), "log_sources": ls,
                     "present": m in t.present_models,
                     "tier": env[m].tier if env.get(m) else "none"}
                    for m, ls in t.required_models.items()
                ],
                "present_models": t.present_models,
                "missing_models": t.missing_models,
                "remediation": t.remediation,
            }
            for t in techs
        ],
        # Back-compat: the prior report exposed these; keep them populated.
        "blind": counts["none"],
        "visible": counts["good"] + counts["partial"],
        "present_data_sources": sorted({env[m].label for m in CIM_MODELS if env[m].present}),
        "missing_data_sources": sorted({
            CIM_MODELS.get(m, m) for t in techs if t.tier == "none" for m in t.missing_models
        }),
    }
