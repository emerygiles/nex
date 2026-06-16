"""Threat profiles — turn a flat blind-spot inventory into a priority queue.

Marcus House's v2 note #5: "When you surface 6 blind spots, rank them by what the org
actually faces. T1486 and T1190 aren't equal to the rest for most shops." A profile is a
weighted watchlist of ATT&CK techniques (0-1 weight = how much this org cares), plus a
short note on *why* each matters. The visibility engine multiplies the weight by the
technique's exposure (blind > partial > good) to rank remediation.

Profiles are deliberately small and editable — this is the org-specific knob, not a model
output. `default` is tuned for the demo's "phish -> cloud exfil" intrusion; the presets
sketch how an industry/threat lens reshuffles the same STIX-derived telemetry math.

--- coverage_logic: OR vs AND across data sources -------------------------------------
A technique maps (via STIX) to MULTIPLE data sources / CIM data models. NEX uses **OR**
to decide "can you see it at all" — if the environment supplies *any one* relevant data
model, the technique isn't fully blind — and then **weights the count and quality** of the
present models for the tier (more + higher-quality sources => "good"; one weak source =>
"partial"). Pure AND is wrong: most techniques are detectable from any of several sources,
so requiring all of them would invent blind spots that don't exist. Pure OR is too generous:
it throws away the quality signal that separates a real detection from a log that's merely
ingested. OR-for-presence + quality-weighted-tier is the defensible middle.
"""
from __future__ import annotations

from config import settings

# weight: 0..1 importance to this org. notes: one-line "why it matters".
_PROFILES: dict[str, dict] = {
    "default": {
        "label": "Phishing → Cloud Exfil (demo)",
        "description": "Tuned for the bundled APT scenario: identity phishing into a cloud "
                       "account, recon, and data exfiltration to attacker storage.",
        "weights": {
            "T1078.004": 0.95, "T1537": 1.0, "T1071.004": 0.85, "T1071.001": 0.8,
            "T1048": 0.9, "T1110": 0.7, "T1059.001": 0.75, "T1566.001": 0.85,
            "T1486": 0.6, "T1190": 0.65, "T1098": 0.7, "T1530": 0.85,
        },
        "notes": {
            "T1078.004": "Valid cloud accounts are the demo's entry point — high blast radius.",
            "T1537": "The planted blind spot: bulk S3 PutObject to an external bucket.",
            "T1071.004": "DNS tunneling is a classic C2/exfil path that flat coverage misses.",
            "T1071.001": "Web-protocol C2 hides in normal egress; needs proxy/flow visibility.",
            "T1048": "Exfiltration over alternative protocols — the exfil tactic this scenario is about.",
            "T1110": "Brute force is the initial credential-access step; already covered here.",
            "T1059.001": "PowerShell execution on the compromised host.",
            "T1566.001": "Spearphishing attachment is the likely real entry vector.",
            "T1486": "Ransomware impact — high severity but not this actor's goal.",
            "T1190": "Public-facing exploitation — relevant if internet-facing apps exist.",
            "T1098": "Account manipulation (e.g. add cross-account access) cements persistence.",
            "T1530": "Direct access to cloud storage objects — adjacent to the exfil gap.",
        },
    },
    "ransomware": {
        "label": "Ransomware-led intrusion",
        "description": "Weighted for a commodity ransomware kill chain: access broker entry, "
                       "lateral movement, defense evasion, encryption for impact.",
        "weights": {
            "T1486": 1.0, "T1490": 0.9, "T1190": 0.85, "T1078": 0.8, "T1059.001": 0.85,
            "T1021.001": 0.8, "T1003": 0.9, "T1562.001": 0.85, "T1112": 0.7, "T1048": 0.7,
        },
        "notes": {
            "T1486": "Data encrypted for impact — the objective itself.",
            "T1490": "Inhibit system recovery (shadow-copy deletion) precedes encryption.",
            "T1190": "Exploited public-facing apps are a top ransomware entry vector.",
            "T1003": "Credential dumping fuels the lateral movement before encryption.",
            "T1562.001": "Disabling security tools is the standard pre-encryption step.",
        },
    },
    "cloud_saas": {
        "label": "Cloud / SaaS-first estate",
        "description": "Weighted for an org whose crown jewels live in cloud and SaaS: "
                       "identity, control-plane, and data-store visibility dominate.",
        "weights": {
            "T1078.004": 1.0, "T1537": 0.95, "T1530": 0.9, "T1098": 0.85, "T1556": 0.85,
            "T1567": 0.9, "T1071.001": 0.7, "T1110": 0.75, "T1528": 0.8, "T1484": 0.75,
        },
        "notes": {
            "T1078.004": "Cloud account compromise is the dominant cloud-estate risk.",
            "T1537": "Transfer to attacker-controlled cloud storage.",
            "T1530": "Direct data-from-cloud-storage access.",
            "T1567": "Exfiltration over web services (e.g. to SaaS storage).",
            "T1556": "Modify authentication process / MFA tampering.",
        },
    },
}


def get_profile(name: str | None = None) -> dict:
    key = (name or getattr(settings, "threat_profile", "default") or "default").lower()
    profile = _PROFILES.get(key, _PROFILES["default"])
    return {"name": key if key in _PROFILES else "default", **profile}


def list_profiles() -> list[dict]:
    return [{"name": k, "label": v["label"], "description": v["description"]} for k, v in _PROFILES.items()]
