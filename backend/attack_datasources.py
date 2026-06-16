"""Data-source (visibility) coverage — the 'gaps under the gaps'.

Credit: Marcus House (Splunk Enterprise Architect) raised this on the project's LinkedIn
post. Detection coverage = rule coverage x DATA-SOURCE coverage. NEX's gap finder only sees
techniques whose telemetry is already in the index. The scariest gaps are techniques you have
**no data source for at all** — they don't show up as "uncovered", they show up as *nothing*,
invisible to the analyst and the agent alike.

This module cross-checks a curated watchlist of high-value ATT&CK techniques against the
ATT&CK data-source families required to even observe them, and flags the ones the environment
has no telemetry for. (A focused, demo-scale slice of ATT&CK's data-source model.)
"""
from __future__ import annotations

# ATT&CK data-source family -> substrings that, if present in an observed sourcetype, mean the
# environment collects that telemetry. Matching is intentionally permissive (family-level).
DATA_SOURCES: dict[str, list[str]] = {
    "User Account / Authentication": ["okta", "auth", "signin", "wineventlog:security", "ldap", "duo"],
    "Process / Command Execution": ["sysmon", "wineventlog", "4688", "edr", "crowdstrike", "carbonblack"],
    "Cloud Audit (control plane)": ["cloudtrail", "aws:", "azure", "gcp", "o365:management"],
    "Network Traffic / Proxy": ["cisco:asa", "pan:", "fortigate", "zeek", "bro", "netflow", "stream:tcp",
                                  "proxy", "bluecoat", "squid", "stream:http"],
    "DNS": ["stream:dns", "named", "dns", "bind"],
    "Email Gateway": ["exchange", "proofpoint", "mimecast", "o365:reporting:messagetrace", "ironport"],
    "File Monitoring / EDR": ["sysmon:11", "filecreate", "edr:file", "carbonblack:file", "fim"],
    "Web Server / WAF": ["apache", "nginx", "iis", ":web", "waf", "modsecurity", "alb"],
}

# Curated high-value technique watchlist. Each names the data-source family required to SEE it.
WATCHLIST: list[dict] = [
    {"technique": "T1110", "name": "Brute Force", "tactic": "Credential Access",
     "data_source": "User Account / Authentication"},
    {"technique": "T1059.001", "name": "PowerShell", "tactic": "Execution",
     "data_source": "Process / Command Execution"},
    {"technique": "T1078.004", "name": "Valid Accounts: Cloud", "tactic": "Initial Access",
     "data_source": "Cloud Audit (control plane)"},
    {"technique": "T1537", "name": "Transfer Data to Cloud Account", "tactic": "Exfiltration",
     "data_source": "Cloud Audit (control plane)"},
    {"technique": "T1071.001", "name": "Application Layer Protocol: Web (C2)", "tactic": "Command and Control",
     "data_source": "Network Traffic / Proxy"},
    {"technique": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
     "data_source": "Network Traffic / Proxy"},
    {"technique": "T1071.004", "name": "DNS (C2 / tunneling)", "tactic": "Command and Control",
     "data_source": "DNS"},
    {"technique": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access",
     "data_source": "Email Gateway"},
    {"technique": "T1486", "name": "Data Encrypted for Impact (ransomware)", "tactic": "Impact",
     "data_source": "File Monitoring / EDR"},
    {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
     "data_source": "Web Server / WAF"},
]


def present_data_sources(observed_sourcetypes: list[str]) -> set[str]:
    obs = [s.lower() for s in observed_sourcetypes]
    present: set[str] = set()
    for family, patterns in DATA_SOURCES.items():
        if any(p in o for p in patterns for o in obs):
            present.add(family)
    return present


def visibility_report(observed_sourcetypes: list[str]) -> dict:
    """Classify each watchlist technique as 'visible' (data source collected) or 'blind' (no data source)."""
    present = present_data_sources(observed_sourcetypes)
    techniques = []
    for t in WATCHLIST:
        visible = t["data_source"] in present
        techniques.append({**t, "status": "visible" if visible else "blind"})
    blind = [t for t in techniques if t["status"] == "blind"]
    return {
        "techniques": techniques,
        "visible": len(techniques) - len(blind),
        "blind": len(blind),
        "present_data_sources": sorted(present),
        "missing_data_sources": sorted({t["data_source"] for t in blind}),
    }
