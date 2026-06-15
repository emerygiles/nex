"""Create the baseline 'existing detections' as real Splunk saved searches.

These represent the SOC's already-deployed coverage. They intentionally cover
T1110, T1059.001, and T1078.004 — but NOT the S3 exfiltration (T1537), which is the
blind spot NEX must discover and close. Each is tagged `ATT&CK=Txxxx` in its
description so NEX can read coverage back via the REST API.

Usage:
    python setup_detections.py --url https://localhost:8089 --user <u> --password <p>
"""
from __future__ import annotations

import argparse
from urllib.parse import quote

import httpx

TAG = "NEX-DET"
BASELINE = [
    ("Okta MFA Fatigue / Brute Force", "T1110",
     "search index=nex sourcetype=okta:im2 technique=T1110 outcome=FAILURE "
     "| stats count by user src_ip | where count > 10"),
    ("Suspicious PowerShell Encoded Command", "T1059.001",
     "search index=nex sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" "
     "technique=T1059.001 | stats count by host user"),
    ("AWS Console Login Without MFA", "T1078.004",
     "search index=nex sourcetype=aws:cloudtrail technique=T1078.004 mfa=false "
     "| stats count by user"),
]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="https://localhost:8089")
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    args = p.parse_args()

    http = httpx.Client(auth=(args.user, args.password), verify=False, timeout=60.0)
    base = args.url.rstrip("/") + "/servicesNS/nobody/search/saved/searches"
    for label, technique, spl in BASELINE:
        name = f"{TAG} - {label}"
        http.request("DELETE", f"{base}/{quote(name, safe='')}", params={"output_mode": "json"})
        r = http.post(base, data={
            "name": name, "search": spl,
            "description": f"Baseline SOC detection. ATT&CK={technique}.",
            "is_scheduled": "1", "cron_schedule": "*/10 * * * *",
            "dispatch.earliest_time": "-15m", "dispatch.latest_time": "now",
            "output_mode": "json",
        })
        print(f"{'OK ' if r.status_code in (200, 201) else f'ERR {r.status_code}'}: {name} [{technique}]")


if __name__ == "__main__":
    main()
