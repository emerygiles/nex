"""Ingest a realistic multi-stage attack dataset into a live Splunk instance via HEC.

This makes NEX's red-teaming REAL: the agent enumerates and searches actual indexed
events, not a mock. The dataset embeds one deliberate detection blind spot — a large
S3 exfiltration (ATT&CK T1537) — alongside activity that *is* covered, so NEX has a
genuine gap to discover and close.

Usage:
    python ingest_demo_data.py --hec-url https://localhost:8088 --token <HEC_TOKEN>
"""
from __future__ import annotations

import argparse
import json
import time

import httpx

INDEX = "nex"


def events() -> list[dict]:
    now = time.time()

    def ev(offset_min, sourcetype, technique, raw, **fields):
        return {
            "time": now - offset_min * 60,
            "host": fields.pop("host", "nex-range"),
            "source": "nex-demo",
            "sourcetype": sourcetype,
            "index": INDEX,
            "event": raw,
            "fields": {"technique": technique, **fields},
        }

    out: list[dict] = []

    # T1110 — Okta MFA fatigue / brute force (COVERED by an existing detection)
    for i in range(42):
        out.append(ev(180 - i, "okta:im2", "T1110",
                      f"Okta auth_via_mfa FAILURE user=j.alvarez ip=45.133.12.9 attempt={i+1}",
                      eventType="user.authentication.auth_via_mfa", outcome="FAILURE",
                      user="j.alvarez", src_ip="45.133.12.9"))
    # T1078 — valid account login after MFA fatigue (uncovered, low signal)
    out.append(ev(136, "okta:im2", "T1078",
                  "Okta session.start SUCCESS user=j.alvarez ip=45.133.12.9",
                  eventType="user.session.start", outcome="SUCCESS", user="j.alvarez"))
    # T1059.001 — encoded PowerShell (COVERED)
    for i in range(6):
        out.append(ev(120 - i, "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "T1059.001",
                      "Sysmon EID1 Image=powershell.exe CommandLine=-enc aQBlAHgA... user=j.alvarez",
                      EventCode="1", host="FIN-WS-07", user="j.alvarez"))
    # T1078.004 — AWS console login without MFA (COVERED)
    out.append(ev(118, "aws:cloudtrail", "T1078.004",
                  "CloudTrail ConsoleLogin user=svc-deploy MFA=false sourceIP=45.133.12.9",
                  eventName="ConsoleLogin", user="svc-deploy", mfa="false"))
    # T1580 — cloud infrastructure discovery (uncovered, low signal)
    for i in range(3):
        out.append(ev(110 - i, "aws:cloudtrail", "T1580",
                      "CloudTrail DescribeInstances user=svc-deploy",
                      eventName="DescribeInstances", user="svc-deploy"))
    # T1537 — Transfer Data to Cloud Account: the PLANTED BLIND SPOT (uncovered, high volume)
    for i in range(300):
        out.append(ev(90 - (i % 60), "aws:cloudtrail", "T1537",
                      f"CloudTrail PutObject user=svc-deploy bucket=ext-billing-archive-9b2 "
                      f"key=dump/{i:04d}.parquet bytes={12000 + i} externalBucket=true",
                      eventName="PutObject", user="svc-deploy",
                      bucket="ext-billing-archive-9b2", external="true"))
    out.append(ev(28, "aws:cloudtrail", "T1537",
                  "CloudTrail PutBucketAcl user=svc-deploy bucket=ext-billing-archive-9b2 "
                  "grant=cross-account-write externalBucket=true",
                  eventName="PutBucketAcl", user="svc-deploy",
                  bucket="ext-billing-archive-9b2", external="true"))
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--hec-url", default="https://localhost:8088")
    p.add_argument("--token", required=True)
    args = p.parse_args()

    evs = events()
    # HEC accepts concatenated JSON objects in one body.
    body = "\n".join(json.dumps(e) for e in evs)
    r = httpx.post(
        f"{args.hec_url}/services/collector/event",
        headers={"Authorization": f"Splunk {args.token}"},
        content=body, verify=False, timeout=60.0,
    )
    r.raise_for_status()
    print(f"Ingested {len(evs)} events into index '{INDEX}'. HEC response: {r.json()}")
    by_t: dict[str, int] = {}
    for e in evs:
        by_t[e["fields"]["technique"]] = by_t.get(e["fields"]["technique"], 0) + 1
    print("By technique:", by_t)


if __name__ == "__main__":
    main()
