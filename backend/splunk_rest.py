"""Splunk REST data plane — the REAL red-team backend.

Implements NEX's tool surface against a live Splunk instance's REST API (port 8089),
so enumeration, search, and detection deployment all hit real knowledge objects and
real indexed data. Used when MODE=splunk_rest. This is the path that proves the
capability end-to-end (the MCP transport is equivalent but is blocked on this box by
a KV Store platform bug; see memory/kvstore-fix.md).

ATT&CK mapping: NEX-managed detections are saved searches whose name starts with the
configured tag and whose description carries `ATT&CK=Txxxx`. Real ESCU content uses
`action.correlationsearch.annotations`; we use description tagging so this runs without
Enterprise Security installed.
"""
from __future__ import annotations

import re
from urllib.parse import quote

import httpx

from config import settings


def _saved_search_path(base: str, name: str) -> str:
    """DELETE/GET URL for a saved search, with the name encoded as a single path segment.

    Using httpx.URL(name).path mis-parses names containing ? # or / (truncates or adds
    segments), so we percent-encode with safe='' instead.
    """
    return f"{base}/servicesNS/nobody/search/saved/searches/{quote(name, safe='')}"

_ATTACK_RE = re.compile(r"ATT&CK=(T\d{4}(?:\.\d{3})?)")

# SPL commands that write, exfiltrate, or execute — never allowed in an agent-run search.
# A detection tool must read telemetry, not delete it or shell out. This blocks a hallucinated
# or adversarial `... | delete` / `| outputlookup` from ever reaching a real, admin-privileged search.
_BLOCKED_SPL = {
    "delete", "outputlookup", "outputcsv", "output", "collect", "tscollect", "mcollect",
    "sendemail", "sendalert", "script", "runshellscript", "crawl", "dump", "loadjob",
    "savedsearch",
}


class UnsafeSPLError(ValueError):
    """Raised when an SPL string contains a write/exfil/execute command."""


def assert_safe_spl(spl: str) -> None:
    """Reject SPL that contains any blocked (write/exfil/execute) command after a pipe."""
    for segment in spl.split("|")[1:]:
        cmd = segment.strip().split(None, 1)[0].lower() if segment.strip() else ""
        if cmd in _BLOCKED_SPL:
            raise UnsafeSPLError(f"blocked unsafe SPL command: '{cmd}'")


class SplunkRest:
    name = "splunk_rest"

    def __init__(self) -> None:
        self._base = settings.splunk_rest_url.rstrip("/")
        self._index = settings.splunk_index
        self._tag = settings.nex_detection_tag
        self._http = httpx.Client(
            auth=(settings.splunk_user, settings.splunk_password),
            verify=settings.splunk_verify_tls, timeout=90.0,
        )

    # --- low-level helpers --------------------------------------------------
    def _normalize(self, spl: str) -> str:
        """Make agent/model-authored SPL runnable & scoped to our index.

        Strips an erroneous leading pipe and guarantees the base search targets our index,
        so a model rule like `| search sourcetype=aws:cloudtrail ...` becomes a valid,
        index-scoped Splunk search.
        """
        spl = spl.strip()
        if spl.startswith("|"):
            spl = spl[1:].lstrip()
        head = spl.split("|", 1)[0]
        if "index=" not in head:
            if head.lower().startswith("search"):
                spl = f"search index={self._index} " + spl[len("search"):].lstrip()
            else:
                spl = f"search index={self._index} {spl}"
        return spl

    def _oneshot(self, spl: str) -> list[dict]:
        """Run a blocking search (index-normalized) and return result rows."""
        return self._oneshot_raw(self._normalize(spl))

    def _oneshot_raw(self, search: str) -> list[dict]:
        """Run SPL verbatim — for generating commands (`| metadata`, `| tstats`) that must
        not be rewritten by `_normalize`. Still safety-checked before it reaches Splunk."""
        assert_safe_spl(search)  # refuse write/exfil/execute commands before they hit Splunk
        r = self._http.post(
            f"{self._base}/services/search/jobs/export",
            # Wide window so demo/lab data isn't missed if it was ingested days earlier.
            data={"search": search, "earliest_time": "-30d", "latest_time": "now",
                  "output_mode": "json", "exec_mode": "oneshot"},
        )
        r.raise_for_status()
        rows = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                import json
                obj = json.loads(line)
                if "result" in obj:
                    rows.append(obj["result"])
            except Exception:  # noqa: BLE001
                pass
        return rows

    # --- read tools ---------------------------------------------------------
    def enumerate_coverage(self) -> dict:
        st_rows = self._oneshot(f"search index={self._index} | stats count by sourcetype")
        sourcetypes = [{"name": r["sourcetype"], "index": self._index, "events": int(r["count"])}
                       for r in st_rows]
        return {"sourcetypes": sourcetypes, "detections": self._list_detections()}

    # CIM data models NEX scores visibility against, and the tstats datamodel name to probe.
    _CIM_DATAMODELS = {
        "Authentication": "Authentication", "Endpoint": "Endpoint",
        "Network_Traffic": "Network_Traffic", "Network_Resolution": "Network_Resolution",
        "Web": "Web", "Email": "Email", "Change": "Change", "Data_Access": "Data_Access",
    }

    def telemetry_posture(self) -> list[dict]:
        """Measured per-sourcetype signals for the tiered visibility engine.

        Production path for Marcus's "data presence != detection capability" point:
          * volume / first-seen / last-seen come from `| metadata type=sourcetypes` (cheap).
          * CIM membership is the real test — for each CIM data model we `| tstats` the
            sourcetypes that actually populate it (accelerated), so "we have the data source"
            only counts as good when it's genuinely CIM-normalized and queryable, not merely
            ingested. A sourcetype ingested but never CIM-mapped scores `partial`, because
            that's exactly when an ESCU/data-model detection silently fails to fire.
        """
        meta = self._oneshot_raw(
            f"| metadata type=sourcetypes index={self._index} "
            f"| fields sourcetype totalCount firstTime lastTime")
        cim_by_st = self._cim_membership()
        out = []
        for r in meta:
            st = r.get("sourcetype")
            if not st:
                continue
            out.append({
                "name": st,
                "events": int(float(r.get("totalCount", 0) or 0)),
                "latest": float(r.get("lastTime", 0) or 0) or None,
                "earliest": float(r.get("firstTime", 0) or 0) or None,
                "cim_models": sorted(cim_by_st.get(st, set())),  # [] = measured, not CIM-mapped
            })
        return out

    def _cim_membership(self) -> dict[str, set[str]]:
        """sourcetype -> {CIM data models it actually populates}, via tstats on each model."""
        by_st: dict[str, set[str]] = {}
        for model, dm in self._CIM_DATAMODELS.items():
            try:
                rows = self._oneshot_raw(
                    f"| tstats count from datamodel={dm} where index={self._index} by sourcetype")
            except Exception:  # noqa: BLE001 - model not installed/accelerated -> treat as absent
                continue
            for r in rows:
                st = r.get("sourcetype") or r.get("sourcetype{}")  # tstats may flatten the field name
                if st:
                    by_st.setdefault(st, set()).add(model)
        return by_st

    def _list_detections(self) -> list[dict]:
        r = self._http.get(
            f"{self._base}/services/saved/searches",
            params={"count": "0", "output_mode": "json", "search": self._tag},
        )
        r.raise_for_status()
        dets = []
        for e in r.json().get("entry", []):
            desc = e.get("content", {}).get("description", "") or ""
            m = _ATTACK_RE.search(desc)
            if not m:
                continue
            dets.append({"name": e["name"], "technique": m.group(1),
                         "tactic": "", "spl": e["content"].get("search", "")})
        return dets

    def map_attack_surface(self) -> list[dict]:
        rows = self._oneshot(f"search index={self._index} | stats count by technique sourcetype")
        covered = {d["technique"] for d in self._list_detections()}
        agg: dict[str, dict] = {}
        for r in rows:
            t = r.get("technique")
            if not t:
                continue
            node = agg.setdefault(t, {"technique": t, "events": 0, "sourcetype": r["sourcetype"]})
            node["events"] += int(r["count"])
        for t, node in agg.items():
            node["covered"] = t in covered
        return list(agg.values())

    def run_search(self, spl: str) -> dict:
        try:
            rows = self._oneshot(spl)
        except UnsafeSPLError:
            # A blocked rule fires nothing; the loop then falls back to a grounded, safe detection.
            return {"hits": 0, "sample": [], "blocked": True}
        total = 0
        for r in rows:
            try:
                total += int(float(r.get("count", 1)))
            except (TypeError, ValueError):
                total += 1
        # If the search didn't aggregate, total events = row count.
        if not any("count" in r for r in rows):
            total = len(rows)
        return {"hits": total, "sample": rows[:3]}

    def coverage_for(self, technique: str) -> int:
        return sum(1 for d in self._list_detections() if d["technique"] == technique)

    def sample_events(self, technique: str) -> list[dict]:
        return self._oneshot(f"search index={self._index} technique={technique} | head 3")

    def count_technique(self, technique: str) -> int:
        rows = self._oneshot(f"search index={self._index} technique={technique} | stats count")
        try:
            return int(rows[0].get("count", 0)) if rows else 0
        except (TypeError, ValueError, IndexError):
            return 0

    # --- write tool ---------------------------------------------------------
    def save_detection(self, name: str, spl: str, technique: str, tactic: str = "") -> dict:
        assert_safe_spl(spl)  # never deploy a saved search containing a write/exfil/execute command
        search = spl if spl.strip().lower().startswith(("search ", "|")) else f"search {spl}"
        saved_name = f"{self._tag} - {name}" if not name.startswith(self._tag) else name
        # Remove any prior version so re-runs are idempotent.
        self._http.delete(_saved_search_path(self._base, saved_name), params={"output_mode": "json"})
        r = self._http.post(
            f"{self._base}/servicesNS/nobody/search/saved/searches",
            data={
                "name": saved_name, "search": search,
                "description": f"NEX auto-authored detection. ATT&CK={technique}. tactic={tactic}",
                "is_scheduled": "1", "cron_schedule": "*/10 * * * *",
                "dispatch.earliest_time": "-15m", "dispatch.latest_time": "now",
                "alert_type": "number of events", "alert_comparator": "greater than",
                "alert_threshold": "0", "output_mode": "json",
            },
        )
        ok = r.status_code in (200, 201)
        return {"ok": ok, "name": saved_name, "status": r.status_code,
                "coverage_for_technique": self.coverage_for(technique)}

    def reset(self) -> dict:
        """Delete NEX auto-authored detections so the blind spot re-opens (repeatable demos).

        Baseline 'existing' detections (description 'Baseline SOC detection') are kept;
        only NEX's own authored ones ('NEX auto-authored') are removed.
        """
        r = self._http.get(f"{self._base}/services/saved/searches",
                            params={"count": "0", "output_mode": "json", "search": self._tag})
        removed = []
        for e in r.json().get("entry", []):
            if "auto-authored" in (e.get("content", {}).get("description", "") or ""):
                self._http.request(
                    "DELETE", _saved_search_path(self._base, e["name"]), params={"output_mode": "json"})
                removed.append(e["name"])
        return {"removed": removed}

    # Safety-net helper: REST mode has no pre-planted answer.
    @property
    def planted_gap(self) -> dict:
        return {}
