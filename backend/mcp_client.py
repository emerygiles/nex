"""Live Splunk MCP Server client (streamable-HTTP / JSON-RPC over POST).

Targets the official Splunk MCP Server app:  https://<host>:8089/services/mcp
Requires an encrypted MCP token (Authorization: Bearer ...).

NOTE: The exact tool names exposed by the Splunk MCP Server are mapped here to
NEX's tool surface. Verify against your instance's `tools/list` (see
`list_tools()`), then adjust `_TOOL_MAP` if names differ. Sandbox mode does not
use this class at all.
"""
from __future__ import annotations

import json
import httpx

from config import settings

_TOOL_MAP = {
    # NEX concept           -> Splunk MCP tool name (verify on your instance)
    "list_knowledge": "list_saved_searches",
    "run_search": "run_search",
    "save_search": "create_saved_search",
}


class LiveMCP:
    name = "live"

    def __init__(self) -> None:
        self._url = settings.splunk_mcp_url
        self._client = httpx.Client(
            verify=settings.splunk_verify_tls,
            timeout=60.0,
            headers={
                "Authorization": f"Bearer {settings.splunk_mcp_token}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        self._id = 0

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        resp = self._client.post(self._url, content=json.dumps(payload))
        resp.raise_for_status()
        text = resp.text.strip()
        # Streamable-HTTP may return SSE framing; take the last data: line.
        if text.startswith("event:") or "\ndata:" in text:
            for line in reversed(text.splitlines()):
                if line.startswith("data:"):
                    text = line[len("data:"):].strip()
                    break
        data = json.loads(text)
        if "error" in data:
            raise RuntimeError(data["error"])
        return data.get("result", {})

    def list_tools(self) -> list[dict]:
        return self._rpc("tools/list").get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> dict:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    # --- NEX tool surface (delegates to MCP tools) --------------------------
    def enumerate_coverage(self) -> dict:
        ko = self.call_tool(_TOOL_MAP["list_knowledge"], {})
        # Shape normalization happens in agent/tools.py; pass through here.
        return {"raw": ko}

    def run_search(self, spl: str) -> dict:
        return self.call_tool(_TOOL_MAP["run_search"], {"query": spl})

    def save_detection(self, name: str, spl: str, technique: str, tactic: str = "") -> dict:
        return self.call_tool(
            _TOOL_MAP["save_search"], {"name": name, "search": spl}
        )
