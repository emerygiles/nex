"""NEX backend — FastAPI.

Exposes:
  GET  /health          -> mode + brain + MCP backend
  GET  /scenario        -> the sandbox attack scenario (for UI priming)
  GET  /run (SSE)       -> streams the agent loop, one event per step
"""
from __future__ import annotations

import json

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from config import settings

app = FastAPI(title="NEX — Autonomous Purple-Team for Splunk", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_mcp():
    """Pick the data-plane backend based on MODE."""
    if settings.mode == "splunk_rest":
        from splunk_rest import SplunkRest
        return SplunkRest()
    if settings.mode == "mcp":
        from mcp_client import LiveMCP
        return LiveMCP()
    from mock_mcp.server import MockMCP
    return MockMCP()


@app.get("/health")
def health():
    plane = {"sandbox": "mock", "mcp": "mcp-server", "splunk_rest": "splunk-rest"}.get(settings.mode, "mock")
    url = {"mcp": settings.splunk_mcp_url, "splunk_rest": settings.splunk_rest_url}.get(settings.mode)
    return {
        "ok": True,
        "mode": settings.mode,
        "brain": settings.ai_provider,
        "mcp": plane,
        "mcp_url": url,
    }


@app.get("/coverage")
def coverage():
    """Current environment + coverage snapshot (no agent run). Feeds the Surface map
    and Detections views and seeds the overview before a sweep."""
    mcp = get_mcp()
    cov = mcp.enumerate_coverage()
    surface = mcp.map_attack_surface()
    return {
        "sourcetypes": cov.get("sourcetypes", []),
        "detections": cov.get("detections", []),
        "surface": surface,
    }


@app.get("/scenario")
def scenario():
    from mock_mcp.server import SCENARIO_PATH
    return json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))


@app.post("/reset")
def reset():
    """Re-open the blind spot (delete NEX auto-authored detections). REST mode only."""
    mcp = get_mcp()
    if hasattr(mcp, "reset"):
        return mcp.reset()
    return {"removed": [], "note": "reset only applies in splunk_rest mode"}


@app.get("/run")
async def run():
    """Stream the agent loop as SSE.

    The loop makes blocking calls (local model inference, Splunk searches). We run it in a
    worker thread and hand events to the event loop via a queue so the SSE stream flushes
    live and uvicorn stays responsive.
    """
    import asyncio
    import threading

    from agent.loop import run_investigation

    mcp = get_mcp()
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def worker():
        try:
            for event in run_investigation(mcp):
                loop.call_soon_threadsafe(queue.put_nowait, event)
        except Exception as e:  # noqa: BLE001 - surface failures as a terminal event
            loop.call_soon_threadsafe(
                queue.put_nowait,
                {"phase": "error", "kind": "status", "message": f"Run failed: {e}", "data": None},
            )
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, None)

    threading.Thread(target=worker, daemon=True).start()

    async def event_gen():
        while True:
            event = await queue.get()
            if event is None:
                break
            yield {"event": "step", "data": json.dumps(event)}

    return EventSourceResponse(event_gen())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host=settings.host, port=settings.port, reload=True)
