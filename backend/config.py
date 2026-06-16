"""Central configuration, loaded from environment / .env."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mode: str = "sandbox"  # sandbox | mcp | splunk_rest

    # MCP transport (blocked on this instance by a KV Store platform bug).
    splunk_mcp_url: str = "https://localhost:8089/services/mcp"
    splunk_mcp_token: str = ""
    splunk_verify_tls: bool = False

    # Splunk REST data plane (real enumeration / search / deploy against a live instance).
    splunk_rest_url: str = "https://localhost:8089"
    splunk_user: str = ""
    splunk_password: str = ""
    splunk_index: str = "nex"
    nex_detection_tag: str = "NEX-DET"  # saved-search name prefix marking NEX-managed detections

    # Production safety. auto_deploy=False makes NEX PROPOSE detections and wait for human
    # approval (POST /deploy) instead of deploying them itself — the prod-safe default.
    auto_deploy: bool = True

    ai_provider: str = "scripted"  # foundation_sec | anthropic | scripted
    splunk_hosted_model: str = "foundation-sec-1.1-8b-instruct"
    anthropic_api_key: str = ""

    # Local Foundation-Sec-8B via an OpenAI-compatible server (Ollama).
    foundation_base_url: str = "http://localhost:11434/v1"
    foundation_model: str = "hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M"
    # If the live model call fails/garbles, fall back to deterministic logic so the demo never breaks.
    ai_safety_net: bool = True

    host: str = "127.0.0.1"
    port: int = 8800


settings = Settings()
