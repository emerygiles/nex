# NEX Architecture

NEX is a closed-loop agentic purple-team. The frontend visualizes a live agent run; the backend runs the agent loop; the agent's hands are the Splunk MCP Server and its brain is a Splunk Hosted Model.

## Component diagram

```mermaid
flowchart TB
    subgraph UI["Frontend — React/Vite/Tailwind/shadcn"]
        recon[ReconPanel]
        graph[AttackGraph · React Flow]
        stream[AgentStream · Framer Motion]
        report[GapReport]
        hub[MitigationHub]
    end

    subgraph API["Backend — Python / FastAPI"]
        rest[REST + SSE]
        loop[Agent Loop\nrecon → attack-think → prove → skeptic → ship]
        tools[MCP Tool Layer]
        brain[Model Client]
    end

    subgraph SPLUNK["Splunk Enterprise 10.4"]
        mcp[(Splunk MCP Server\n:8089/services/mcp)]
        hosted[(Hosted Model\nFoundation-sec-1.1-8b)]
        idx[(Indexes · Sourcetypes\nSaved-search detections)]
    end

    mock[(Mock MCP\nbundled APT dataset)]

    UI <-->|SSE events / REST| rest
    rest --> loop
    loop --> brain
    loop --> tools
    brain -->|reason, write detection| hosted
    tools -->|enumerate, run SPL, deploy| mcp
    mcp --> idx
    tools -. sandbox mode .-> mock

    classDef splunk fill:#15212B,stroke:#FF6A00,color:#fff;
    class mcp,hosted,idx splunk;
```

## Data flow (one gap-closing run)

1. UI starts a run → `POST /run` → backend opens an **SSE** stream.
2. **Recon**: `enumerate_coverage()` / `map_attack_surface()` via MCP → indexes, sourcetypes, existing detections. Streamed to `ReconPanel` + `AttackGraph`.
3. **Attack-think**: Model Client asks Foundation-sec for the ATT&CK technique most likely uncovered → candidate TTP. Streamed to `AgentStream`.
4. **Prove**: `generate_detection()` drafts SPL → `test_detection(spl)` runs it via MCP → **0 hits = gap**. Node turns red in `AttackGraph`.
5. **Skeptic gate**: second model pass attempts to disprove the gap; false positives dropped before reporting.
6. **Ship**: emit SPL + Sigma + metadata to `MitigationHub`; `deploy_detection()` installs a saved search via MCP. Re-test → node flips **green**.

## Mode switch

`MODE=sandbox` routes the **MCP Tool Layer** to the in-process **Mock MCP** (bundled `data/apt_scenario/`) so the whole loop runs with no Splunk. `MODE=live` routes to `SPLUNK_MCP_URL`. The agent loop, prompts, and UI are identical in both modes.

## AI provider switch

`AI_PROVIDER=splunk` calls the hosted **Foundation-sec-1.1-8b** (target: Best Use of Hosted Models). `AI_PROVIDER=anthropic` is a dev-time fallback. Both implement the same `ModelClient` interface.

## Trust & safety

- MCP requires an **encrypted RS256 token**; `deploy_detection` is the only state-changing tool and is gated behind an explicit UI confirm.
- Secrets live only in `backend/.env` (gitignored). Self-signed TLS handled via `SPLUNK_VERIFY_TLS`.
