# RAGdrag MCP Server — Design Spec

**Date:** 2026-03-25
**Status:** Approved
**Owner:** Forge

---

## Purpose

Expose ragdrag's 27 kill chain techniques as MCP tools so AI agents (Claude Code, Codex, br scan) can discover and run RAG security tests programmatically. Stateless, stdio-first, community-ready.

## Decision Log

| Decision | Choice | Why |
|----------|--------|-----|
| Consumer | Internal (br scan) + community (Claude Code, Codex) | Build for ourselves, open enough for others |
| Tool granularity | Hybrid: phase-level + individual techniques | Progressive disclosure. Broad tools for most use, precision when needed |
| Transport priority | stdio primary, HTTP secondary | Claude Code and Codex both use stdio. HTTP for forge cluster / br scan remote |
| State management | Stateless | No target data stored. Avoids liability. Agent owns context |
| Architecture | New package alongside CLI (Approach 3) | Zero risk to shipped CLI. MCP can evolve independently |
| Future state | MCP-native rebuild in ~1 month | Let the interface mature with real usage, then rebuild clean |

## Architecture

```
ragdrag/                    (existing, untouched)
├── ragdrag/
│   └── core/               ← MCP server imports from here
│       ├── fingerprint.py   (returns FingerprintResult)
│       ├── exfiltrate.py    (returns ExfiltrateResult)
│       ├── listener.py
│       └── ...
│
ragdrag-mcp/                (new package, same repo)
├── ragdrag_mcp/
│   ├── __init__.py
│   ├── __main__.py          ← entry point (python -m ragdrag_mcp)
│   ├── server.py            ← MCP server setup, tool registration
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── fingerprint.py   ← R1 phase tool (runs all R1 techniques)
│   │   ├── probe.py         ← R2
│   │   ├── exfiltrate.py    ← R3
│   │   ├── poison.py        ← R4
│   │   ├── hijack.py        ← R5
│   │   ├── evade.py         ← R6
│   │   ├── discovery.py     ← list_techniques, list_payloads, get_payload
│   │   └── techniques/      ← individual technique sub-tools (rd_0101, etc.)
│   └── transports/
│       ├── __init__.py
│       ├── stdio.py          ← primary: subprocess transport
│       └── http.py           ← secondary: Streamable HTTP transport
├── pyproject.toml
└── README.md
```

**Key constraint:** ragdrag-mcp imports from ragdrag.core. It never duplicates logic. The core functions already return dataclasses with .to_dict() methods — those become MCP tool results directly.

## Tool Interface

### Discovery Tools

| Tool | Input | Output |
|------|-------|--------|
| `ragdrag_list_techniques` | `{phase?}` | `{techniques: [{id, name, phase, atlas_tactic, description}]}` |
| `ragdrag_list_payloads` | `{category?}` | `{payloads: [{name, description, query_count, target_type}]}` |
| `ragdrag_get_payload` | `{name}` | `{queries: [...]}` |

The agent calls `ragdrag_list_techniques` first to learn the kill chain. Progressive disclosure.

### Phase-Level Tools

| Tool | Input | Output |
|------|-------|--------|
| `ragdrag_fingerprint` | `{target, query_field?, response_field?, scan_ports?}` | `{rag_detected, vector_db, findings[], timing}` |
| `ragdrag_probe` | `{target, depth?, query_field?}` | `{chunk_size, threshold, kb_scope, findings[]}` |
| `ragdrag_exfiltrate` | `{target, deep?, query_field?, response_field?}` | `{findings[], guardrail_detected, bypass_findings[]}` |
| `ragdrag_poison` | `{target, document_url?, technique?}` | `{injected, retrieval_dominance, findings[]}` |
| `ragdrag_hijack` | `{target, technique?, persistence?}` | `{redirected, context_saturated, findings[]}` |
| `ragdrag_evade` | `{target, technique?, original_query?}` | `{bypassed, detection_score, findings[]}` |

Every tool requires `target` (the RAG endpoint URL). No state carried between calls.

### Individual Technique Tools

Named `ragdrag_rd_XXXX` (e.g., `ragdrag_rd_0101`, `ragdrag_rd_0302`). Same input pattern as the parent phase tool but scoped to one technique. Agent discovers these via `ragdrag_list_techniques` or by listing tools with prefix `ragdrag_rd_`.

### All Tool Results

Every tool returns:
```json
{
  "success": true,
  "technique_id": "RD-0101",
  "findings": [...],
  "metadata": {"target": "...", "timestamp": "...", "version": "0.1.0"}
}
```

Findings follow the existing dataclass structure (technique_id, technique_name, confidence, detail, evidence).

## Transports

### stdio (primary)

The default. Agent spawns ragdrag-mcp as a subprocess.

**Launch:** `python -m ragdrag_mcp`

**Integration:**

Claude Code:
```bash
claude mcp add ragdrag -- python -m ragdrag_mcp
```

Codex:
```json
{"ragdrag": {"command": "python", "args": ["-m", "ragdrag_mcp"]}}
```

### HTTP (secondary)

For remote/team use. br scan on forge-1 connecting to ragdrag-mcp on the same box or across the cluster.

**Launch:** `python -m ragdrag_mcp --http --port 8400`

Streamable HTTP transport per MCP spec.

## Dependencies

```toml
[project]
dependencies = [
    "ragdrag>=0.1.0",     # core library
    "mcp>=1.0",           # Python MCP SDK
    "httpx>=0.27",        # HTTP client (inherited from ragdrag)
]
```

## What Ships vs What's Stubbed

**Ships working:**
- Discovery tools (list_techniques, list_payloads, get_payload)
- ragdrag_fingerprint (R1 — wraps existing run_full_fingerprint)
- ragdrag_exfiltrate (R3 — wraps existing run_exfiltrate)
- ragdrag_rd_0101, ragdrag_rd_0102 (individual technique examples)
- stdio transport

**Stubbed (returns "not yet implemented"):**
- ragdrag_probe (R2 — core not implemented yet)
- ragdrag_poison (R4 — core not implemented yet)
- ragdrag_hijack (R5 — core not implemented yet)
- ragdrag_evade (R6 — core not implemented yet)
- HTTP transport
- Remaining individual technique tools

Matches the CLI: only R1 and R3 have working core implementations. MCP server doesn't promise more than the core delivers.

## Future State: br scan Migration

**Not in this build.** Documented for the architecture conversation.

Current br scan has built-in tool parsers (nmap, ffuf, nuclei, searchsploit, Python script executor). Future state: br scan becomes a pure reasoning agent that connects to ragdrag-mcp as its tool layer. The parsers migrate into ragdrag core.

Migration path:
1. ragdrag-mcp ships and stabilizes (this spec)
2. br scan adds ragdrag-mcp as an MCP client alongside its existing tools
3. Existing br scan tools migrate into ragdrag core one at a time
4. MCP-native rebuild (Approach 2) completes the transition

Timeline: ~1 month after ragdrag-mcp ships.

## Security

- **Stateless:** No target data persisted. No engagement logs. No findings stored.
- **Authorization disclaimer:** Tool descriptions include "for authorized security testing only."
- **Input validation:** Target URL validated before any HTTP calls. Same checks as CLI.
- **No credential storage:** The listener tool (ragdrag listen) is CLI-only. Not exposed via MCP.

## Success Criteria

1. `claude mcp add ragdrag -- python -m ragdrag_mcp` works in Claude Code
2. Agent can discover techniques via `ragdrag_list_techniques`
3. Agent can run `ragdrag_fingerprint` against a target and get structured findings
4. Agent can chain R1 → R3 without human intervention
5. Zero changes to the existing ragdrag CLI package
