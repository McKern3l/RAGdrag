# Changelog

## v0.5.0 - Full Kill Chain (2026-04-01)

### Added
- **R4 Poison phase** with 4 techniques:
  - RD-0401: Document Injection (ingestion endpoint discovery, injection, verification)
  - RD-0402: Embedding Dominance (test if injected docs dominate retrieval)
  - RD-0403: Credential Trap (inject docs directing users to attacker infrastructure)
  - RD-0404: Instruction Injection via Retrieval (inject directives that influence LLM behavior)
- **R5 Hijack phase** with 4 techniques:
  - RD-0501: Retrieval Redirection (replace expected responses with attacker content)
  - RD-0502: Context Window Saturation (flood context with attacker documents)
  - RD-0503: Agent Tool Manipulation (inject docs that trigger tool calls)
  - RD-0504: Persistent Backdoor via RAG (verify persistence across query types)
- **R6 Evade phase** with 4 techniques:
  - RD-0601: Semantic Substitution (3 strategies: academic, business, indirect)
  - RD-0602: Retrieval Camouflage (wrap payloads in organizational content)
  - RD-0603: Query Pattern Obfuscation (noise interleaving)
  - RD-0604: Multi-Turn Context Building (progressive disclosure, role assumption)
- CLI commands: `ragdrag poison`, `ragdrag hijack`, `ragdrag evade`
- `ragdrag scan` now chains all 6 phases (R1-R6) with JSON output
- Cross-phase composition: Hijack imports from Poison + Evade
- pytest testpaths configuration

### Changed
- Renamed `test_*` functions in source modules to `assess_*` to prevent pytest collection conflicts
- `ragdrag scan` default phases expanded from R1,R2,R3 to R1,R2,R3,R4,R5,R6

## v0.2.0 - R2 Probe (2026-04-01)

### Added
- **R2 Probe phase** with 5 techniques for mapping RAG pipeline internals:
  - RD-0201: Chunk Boundary Detection (source counts, chunk sizes, cross-topic analysis, response variation)
  - RD-0202: Similarity Threshold Mapping (7-level relevance degradation, cutoff detection)
  - RD-0203: Retrieval Count Estimation (top-k detection, fixed vs dynamic)
  - RD-0204: Knowledge Base Scope Mapping (6 domain categories, coverage/gap analysis)
  - RD-0205: Embedding Model Fingerprinting (multilingual, code-aware, domain-specific, general classification)
- Debug endpoint discovery (13 common paths: /debug/config, /admin/stats, etc.)
- `ragdrag probe` CLI command with `--depth quick|full`
- `ragdrag scan` command chaining R1, R2, R3 phases
- Shared data structures in `ragdrag/core/models.py` (Finding dataclass)
- Payload loader utility (`ragdrag/utils/payloads.py`)
- Generalized JSON reporter (accepts any result with `.to_dict()`)
- ProbeResult dataclass with `.to_dict()` serialization
- 70 tests (probe techniques, shared models, payload loader)

### Changed
- Extracted Finding from fingerprint.py to shared models.py
- JSON reporter now accepts any phase result, not just FingerprintResult

## v0.1.0-alpha - Initial Release (2026-03-25)

### Added
- R1 Fingerprint phase (RD-0101: RAG presence detection, RD-0102: Vector DB fingerprinting)
- R3 Exfiltrate phase (RD-0301: Direct knowledge extraction, RD-0302: Guardrail-aware extraction)
- RAGdrag taxonomy: 27 techniques across 6 phases
- CLI: `ragdrag fingerprint`, `ragdrag exfiltrate`, `ragdrag listen`
- JSON reporter for findings output
- Lab servers (open + guarded RAG targets)
- 7 payload files for curated query sets
