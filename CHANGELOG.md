# Changelog

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
