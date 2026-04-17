# PromptArmor

> **Passive behavioral monitoring for agentic AI systems — detecting information leakage that requires no adversarial prompting.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Research Status](https://img.shields.io/badge/status-active%20research-orange.svg)]()
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Origin Story

This project started with an observation, not an exploit.

While using **Claude Code** with a locally-substituted **Mistral 7B** backend (via Ollama), I noticed something unexpected: the model began emitting fragments of what appeared to be Claude Code's internal system prompt and agent schema — **without any adversarial prompting**. No jailbreaks. No prompt injection. No crafted inputs designed to elicit leakage.

The leak emerged from **cognitive load conditions** — specifically, after extended churn periods (~9–10 minutes) where the local model struggled to resolve a complex multi-step task. Under that pressure, context boundary maintenance failed. The result was passive, involuntary disclosure of:

- Claude Code's identity framing and security policies
- Memory architecture and behavioral constraints
- Full agent schema including subagent types, tool grants, and orchestration parameters (`run_in_background`, `worktree` isolation, `SendMessage`)

**Finding**: Extended churn time is a novel leading indicator of context boundary failure — a real-time alerting primitive that existing monitoring tools completely miss.

This isn't a theoretical vulnerability. It's an observed, reproducible behavior pattern with significant implications for any organization deploying local models as drop-in replacements for commercial AI backends.

PromptArmor is the detection and monitoring framework built from that observation.

---

## What PromptArmor Does

PromptArmor monitors AI agent output streams in real time, looking for behavioral signatures that indicate context boundary failure and information leakage — **before** sensitive data leaves the system perimeter.

```
Agent Output Stream
       │
       ▼
┌─────────────────────┐
│   PromptArmor       │
│   Monitor           │
│  ┌───────────────┐  │
│  │ Identity      │  │──► ALERT: System prompt fragment detected
│  │ Leak Detector │  │
│  └───────────────┘  │
│  ┌───────────────┐  │
│  │ Schema        │  │──► ALERT: Agent schema exposure (CRITICAL)
│  │ Leak Detector │  │
│  └───────────────┘  │
│  ┌───────────────┐  │
│  │ Churn Time    │  │──► WARNING: Context boundary stress indicator
│  │ Monitor       │  │
│  └───────────────┘  │
└─────────────────────┘
```

### Key Differentiator: Passive Leakage Detection

Most AI security tools focus on **input-side** threats (prompt injection, jailbreaks). PromptArmor focuses on the **output-side** — specifically the class of leakage that emerges from cognitive load conditions with no adversarial input required.

This matters because:
- Output monitoring is often absent or minimal in agentic deployments
- Local model substitution (cost reduction strategy) dramatically increases this risk surface
- Churn-based leakage bypasses all input-side defenses by definition

---

## Research Findings

| ID | Severity | Title | OWASP LLM Mapping |
|----|----------|-------|-------------------|
| [001](research/findings/finding-001-system-prompt-leakage.md) | 🟠 High | System Prompt & Identity Leakage via Claude Code Backend Substitution | LLM07:2025 |
| [002](research/findings/finding-002-agent-schema-exposure.md) | 🔴 Critical | Full Agent Schema Exposure via Context Boundary Failure | LLM07:2025, LLM08:2025 |

Full methodology: [research/findings/METHODOLOGY.md](research/findings/METHODOLOGY.md)

---

## Repository Structure

```
PromptArmor/
├── README.md
├── research/
│   └── findings/
│       ├── METHODOLOGY.md                        # Research framework
│       ├── finding-001-system-prompt-leakage.md  # High severity
│       └── finding-002-agent-schema-exposure.md  # Critical severity
├── detectors/
│   ├── schema_leak.py                            # Agent schema leak detector
│   └── identity_leak.py                          # Identity/system prompt detector
└── signatures/
    └── detection_patterns.py                     # Regex pattern library + OWASP mappings
```

---

## Detectors

### Quick Start

```bash
git clone https://github.com/Kali-ai007/PromptArmor
cd PromptArmor
pip install -r requirements.txt

# Scan a captured output stream
python detectors/schema_leak.py --input output_sample.txt

# Run identity leak detector
python detectors/identity_leak.py --input output_sample.txt --verbose

# Use as a library
python -c "
from detectors.schema_leak import SchemaLeakDetector
detector = SchemaLeakDetector()
results = detector.analyze('your agent output here...')
print(results)
"
```

### Schema Leak Detector (`detectors/schema_leak.py`)

Detects exposure of agent orchestration parameters, subagent type definitions, tool grant structures, and background execution flags. Maps findings to OWASP LLM07/LLM08:2025.

### Identity Leak Detector (`detectors/identity_leak.py`)

Detects system prompt fragments, identity constraint language, memory architecture references, and behavioral policy disclosures.

### Detection Signatures (`signatures/detection_patterns.py`)

Curated regex pattern library with severity ratings, confidence scores, and OWASP mappings. Designed for extensibility — add your own signatures without modifying core detector logic.

---

## The Churn Time Hypothesis

One of this research's novel contributions is identifying **extended model churn time** as a leading indicator of context boundary failure.

**Observation**: In controlled testing, schema leakage consistently occurred after ~9–10 minutes of unresolved task churn by the local model backend. This suggests:

1. Context boundary maintenance degrades under sustained cognitive load
2. The degradation timeline is potentially predictable
3. Real-time churn monitoring could serve as an early warning system — alerting before leakage occurs rather than after

This has implications for monitoring system design: churn duration thresholds could trigger preemptive session termination or elevated scrutiny, rather than waiting for confirmed leakage.

---

## OWASP LLM Top 10 2025 Mappings

| OWASP ID | Name | Relevance |
|----------|------|-----------|
| LLM07:2025 | System Prompt Leakage | Direct — both findings involve system prompt/config exposure |
| LLM08:2025 | Vector and Embedding Weaknesses | Agent schema exposure reveals internal orchestration architecture |
| LLM06:2025 | Excessive Agency | Leaked tool grants reveal capability surface to potential attackers |

---

## Research Context

- **Institution**: Illinois Institute of Technology
- **Focus**: Agentic AI security, output-side behavioral monitoring
- **Test Environment**: Claude Code + Mistral 7B (Ollama) backend substitution
- **Status**: Active research — findings being formalized, detector tooling in development

---

## License

MIT License — see [LICENSE](LICENSE) for details.

Research findings may be cited with attribution.
