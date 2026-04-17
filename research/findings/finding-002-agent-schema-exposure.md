# Finding #002: Full Agent Schema Exposure via Context Boundary Failure

**Severity**: 🔴 Critical  
**Status**: Confirmed  
**OWASP LLM Top 10 2025**: LLM07:2025, LLM08:2025  
**Date Observed**: 2026  
**Researcher**: Kali-ai007

---

## Summary

Under cognitive load conditions triggering context boundary failure, Mistral 7B (substituted as a Claude Code backend) exposed the full internal agent orchestration schema — including subagent type definitions, tool grants, background execution flags, worktree isolation parameters, and inter-agent communication primitives (`SendMessage`). This finding is rated Critical because the exposed information is sufficient to reconstruct Claude Code's internal agent architecture.

---

## Affected Component

- **Agent Framework**: Claude Code
- **Backend**: Mistral 7B (Ollama, local inference)
- **Trigger**: Escalation of cognitive load beyond identity/policy leakage threshold → full schema emission

---

## Technical Description

### Leakage Mechanism

Building on the context boundary failure described in Finding #001, at greater cognitive load (or further into extended churn), the local model's context boundary degradation progresses past surface-level identity fragments into deeper structural content — the agent orchestration schema that Claude Code uses to coordinate subagents and manage tool access.

This schema is not a natural-language system prompt artifact; it is structured configuration data that the local model has ingested as part of its operational context. Its emission represents a qualitatively more severe failure than identity leakage.

### Leaked Schema Components

| Component | Description | Security Implication |
|-----------|-------------|----------------------|
| Subagent type definitions | Named subagent categories with capability profiles | Reveals the agent's internal delegation architecture |
| Tool grants | Per-subagent tool access lists | Enumerates available tool surface; enables targeted capability probing |
| `run_in_background` flag | Background execution parameter | Reveals async execution capability and its conditions |
| `worktree` isolation | Workspace isolation parameter | Reveals filesystem isolation model and potential bypass surface |
| `SendMessage` primitive | Inter-agent communication method | Reveals agent communication topology |

### Observed Output Pattern

Schema leakage manifests as structured fragments in the output stream that do not match expected task output. Key markers:
- JSON-like or YAML-like structured data appearing in natural language output
- Parameter names using `snake_case` or `camelCase` inconsistent with the model's normal output style
- Explicit capability or permission language ("can", "allowed to", "has access to") applied to subagent names

---

## Detection Signatures

See `signatures/detection_patterns.py` → `SCHEMA_LEAK_PATTERNS` for the full regex pattern library.

Key signature families:
- `SUBAGENT_DISCLOSURE`: Patterns matching subagent type naming conventions
- `TOOL_GRANT_FRAGMENT`: Patterns matching tool permission/grant language
- `ORCHESTRATION_PARAM`: Patterns matching known orchestration parameter names
- `STRUCTURED_LEAK`: Patterns detecting structured data in unexpected output contexts

---

## Impact Assessment

### Confidentiality Impact: Critical
The agent schema represents the core internal architecture of the agentic system. Its exposure is equivalent to leaking an internal API specification or system design document — it enables informed reverse-engineering of the system's operational model.

### Integrity Impact: High
Knowledge of tool grants and subagent capabilities enables attackers to craft inputs specifically targeting high-privilege subagents or tool paths that would not have been discoverable through external probing.

### Availability Impact: Medium
Schema leakage indicates severe context boundary failure that correlates with significant task performance degradation and potential session instability.

---

## CVSS-Adjacent Score

| Metric | Value |
|--------|-------|
| Attack Vector | Local (agentic session) |
| Attack Complexity | Low (passive observation sufficient) |
| Privileges Required | None |
| User Interaction | None |
| Scope | Changed (reveals internal architecture) |
| Confidentiality | High |
| Integrity | High |
| Availability | Medium |
| **Estimated Score** | **~8.6 (High → Critical boundary)** |

---

## Mitigation Recommendations

1. **Pre-production load testing**: Any local model intended as an agent backend must be stress-tested for context boundary stability under representative task loads before deployment
2. **Schema isolation**: Agent orchestration schema should be separated from primary model context where architecturally possible — or encoded in a format less prone to verbatim reproduction
3. **Output anomaly detection**: Deploy structured-data detectors on agent output streams; unexpected JSON/YAML fragments in natural language output are high-confidence leakage indicators
4. **Session termination policy**: Define hard limits on session churn time; treat extended unresolved churn as a security event, not just a performance event
5. **Local model risk scoring**: Evaluate local model substitutes against a risk matrix that includes context boundary stability, not just task performance metrics

---

## Relationship to Finding #001

Finding #002 represents a **severity escalation** of the same underlying vulnerability — context boundary failure under cognitive load. The progression is:

```
Normal operation
    → Extended churn begins (Finding #001 risk zone)
        → Identity/policy fragments appear (Finding #001)
            → Continued churn escalation
                → Full schema emission (Finding #002)
```

This suggests a **temporal attack surface**: the longer a session remains in unresolved churn, the more severe the potential leakage. Churn time monitoring therefore provides a leading indicator for both findings simultaneously.

---

## OWASP Mappings

### LLM07:2025 — System Prompt Leakage
Schema configuration is embedded in the operational context alongside the system prompt; its leakage is an extension of the same failure mode.

### LLM08:2025 — Vector and Embedding Weaknesses
The agent schema defines how the system's capability vectors are organized and delegated. Its exposure reveals the internal topology of the system's operational capability space.

---

## References

- [OWASP LLM Top 10 2025 - LLM07](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP LLM Top 10 2025 - LLM08](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [PromptArmor Methodology](METHODOLOGY.md)
- [Finding #001 - System Prompt Leakage](finding-001-system-prompt-leakage.md)
