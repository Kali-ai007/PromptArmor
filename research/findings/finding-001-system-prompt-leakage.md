# Finding #001: System Prompt & Identity Leakage via Claude Code Backend Substitution

**Severity**: 🟠 High  
**Status**: Confirmed  
**OWASP LLM Top 10 2025**: LLM07:2025 — System Prompt Leakage  
**Date Observed**: 2026  
**Researcher**: Kali-ai007

---

## Summary

When Mistral 7B (via Ollama) is substituted as the backend for Claude Code under sustained cognitive load conditions, the local model involuntarily emits fragments of Claude Code's internal system prompt — including identity framing, security policy language, memory architecture references, and behavioral constraints. No adversarial prompting was required to trigger this leakage.

---

## Affected Component

- **Agent Framework**: Claude Code
- **Backend**: Mistral 7B (Ollama, local inference)
- **Trigger**: Complex multi-step task induction → extended churn → context boundary failure

---

## Technical Description

### Leakage Mechanism

Claude Code operates with a structured internal system prompt that establishes its identity, security posture, memory model, and behavioral constraints. When Mistral 7B is substituted as the backend, the local model receives this system prompt as part of its context. Under normal conditions, the model maintains context boundaries and does not reproduce system prompt content in its output.

Under sustained cognitive load — specifically, when assigned a complex task the model cannot resolve over an extended period (~9–10 minutes of observed churn) — context boundary maintenance degrades. The model begins to "reach" into its context window for structure, inadvertently reproducing system prompt fragments in its output stream.

### Leaked Content Categories

| Category | Description | Example Pattern |
|----------|-------------|-----------------|
| Identity framing | Model's self-description as an AI assistant | References to "Claude", "Anthropic", "I am" identity language |
| Security policy | Stated operational constraints | "I should not", "I am not able to", policy refusal language |
| Memory architecture | Internal memory model references | References to session context, persistent vs. ephemeral memory |
| Behavioral constraints | Hardcoded behavioral limits | Refusal categories, escalation conditions |

---

## Detection Signatures

See `signatures/detection_patterns.py` → `IDENTITY_LEAK_PATTERNS` for the full regex pattern library.

Key signature families:
- `IDENTITY_DISCLOSURE`: Patterns matching first-person identity assertion language
- `POLICY_FRAGMENT`: Patterns matching constraint/refusal policy language
- `MEMORY_REFERENCE`: Patterns matching memory architecture terminology
- `ANTHROPIC_ARTIFACT`: Patterns matching Anthropic-specific terminology and framing

---

## Impact Assessment

### Confidentiality Impact: High
System prompt content represents proprietary configuration that organizations and tool developers reasonably expect to remain internal. Exposure reveals the agent's operational design to any observer of the output stream.

### Integrity Impact: Medium
Knowledge of behavioral constraints enables targeted circumvention attempts in future sessions.

### Availability Impact: Low
Leakage events do not directly impair agent availability but indicate context boundary failure that may degrade task performance.

---

## Mitigation Recommendations

1. **Output stream filtering**: Deploy regex-based filters on agent output before forwarding to end users or logging systems
2. **Churn time monitoring**: Implement session-level timers that trigger review or termination after extended unresolved task churn (recommended threshold: 5–7 minutes)
3. **Backend validation**: Verify that local model substitutes have been evaluated for context boundary stability under load before production deployment
4. **System prompt segmentation**: Where possible, avoid placing highly sensitive constraint language in the primary system prompt context provided to local models

---

## OWASP LLM07:2025 Mapping

This finding directly maps to **LLM07:2025 (System Prompt Leakage)**:

> *"System prompt leakage occurs when an LLM reveals confidential instructions, business logic, or sensitive configurations embedded in its system prompt."*

The novel aspect of this finding relative to the standard LLM07 description is the **passive trigger mechanism** — leakage occurs without adversarial extraction attempts, driven purely by cognitive load conditions.

---

## References

- [OWASP LLM Top 10 2025 - LLM07](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [PromptArmor Methodology](METHODOLOGY.md)
- [Finding #002 - Agent Schema Exposure](finding-002-agent-schema-exposure.md)
