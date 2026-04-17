"""
PromptArmor Detection Signature Library
========================================
Regex pattern library for detecting system prompt leakage and agent schema
exposure in agentic AI output streams.

Each pattern includes:
  - regex: compiled pattern
  - severity: critical / high / medium / low
  - confidence: float 0.0–1.0 (expected true positive rate)
  - owasp: relevant OWASP LLM Top 10 2025 mapping
  - description: human-readable explanation

Usage:
    from signatures.detection_patterns import IDENTITY_LEAK_PATTERNS, SCHEMA_LEAK_PATTERNS
    from signatures.detection_patterns import match_patterns

    results = match_patterns(output_text)
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Pattern:
    name: str
    regex: re.Pattern
    severity: str          # "critical" | "high" | "medium" | "low"
    confidence: float      # 0.0 – 1.0
    owasp: list[str]       # e.g. ["LLM07:2025"]
    description: str
    family: str            # pattern family grouping


@dataclass
class PatternMatch:
    pattern: Pattern
    matched_text: str
    start: int
    end: int
    context_window: str    # surrounding text for review


# ─────────────────────────────────────────────────────────────────────────────
# IDENTITY LEAK PATTERNS
# Detect system prompt identity framing, policy language, memory architecture
# ─────────────────────────────────────────────────────────────────────────────

IDENTITY_LEAK_PATTERNS: list[Pattern] = [

    Pattern(
        name="IDENTITY_DISCLOSURE_CLAUDE",
        regex=re.compile(
            r"\b(I am Claude|as Claude|Claude, (made|created|built) by Anthropic"
            r"|I'm Claude|my name is Claude)\b",
            re.IGNORECASE
        ),
        severity="high",
        confidence=0.90,
        owasp=["LLM07:2025"],
        description="Direct identity disclosure referencing Claude/Anthropic branding in output.",
        family="IDENTITY_DISCLOSURE"
    ),

    Pattern(
        name="IDENTITY_DISCLOSURE_GENERIC",
        regex=re.compile(
            r"\b(I am an AI (assistant|language model|system)"
            r"|as an AI assistant I (should|must|cannot|will not)"
            r"|my (training|design|purpose) (is|was) to)\b",
            re.IGNORECASE
        ),
        severity="high",
        confidence=0.75,
        owasp=["LLM07:2025"],
        description="Generic AI identity constraint language appearing unexpectedly in output.",
        family="IDENTITY_DISCLOSURE"
    ),

    Pattern(
        name="POLICY_FRAGMENT_REFUSAL",
        regex=re.compile(
            r"\b(I (am|was) (instructed|trained|designed|programmed) (to|not to)"
            r"|I (should|must|cannot|will not|am not able to) (?:do|help with|assist with|provide)"
            r"|my (guidelines|instructions|constraints|policies) (say|state|require|prohibit))\b",
            re.IGNORECASE
        ),
        severity="high",
        confidence=0.80,
        owasp=["LLM07:2025"],
        description="Policy/constraint language from system prompt appearing in task output.",
        family="POLICY_FRAGMENT"
    ),

    Pattern(
        name="POLICY_FRAGMENT_SAFETY",
        regex=re.compile(
            r"\b(safe(ty)? (guidelines|policy|policies|constraints|instructions)"
            r"|content (policy|guidelines|restrictions)"
            r"|harmful (content|outputs?|responses?)"
            r"|I('m| am) not (allowed|permitted|supposed) to)\b",
            re.IGNORECASE
        ),
        severity="high",
        confidence=0.78,
        owasp=["LLM07:2025"],
        description="Safety policy language from system prompt leaking into output.",
        family="POLICY_FRAGMENT"
    ),

    Pattern(
        name="MEMORY_ARCHITECTURE_REFERENCE",
        regex=re.compile(
            r"\b(my (memory|context|conversation history|session)"
            r"|persistent (memory|storage|context)"
            r"|(across|between) (sessions?|conversations?|contexts?)"
            r"|I (don't|do not|cannot) (remember|retain|store) (information |data )?(between|across))\b",
            re.IGNORECASE
        ),
        severity="medium",
        confidence=0.65,
        owasp=["LLM07:2025"],
        description="References to internal memory architecture appearing in output.",
        family="MEMORY_REFERENCE"
    ),

    Pattern(
        name="ANTHROPIC_ARTIFACT_LANGUAGE",
        regex=re.compile(
            r"\b(Anthropic|Constitutional AI|RLHF|harmlessness|helpfulness|honesty"
            r"|my (values|principles|constitution)|aligned (AI|system|assistant))\b",
            re.IGNORECASE
        ),
        severity="high",
        confidence=0.85,
        owasp=["LLM07:2025"],
        description="Anthropic-specific terminology or Constitutional AI language in output.",
        family="ANTHROPIC_ARTIFACT"
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# SCHEMA LEAK PATTERNS
# Detect agent orchestration schema, tool grants, subagent definitions
# ─────────────────────────────────────────────────────────────────────────────

SCHEMA_LEAK_PATTERNS: list[Pattern] = [

    Pattern(
        name="ORCHESTRATION_PARAM_RUN_IN_BACKGROUND",
        regex=re.compile(
            r"\brun_in_background\b",
            re.IGNORECASE
        ),
        severity="critical",
        confidence=0.97,
        owasp=["LLM07:2025", "LLM08:2025"],
        description="Direct exposure of run_in_background orchestration parameter.",
        family="ORCHESTRATION_PARAM"
    ),

    Pattern(
        name="ORCHESTRATION_PARAM_WORKTREE",
        regex=re.compile(
            r"\b(worktree[_\s]isolation|isolated[_\s]worktree"
            r"|worktree[_\s]parameter|run.*worktree)\b",
            re.IGNORECASE
        ),
        severity="critical",
        confidence=0.95,
        owasp=["LLM07:2025", "LLM08:2025"],
        description="Worktree isolation parameter exposure revealing filesystem isolation model.",
        family="ORCHESTRATION_PARAM"
    ),

    Pattern(
        name="INTER_AGENT_SENDMESSAGE",
        regex=re.compile(
            r"\bSendMessage\b|\bsend_message\b",
            re.IGNORECASE
        ),
        severity="critical",
        confidence=0.95,
        owasp=["LLM07:2025", "LLM08:2025"],
        description="SendMessage inter-agent communication primitive exposed in output.",
        family="ORCHESTRATION_PARAM"
    ),

    Pattern(
        name="SUBAGENT_TYPE_DISCLOSURE",
        regex=re.compile(
            r"\b(subagent[_\s]type|agent[_\s]type[_\s]definition"
            r"|subagent[_\s]profile|agent[_\s]capabilities?[_\s]profile"
            r"|type:\s*['\"]?(orchestrator|executor|planner|researcher|coder)['\"]?)\b",
            re.IGNORECASE
        ),
        severity="critical",
        confidence=0.90,
        owasp=["LLM07:2025", "LLM08:2025"],
        description="Subagent type definition or profile disclosure.",
        family="SUBAGENT_DISCLOSURE"
    ),

    Pattern(
        name="TOOL_GRANT_DISCLOSURE",
        regex=re.compile(
            r"\b(tool[_\s]grants?|granted[_\s]tools?"
            r"|allowed[_\s]tools?|permitted[_\s]tools?"
            r"|tool[_\s]access[_\s]list|tools?:\s*\[)",
            re.IGNORECASE
        ),
        severity="critical",
        confidence=0.88,
        owasp=["LLM07:2025", "LLM08:2025"],
        description="Tool grant structure or access list exposed in output.",
        family="TOOL_GRANT_FRAGMENT"
    ),

    Pattern(
        name="STRUCTURED_DATA_IN_NATURAL_LANGUAGE",
        regex=re.compile(
            r'(\{\s*"[a-z_]+"\s*:\s*(?:"[^"]*"|\[|\{|true|false|null|\d+))'
            r'|(\b[a-z_]{3,}\s*:\s*(?:true|false|null|\d+\s*[,\}])")',
            re.IGNORECASE
        ),
        severity="medium",
        confidence=0.55,
        owasp=["LLM07:2025"],
        description=(
            "Unexpected structured data (JSON-like) in natural language output. "
            "Lower confidence — requires human review to confirm schema leakage vs. intentional output."
        ),
        family="STRUCTURED_LEAK"
    ),

    Pattern(
        name="AGENT_ORCHESTRATION_LANGUAGE",
        regex=re.compile(
            r"\b(orchestrat(e|or|ion)|spawn(ing)?[_\s]agent"
            r"|delegate[_\s]to[_\s](sub)?agent|agent[_\s]handoff"
            r"|task[_\s]decomposition[_\s]schema)\b",
            re.IGNORECASE
        ),
        severity="high",
        confidence=0.72,
        owasp=["LLM08:2025"],
        description="Agent orchestration architectural language appearing in output.",
        family="SUBAGENT_DISCLOSURE"
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# CHURN TIME THRESHOLDS
# Timing-based risk thresholds for session monitoring
# ─────────────────────────────────────────────────────────────────────────────

CHURN_TIME_THRESHOLDS = {
    "warning":  300,    # 5 minutes  — elevated monitoring, check outputs closely
    "elevated": 480,    # 8 minutes  — pre-leakage zone based on observed data
    "critical":  600,   # 10 minutes — observed schema leakage threshold
}


# ─────────────────────────────────────────────────────────────────────────────
# COMBINED PATTERN REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

ALL_PATTERNS: list[Pattern] = IDENTITY_LEAK_PATTERNS + SCHEMA_LEAK_PATTERNS


# ─────────────────────────────────────────────────────────────────────────────
# MATCH UTILITY
# ─────────────────────────────────────────────────────────────────────────────

def match_patterns(
    text: str,
    patterns: Optional[list[Pattern]] = None,
    context_chars: int = 120,
) -> list[PatternMatch]:
    """
    Apply patterns against a text and return all matches with context windows.

    Args:
        text: The agent output text to scan.
        patterns: List of Pattern objects to apply. Defaults to ALL_PATTERNS.
        context_chars: Number of characters of surrounding context to capture.

    Returns:
        List of PatternMatch objects, sorted by position in text.
    """
    if patterns is None:
        patterns = ALL_PATTERNS

    matches: list[PatternMatch] = []

    for pattern in patterns:
        for m in pattern.regex.finditer(text):
            start = m.start()
            end = m.end()
            ctx_start = max(0, start - context_chars)
            ctx_end = min(len(text), end + context_chars)
            context = text[ctx_start:ctx_end]

            matches.append(PatternMatch(
                pattern=pattern,
                matched_text=m.group(0),
                start=start,
                end=end,
                context_window=context,
            ))

    matches.sort(key=lambda x: x.start)
    return matches


def summarize_matches(matches: list[PatternMatch]) -> dict:
    """Return a structured summary of match results."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    families_hit = set()
    owasp_hit = set()

    for m in matches:
        severity_counts[m.pattern.severity] += 1
        families_hit.add(m.pattern.family)
        owasp_hit.update(m.pattern.owasp)

    overall = "clean"
    if severity_counts["critical"] > 0:
        overall = "critical"
    elif severity_counts["high"] > 0:
        overall = "high"
    elif severity_counts["medium"] > 0:
        overall = "medium"
    elif severity_counts["low"] > 0:
        overall = "low"

    return {
        "overall_severity": overall,
        "total_matches": len(matches),
        "severity_breakdown": severity_counts,
        "families_triggered": sorted(families_hit),
        "owasp_mappings": sorted(owasp_hit),
    }
