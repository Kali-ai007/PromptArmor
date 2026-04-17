#!/usr/bin/env python3
"""
PromptArmor — Schema Leak Detector
====================================
Detects agent schema exposure in agentic AI output streams:
  - Subagent type definitions
  - Tool grant structures
  - Orchestration parameters (run_in_background, worktree, SendMessage)
  - Background execution flags

Maps findings to OWASP LLM07:2025 and LLM08:2025.

Usage:
    # CLI
    python detectors/schema_leak.py --input output.txt
    python detectors/schema_leak.py --input output.txt --verbose
    python detectors/schema_leak.py --input output.txt --json

    # Library
    from detectors.schema_leak import SchemaLeakDetector
    detector = SchemaLeakDetector()
    result = detector.analyze(text)
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

# Allow running from repo root or detectors/ directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from signatures.detection_patterns import (
    SCHEMA_LEAK_PATTERNS,
    CHURN_TIME_THRESHOLDS,
    Pattern,
    PatternMatch,
    match_patterns,
    summarize_matches,
)


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SchemaLeakResult:
    """Result of a schema leak analysis run."""
    scanned_chars: int
    overall_severity: str          # "clean" | "low" | "medium" | "high" | "critical"
    total_matches: int
    severity_breakdown: dict
    families_triggered: list[str]
    owasp_mappings: list[str]
    churn_risk_level: Optional[str]    # None | "warning" | "elevated" | "critical"
    churn_seconds: Optional[float]
    matches: list[dict]            # serialized PatternMatch list
    scan_duration_ms: float


# ─────────────────────────────────────────────────────────────────────────────
# Detector
# ─────────────────────────────────────────────────────────────────────────────

class SchemaLeakDetector:
    """
    Detects agent schema leakage in agentic AI output streams.

    Schema leakage occurs when a local model backend (e.g., Mistral 7B via Ollama)
    substituted for a commercial agent (e.g., Claude Code) emits internal
    orchestration schema under cognitive load conditions.

    This detector applies the SCHEMA_LEAK_PATTERNS signature library and
    optionally incorporates churn-time-based risk scoring.
    """

    def __init__(self, custom_patterns: Optional[list[Pattern]] = None):
        """
        Args:
            custom_patterns: Additional patterns to include alongside defaults.
                             If None, uses SCHEMA_LEAK_PATTERNS only.
        """
        self.patterns = SCHEMA_LEAK_PATTERNS[:]
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def analyze(
        self,
        text: str,
        churn_seconds: Optional[float] = None,
    ) -> SchemaLeakResult:
        """
        Analyze an agent output string for schema leakage.

        Args:
            text: The agent output text to scan.
            churn_seconds: Optional elapsed session churn time in seconds.
                           If provided, adds churn-based risk scoring.

        Returns:
            SchemaLeakResult with match details and severity assessment.
        """
        t0 = time.perf_counter()

        matches: list[PatternMatch] = match_patterns(text, self.patterns)
        summary = summarize_matches(matches)

        # Churn time risk assessment
        churn_risk = None
        if churn_seconds is not None:
            if churn_seconds >= CHURN_TIME_THRESHOLDS["critical"]:
                churn_risk = "critical"
            elif churn_seconds >= CHURN_TIME_THRESHOLDS["elevated"]:
                churn_risk = "elevated"
            elif churn_seconds >= CHURN_TIME_THRESHOLDS["warning"]:
                churn_risk = "warning"

        # Elevate severity if churn is in critical zone and no matches yet
        # (churn is a leading indicator — alert before confirmed leakage)
        effective_severity = summary["overall_severity"]
        if churn_risk == "critical" and effective_severity == "clean":
            effective_severity = "medium"  # pre-leakage warning

        elapsed_ms = (time.perf_counter() - t0) * 1000

        serialized_matches = []
        for m in matches:
            serialized_matches.append({
                "pattern_name": m.pattern.name,
                "severity": m.pattern.severity,
                "confidence": m.pattern.confidence,
                "family": m.pattern.family,
                "owasp": m.pattern.owasp,
                "matched_text": m.matched_text,
                "position": {"start": m.start, "end": m.end},
                "context": m.context_window,
                "description": m.pattern.description,
            })

        return SchemaLeakResult(
            scanned_chars=len(text),
            overall_severity=effective_severity,
            total_matches=summary["total_matches"],
            severity_breakdown=summary["severity_breakdown"],
            families_triggered=summary["families_triggered"],
            owasp_mappings=summary["owasp_mappings"],
            churn_risk_level=churn_risk,
            churn_seconds=churn_seconds,
            matches=serialized_matches,
            scan_duration_ms=round(elapsed_ms, 2),
        )

    def analyze_file(
        self,
        path: str | Path,
        churn_seconds: Optional[float] = None,
    ) -> SchemaLeakResult:
        """Convenience wrapper: read a file and analyze its contents."""
        text = Path(path).read_text(encoding="utf-8")
        return self.analyze(text, churn_seconds=churn_seconds)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "clean":    "\033[92m",   # green
    "low":      "\033[96m",   # cyan
    "medium":   "\033[93m",   # yellow
    "high":     "\033[91m",   # red
    "critical": "\033[95m",   # magenta
}
RESET = "\033[0m"


def _color(severity: str, text: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"


def print_human_report(result: SchemaLeakResult, verbose: bool = False) -> None:
    """Print a human-readable terminal report."""

    print("\n" + "═" * 60)
    print("  PromptArmor — Schema Leak Detector")
    print("═" * 60)

    sev_label = _color(result.overall_severity, result.overall_severity.upper())
    print(f"\n  Result:          {sev_label}")
    print(f"  Scanned:         {result.scanned_chars:,} characters")
    print(f"  Matches found:   {result.total_matches}")
    print(f"  Scan time:       {result.scan_duration_ms:.1f} ms")

    if result.churn_seconds is not None:
        churn_label = result.churn_risk_level or "none"
        print(f"  Churn time:      {result.churn_seconds:.0f}s  [{_color(churn_label, churn_label.upper())}]")

    if result.total_matches > 0:
        print(f"\n  Severity breakdown:")
        for sev, count in result.severity_breakdown.items():
            if count > 0:
                print(f"    {_color(sev, sev.upper()):<20} {count}")

        print(f"\n  Families triggered: {', '.join(result.families_triggered)}")
        print(f"  OWASP mappings:     {', '.join(result.owasp_mappings)}")

    if verbose and result.matches:
        print("\n  ── Match Details ──────────────────────────────────────")
        for i, m in enumerate(result.matches, 1):
            print(f"\n  [{i}] {_color(m['severity'], m['pattern_name'])}")
            print(f"      Severity:   {m['severity']}  (confidence: {m['confidence']:.0%})")
            print(f"      Family:     {m['family']}")
            print(f"      OWASP:      {', '.join(m['owasp'])}")
            print(f"      Matched:    \"{m['matched_text']}\"")
            print(f"      Position:   chars {m['position']['start']}–{m['position']['end']}")
            print(f"      Context:    ...{m['context'][:100]}...")

    print("\n" + "═" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="PromptArmor Schema Leak Detector — scan agent output for schema exposure"
    )
    parser.add_argument("--input", "-i", required=True, help="Path to agent output file")
    parser.add_argument("--churn", "-c", type=float, default=None,
                        help="Session churn time in seconds (optional, for risk scoring)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed match information")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--exit-code", action="store_true",
                        help="Exit with code 1 if any matches found (for CI/CD use)")
    args = parser.parse_args()

    detector = SchemaLeakDetector()
    result = detector.analyze_file(args.input, churn_seconds=args.churn)

    if args.json:
        print(json.dumps(asdict(result), indent=2))
    else:
        print_human_report(result, verbose=args.verbose)

    if args.exit_code and result.total_matches > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
