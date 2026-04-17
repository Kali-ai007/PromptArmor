#!/usr/bin/env python3
"""
PromptArmor — Identity Leak Detector
======================================
Detects system prompt identity and policy leakage in agentic AI output streams:
  - Model identity assertions (Claude, Anthropic branding)
  - Security policy and constraint language
  - Memory architecture references
  - Constitutional AI / Anthropic-specific terminology
  - Behavioral constraint disclosures

Maps findings to OWASP LLM07:2025.

Usage:
    # CLI
    python detectors/identity_leak.py --input output.txt
    python detectors/identity_leak.py --input output.txt --verbose
    python detectors/identity_leak.py --input output.txt --json

    # Library
    from detectors.identity_leak import IdentityLeakDetector
    detector = IdentityLeakDetector()
    result = detector.analyze(text)
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from signatures.detection_patterns import (
    IDENTITY_LEAK_PATTERNS,
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
class IdentityLeakResult:
    """Result of an identity/system-prompt leak analysis run."""
    scanned_chars: int
    overall_severity: str
    total_matches: int
    severity_breakdown: dict
    families_triggered: list[str]
    owasp_mappings: list[str]
    churn_risk_level: Optional[str]
    churn_seconds: Optional[float]
    high_confidence_matches: int   # matches with confidence >= 0.80
    matches: list[dict]
    scan_duration_ms: float


# ─────────────────────────────────────────────────────────────────────────────
# Detector
# ─────────────────────────────────────────────────────────────────────────────

class IdentityLeakDetector:
    """
    Detects system prompt identity and policy leakage in agentic AI output streams.

    Identity leakage occurs when a local model backend emits fragments of the
    commercial agent's identity framing, security policies, or behavioral
    constraints under cognitive load conditions — without any adversarial prompting.

    This is the earliest-stage leakage type in the observed progression:
        Identity/policy fragments → Full agent schema exposure (see SchemaLeakDetector)

    Monitoring for identity leakage provides earlier warning than schema leak
    detection alone.
    """

    def __init__(
        self,
        custom_patterns: Optional[list[Pattern]] = None,
        confidence_threshold: float = 0.0,
    ):
        """
        Args:
            custom_patterns: Additional patterns alongside defaults.
            confidence_threshold: Minimum confidence score to include a match (0.0–1.0).
                                  Use 0.75+ for low-noise production monitoring.
        """
        self.patterns = IDENTITY_LEAK_PATTERNS[:]
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        self.confidence_threshold = confidence_threshold

    def analyze(
        self,
        text: str,
        churn_seconds: Optional[float] = None,
    ) -> IdentityLeakResult:
        """
        Analyze agent output for identity and system prompt leakage.

        Args:
            text: The agent output text to scan.
            churn_seconds: Optional elapsed session churn time in seconds.

        Returns:
            IdentityLeakResult with full match details.
        """
        t0 = time.perf_counter()

        all_matches = match_patterns(text, self.patterns)

        # Apply confidence threshold filter
        matches = [
            m for m in all_matches
            if m.pattern.confidence >= self.confidence_threshold
        ]

        summary = summarize_matches(matches)
        high_conf = sum(1 for m in matches if m.pattern.confidence >= 0.80)

        # Churn risk
        churn_risk = None
        if churn_seconds is not None:
            if churn_seconds >= CHURN_TIME_THRESHOLDS["critical"]:
                churn_risk = "critical"
            elif churn_seconds >= CHURN_TIME_THRESHOLDS["elevated"]:
                churn_risk = "elevated"
            elif churn_seconds >= CHURN_TIME_THRESHOLDS["warning"]:
                churn_risk = "warning"

        effective_severity = summary["overall_severity"]
        if churn_risk == "elevated" and effective_severity == "clean":
            effective_severity = "low"  # churn alone is a weak signal for identity leak
        elif churn_risk == "critical" and effective_severity == "clean":
            effective_severity = "medium"

        elapsed_ms = (time.perf_counter() - t0) * 1000

        serialized = []
        for m in matches:
            serialized.append({
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

        return IdentityLeakResult(
            scanned_chars=len(text),
            overall_severity=effective_severity,
            total_matches=len(matches),
            severity_breakdown=summary["severity_breakdown"],
            families_triggered=summary["families_triggered"],
            owasp_mappings=summary["owasp_mappings"],
            churn_risk_level=churn_risk,
            churn_seconds=churn_seconds,
            high_confidence_matches=high_conf,
            matches=serialized,
            scan_duration_ms=round(elapsed_ms, 2),
        )

    def analyze_file(
        self,
        path: str | Path,
        churn_seconds: Optional[float] = None,
    ) -> IdentityLeakResult:
        """Convenience wrapper: read a file and analyze its contents."""
        text = Path(path).read_text(encoding="utf-8")
        return self.analyze(text, churn_seconds=churn_seconds)

    def analyze_stream(
        self,
        chunks: list[str],
        churn_seconds: Optional[float] = None,
    ) -> IdentityLeakResult:
        """
        Analyze a streaming output by joining chunks and scanning the full buffer.

        Suitable for real-time monitoring: accumulate chunks, call periodically.

        Args:
            chunks: List of output text chunks (e.g., from a streaming API).
            churn_seconds: Current elapsed churn time.
        """
        return self.analyze("\n".join(chunks), churn_seconds=churn_seconds)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "clean":    "\033[92m",
    "low":      "\033[96m",
    "medium":   "\033[93m",
    "high":     "\033[91m",
    "critical": "\033[95m",
}
RESET = "\033[0m"


def _color(severity: str, text: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"


def print_human_report(result: IdentityLeakResult, verbose: bool = False) -> None:
    print("\n" + "═" * 60)
    print("  PromptArmor — Identity Leak Detector")
    print("═" * 60)

    sev_label = _color(result.overall_severity, result.overall_severity.upper())
    print(f"\n  Result:              {sev_label}")
    print(f"  Scanned:             {result.scanned_chars:,} characters")
    print(f"  Total matches:       {result.total_matches}")
    print(f"  High-conf matches:   {result.high_confidence_matches}")
    print(f"  Scan time:           {result.scan_duration_ms:.1f} ms")

    if result.churn_seconds is not None:
        churn_label = result.churn_risk_level or "none"
        print(f"  Churn time:          {result.churn_seconds:.0f}s  "
              f"[{_color(churn_label, churn_label.upper())}]")

    if result.total_matches > 0:
        print(f"\n  Severity breakdown:")
        for sev, count in result.severity_breakdown.items():
            if count > 0:
                print(f"    {_color(sev, sev.upper()):<20} {count}")

        print(f"\n  Families triggered:  {', '.join(result.families_triggered)}")
        print(f"  OWASP mappings:      {', '.join(result.owasp_mappings)}")

    if verbose and result.matches:
        print("\n  ── Match Details ──────────────────────────────────────")
        for i, m in enumerate(result.matches, 1):
            print(f"\n  [{i}] {_color(m['severity'], m['pattern_name'])}")
            print(f"      Severity:    {m['severity']}  (confidence: {m['confidence']:.0%})")
            print(f"      Family:      {m['family']}")
            print(f"      OWASP:       {', '.join(m['owasp'])}")
            print(f"      Matched:     \"{m['matched_text']}\"")
            print(f"      Position:    chars {m['position']['start']}–{m['position']['end']}")
            print(f"      Context:     ...{m['context'][:100]}...")

    print("\n" + "═" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="PromptArmor Identity Leak Detector — scan agent output for system prompt leakage"
    )
    parser.add_argument("--input", "-i", required=True, help="Path to agent output file")
    parser.add_argument("--churn", "-c", type=float, default=None,
                        help="Session churn time in seconds (optional)")
    parser.add_argument("--confidence", type=float, default=0.0,
                        help="Minimum confidence threshold (0.0–1.0). Default: 0.0")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed match information")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--exit-code", action="store_true",
                        help="Exit with code 1 if any matches found (for CI/CD use)")
    args = parser.parse_args()

    detector = IdentityLeakDetector(confidence_threshold=args.confidence)
    result = detector.analyze_file(args.input, churn_seconds=args.churn)

    if args.json:
        print(json.dumps(asdict(result), indent=2))
    else:
        print_human_report(result, verbose=args.verbose)

    if args.exit_code and result.total_matches > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
