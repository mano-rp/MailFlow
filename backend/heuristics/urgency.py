"""
Step 1: Urgency & Coercion Detection Module
Identifies psychological pressure, artificial deadlines, and fear-inducing triggers.
"""

import re
from typing import List, Tuple
from .base import StepResult

# Compiled patterns with individual risk weights
URGENCY_PATTERNS: List[Tuple[re.Pattern, int, str]] = [
    (re.compile(r"\b(urgent|urgently|immediate action required|action required immediately)\b", re.I), 35, "High Urgency Call-to-Action"),
    (re.compile(r"\b(within\s+(?:24|12|48|2|1)\s*(?:hours?|hrs?)|expires\s+today|deadline\s+approaching)\b", re.I), 30, "Time-Pressure Artificial Deadline"),
    (re.compile(r"\b(account\s+(?:suspended|locked|disabled|terminated|closed)|access\s+revoked)\b", re.I), 35, "Account Suspension Threat"),
    (re.compile(r"\b(final\s+notice|last\s+chance|immediate\s+response\s+required|warning\s+notice)\b", re.I), 25, "Coercive Final Notice Warning"),
    (re.compile(r"\b(hurry\s+up|offer\s+expires|limited\s+time\s+remaining|act\s+now)\b", re.I), 20, "Hurry / Pressure Trigger"),
    (re.compile(r"\b(failure\s+to\s+comply|legal\s+action|lawsuit|penalty\s+applied)\b", re.I), 30, "Legal / Compliance Intimidation"),
]


def evaluate_urgency(subject: str, snippet: str, sender: str = "") -> StepResult:
    """
    Evaluates urgency and psychological coercion indicators across subject and preview snippet.
    """
    text = f"{subject} {snippet}".strip()
    if not text:
        return StepResult(step_name="Urgency & Coercion Check", score=0.0, matched_rules=[])

    matched_rules: List[str] = []
    total_score = 0

    for pattern, weight, rule_desc in URGENCY_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            matched_rules.append(f"{rule_desc} (matched: '{matches[0]}')")
            total_score += weight

    clamped_score = min(float(total_score), 100.0)
    description = (
        f"Detected {len(matched_rules)} urgency coercion signals."
        if matched_rules
        else "No urgency or time-pressure coercion patterns detected."
    )

    return StepResult(
        step_name="Urgency & Coercion Check",
        score=clamped_score,
        weight=1.1,
        matched_rules=matched_rules,
        description=description,
    )
