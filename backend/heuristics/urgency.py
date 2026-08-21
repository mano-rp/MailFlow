"""
Step 1: Urgency & Coercion Detection Module
Identifies psychological pressure, artificial deadlines, service loss threats, and fear-inducing triggers.
"""

import re
from typing import List, Tuple
from .base import StepResult

URGENCY_PATTERNS: List[Tuple[re.Pattern, int, str]] = [
    # Explicit Urgency & Deadlines
    (re.compile(r"\b(urgent|urgently|immediate action required|action required immediately|urgent\s+task|action\s+required:?)\b", re.I), 25, "High Urgency Call-to-Action"),
    (re.compile(r"\b(within\s+(?:24|12|48|2|1)\s*(?:hours?|hrs?)|expires\s+today|deadline\s+approaching|time\s+sensitive|act\s+today)\b", re.I), 20, "Time-Pressure Artificial Deadline"),
    
    # Intimidation & Service Termination Threats
    (re.compile(r"\b(account\s+(?:suspended|locked|disabled|terminated|closed)|access\s+revoked)\b", re.I), 30, "Account Suspension Threat"),
    (re.compile(r"\b(failure\s+to\s+(?:act|verify|update|comply)|permanently\s+(?:rejected|deleted|disabled|lost)|messages?\s+will\s+be\s+(?:permanently\s+)?(?:deleted|rejected|lost)|verify\s+to\s+avoid\s+loss)\b", re.I), 30, "Permanent Loss / Deletion Intimidation"),
    (re.compile(r"\b(final\s+notice|last\s+chance|immediate\s+response\s+required|warning\s+notice)\b", re.I), 20, "Coercive Final Notice Warning"),
    (re.compile(r"\b(failure\s+to\s+comply|legal\s+action|lawsuit|penalty\s+applied|compliance\s+audit)\b", re.I), 25, "Legal / Compliance Intimidation"),

    # Executive Impersonation / Secrecy & Isolation Pretext
    (re.compile(r"\b(strictly\s+confidential|do\s+not\s+discuss\s+(?:this\s+)?with\s+anyone|keep\s+this\s+between\s+us|handle\s+this\s+discreetly)\b", re.I), 25, "Secrecy & Isolation Pretext"),
    (re.compile(r"\b(are\s+you\s+at\s+your\s+desk|need\s+a\s+quick\s+favor|in\s+a\s+meeting\s+(?:right\s+now|cannot\s+talk)|don'?t\s+call\s+me|available\s+for\s+a\s+quick\s+task)\b", re.I), 25, "Executive Impersonation / Availability Bait"),
]


def evaluate_urgency(subject: str, snippet: str, sender: str = "") -> StepResult:
    """
    Evaluates urgency, psychological coercion, and service loss threats.
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

    clamped_score = min(float(total_score), 65.0)
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
