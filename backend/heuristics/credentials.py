"""
Step 3: Credential Harvesting & Auth Manipulation Module
Detects password harvesting lures, fake 2FA, session expiry traps, and malicious signature links.
"""

import re
from typing import List, Tuple
from .base import StepResult

CREDENTIAL_PATTERNS: List[Tuple[re.Pattern, int, str]] = [
    (re.compile(r"\b(password\s+(?:reset|expiry|expired|change\s+request)|reset\s+your\s+password)\b", re.I), 35, "Password Reset / Expiry Lure"),
    (re.compile(r"\b(verify\s+(?:your\s+)?(?:account|credentials|identity|email)|re-?authenticate|validate\s+account)\b", re.I), 40, "Account Credential Verification"),
    (re.compile(r"\b(unusual\s+(?:activity|sign-?in|login|access)|suspicious\s+login\s+attempt|unauthorized\s+access)\b", re.I), 30, "Fake Security Alert / Breach Lure"),
    (re.compile(r"\b(2fa\s+(?:code|verification|disabled|required)|mfa\s+prompt|one-time\s+passcode|otp\s+code)\b", re.I), 35, "Two-Factor / MFA Hijacking Lure"),
    (re.compile(r"\b(docusign\s+(?:sign|document|view)|adobe\s+sign|review\s+shared\s+document|secure\s+portal)\b", re.I), 25, "Document Signature Phishing"),
    (re.compile(r"\b(click\s+here\s+to\s+(?:login|sign\s+in|confirm|update)|log\s*in\s+to\s+keep\s+access)\b", re.I), 30, "Deceptive Auth Redirect Call"),
]


def evaluate_credentials(subject: str, snippet: str, sender: str = "") -> StepResult:
    """
    Evaluates credential harvesting and authentication manipulation signals.
    """
    text = f"{subject} {snippet}".strip()
    if not text:
        return StepResult(step_name="Credential Harvesting Check", score=0.0, matched_rules=[])

    matched_rules: List[str] = []
    total_score = 0

    for pattern, weight, rule_desc in CREDENTIAL_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            matched_rules.append(f"{rule_desc} (matched: '{matches[0]}')")
            total_score += weight

    clamped_score = min(float(total_score), 100.0)
    description = (
        f"Detected {len(matched_rules)} credential harvesting patterns."
        if matched_rules
        else "No credential harvesting or auth manipulation patterns detected."
    )

    return StepResult(
        step_name="Credential Harvesting Check",
        score=clamped_score,
        weight=1.2,
        matched_rules=matched_rules,
        description=description,
    )
