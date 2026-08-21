"""
Step 3: Credential Harvesting & Auth Manipulation Module
Detects password harvesting lures, fake 2FA, session expiry traps, quishing, and malicious signature links.
"""

import re
from typing import List, Tuple
from .base import StepResult

CREDENTIAL_PATTERNS: List[Tuple[re.Pattern, int, str]] = [
    # Password & Account Hijacking
    (re.compile(r"\b(password\s+(?:reset|expiry|expired|change\s+request|will\s+expire)|reset\s+your\s+password|update\s+your\s+password)\b", re.I), 30, "Password Reset / Expiry Lure"),
    (re.compile(r"\b(verify\s+(?:your\s+)?(?:account|credentials|identity|email|details)|re-?authenticate|validate\s+(?:your\s+)?account)\b", re.I), 35, "Account Credential Verification"),
    (re.compile(r"\b(unusual\s+(?:activity|sign-?in|login|access)|suspicious\s+login\s+attempt|unauthorized\s+access|security\s+alert\s+for\s+your\s+account)\b", re.I), 25, "Fake Security Alert / Breach Lure"),
    (re.compile(r"\b(2fa\s+(?:code|verification|disabled|required|reset)|mfa\s+(?:prompt|code|device)|one-time\s+passcode|otp\s+code)\b", re.I), 30, "Two-Factor / MFA Hijacking Lure"),
    
    # Document & Portal Phishing
    (re.compile(r"\b(docusign\s+(?:sign|document|view|envelope)|adobe\s+sign|review\s+shared\s+document|secure\s+portal\s+login|encrypted\s+message\s+received)\b", re.I), 25, "Document Signature Phishing"),
    (re.compile(r"\b(click\s+here\s+to\s+(?:login|sign\s+in|confirm|update|access|view)|log\s*in\s+to\s+keep\s+access|keep\s+same\s+password)\b", re.I), 25, "Deceptive Auth Redirect Call"),

    # Quishing (QR Code Phishing)
    (re.compile(r"\b(scan\s+(?:the\s+)?qr\s*code|qr\s*code\s+to\s+(?:login|verify|authenticate|view|sign)|open\s+camera\s+to\s+scan)\b", re.I), 40, "QR Code Phishing (Quishing) Vector"),

    # OAuth & Consent Phishing
    (re.compile(r"\b(authorize\s+(?:this\s+)?app(?:lication)?|grant\s+(?:api\s+)?permissions?|consent\s+required\s+for\s+access|third-party\s+app\s+access)\b", re.I), 30, "OAuth Consent / App Hijack Lure"),

    # Malicious Attachment & Macro Execution Lures
    (re.compile(r"\b(enable\s+(?:macros|content|editing)\s+to\s+view|attachment\s+is\s+encrypted|password\s+for\s+the\s+zip\s+is)\b", re.I), 50, "Malicious Macro / Password-Protected Payload Lure"),
    (re.compile(r"\b\.(?:html?|iso|img|vbs|hta|scr|exe)\s+attachment\b", re.I), 50, "High-Risk Executable / HTML Attachment Phishing"),
]


def evaluate_credentials(subject: str, snippet: str, sender: str = "") -> StepResult:
    """
    Evaluates credential harvesting, authentication manipulation, and quishing signals.
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

    clamped_score = min(float(total_score), 75.0)
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
