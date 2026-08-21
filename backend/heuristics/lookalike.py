"""
Step 4: Sender & Lookalike Domain Anomaly Module
Detects homoglyphs, typosquatting (e.g. paypa1, micros0ft, g00gle), suspicious subdomains, and sender spoofing.
"""

import re
from typing import List, Tuple
from .base import StepResult

# Common homoglyph substitutions and deceptive brands
LOOKALIKE_PATTERNS: List[Tuple[re.Pattern, int, str]] = [
    (re.compile(r"(paypa[l1i]|micros[0o]ft|g[0o]{2}gle|app[l1]e|amaz[0o]n|netf[l1]ix|dr[0o]pb[0o]x|c[1i]t[1i]bank|chase-verify)", re.I), 50, "Brand Typosquatting / Homoglyph Domain"),
    (re.compile(r"([a-z0-9\-_]+(?:-security|-support|-verify|-billing|-auth|-login|-service)\.[a-z]{2,})", re.I), 40, "Deceptive Keyword-Laden Security Domain"),
    (re.compile(r"\.(xyz|top|work|click|country|gq|cf|tk|ml|ga|rest|bar|bid|stream)\b", re.I), 30, "High-Risk Top-Level Domain (TLD)"),
    (re.compile(r"(?:support|security|admin|billing|helpdesk)@[a-z0-9\-_]+\.[a-z0-9\-_]+\.[a-z]{2,}", re.I), 25, "Multi-tier Generic Admin Subdomain"),
    (re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", re.I), 45, "Raw IP Address in Sender / Lure"),
]


def evaluate_lookalike(sender: str, subject: str = "", snippet: str = "") -> StepResult:
    """
    Evaluates sender identity, lookalike domains, and homoglyph spoofing signals.
    """
    sender_clean = sender.lower().strip()
    full_text = f"{sender} {subject} {snippet}".strip()

    matched_rules: List[str] = []
    total_score = 0

    for pattern, weight, rule_desc in LOOKALIKE_PATTERNS:
        matches = pattern.findall(sender_clean)
        if not matches:
            matches = pattern.findall(full_text)

        if matches:
            matched_rules.append(f"{rule_desc} (flagged: '{matches[0]}')")
            total_score += weight

    # Check for obvious digit replacement in sender string (e.g. micros0ft, paypa1)
    if re.search(r"[a-z]+[0-9]+[a-z]+", sender_clean):
        if not any("Typosquatting" in r for r in matched_rules):
            matched_rules.append("Suspicious alphanumeric character substitution in sender")
            total_score += 25

    clamped_score = min(float(total_score), 100.0)
    description = (
        f"Detected {len(matched_rules)} domain or identity spoofing anomalies."
        if matched_rules
        else "Sender domain format appears normal with no homoglyphs detected."
    )

    return StepResult(
        step_name="Sender / Lookalike Anomaly Check",
        score=clamped_score,
        weight=1.3,
        matched_rules=matched_rules,
        description=description,
    )
