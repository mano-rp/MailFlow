"""
Step 2: Financial Vector & Payment Redirection Module
Detects wire transfer redirects, fake invoices, crypto demands, and bank account tampering.
"""

import re
from typing import List, Tuple
from .base import StepResult

FINANCIAL_PATTERNS: List[Tuple[re.Pattern, int, str]] = [
    (re.compile(r"\b(wire\s+transfer|direct\s+wire|fund\s+transfer|electronic\s+transfer)\b", re.I), 35, "Wire Transfer Vector"),
    (re.compile(r"\b(updated\s+(?:bank\s+details|banking\s+information|payment\s+instructions)|new\s+(?:iban|bank\s+account|routing\s+number))\b", re.I), 45, "Bank Account Redirection / IBAN Tampering"),
    (re.compile(r"\b(invoice\s*#?\s*[A-Z0-9\-_]+|unpaid\s+invoice|overdue\s+payment|payment\s+remittance|billing\s+statement)\b", re.I), 25, "Invoice / Billing Vector"),
    (re.compile(r"\b(swift\s+code|routing\s+number|ach\s+transfer|sort\s+code)\b", re.I), 30, "Banking Routing Identifiers"),
    (re.compile(r"\b(gift\s+cards?|itunes\s+card|steam\s+card|apple\s+gift|google\s+play\s+card|vanilla\s+visa)\b", re.I), 45, "Gift Card Payment Extortion"),
    (re.compile(r"\b(crypto|bitcoin|btc|usdt|ethereum|wallet\s+address|blockchain\s+transfer)\b", re.I), 35, "Cryptocurrency Demand"),
    (re.compile(r"\b(remittance\s+advice|payroll\s+update|direct\s+deposit\s+form)\b", re.I), 30, "Payroll / Remittance Tampering"),
]


def evaluate_financial(subject: str, snippet: str, sender: str = "") -> StepResult:
    """
    Evaluates financial fraud, payment manipulation, and BEC invoice tampering signals.
    """
    text = f"{subject} {snippet}".strip()
    if not text:
        return StepResult(step_name="Financial & Invoice Redirection Check", score=0.0, matched_rules=[])

    matched_rules: List[str] = []
    total_score = 0

    for pattern, weight, rule_desc in FINANCIAL_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            matched_rules.append(f"{rule_desc} (matched: '{matches[0]}')")
            total_score += weight

    clamped_score = min(float(total_score), 100.0)
    description = (
        f"Detected {len(matched_rules)} financial or invoice redirection vectors."
        if matched_rules
        else "No payment redirection or invoice tampering signals detected."
    )

    return StepResult(
        step_name="Financial & Invoice Redirection Check",
        score=clamped_score,
        weight=1.2,
        matched_rules=matched_rules,
        description=description,
    )
