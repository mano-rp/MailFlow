"""
Step 2: Financial Vector & Payment Redirection Module
Detects wire transfer redirects, fake invoices, crypto demands, payroll tampering, and bank account redirection.
"""

import re
from typing import List, Tuple
from .base import StepResult

FINANCIAL_PATTERNS: List[Tuple[re.Pattern, int, str]] = [
    # Banking Redirection & Account Tampering
    (re.compile(r"\b(updated\s+(?:bank\s+details|banking\s+information|payment\s+instructions)|new\s+(?:iban|bank\s+account|routing\s+number|beneficiary\s+details))\b", re.I), 35, "Bank Account Redirection / IBAN Tampering"),
    (re.compile(r"\b(earlier\s+current\s+account\s+is\s+temporarily\s+frozen|shifted\s+our\s+current\s+account|temporary\s+account\s+due\s+to\s+audit)\b", re.I), 25, "Deceptive Audit / Account Migration Pretext"),
    (re.compile(r"\b(swift\s+code|routing\s+number|ach\s+transfer|sort\s+code|beneficiary\s+bank)\b", re.I), 20, "Banking Routing Identifiers"),

    # Wire Transfers & Invoices
    (re.compile(r"\b(wire\s+transfer|direct\s+wire|fund\s+transfer|electronic\s+funds?\s+transfer)\b", re.I), 25, "Wire Transfer Vector"),
    (re.compile(r"\b(invoice\s*#?\s*[A-Z0-9\-_]+|unpaid\s+invoice|overdue\s+payment|payment\s+remittance|billing\s+statement|remittance\s+advice)\b", re.I), 20, "Invoice / Billing Vector"),

    # Payroll & Direct Deposit Fraud
    (re.compile(r"\b(update\s+(?:my\s+)?direct\s+deposit|change\s+(?:my\s+)?payroll|direct\s+deposit\s+form|payroll\s+routing\s+change)\b", re.I), 35, "Payroll / Direct Deposit Impersonation"),
    (re.compile(r"\b(w-2\s+information|tax\s+refund\s+pending|irs\s+refund\s+claim)\b", re.I), 30, "Tax / W-2 Form Fraud Lure"),

    # Untraceable Extortion & Card Schemes
    (re.compile(r"\b(gift\s+cards?|itunes\s+card|steam\s+card|apple\s+gift|google\s+play\s+card|vanilla\s+visa|amazon\s+gift\s+card)\b", re.I), 45, "Gift Card Payment Extortion / BEC Task"),
    (re.compile(r"\b(crypto|bitcoin|btc|usdt|ethereum|wallet\s+address|blockchain\s+transfer|send\s+to\s+this\s+address)\b", re.I), 35, "Cryptocurrency Extortion Demand"),
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

    clamped_score = min(float(total_score), 70.0)
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
