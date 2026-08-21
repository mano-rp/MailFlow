"""
Step 4: Sender & Lookalike Domain Anomaly Module
Detects homoglyphs, typosquatting (e.g. paypa1, micros0ft, g00gle), suspicious subdomains, and sender spoofing.
"""

import re
from typing import List, Tuple, Set
from .base import StepResult

# Legitimate trusted root domains to avoid false-positive lookalike detections
TRUSTED_ROOT_DOMAINS: Set[str] = {
    "google.com", "gmail.com", "microsoft.com", "office.com", "outlook.com",
    "paypal.com", "apple.com", "amazon.com", "netflix.com", "github.com",
    "linkedin.com", "substack.com", "internshala.com", "youtube.com", "adobe.com",
    "docusign.com", "zoom.us", "dropbox.com", "slack.com", "stripe.com"
}

# Strict homoglyph patterns that ONLY match actual deceptive character substitutions
STRICT_HOMOGLYPH_PATTERNS: List[Tuple[re.Pattern, int, str]] = [
    (re.compile(r"\b(?:paypa[1!i]|p[a4]ypal|p[a4]ypa[1!i])\b", re.I), 55, "PayPal Typosquatting / Homoglyph"),
    (re.compile(r"\b(?:micros0ft|m1crosoft|m1cr0s0ft|m[i1]cr0soft)\b", re.I), 55, "Microsoft Typosquatting / Homoglyph"),
    (re.compile(r"\b(?:g(?:0[0o]|o0)gle|g00g1e|goog1e)\b", re.I), 55, "Google Typosquatting / Homoglyph"),
    (re.compile(r"\b(?:app[1i]e|appl[e3]|4pple)\b", re.I), 55, "Apple Typosquatting / Homoglyph"),
    (re.compile(r"\b(?:amaz0n|amz[0o]n|4mazon)\b", re.I), 55, "Amazon Typosquatting / Homoglyph"),
    (re.compile(r"\b(?:netf[1i]x|n3tflix|netf1ix)\b", re.I), 55, "Netflix Typosquatting / Homoglyph"),
    (re.compile(r"\b(?:dr0pb0x|dr0pbox|dropb0x)\b", re.I), 55, "Dropbox Typosquatting / Homoglyph"),
    (re.compile(r"\b(?:c[1i]t[1i]bank|c1tibank|cit1bank)\b", re.I), 55, "Citibank Typosquatting / Homoglyph"),
    (re.compile(r"\b(?:wellsfarg0|w3llsfargo)\b", re.I), 55, "Wells Fargo Typosquatting / Homoglyph"),
    (re.compile(r"\b(?:chase[-_]verify|chase[-_]security|bofa[-_]auth)\b", re.I), 55, "Bank Domain Impersonation"),
]

# Deceptive infrastructure patterns
INFRASTRUCTURE_PATTERNS: List[Tuple[re.Pattern, int, str]] = [
    (re.compile(r"([a-z0-9\-_]+(?:-security|-support|-verify|-billing|-auth|-login|-service|-alert)\.[a-z]{2,})", re.I), 40, "Deceptive Keyword-Laden Security Domain"),
    (re.compile(r"\.(xyz|top|work|click|country|gq|cf|tk|ml|ga|rest|bar|bid|stream|buzz|monster|fit|live)\b", re.I), 35, "High-Risk Top-Level Domain (TLD)"),
    (re.compile(r"(?:support|security|admin|billing|helpdesk|service|verify)@[a-z0-9\-_]+\.[a-z0-9\-_]+\.[a-z]{2,}", re.I), 30, "Multi-tier Generic Admin Subdomain"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 45, "Raw IP Address in Sender / Lure"),
]


def extract_email_address(text: str) -> str:
    """Extracts email address if present in a string."""
    match = re.search(r"[\w\.\-]+@([\w\-]+\.[\w\-]+)", text)
    return match.group(0).lower() if match else ""


def evaluate_lookalike(sender: str, subject: str = "", snippet: str = "") -> StepResult:
    """
    Evaluates sender identity, lookalike domains, and homoglyph spoofing signals.
    """
    sender_clean = sender.lower().strip()
    email_addr = extract_email_address(sender_clean)
    
    # Extract domain from email if available
    domain = email_addr.split("@")[-1] if "@" in email_addr else sender_clean

    # Check if domain belongs to a trusted provider
    is_trusted_domain = any(domain.endswith(trusted) for trusted in TRUSTED_ROOT_DOMAINS)

    matched_rules: List[str] = []
    total_score = 0

    # 1. Strict homoglyph check on sender string and domain
    for pattern, weight, rule_desc in STRICT_HOMOGLYPH_PATTERNS:
        matches = pattern.findall(sender_clean)
        if matches:
            matched_rules.append(f"{rule_desc} (flagged: '{matches[0]}')")
            total_score += weight

    # 2. Check for deceptive infrastructure (skip if trusted domain)
    if not is_trusted_domain:
        for pattern, weight, rule_desc in INFRASTRUCTURE_PATTERNS:
            matches = pattern.findall(sender_clean)
            if not matches and "@" in sender_clean:
                matches = pattern.findall(email_addr)

            if matches:
                matched_rules.append(f"{rule_desc} (flagged: '{matches[0]}')")
                total_score += weight

        # 3. Check for obvious digit replacement in sender string (e.g. micros0ft, paypa1)
        if re.search(r"[a-z]{3,}[0-9]+[a-z]{2,}", sender_clean):
            if not any("Typosquatting" in r for r in matched_rules):
                matched_rules.append("Suspicious alphanumeric character substitution in sender")
                total_score += 30

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
