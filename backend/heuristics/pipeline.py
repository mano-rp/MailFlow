"""
MailFlow Multi-Step Detection Pipeline
Coordinates all 4 heuristic steps, aggregates multi-vector threat scores, evaluates compound attack vectors, and constructs SME explanations.
"""

import hashlib
from datetime import datetime, timezone
from typing import List
from .base import StepResult, ThreatRecord, ScanPayload
from .urgency import evaluate_urgency
from .financial import evaluate_financial
from .credentials import evaluate_credentials
from .lookalike import evaluate_lookalike


def generate_scan_id(sender: str, subject: str) -> str:
    """Generates a stable deterministic ID for an email entity."""
    content = f"{sender.strip().lower()}|{subject.strip().lower()}"
    return f"mf_{hashlib.sha256(content.encode('utf-8')).hexdigest()[:12]}"


def run_pipeline(payload: ScanPayload) -> ThreatRecord:
    """
    Executes the multi-step heuristic pipeline and constructs a finalized threat record.
    """
    sender = payload.sender.strip()
    subject = payload.subject.strip()
    snippet = (payload.snippet or "").strip()

    # Run the 4 heuristic evaluation steps
    step1: StepResult = evaluate_urgency(subject=subject, snippet=snippet, sender=sender)
    step2: StepResult = evaluate_financial(subject=subject, snippet=snippet, sender=sender)
    step3: StepResult = evaluate_credentials(subject=subject, snippet=snippet, sender=sender)
    step4: StepResult = evaluate_lookalike(sender=sender, subject=subject, snippet=snippet)

    steps: List[StepResult] = [step1, step2, step3, step4]

    # Cybersecurity composite scoring:
    step_scores = [s.score for s in steps]
    primary_score = max(step_scores) if step_scores else 0.0

    if primary_score > 0:
        secondary_sum = sum(s for s in step_scores) - primary_score
        composite = primary_score + (secondary_sum * 0.25)

        # High-Risk Multi-Vector Compound Attack Rules:
        # 1. Deceptive URL Userinfo Spoofing (@ syntax) or High-Risk Phishing TLD in link
        if any("Userinfo Spoofing" in r or "High-Risk Phishing TLD" in r or "Quota Portal" in r for r in step4.matched_rules):
            composite = max(composite, 85.0)

        # 2. Mailbox Storage / Quota Phish + Credential Verification / Login Demand
        if any("Mailbox Storage" in r for r in step3.matched_rules) and (step3.score >= 35 or step1.score >= 25):
            composite = max(composite, 84.0)

        # 3. Lookalike domain on sender + (Credentials OR Financial)
        if step4.score >= 45 and (step3.score >= 25 or step2.score >= 25):
            composite = max(composite, 82.0)

        # 4. Executive Secrecy/Urgency + Gift Card / Crypto Extortion
        if step1.score >= 25 and (any("Gift Card" in r or "Crypto" in r for r in step2.matched_rules)):
            composite = max(composite, 80.0)

        # 5. High-Risk Macro / Executable Payload Lures
        if any("Macro" in r or "Executable" in r for r in step3.matched_rules):
            composite = max(composite, 85.0)

        # 6. Account Suspension Threat + Credential Verification Trap + High Urgency
        if step1.score >= 45 and step3.score >= 40:
            composite = max(composite, 80.0)

        final_score = int(min(max(round(composite), 0), 100))
    else:
        final_score = 0

    # Determine Tier, Color, Action, and Threat Type
    if final_score >= 75:
        tier = "high"
        color = "red"
        action = "quarantine_slide"
        if any("Userinfo Spoofing" in r for r in step4.matched_rules):
            threat_type = "Deceptive URL Spoofing / Phish"
        elif any("Mailbox Storage" in r for r in step3.matched_rules):
            threat_type = "Mailbox Quota Phishing Attack"
        elif any("Macro" in r or "Executable" in r for r in step3.matched_rules):
            threat_type = "Malicious Payload / Attachment Phish"
        elif any("Gift Card" in r for r in step2.matched_rules) and step1.score >= 25:
            threat_type = "Executive Impersonation / Gift Card Fraud"
        elif step4.score >= 45:
            threat_type = "Lookalike Domain / Targeted Phishing"
        elif step2.score >= 50:
            threat_type = "Urgent Financial / BEC Fraud"
        elif step3.score >= 50:
            threat_type = "Credential Harvesting / Phishing Attack"
        else:
            threat_type = "High-Risk Social Engineering"
    elif final_score >= 36:
        tier = "moderate"
        color = "yellow"
        action = "flag_warning"
        if any("QR Code" in r for r in step3.matched_rules):
            threat_type = "QR Code Verification Notice"
        elif any("Mailbox Storage" in r for r in step3.matched_rules):
            threat_type = "Mailbox Storage Notice"
        elif any("Bank Account Redirection" in r or "Audit" in r for r in step2.matched_rules):
            threat_type = "Unverified Bank Account Update"
        elif step2.score >= 20:
            threat_type = "Unverified Invoice Reference"
        elif any("Executive Impersonation" in r or "Secrecy" in r for r in step1.matched_rules):
            threat_type = "Executive Urgency Lure"
        elif step3.score >= 25:
            threat_type = "Suspicious Auth / Portal Request"
        elif step1.score >= 20:
            threat_type = "Coercive Urgency / Marketing Lure"
        else:
            threat_type = "Suspicious Social Engineering"
    else:
        tier = "low"
        color = "green"
        action = "verified"
        threat_type = "Verified Safe"

    # Construct plain-English explanation
    explanation = generate_explanation(tier, steps, final_score)

    scan_id = generate_scan_id(sender, subject)
    timestamp = datetime.now(timezone.utc).isoformat()

    return ThreatRecord(
        id=scan_id,
        timestamp=timestamp,
        sender=sender,
        subject=subject,
        snippet=snippet,
        risk_score=final_score,
        tier=tier,
        color=color,
        action=action,
        threat_type=threat_type,
        matched_steps=steps,
        explanation=explanation,
    )


def generate_explanation(tier: str, steps: List[StepResult], score: int) -> str:
    """Generates an intuitive, non-technical plain English explanation for SME users."""
    active_matches = []
    for step in steps:
        for rule in step.matched_rules:
            active_matches.append(rule)

    if tier == "high":
        if active_matches:
            top_reasons = "; ".join(active_matches[:2])
            return f"High-risk threat detected (Score {score}/100). Flagged for: {top_reasons}. Quarantined to protect your organization."
        return f"High-risk threat detected (Score {score}/100). Coercive vectors and deceptive indicators exceed enterprise safety thresholds."

    if tier == "moderate":
        if active_matches:
            reasons = "; ".join(active_matches[:2])
            return f"Moderate caution advised (Score {score}/100). Detected: {reasons}. Verify sender authenticity before interacting."
        return f"Moderate caution advised (Score {score}/100). Contains potential social engineering patterns."

    return f"Clean (Score {score}/100). No urgency coercion, payment tampering, or lookalike anomalies detected."
