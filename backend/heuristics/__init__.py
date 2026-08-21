"""
MailFlow Multi-Step Heuristic Detection Engine
"""

from .base import StepResult, ScanPayload, ThreatRecord
from .urgency import evaluate_urgency
from .financial import evaluate_financial
from .credentials import evaluate_credentials
from .lookalike import evaluate_lookalike
from .pipeline import run_pipeline, generate_scan_id

__all__ = [
    "StepResult",
    "ScanPayload",
    "ThreatRecord",
    "evaluate_urgency",
    "evaluate_financial",
    "evaluate_credentials",
    "evaluate_lookalike",
    "run_pipeline",
    "generate_scan_id",
]
