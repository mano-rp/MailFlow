"""
Base models and structures for the MailFlow heuristic evaluation engine.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class StepResult(BaseModel):
    step_name: str
    score: float = Field(ge=0.0, le=100.0, description="Step severity score from 0 to 100")
    weight: float = Field(default=1.0, description="Weight factor for composite calculation")
    matched_rules: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class ScanPayload(BaseModel):
    sender: str
    subject: str
    snippet: Optional[str] = ""


class ThreatRecord(BaseModel):
    id: str
    timestamp: str
    sender: str
    subject: str
    snippet: str
    risk_score: int
    tier: str  # "low" | "moderate" | "high"
    color: str  # "green" | "yellow" | "red"
    action: str  # "verified" | "flag_warning" | "quarantine_slide"
    threat_type: str
    matched_steps: List[StepResult]
    explanation: str
