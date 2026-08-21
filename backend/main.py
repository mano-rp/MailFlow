"""
MailFlow Shield Backend API
FastAPI health-check, multi-step heuristic scanning engine, and threat registry.
"""

from datetime import datetime, timezone
import time
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from heuristics import ScanPayload, ThreatRecord, run_pipeline

app = FastAPI(
    title="MailFlow Shield API",
    description="Backend API for MailFlow SME Email Shield browser extension",
    version="0.1.0",
)

# Enable CORS for all origins (Chrome Extension & localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan and threat registry
SCAN_HISTORY: Dict[str, ThreatRecord] = {}
QUARANTINED_IDS: set = set()
MODERATE_IDS: set = set()


class ScanPingRequest(BaseModel):
    sender: str
    subject: str


class PingResponse(BaseModel):
    status: str
    version: str
    timestamp: str


class ScanPingResponse(BaseModel):
    status: str
    mock_verdict: str
    latency_ms: int


class RestoreRequest(BaseModel):
    id: str


class ThreatListResponse(BaseModel):
    high_risk: List[ThreatRecord]
    moderate_risk: List[ThreatRecord]
    total_quarantined: int
    total_moderate: int


@app.get("/api/ping", response_model=PingResponse)
async def get_ping():
    """Health check endpoint for Chrome extension heartbeat."""
    return {
        "status": "online",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan", response_model=ThreatRecord)
async def post_scan(payload: ScanPayload):
    """
    Sub-50ms Multi-Step Heuristic Threat Evaluation Endpoint.
    Evaluates urgency, financial vectors, credentials, and lookalike anomalies.
    """
    start_time = time.perf_counter()
    record = run_pipeline(payload)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000)

    # Persist in memory registry
    SCAN_HISTORY[record.id] = record
    if record.tier == "high":
        QUARANTINED_IDS.add(record.id)
    elif record.tier == "moderate":
        MODERATE_IDS.add(record.id)

    return record


@app.post("/api/scan-ping", response_model=ScanPingResponse)
async def post_scan_ping(payload: ScanPingRequest):
    """Backwards-compatible lightweight test endpoint."""
    return {
        "status": "received",
        "mock_verdict": "safe",
        "latency_ms": 12,
    }


@app.get("/api/threats", response_model=ThreatListResponse)
async def get_threats():
    """Returns categorized threat records for the MailFlow dashboard & tab view."""
    high_records = [
        SCAN_HISTORY[tid]
        for tid in QUARANTINED_IDS
        if tid in SCAN_HISTORY
    ]
    moderate_records = [
        SCAN_HISTORY[tid]
        for tid in MODERATE_IDS
        if tid in SCAN_HISTORY
    ]

    return {
        "high_risk": high_records,
        "moderate_risk": moderate_records,
        "total_quarantined": len(high_records),
        "total_moderate": len(moderate_records),
    }


@app.post("/api/threats/restore")
async def restore_threat(payload: RestoreRequest):
    """Restores an email from quarantine."""
    if payload.id in QUARANTINED_IDS:
        QUARANTINED_IDS.remove(payload.id)
        return {"status": "restored", "id": payload.id}
    return {"status": "not_found", "id": payload.id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
