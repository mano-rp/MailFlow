from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="MailFlow Shield API",
    description="Backend API for MailFlow SME Email Shield browser extension",
    version="0.1.0",
)

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


@app.get("/api/ping", response_model=PingResponse)
async def get_ping():
    return {
        "status": "online",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan-ping", response_model=ScanPingResponse)
async def post_scan_ping(payload: ScanPingRequest):
    return {
        "status": "received",
        "mock_verdict": "safe",
        "latency_ms": 12,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
