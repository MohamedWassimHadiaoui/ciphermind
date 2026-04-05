"""
Main FastAPI Application - CipherMind AI Cyber Shield

This is the web server that connects everything together:
- Serves the HTML dashboard (frontend)
- Provides API endpoints for the phishing analysis pipeline
- Handles human-in-the-loop remediation approval/rejection
- Serves audit logs for transparency

ENDPOINTS:
  GET  /                              → Dashboard (HTML page)
  GET  /api/samples                   → Demo phishing samples
  POST /api/analyze                   → Run phishing analysis
  POST /api/remediate/{id}            → Generate remediation actions
  POST /api/actions/{id}/approve/{aid} → Human approves an action
  POST /api/actions/{id}/reject/{aid}  → Human rejects an action
  GET  /api/remediation/{id}          → Get remediation status
  GET  /api/audit/logs                → Get all audit logs
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
import json
import time
from collections import defaultdict

from backend.engines.phishing_analyzer import analyze_email
from backend.engines.remediation import (
    generate_remediation, approve_action, reject_action, get_remediation
)
from backend.engines.audit_logger import init_db, get_logs
from backend.engines.ml_detector import init_ml_model
from backend.engines.feedback_learner import record_feedback, get_feedback_stats
from backend.rag.knowledge_base import init_knowledge_base

# ============================================================
# Create the FastAPI app
# ============================================================
app = FastAPI(
    title="CipherMind - AI Cyber Shield",
    description="AI-powered phishing detection for the Tunisian cyberspace with human-in-the-loop control",
    version="1.0.0"
)

# Allow the frontend to talk to the backend (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# Rate Limiting (protect Groq API credits)
# ============================================================
_rate_limit = defaultdict(list)
RATE_LIMIT_MAX = 10        # max requests per window
RATE_LIMIT_WINDOW = 60     # window in seconds

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Simple rate limiter for analysis endpoints to prevent API abuse."""
    if request.url.path in ("/api/analyze", "/api/remediate"):
        client_ip = request.client.host
        now = time.time()
        # Clean old entries
        _rate_limit[client_ip] = [t for t in _rate_limit[client_ip] if now - t < RATE_LIMIT_WINDOW]
        if len(_rate_limit[client_ip]) >= RATE_LIMIT_MAX:
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again in a minute.")
        _rate_limit[client_ip].append(now)
    return await call_next(request)


# ============================================================
# Startup: Initialize database and knowledge base
# ============================================================
@app.on_event("startup")
async def startup():
    """Run when the server starts - set up database and load RAG knowledge base."""
    print("[CipherMind] Initializing audit database...")
    init_db()
    print("[CipherMind] Loading Tunisian phishing knowledge base (RAG)...")
    init_knowledge_base()
    print("[CipherMind] Training ML phishing detector...")
    init_ml_model()
    print("[CipherMind] Ready! Dashboard at http://localhost:8000")


# ============================================================
# Serve the frontend dashboard
# ============================================================
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the main dashboard HTML page."""
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


# ============================================================
# API Request/Response Models (Pydantic)
# ============================================================
class AnalyzeRequest(BaseModel):
    """What the frontend sends when user clicks 'Analyze'."""
    email_content: str
    sender: Optional[str] = ""

    def validate_size(self):
        """Reject oversized inputs that could abuse the LLM API."""
        if len(self.email_content) > 10000:
            raise HTTPException(status_code=400, detail="Email content too long (max 10000 characters)")
        if self.sender and len(self.sender) > 200:
            raise HTTPException(status_code=400, detail="Sender field too long (max 200 characters)")

class ActionDecision(BaseModel):
    """What the frontend sends when user approves/rejects an action."""
    operator: Optional[str] = "human_operator"
    reason: Optional[str] = ""


# ============================================================
# Demo Phishing Samples (loaded from samples/phishing_samples.json)
# ============================================================
SAMPLES_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples", "phishing_samples.json")

def _load_samples():
    """Load demo samples from JSON file."""
    with open(SAMPLES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

DEMO_SAMPLES = _load_samples()


# ============================================================
# API Endpoints
# ============================================================

@app.get("/api/samples")
async def get_samples():
    """Return demo phishing samples for testing."""
    return {"samples": DEMO_SAMPLES}


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest):
    """
    Run the full 6-stage phishing analysis pipeline.
    This is the main endpoint that does all the work.
    """
    request.validate_size()
    result = await analyze_email(request.email_content, request.sender)
    return result


@app.post("/api/remediate/{analysis_id}")
async def remediate(analysis_id: str):
    """
    Generate remediation actions for a completed analysis.
    All actions require human approval before execution.
    """
    # We need the analysis result to generate context-aware remediation
    # For simplicity, we pass a minimal result structure
    # In production, you'd retrieve the full analysis from a database
    from backend.engines.audit_logger import get_logs
    logs = get_logs(analysis_id=analysis_id, limit=1)

    if not logs:
        return {"error": "Analysis not found"}

    # Reconstruct minimal analysis result from audit log
    log_meta = logs[0].get("metadata", {})
    analysis_result = {
        "analysis_id": analysis_id,
        "final_verdict": {
            "is_phishing": log_meta.get("final_score", 0) >= 0.5,
            "threat_level": log_meta.get("threat_level", "unknown"),
            "confidence": log_meta.get("final_score", 0),
            "explanation": logs[0].get("details", ""),
            "targeted_institution": None,
            "attack_techniques": [],
            "risk_to_citizen": ""
        }
    }

    result = await generate_remediation(analysis_result)
    return result


@app.post("/api/actions/{analysis_id}/approve/{action_id}")
async def approve(analysis_id: str, action_id: str, decision: ActionDecision = None):
    """Human operator approves a remediation action."""
    if decision is None:
        decision = ActionDecision()
    result = approve_action(analysis_id, action_id, decision.operator)
    return result


@app.post("/api/actions/{analysis_id}/reject/{action_id}")
async def reject(analysis_id: str, action_id: str, decision: ActionDecision = None):
    """Human operator rejects a remediation action."""
    if decision is None:
        decision = ActionDecision()
    result = reject_action(analysis_id, action_id, decision.operator, decision.reason)
    return result


@app.get("/api/remediation/{analysis_id}")
async def get_remediation_status(analysis_id: str):
    """Get the current remediation status and actions."""
    result = get_remediation(analysis_id)
    if not result:
        return {"error": "No remediation found for this analysis"}
    return result


@app.get("/api/audit/logs")
async def audit_logs(analysis_id: str = None, limit: int = 100):
    """
    Get audit logs - every AI decision and human action is recorded here.
    This provides the TOTAL TRACEABILITY required by the hackathon.
    """
    logs = get_logs(analysis_id=analysis_id, limit=limit)
    return {"logs": logs, "total": len(logs)}


# ============================================================
# Feedback / Learning Endpoints
# ============================================================
class FeedbackRequest(BaseModel):
    """Feedback from human operator on AI accuracy."""
    email_content: str
    ai_verdict_phishing: bool
    human_agreed: bool
    threat_level: Optional[str] = ""


@app.post("/api/feedback/{analysis_id}")
async def submit_feedback(analysis_id: str, feedback: FeedbackRequest):
    """
    Record human feedback on an AI decision.
    This feeds into the Learning/Adaptation module.
    """
    result = record_feedback(
        analysis_id=analysis_id,
        email_content=feedback.email_content,
        ai_verdict=feedback.ai_verdict_phishing,
        human_agreed=feedback.human_agreed,
        threat_level=feedback.threat_level
    )
    return {"success": True, "feedback": result}


@app.get("/api/feedback/stats")
async def feedback_stats():
    """Get learning/adaptation statistics from accumulated human feedback."""
    return get_feedback_stats()


# ============================================================
# Documentation Endpoints (serve project deliverables)
# ============================================================
DOCS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs")

@app.get("/api/docs/architecture")
async def get_architecture():
    """Serve the architecture document."""
    path = os.path.join(DOCS_DIR, "architecture.md")
    with open(path, "r", encoding="utf-8") as f:
        return {"title": "Architecture Document", "content": f.read()}

@app.get("/api/docs/transparency")
async def get_transparency():
    """Serve the transparency note."""
    path = os.path.join(DOCS_DIR, "transparency_note.md")
    with open(path, "r", encoding="utf-8") as f:
        return {"title": "Transparency Note", "content": f.read()}

@app.get("/api/docs/stack")
async def get_stack():
    """Serve tech stack and Docker info."""
    dockerfile_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Dockerfile")
    compose_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docker-compose.yml")
    dockerfile = ""
    compose = ""
    try:
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            dockerfile = f.read()
    except FileNotFoundError:
        dockerfile = "Dockerfile not found"
    try:
        with open(compose_path, "r", encoding="utf-8") as f:
            compose = f.read()
    except FileNotFoundError:
        compose = "docker-compose.yml not found"
    return {"dockerfile": dockerfile, "docker_compose": compose}
