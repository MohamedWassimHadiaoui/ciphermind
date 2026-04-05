# Architecture Document - CipherMind

## System Overview

```
┌──────────────────────────────────────────────────────────┐
│                    Web Browser (Client)                    │
│              Frontend Dashboard (index.html)               │
│    ┌──────────┐  ┌──────────────┐  ┌──────────────┐      │
│    │ Analysis  │  │ Remediation  │  │  Audit Logs  │      │
│    │   (XAI)   │  │   (HITL)     │  │(Traceability)│      │
│    └──────────┘  └──────────────┘  └──────────────┘      │
└───────────────────────┬──────────────────────────────────┘
                        │ HTTP/REST API
                        ▼
┌──────────────────────────────────────────────────────────┐
│                  FastAPI Backend (main.py)                 │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Phishing Analyzer Engine                 │ │
│  │                                                      │ │
│  │  ┌────────┐ ┌────────┐ ┌──────┐ ┌───────┐          │ │
│  │  │Stage 1:│ │Stage 2:│ │Stg 3:│ │Stage 4│          │ │
│  │  │  ETL   │→│ Rules  │→│  ML  │→│  RAG  │          │ │
│  │  │Pipeline│ │Engine  │ │Model │ │ChromaDB│         │ │
│  │  └────────┘ └────────┘ └──────┘ └───────┘          │ │
│  │       │          │         │         │               │ │
│  │       ▼          ▼         ▼         ▼               │ │
│  │  ┌─────────────────┐  ┌──────────────────────┐      │ │
│  │  │  Stage 5: LLM   │  │  Stage 6: Threat     │      │ │
│  │  │  Groq/Llama 3.3 │→ │  Aggregation         │      │ │
│  │  │  (+ RAG context) │  │  30% R + 20% ML      │      │ │
│  │  │                  │  │  + 50% LLM = Verdict  │      │ │
│  │  └─────────────────┘  └──────────────────────┘      │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                           │
│  ┌──────────────────┐  ┌──────────────────────────────┐  │
│  │ Remediation Engine│  │      Audit Logger            │  │
│  │  (HITL Actions)   │  │   (SQLite Database)          │  │
│  └──────────────────┘  └──────────────────────────────┘  │
│                                                           │
│  ┌──────────────────────────────────────────────────────┐ │
│  │          Feedback / Learning Module                    │ │
│  │  (Human feedback → stored → future ML retraining)     │ │
│  └──────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
   ┌───────────┐ ┌───────────┐ ┌──────────┐
   │  ChromaDB  │ │  SQLite   │ │  Groq    │
   │ (Vectors)  │ │  (Audit)  │ │   API    │
   └───────────┘ └───────────┘ └──────────┘
```

## Data Flow

### 1. Phishing Analysis Flow (6 Stages)
```
User pastes email → POST /api/analyze
  → Stage 1: run_etl_pipeline() - extract URLs, detect language, normalize
  → Stage 2: extract_features() - regex patterns, URL checks, urgency detection
  → Stage 3: predict_phishing() - TF-IDF + Logistic Regression ML classifier
  → Stage 4: query_similar_patterns() - ChromaDB vector similarity search
  → Stage 5: analyze_with_llm() - Groq structured prompt with features + RAG context
  → Stage 6: compute_final_verdict() - weighted: 30% rules + 20% ML + 50% LLM
  → log_event() - record decision in audit trail
  → Return JSON with full XAI breakdown
```

### 2. Remediation Flow (Human-in-the-Loop)
```
Analysis complete → POST /api/remediate/{id}
  → generate_remediation() - LLM generates 3-5 context-aware actions
  → All actions set to "pending_approval" status
  → Human reviews each action on dashboard
  → POST /api/actions/{id}/approve/{aid} or /reject/{aid}
  → log_event() - record human decision in audit trail
  → Action status updated (approved/rejected)
```

### 3. Audit Trail Flow
```
Every AI decision → log_event(actor="ai_engine")
Every human action → log_event(actor="human_operator")
  → Stored in SQLite with: timestamp, analysis_id, event_type, actor, action, details, metadata
  → Queryable via GET /api/audit/logs
  → Displayed in Audit Logs tab with filtering
```

### 4. Feedback / Learning Flow
```
After analysis → Human submits feedback (agree/disagree with AI)
  → Stored in feedback_data.json with email snippet + correct label
  → GET /api/feedback/stats shows AI accuracy rate
  → Feedback data can be used to retrain ML model
```

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Backend | FastAPI (Python) | REST API server, 10 endpoints |
| LLM | Groq (Llama 3.3 70B) | Contextual phishing analysis |
| LLM Fallback | Google Gemini 2.0 Flash | Secondary LLM if Groq unavailable |
| ML Model | scikit-learn (TF-IDF + LogReg) | Fast statistical classification |
| Vector DB | ChromaDB | RAG knowledge base (8 patterns) |
| Database | SQLite | Audit trail persistence |
| Frontend | HTML/CSS/JS (vanilla) | Dashboard interface (3 tabs) |
| Container | Docker + docker-compose | Deployment & reproducibility |

## Weighted Scoring Formula

| Scenario | Formula | Rationale |
|----------|---------|-----------|
| All 3 signals | 30% Rules + 20% ML + 50% LLM | LLM provides nuance; rules/ML are safety nets |
| No LLM | 60% Rules + 40% ML | Graceful degradation without API |
| No ML | 40% Rules + 60% LLM | Still accurate with 2 signals |
| Rules only | 100% Rules | Minimum viable detection always available |

## Security Considerations

- Input sanitization on all API endpoints (Pydantic validation)
- CORS configured for API access control
- No credentials stored in code (environment variables via .env)
- Prompt injection mitigation through structured prompting
- JSON-only LLM output reduces attack surface
- All AI actions require human approval before execution
