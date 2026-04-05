# CipherMind - AI Cyber Shield

> **Hackathon AI x Cybersecurity** | Securinets FST | Theme: "AI Augmented Cyber Defense, but Human Controlled"

CipherMind is an AI-powered phishing detection system designed to protect Tunisian citizens in cyberspace. It detects, analyzes, and helps respond to phishing threats while keeping **humans in full control** of all critical decisions.

## What It Does

CipherMind acts as a **security co-pilot** covering two phases:

1. **Preventive (Préventif):** Analyzes emails/messages to detect phishing attempts using a 6-stage AI pipeline
2. **Corrective (Correctif):** Generates remediation actions that require explicit human approval before execution

## Architecture - 6-Stage Analysis Pipeline

```
Email Input
    │
    ▼
┌─────────────────────────────────┐
│  Stage 1: ETL Pipeline          │  ← Extract URLs, phones, amounts
│  (Extract, Transform, Load)     │     Detect language (FR/AR/EN), normalize text
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  Stage 2: Rule-Based Engine     │  ← Regex patterns, URL analysis, urgency detection
│  (Deterministic, Explainable)   │     French + Tunisian Arabic (Derja) patterns
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  Stage 3: ML Classifier         │  ← scikit-learn TF-IDF + Logistic Regression
│  (Statistical Detection)        │     Trained on 27 phishing/legit samples
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  Stage 4: RAG Context Retrieval │  ← ChromaDB vector search
│  (Tunisian Threat Intelligence) │     8 known Tunisian phishing patterns
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  Stage 5: LLM Analysis          │  ← Groq (Llama 3.3 70B)
│  (Contextual Understanding)     │     Structured prompt with features + RAG context
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  Stage 6: Threat Aggregation    │  ← Weighted: 30% rules + 20% ML + 50% LLM
│  (Final Verdict + XAI)          │     Graceful degradation if signals unavailable
└─────────────────────────────────┘
               │
               ▼
    Dashboard with XAI + Human-in-the-Loop Remediation
```

## Key Features

### Human Control (30% of evaluation)
- **Zero auto-actions:** AI proposes remediation, humans must approve/reject each action
- **Per-stage audit trail:** Every pipeline stage (ETL, Rules, ML, RAG, LLM, Verdict) logged individually to SQLite with full metadata
- **Feedback loop:** Human feedback stored to improve system accuracy over time

### Explainable AI - XAI (30% of evaluation)
- **Rule findings:** Each triggered rule shown with specific evidence from the email
- **ML key words:** Top 5 words that influenced the ML model, with weights and direction
- **LLM explanation:** Natural language explanation citing specific evidence
- **Score breakdown:** Visual meters showing Rules, ML, LLM, and Final scores with formula
- **RAG matches:** Similar known Tunisian attacks with similarity scores (noise-filtered by distance threshold)

### Engineering Depth (25% of evaluation)
- **6-stage pipeline:** ETL → Rules → ML → RAG → LLM → Aggregation
- **3 independent AI signals:** Not a basic API wrapper - real multi-model architecture
- **RAG with ChromaDB:** Vector-based similarity search with distance thresholding to filter noisy matches
- **Structured prompts:** Pre/post-processing around LLM calls with JSON validation
- **Input sanitization:** Prompt injection defense strips known attack patterns before LLM analysis
- **Legitimate domain whitelist:** Official Tunisian domains (biat.com.tn, poste.tn, etc.) excluded from false-positive URL flagging
- **Docker-ready:** Full containerization with docker-compose

### Tunisian Impact (25% of evaluation)
- **8 local threat patterns:** BIAT, La Poste, Ooredoo, CNSS, Tunisie Telecom, e-Dinar, job scams, crypto scams
- **Bilingual detection:** French + Tunisian Arabic (Derja) urgency patterns
- **Local remediation:** Actions include reporting to Tunisian CERT (ANSI)

### Innovation & UX (20% of evaluation)
- **Cybersecurity-themed dashboard:** Dark theme with real-time pipeline visualization
- **Interactive analysis:** Click demo samples or paste your own emails
- **Score breakdown:** Visual confidence meters and scoring formula transparency
- **Built-in Docs tab:** Architecture diagram, transparency note, dataset/bias docs, AI defense writeup, and Docker config all viewable from the dashboard (no need to dig through the repo)

## Quick Start

### Prerequisites
- Python 3.10+
- A Groq API key ([Get one free](https://console.groq.com/keys))

### Setup
```bash
# Clone the repo
git clone https://github.com/MohamedWassimHadiaoui/ciphermind.git
cd ciphermind

# Create .env file with your API key
cp .env.example .env
# Edit .env and add your GROQ_API_KEY

# Install dependencies
pip install -r requirements.txt

# Run the server
python -m uvicorn backend.main:app --port 8000

# Open http://localhost:8000 in your browser
```

### With Docker
```bash
# Set your API key
echo "GROQ_API_KEY=your_key_here" > .env

# Build and run
docker-compose up --build

# Open http://localhost:8000
```

## Project Structure
```
ciphermind/
├── backend/
│   ├── main.py                    # FastAPI app + 10 API endpoints
│   ├── engines/
│   │   ├── phishing_analyzer.py   # 6-stage analysis pipeline (CORE)
│   │   ├── etl_pipeline.py        # Extract, Transform, Load
│   │   ├── ml_detector.py         # TF-IDF + Logistic Regression classifier
│   │   ├── remediation.py         # Human-in-the-loop remediation
│   │   ├── audit_logger.py        # SQLite audit trail
│   │   └── feedback_learner.py    # Learning from human feedback
│   └── rag/
│       ├── knowledge_base.py      # ChromaDB RAG setup
│       └── tunisian_patterns.json # 8 Tunisian threat patterns
├── frontend/
│   └── index.html                 # Dashboard (single-page app, 4 tabs)
├── samples/
│   └── phishing_samples.json      # 5 demo samples (4 phishing + 1 legit)
├── docs/
│   ├── architecture.md            # Detailed architecture document
│   └── transparency_note.md       # Algorithm justification + bias management
├── tests/
│   └── test_analyzer.py           # Pipeline smoke tests
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard |
| GET | `/api/samples` | 5 demo phishing samples |
| POST | `/api/analyze` | Run 6-stage phishing analysis |
| POST | `/api/remediate/{id}` | Generate remediation actions |
| POST | `/api/actions/{id}/approve/{aid}` | Approve an action (human control) |
| POST | `/api/actions/{id}/reject/{aid}` | Reject an action (human control) |
| GET | `/api/remediation/{id}` | Get remediation status |
| GET | `/api/audit/logs` | Per-stage audit trail (6 events per analysis) |
| POST | `/api/feedback/{id}` | Submit feedback on AI accuracy |
| GET | `/api/feedback/stats` | Get learning statistics |
| GET | `/api/docs/architecture` | Architecture document |
| GET | `/api/docs/transparency` | Transparency note |
| GET | `/api/docs/stack` | Dockerfile + docker-compose |

## Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Backend | Python FastAPI | Async, fast, auto-docs, Pydantic validation |
| LLM | Groq (Llama 3.3 70B) | Free API, fast inference, multilingual |
| Vector DB | ChromaDB | Built-in embeddings, persistent, simple API |
| ML | scikit-learn (TF-IDF + LogReg) | Fast, interpretable, works with small datasets |
| Database | SQLite | Zero config, serverless, reliable |
| Frontend | HTML/CSS/JS (vanilla) | Single file, dark cyber theme, no framework |
| Container | Docker + docker-compose | Reproducible deployment |

## Team
- **Team Name:** CipherMind
- **Event:** Hackathon AI x Cybersecurity - Securinets FST (April 2026)
