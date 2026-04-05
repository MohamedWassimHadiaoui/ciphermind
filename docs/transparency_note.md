# Transparency Note - CipherMind AI Cyber Shield

## 1. Algorithms & Models Used

### ETL Pipeline (Stage 1)
- **Algorithm:** Regex-based entity extraction + rule-based language detection
- **Why:** Structures raw input before any AI processing; shows data engineering depth
- **Limitations:** Simple language detection (character frequency + keyword matching)

### Rule-Based Engine (Stage 2)
- **Algorithm:** Regular expression pattern matching
- **Why:** Deterministic, fully explainable, zero false positives for known patterns
- **Limitations:** Cannot detect novel phishing techniques not covered by rules

### ML Classifier (Stage 3)
- **Model:** scikit-learn TF-IDF + Logistic Regression
- **Why:** Fast (milliseconds), interpretable coefficients, works with small datasets
- **Training Data:** 27 samples (15 phishing + 12 legitimate, Tunisian context)
- **Limitations:** Small training set; needs more data for production accuracy

### RAG - Retrieval Augmented Generation (Stage 4)
- **Model:** ChromaDB with default embedding model (all-MiniLM-L6-v2)
- **Why:** Enables similarity search against known Tunisian phishing patterns without fine-tuning
- **Limitations:** Quality depends on the knowledge base coverage (currently 8 patterns)

### LLM Analysis (Stage 5)
- **Model:** Groq (Llama 3.3 70B) - primary; Google Gemini 2.0 Flash - fallback
- **Why:** Free API, fast inference, good multilingual support (French/Arabic)
- **Limitations:** May hallucinate; requires structured prompting and JSON output validation

### Weighted Scoring / Threat Aggregation (Stage 6)
- **Formula:** `final_score = (0.3 × rules) + (0.2 × ML) + (0.5 × LLM)`
- **Fallback:** `(0.6 × rules) + (0.4 × ML)` when LLM is unavailable
- **Why:** Combines deterministic rules (reliable) with ML (fast) and LLM (nuanced)
- **The 30/20/50 split ensures no single signal dominates the verdict**

## 2. Dataset & Knowledge Base

### Source
- 8 phishing patterns manually curated from publicly reported Tunisian phishing campaigns
- 27 ML training samples (15 phishing + 12 legitimate) with Tunisian context
- Patterns cover: BIAT, La Poste, Ooredoo, Tunisie Telecom, CNSS, e-Dinar Smart, job scams, crypto scams

### Bias Management
- **Language bias:** Patterns include both French and Tunisian Arabic (Derja) to avoid missing non-French attacks
- **False positive mitigation:** Demo sample #5 is a legitimate BIAT email to test that the system doesn't over-flag
- **Confidence thresholds:** The system reports confidence levels rather than binary yes/no, letting humans make the final call
- **Human override:** Operators can reject any AI decision, and feedback is stored for improvement

## 3. AI Defense Measures

### Prompt Injection Protection
- User input is clearly delimited in the prompt with section headers
- The LLM is instructed to respond ONLY with JSON, reducing the attack surface
- Post-processing validates the JSON structure before displaying results

### Hallucination Mitigation
- Rule-based layer provides ground truth independent of the LLM
- RAG context gives the LLM real examples instead of relying on training data
- Weighted scoring limits the LLM's influence to 50% of the final score

### Human Oversight
- All remediation actions require explicit human approval
- Full audit trail enables post-incident review
- The dashboard shows the AI's reasoning for every decision
- Feedback loop allows humans to correct AI mistakes

## 4. Data Sovereignty

- All data is processed locally (no external data storage)
- SQLite database stays on the local machine
- ChromaDB vector store is local
- Only the LLM API call sends data externally (to Groq's API)
- In production, this could be replaced with a locally-hosted LLM for full sovereignty

## 5. Limitations & Known Issues

1. The knowledge base is small (8 patterns) - a production system would need continuous updates
2. ML training set is small (27 samples) - accuracy improves with more data
3. The LLM may produce inconsistent results for edge cases
4. Email header analysis (SPF, DKIM) is not implemented in the MVP
5. The remediation execution is simulated - real integration would require organizational infrastructure
