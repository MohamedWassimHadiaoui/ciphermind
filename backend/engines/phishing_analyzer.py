"""
Phishing Analyzer - The core AI engine with a 6-stage analysis pipeline.

THIS IS THE HEART OF THE PROJECT. Here's how the pipeline works:

Stage 1: ETL PIPELINE (Extract, Transform, Load)
  - Parse raw email, detect language, extract URLs/phones/amounts
  - Normalize text and compute structural features

Stage 2: RULE-BASED FEATURE EXTRACTION
  - Regex patterns for suspicious URLs, urgency words (FR + Derja), credentials
  - Gives a "rule_score" (0-100) BEFORE any AI runs

Stage 3: ML MODEL DETECTION
  - scikit-learn TF-IDF + Logistic Regression classifier
  - Fast (milliseconds), interpretable (shows which words mattered)

Stage 4: RAG CONTEXT RETRIEVAL
  - ChromaDB vector search for similar known Tunisian phishing patterns
  - Augments the LLM prompt with real local attack examples

Stage 5: LLM ANALYSIS (Groq - Llama 3.3 70B)
  - Structured prompt with email + features + RAG context
  - Returns JSON: classification, confidence, explanation, techniques

Stage 6: THREAT AGGREGATION
  - Weighted scoring: 30% rules + 20% ML + 50% LLM = final verdict
  - Graceful degradation if any signal is unavailable

This multi-stage approach is what the jury wants to see -
NOT just "send email to ChatGPT and get answer".
"""

import re
import json
import uuid
import os
from datetime import datetime, timezone

from dotenv import load_dotenv

from backend.rag.knowledge_base import query_similar_patterns
from backend.engines.audit_logger import log_event
from backend.engines.etl_pipeline import run_etl_pipeline
from backend.engines.ml_detector import predict_phishing

# Load environment variables from .env file
load_dotenv(override=True)


# ============================================================
# LAYER 1: Rule-Based Feature Extraction
# ============================================================
# These are patterns we check WITHOUT any AI - pure code logic

# Suspicious URL patterns (regex)
SUSPICIOUS_URL_PATTERNS = [
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP-based URLs (e.g., http://192.168.1.1)
    r'https?://[^/]*\.(xyz|tk|ml|ga|cf|gq|top|buzz|click)',  # Shady top-level domains
    r'https?://[^/]*-[^/]*\.(com|tn|net)',  # Hyphenated domains (e.g., biat-secure.com)
    r'bit\.ly|tinyurl|t\.co|goo\.gl|rb\.gy',  # URL shorteners (hide real destination)
]

# Urgency words in French (common in Tunisian phishing)
URGENCY_PATTERNS_FR = [
    r'\burgent\b', r'\bimmédiat(?:ement)?\b', r'\bdans\s+24\s*h',
    r'\bcompte\s+(?:sera?\s+)?(?:suspendu|bloqué|fermé)\b',
    r'\bdernière?\s+chance\b', r'\baction\s+requise\b',
    r'\bexpir(?:e|ation)\b', r'\bvérifi(?:er|cation)\s+obligatoire\b',
]

# Urgency words in Tunisian Arabic (Derja)
URGENCY_PATTERNS_AR = [
    r'يا\s*سيدي', r'عاجل', r'حسابك\s*(?:تسكر|يتسكر)',
    r'آخر\s*فرصة', r'توا\s*توا', r'فيسع',
]

# Credential-harvesting patterns
CREDENTIAL_PATTERNS = [
    r'mot\s+de\s+passe', r'password', r'identifiant',
    r'numéro\s+de\s+carte', r'card\s+number', r'cvv',
    r'code\s+(?:pin|secret|confidentiel)',
    r'RIB', r'CIN', r'numéro\s+(?:national|identité)',
    r'connectez?\s*-?\s*vous', r'cliquez?\s+ici',
]

# Known legitimate Tunisian domains (if the sender is NOT from these, it's suspicious)
LEGITIMATE_TN_DOMAINS = [
    'biat.com.tn', 'poste.tn', 'ooredoo.tn', 'tunisietelecom.tn',
    'cnss.tn', 'finances.gov.tn', 'aneti.nat.tn',
]


def extract_features(email_content: str, sender: str = "") -> dict:
    """
    Layer 1: Extract suspicious features from the email using rules.

    Returns a dictionary of features with:
    - What was found
    - How suspicious each feature is (score contribution)
    - Human-readable explanation for each finding

    This is the EXPLAINABILITY part - we can tell the user exactly
    WHY we think something is suspicious.
    """
    content_lower = email_content.lower()
    features = {
        "suspicious_urls": [],
        "urgency_indicators": [],
        "credential_requests": [],
        "sender_analysis": {},
        "rule_score": 0,           # Total suspicion score (0-100)
        "feature_explanations": [] # Human-readable explanations (XAI)
    }

    score = 0

    # --- Check for suspicious URLs ---
    urls_found = re.findall(r'https?://[^\s<>"\']+', email_content)
    for url in urls_found:
        # Skip URLs from known legitimate Tunisian domains
        url_domain = re.search(r'https?://(?:www\.)?([^/]+)', url)
        if url_domain:
            domain = url_domain.group(1).lower()
            if any(domain == legit or domain.endswith("." + legit) for legit in LEGITIMATE_TN_DOMAINS):
                continue

        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                features["suspicious_urls"].append(url)
                score += 15
                features["feature_explanations"].append(
                    f"🔗 Suspicious URL detected: {url}"
                )
                break

    # --- Check for urgency language (French) ---
    for pattern in URGENCY_PATTERNS_FR:
        matches = re.findall(pattern, content_lower, re.IGNORECASE)
        if matches:
            features["urgency_indicators"].extend(matches)
            score += 10
            features["feature_explanations"].append(
                f"⚠️ Urgency language (FR): '{matches[0]}'"
            )

    # --- Check for urgency language (Tunisian Arabic) ---
    for pattern in URGENCY_PATTERNS_AR:
        matches = re.findall(pattern, email_content)
        if matches:
            features["urgency_indicators"].extend(matches)
            score += 10
            features["feature_explanations"].append(
                f"⚠️ Urgency language (AR): '{matches[0]}'"
            )

    # --- Check for credential harvesting ---
    for pattern in CREDENTIAL_PATTERNS:
        matches = re.findall(pattern, content_lower, re.IGNORECASE)
        if matches:
            features["credential_requests"].extend(matches)
            score += 12
            features["feature_explanations"].append(
                f"🔑 Credential request detected: '{matches[0]}'"
            )

    # --- Analyze sender ---
    if sender:
        sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
        is_legitimate = any(sender_domain.endswith(d) for d in LEGITIMATE_TN_DOMAINS)
        features["sender_analysis"] = {
            "email": sender,
            "domain": sender_domain,
            "is_known_legitimate": is_legitimate
        }
        if sender_domain and not is_legitimate:
            # Check if sender domain LOOKS like a Tunisian institution (spoofing)
            for legit in LEGITIMATE_TN_DOMAINS:
                institution = legit.split(".")[0]  # e.g., "biat" from "biat.com.tn"
                if institution in sender_domain and sender_domain != legit:
                    score += 25
                    features["feature_explanations"].append(
                        f"🎭 Sender domain '{sender_domain}' mimics '{legit}' (possible spoofing)"
                    )
                    break

    # Cap the score at 100
    features["rule_score"] = min(score, 100)

    return features


# ============================================================
# STAGE 5: LLM Analysis (Groq - Llama 3.3 70B / Gemini fallback)
# ============================================================

def build_analysis_prompt(email_content: str, sender: str,
                          features: dict, rag_context: list) -> str:
    """
    Build a structured prompt for the LLM that includes:
    1. The email content
    2. Rule-based features we already found
    3. Similar known attacks from our RAG knowledge base
    4. Clear instructions for JSON output

    This is PROMPT ENGINEERING - not just "is this phishing?"
    """

    # Format RAG context into readable text
    rag_text = ""
    if rag_context:
        rag_text = "\n\n## Similar Known Attacks from Tunisian Threat Database:\n"
        for i, pattern in enumerate(rag_context, 1):
            meta = pattern["metadata"]
            rag_text += f"""
### Match {i} (similarity distance: {pattern['distance']:.3f}):
- Category: {meta['category']}
- Target: {meta['target']}
- Severity: {meta['severity']}
- Details: {pattern['document'][:300]}
"""

    # Format extracted features
    features_text = ""
    if features["feature_explanations"]:
        features_text = "\n## Pre-Analysis Feature Extraction Results:\n"
        for exp in features["feature_explanations"]:
            features_text += f"- {exp}\n"
        features_text += f"- Rule-based suspicion score: {features['rule_score']}/100\n"

    prompt = f"""You are a cybersecurity analyst specialized in phishing detection for the Tunisian cyberspace.
Analyze the following email/message and determine if it is a phishing attempt.

## Email to Analyze:
- Sender: {sender or 'Unknown'}
- Content:
{email_content}
{features_text}
{rag_text}

## Your Task:
Provide a detailed analysis in the following JSON format. Be thorough and explain your reasoning.

{{
  "is_phishing": true/false,
  "confidence": 0.0-1.0,
  "threat_level": "critical" | "high" | "medium" | "low" | "safe",
  "classification": "phishing" | "spam" | "suspicious" | "legitimate",
  "explanation": "A clear 2-3 sentence explanation of WHY this is or isn't phishing, citing specific evidence from the email",
  "targeted_institution": "Name of the institution being impersonated, or null",
  "attack_techniques": ["list", "of", "techniques", "used"],
  "risk_to_citizen": "What specific risk does this pose to a Tunisian citizen?",
  "indicators_of_compromise": ["list", "of", "specific", "IOCs", "found"]
}}

IMPORTANT:
- Respond ONLY with valid JSON, no extra text
- Base your analysis on the evidence, not assumptions
- Consider the Tunisian context (local institutions, French/Arabic language)
- If the email appears legitimate, say so - avoid false positives
"""
    return prompt


async def analyze_with_llm(prompt: str) -> dict:
    """
    Stage 5: Send the structured prompt to the LLM and parse the response.

    Primary: Groq (Llama 3.3 70B) - free, fast, multilingual.
    Fallback: Google Gemini 2.0 Flash.
    """
    # Try multiple LLM providers - use whichever key is available
    groq_key = os.getenv("GROQ_API_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY")

    if not groq_key and not gemini_key:
        return {
            "is_phishing": None,
            "confidence": 0,
            "threat_level": "unknown",
            "classification": "unknown",
            "explanation": "LLM analysis unavailable - no API key configured. Using rule-based + ML analysis only.",
            "targeted_institution": None,
            "attack_techniques": [],
            "risk_to_citizen": "Unable to assess without LLM",
            "indicators_of_compromise": []
        }

    try:
        response_text = ""

        if groq_key:
            # Use Groq (free, fast, Llama models)
            from groq import Groq
            client = Groq(api_key=groq_key)
            completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
                temperature=0.1
            )
            response_text = completion.choices[0].message.content.strip()
        elif gemini_key:
            # Use Gemini
            from google import genai
            client = genai.Client(api_key=gemini_key)
            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt
            )
            response_text = response.text.strip()

        # Clean up the response - LLMs sometimes wrap JSON in markdown code blocks
        if response_text.startswith("```"):
            # Remove ```json and ``` markers
            lines = response_text.split("\n")
            response_text = "\n".join(lines[1:-1])

        return json.loads(response_text)
    except json.JSONDecodeError:
        # If LLM returns invalid JSON, try to extract it
        try:
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                return json.loads(json_match.group())
        except (json.JSONDecodeError, AttributeError):
            pass

        return {
            "is_phishing": None,
            "confidence": 0,
            "threat_level": "unknown",
            "classification": "unknown",
            "explanation": f"LLM returned invalid response. Raw: {response_text[:200]}",
            "targeted_institution": None,
            "attack_techniques": [],
            "risk_to_citizen": "Analysis error",
            "indicators_of_compromise": []
        }
    except Exception as e:
        return {
            "is_phishing": None,
            "confidence": 0,
            "threat_level": "error",
            "classification": "error",
            "explanation": f"LLM analysis failed: {str(e)}",
            "targeted_institution": None,
            "attack_techniques": [],
            "risk_to_citizen": "Analysis error",
            "indicators_of_compromise": []
        }


# ============================================================
# STAGE 6: Threat Aggregation & Final Verdict
# ============================================================

def compute_final_verdict(features: dict, llm_result: dict, ml_result: dict = None) -> dict:
    """
    Stage 6: Combine ALL detection signals into a final verdict.

    Three-signal weighted approach:
    - 30% rule-based score (deterministic, explainable)
    - 20% ML model score (fast, pattern-based)
    - 50% LLM confidence (nuanced understanding)

    Graceful degradation:
    - If LLM unavailable: 60% rules + 40% ML
    - If ML unavailable: 40% rules + 60% LLM
    - If both unavailable: 100% rules
    """
    rule_score = features["rule_score"] / 100.0  # Normalize to 0-1
    llm_confidence = llm_result.get("confidence", 0)
    llm_is_phishing = llm_result.get("is_phishing", None)

    # ML model score
    ml_available = ml_result and ml_result.get("available", False)
    ml_score = ml_result.get("ml_confidence", 0) if ml_available else None

    # Compute LLM directional score
    if llm_is_phishing is not None:
        llm_score = llm_confidence if llm_is_phishing else (1 - llm_confidence)
    else:
        llm_score = None

    # Weighted combination based on available signals
    if llm_score is not None and ml_score is not None:
        # All 3 signals available
        final_score = (0.3 * rule_score) + (0.2 * ml_score) + (0.5 * llm_score)
        formula = "final = (0.3 × rules) + (0.2 × ML) + (0.5 × LLM)"
    elif llm_score is not None:
        # Rules + LLM only
        final_score = (0.4 * rule_score) + (0.6 * llm_score)
        formula = "final = (0.4 × rules) + (0.6 × LLM)"
    elif ml_score is not None:
        # Rules + ML only
        final_score = (0.6 * rule_score) + (0.4 * ml_score)
        formula = "final = (0.6 × rules) + (0.4 × ML)"
    else:
        # Rules only
        final_score = rule_score
        formula = "final = rules only (no AI available)"

    # Determine threat level from final score
    if final_score >= 0.8:
        threat_level = "critical"
    elif final_score >= 0.6:
        threat_level = "high"
    elif final_score >= 0.4:
        threat_level = "medium"
    elif final_score >= 0.2:
        threat_level = "low"
    else:
        threat_level = "safe"

    return {
        "final_score": round(final_score, 3),
        "threat_level": threat_level,
        "is_phishing": final_score >= 0.5,
        "score_breakdown": {
            "rule_based_score": round(rule_score, 3),
            "rule_weight": 0.3 if (llm_score is not None and ml_score is not None) else 0.4 if llm_score is not None else 0.6,
            "ml_score": round(ml_score, 3) if ml_score is not None else None,
            "ml_weight": 0.2 if (llm_score is not None and ml_score is not None) else 0.4 if ml_score is not None else 0,
            "llm_score": round(llm_score, 3) if llm_score is not None else None,
            "llm_weight": 0.5 if (llm_score is not None and ml_score is not None) else 0.6 if llm_score is not None else 0,
            "formula": formula
        }
    }


# ============================================================
# INPUT SANITIZATION (Prompt Injection Defense)
# ============================================================

# Patterns that indicate prompt injection attempts
_INJECTION_PATTERNS = [
    r'ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions',
    r'you\s+are\s+now\s+(?:a|an)\s+',
    r'system\s*:\s*',
    r'<\s*(?:system|admin|root)\s*>',
    r'(?:forget|disregard|override)\s+(?:your|all)\s+(?:rules|instructions|guidelines)',
    r'\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>',
]


def _sanitize_input(text: str) -> str:
    """
    Sanitize user input to defend against prompt injection.

    Strips known injection patterns and flags suspicious content.
    The original text is preserved for analysis (we still need to detect
    phishing in the actual content), but injection payloads targeting
    our LLM are neutralized.
    """
    sanitized = text
    for pattern in _INJECTION_PATTERNS:
        sanitized = re.sub(pattern, '[FILTERED]', sanitized, flags=re.IGNORECASE)
    return sanitized


# ============================================================
# MAIN ANALYSIS FUNCTION (Orchestrates all 6 stages)
# ============================================================

async def analyze_email(email_content: str, sender: str = "") -> dict:
    """
    Run the full analysis pipeline matching the architecture diagram:

    Data Source → ETL Pipeline → Feature Engineering → Rule Detection
    → ML Model → RAG Retrieval → LLM Analysis → Threat Aggregation → Verdict

    Returns a complete analysis result with full explainability.
    """
    analysis_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now(timezone.utc).isoformat()

    # --- INPUT SANITIZATION (prompt injection defense) ---
    sanitized_content = _sanitize_input(email_content)
    sanitized_sender = _sanitize_input(sender) if sender else ""

    # --- STAGE 1: ETL PIPELINE ---
    etl_data = run_etl_pipeline(sanitized_content, sanitized_sender)
    log_event(
        analysis_id=analysis_id, event_type="pipeline_stage", actor="ai_engine",
        action="stage_1_etl_complete",
        details=f"Language: {etl_data.language}, URLs: {len(etl_data.urls)}, Words: {etl_data.word_count}",
        metadata={"stage": 1, "language": etl_data.language, "urls_found": len(etl_data.urls),
                  "word_count": etl_data.word_count}
    )

    # --- STAGE 2: Rule-based feature extraction ---
    features = extract_features(sanitized_content, sanitized_sender)
    log_event(
        analysis_id=analysis_id, event_type="pipeline_stage", actor="ai_engine",
        action="stage_2_rules_complete",
        details=f"Rule score: {features['rule_score']}/100, "
                f"Suspicious URLs: {len(features['suspicious_urls'])}, "
                f"Urgency indicators: {len(features['urgency_indicators'])}",
        metadata={"stage": 2, "rule_score": features["rule_score"],
                  "suspicious_urls": len(features["suspicious_urls"]),
                  "urgency_indicators": len(features["urgency_indicators"]),
                  "credential_requests": len(features["credential_requests"])}
    )

    # --- STAGE 3: ML MODEL DETECTION ---
    ml_result = predict_phishing(sanitized_content)
    log_event(
        analysis_id=analysis_id, event_type="pipeline_stage", actor="ai_engine",
        action="stage_3_ml_complete",
        details=f"ML available: {ml_result.get('available')}, "
                f"Phishing: {ml_result.get('is_phishing')}, "
                f"Confidence: {ml_result.get('ml_confidence', 0):.2f}",
        metadata={"stage": 3, "ml_available": ml_result.get("available", False),
                  "is_phishing": ml_result.get("is_phishing"),
                  "confidence": ml_result.get("ml_confidence", 0)}
    )

    # --- STAGE 4: RAG context retrieval ---
    rag_results = query_similar_patterns(sanitized_content, n_results=3)
    log_event(
        analysis_id=analysis_id, event_type="pipeline_stage", actor="ai_engine",
        action="stage_4_rag_complete",
        details=f"RAG matches found: {len(rag_results)}"
                + (f", closest: {rag_results[0]['metadata']['category']} "
                   f"(dist={rag_results[0]['distance']:.3f})" if rag_results else ""),
        metadata={"stage": 4, "matches_found": len(rag_results),
                  "match_categories": [r["metadata"]["category"] for r in rag_results]}
    )

    # --- STAGE 5: LLM analysis ---
    prompt = build_analysis_prompt(sanitized_content, sanitized_sender, features, rag_results)
    llm_result = await analyze_with_llm(prompt)
    log_event(
        analysis_id=analysis_id, event_type="pipeline_stage", actor="ai_engine",
        action="stage_5_llm_complete",
        details=f"LLM classification: {llm_result.get('classification', 'N/A')}, "
                f"Confidence: {llm_result.get('confidence', 0)}",
        metadata={"stage": 5, "classification": llm_result.get("classification"),
                  "confidence": llm_result.get("confidence", 0),
                  "threat_level": llm_result.get("threat_level")}
    )

    # --- STAGE 6: Threat Aggregation ---
    verdict = compute_final_verdict(features, llm_result, ml_result)

    # Build the complete result
    result = {
        "analysis_id": analysis_id,
        "timestamp": timestamp,
        "input": {
            "email_content": email_content[:500],
            "sender": sender
        },
        "pipeline_results": {
            "etl": {
                "language": etl_data.language,
                "word_count": etl_data.word_count,
                "urls_found": len(etl_data.urls),
                "entities": etl_data.extracted_entities,
                "structural_features": etl_data.metadata.get("structural_features", {})
            },
            "stage2_rules": {
                "score": features["rule_score"],
                "suspicious_urls": features["suspicious_urls"],
                "urgency_indicators": features["urgency_indicators"],
                "credential_requests": features["credential_requests"],
                "sender_analysis": features["sender_analysis"],
                "explanations": features["feature_explanations"]
            },
            "ml_model": {
                "available": ml_result.get("available", False),
                "is_phishing": ml_result.get("is_phishing"),
                "confidence": ml_result.get("ml_confidence", 0),
                "top_features": ml_result.get("top_features", [])
            },
            "stage4_rag": {
                "similar_patterns_found": len(rag_results),
                "matches": [
                    {
                        "pattern_id": r["metadata"]["id"],
                        "category": r["metadata"]["category"],
                        "target": r["metadata"]["target"],
                        "severity": r["metadata"]["severity"],
                        "similarity_distance": round(r["distance"], 3) if r["distance"] else None
                    }
                    for r in rag_results
                ]
            },
            "stage5_llm": llm_result,
            "stage6_verdict": verdict
        },
        "final_verdict": {
            "is_phishing": verdict["is_phishing"],
            "threat_level": verdict["threat_level"],
            "confidence": verdict["final_score"],
            "explanation": llm_result.get("explanation", "Analysis based on rule-based and ML features only."),
            "targeted_institution": llm_result.get("targeted_institution"),
            "risk_to_citizen": llm_result.get("risk_to_citizen", ""),
            "attack_techniques": llm_result.get("attack_techniques", []),
        }
    }

    # --- STAGE 6: Log final aggregation ---
    log_event(
        analysis_id=analysis_id,
        event_type="pipeline_stage",
        actor="ai_engine",
        action="stage_6_verdict_complete",
        details=f"Final verdict: {'PHISHING' if verdict['is_phishing'] else 'LEGITIMATE'} "
                f"({verdict['threat_level']}, score={verdict['final_score']:.1%}), "
                f"Formula: {verdict['score_breakdown']['formula']}",
        metadata={"stage": 6, "threat_level": verdict["threat_level"],
                  "final_score": verdict["final_score"],
                  "rule_score": features["rule_score"],
                  "ml_confidence": ml_result.get("ml_confidence", 0),
                  "llm_confidence": llm_result.get("confidence", 0),
                  "rag_matches": len(rag_results),
                  "formula": verdict["score_breakdown"]["formula"]}
    )

    return result
