"""
Learning / Adaptation Module - Learns from human feedback.

WHY THIS EXISTS:
The architecture diagram shows a "Learning / Adaptation Module" that feeds back
into the ML Model Detection. This creates a FEEDBACK LOOP:

  AI analyzes email → Human approves/rejects → System learns from decision

HOW IT WORKS:
1. Every time a human approves or rejects a remediation action, we record
   the original email content and the human's decision
2. This feedback is stored in a JSON file (persistent across restarts)
3. When enough feedback accumulates, it can be used to retrain the ML model
4. The dashboard shows feedback statistics

This addresses the "Adaptatif" (Adaptive) phase from the hackathon requirements:
"Apprendre des nouvelles techniques d'attaque"
"""

import json
import os
from datetime import datetime, timezone

FEEDBACK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "feedback_data.json"
)


def _load_feedback() -> list:
    """Load existing feedback from disk."""
    if os.path.exists(FEEDBACK_PATH):
        try:
            with open(FEEDBACK_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


def _save_feedback(feedback: list):
    """Save feedback to disk."""
    with open(FEEDBACK_PATH, "w", encoding="utf-8") as f:
        json.dump(feedback, f, indent=2, ensure_ascii=False)


def record_feedback(analysis_id: str, email_content: str, ai_verdict: bool,
                    human_agreed: bool, threat_level: str = ""):
    """
    Record human feedback on an AI decision.

    Parameters:
    - analysis_id: Which analysis this feedback is for
    - email_content: The original email that was analyzed
    - ai_verdict: What the AI said (True=phishing, False=legitimate)
    - human_agreed: Did the human agree with the AI?
    - threat_level: The AI's threat level assessment
    """
    feedback = _load_feedback()

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "analysis_id": analysis_id,
        "email_snippet": email_content[:200],  # Store a snippet only
        "ai_verdict_phishing": ai_verdict,
        "human_agreed": human_agreed,
        "correct_label": ai_verdict if human_agreed else (not ai_verdict),
        "threat_level": threat_level
    }

    feedback.append(entry)
    _save_feedback(feedback)

    return entry


def get_feedback_stats() -> dict:
    """
    Get statistics about human feedback.
    Shows how often the AI was correct/incorrect.
    """
    feedback = _load_feedback()

    if not feedback:
        return {
            "total_feedback": 0,
            "ai_accuracy": None,
            "agreement_rate": None,
            "false_positives": 0,
            "false_negatives": 0,
            "feedback_entries": []
        }

    total = len(feedback)
    agreements = sum(1 for f in feedback if f["human_agreed"])
    false_positives = sum(1 for f in feedback if f["ai_verdict_phishing"] and not f["human_agreed"])
    false_negatives = sum(1 for f in feedback if not f["ai_verdict_phishing"] and not f["human_agreed"])

    return {
        "total_feedback": total,
        "ai_accuracy": round(agreements / total, 3) if total > 0 else None,
        "agreement_rate": f"{agreements}/{total}",
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "feedback_entries": feedback[-10:]  # Last 10 entries
    }


def get_training_data_from_feedback() -> list:
    """
    Convert accumulated human feedback into training data
    that can be used to retrain the ML model.

    Returns list of (text, label) tuples where label is the
    HUMAN-CORRECTED label, not the AI's original prediction.
    """
    feedback = _load_feedback()

    training_data = []
    for entry in feedback:
        text = entry["email_snippet"]
        # Use the human-corrected label
        label = 1 if entry["correct_label"] else 0
        training_data.append((text, label))

    return training_data
