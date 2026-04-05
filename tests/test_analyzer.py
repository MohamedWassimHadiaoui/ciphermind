"""Basic smoke tests for CipherMind pipeline."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.engines.etl_pipeline import run_etl_pipeline, EmailData
from backend.engines.ml_detector import init_ml_model, predict_phishing
from backend.engines.phishing_analyzer import extract_features


def test_etl_pipeline():
    """Verify ETL pipeline processes email correctly."""
    result = run_etl_pipeline(
        "Votre compte sera suspendu. Cliquez ici: http://fake-biat.com/verify",
        "scam@fake-biat.com"
    )
    assert isinstance(result, EmailData)
    assert result.language == "french"
    assert len(result.urls) > 0
    assert result.word_count > 0
    print("  ETL pipeline: OK")


def test_rule_engine():
    """Verify rule-based feature extraction finds patterns."""
    features = extract_features(
        "Urgent! Votre compte sera suspendu dans 24h. "
        "Cliquez ici: http://biat-secure.com/verify. "
        "Entrez votre mot de passe et code PIN.",
        "alert@biat-secure.com"
    )
    assert features["rule_score"] > 0
    assert len(features["suspicious_urls"]) > 0
    assert len(features["urgency_indicators"]) > 0
    assert len(features["credential_requests"]) > 0
    assert len(features["feature_explanations"]) > 0
    print(f"  Rule engine: OK (score={features['rule_score']})")


def test_ml_detector():
    """Verify ML model trains and predicts."""
    init_ml_model()
    result = predict_phishing("Votre compte sera suspendu urgent mot de passe")
    assert result["available"] is True
    assert isinstance(result["is_phishing"], bool)
    assert 0 <= result["ml_confidence"] <= 1
    assert len(result["top_features"]) > 0
    print(f"  ML detector: OK (phishing={result['is_phishing']}, conf={result['ml_confidence']:.2f})")


def test_legitimate_email():
    """Verify legitimate email gets low score."""
    features = extract_features(
        "Nous avons le plaisir de vous informer que les nouveaux taux sont disponibles. "
        "Consultez https://www.biat.com.tn/epargne pour plus de détails.",
        "newsletter@biat.com.tn"
    )
    assert features["rule_score"] < 50, f"Legit email scored too high: {features['rule_score']}"
    print(f"  Legitimate email test: OK (score={features['rule_score']})")


if __name__ == "__main__":
    print("Running CipherMind smoke tests...\n")
    test_etl_pipeline()
    test_rule_engine()
    test_ml_detector()
    test_legitimate_email()
    print("\nAll tests passed!")
