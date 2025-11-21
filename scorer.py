"""Scoring utilities for the CI/CD security linter skeleton."""
from models import Finding


def compute_score(findings: list[Finding]) -> int:
    """Compute an overall security score (0–100) based on findings."""

    severity_weights = {
        "HIGH": 30,
        "MEDIUM": 15,
        "LOW": 5,
    }

    total = 0
    for finding in findings:
        total += severity_weights.get(finding.severity, 0)

    return min(total, 100)


def classify_risk(score: int) -> str:
    """Classify risk level from the score: LOW, MEDIUM, or HIGH."""

    if score <= 30:
        return "LOW"
    if score <= 70:
        return "MEDIUM"
    return "HIGH"


def traffic_light(risk_level: str) -> str:
    """
    Map risk level to a traffic-light emoji:
    LOW -> 🟩
    MEDIUM -> 🟨
    HIGH -> 🟥
    """

    mapping = {
        "LOW": "🟩",
        "MEDIUM": "🟨",
        "HIGH": "🟥",
    }

    return mapping.get(risk_level, "⬜")
