"""Scoring utilities for the CI/CD security linter skeleton."""
from models import Finding


def compute_score(findings: list[Finding]) -> int:
    """
    Compute an overall security score (0–100) based on findings.
    In this step, do not implement the scoring logic yet.
    """
    raise NotImplementedError()


def classify_risk(score: int) -> str:
    """
    Classify risk level from the score: LOW, MEDIUM, or HIGH.
    In this step, do not implement the actual thresholds yet.
    """
    raise NotImplementedError()
