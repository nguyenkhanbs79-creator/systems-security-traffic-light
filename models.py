"""Data models for the CI/CD security linter skeleton."""
from dataclasses import dataclass, field


@dataclass
class StepConfig:
    """Represents a single CI step configuration."""

    name: str | None = None
    run: str | None = None
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class JobConfig:
    """Represents a CI job configuration."""

    id: str
    name: str | None = None
    steps: list[StepConfig] = field(default_factory=list)


@dataclass
class WorkflowConfig:
    """Represents a CI/CD workflow configuration."""

    name: str | None = None
    jobs: list[JobConfig] = field(default_factory=list)


@dataclass
class Finding:
    """Represents a security finding detected in the workflow."""

    id: str
    severity: str
    rule_id: str
    title: str
    description: str
    job_id: str | None = None
    step_name: str | None = None


@dataclass
class AnalysisResult:
    """Represents the aggregated CI/CD security analysis result."""

    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    risk_level: str = "LOW"
