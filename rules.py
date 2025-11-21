"""Security rule implementations for the CI/CD security linter."""
from __future__ import annotations

import re

from models import Finding, WorkflowConfig


def _run_looks_like_secret(cmd: str) -> bool:
    """Return True if a run command appears to contain hard-coded secrets."""

    lowered = cmd.lower()

    # Simple keyword checks
    if "api_key=" in lowered or "token=" in lowered or "password" in lowered:
        return True

    # Heuristic for long random-looking strings (potential tokens)
    return bool(re.search(r"[A-Za-z0-9]{20,}", cmd))


def _env_contains_secret(env: dict[str, str]) -> bool:
    """Return True if environment variables look like they include secrets."""

    for key, value in env.items():
        lowered_key = key.lower()
        if any(token in lowered_key for token in ("key", "token", "secret", "password")):
            if isinstance(value, str) and value.strip():
                return True
    return False


def check_secret_exposure(workflow: WorkflowConfig) -> list[Finding]:
    """
    Detect potential secret exposure in workflow run commands or environment variables.
    """

    findings: list[Finding] = []

    for job in workflow.jobs:
        for index, step in enumerate(job.steps):
            cmd = step.run or ""
            env = step.env or {}

            if _run_looks_like_secret(cmd) or _env_contains_secret(env):
                findings.append(
                    Finding(
                        id=f"{job.id}_{index}_secret_exposure",
                        severity="HIGH",
                        rule_id="SECRET_EXPOSURE",
                        title=f"Possible secret exposure in job '{job.id}'",
                        description="Run command or environment variables appear to contain hard-coded secrets.",
                        job_id=job.id,
                        step_name=step.name,
                    )
                )

    return findings


def _is_dangerous_command(run: str | None) -> bool:
    """Return True if a command includes download-and-execute patterns."""

    if not run:
        return False
    cmd = run.lower()
    return ("curl" in cmd and "bash" in cmd) or ("wget" in cmd and "sh" in cmd)


def check_dangerous_commands(workflow: WorkflowConfig) -> list[Finding]:
    """
    Rule: detect dangerous command patterns such as curl|bash or wget|sh.
    """

    findings: list[Finding] = []

    for job in workflow.jobs:
        for index, step in enumerate(job.steps):
            if _is_dangerous_command(step.run):
                findings.append(
                    Finding(
                        id=f"{job.id}_dangerous_command_{index}",
                        severity="HIGH",
                        rule_id="DANGEROUS_COMMAND",
                        title=f"Dangerous command pattern in job '{job.id}'",
                        description=(
                            "This step uses a potentially dangerous download-and-execute pattern "
                            "such as 'curl | bash' or 'wget | sh', which can be abused by attackers."
                        ),
                        job_id=job.id,
                        step_name=step.name,
                    )
                )

    return findings


def _job_matches(job_id: str, job_name: str | None, keyword: str) -> bool:
    """Check whether a job id or name contains the given keyword (case-insensitive)."""

    jid = job_id.lower()
    jname = (job_name or "").lower()
    return keyword in jid or keyword in jname


def _workflow_has_quality_steps(workflow: WorkflowConfig) -> bool:
    """Determine whether any step mentions quality or security related keywords."""

    keywords = ("test", "lint", "scan", "security", "audit")
    for job in workflow.jobs:
        for step in job.steps:
            text = f"{step.name or ''} {step.run or ''}".lower()
            if any(keyword in text for keyword in keywords):
                return True
    return False


def check_pipeline_design(workflow: WorkflowConfig) -> list[Finding]:
    """
    Check pipeline design issues such as missing tests before deploy
    or absent quality/security steps.
    """

    findings: list[Finding] = []

    deploy_jobs = [job for job in workflow.jobs if _job_matches(job.id, job.name, "deploy")]
    test_jobs = [job for job in workflow.jobs if _job_matches(job.id, job.name, "test")]

    if deploy_jobs and not test_jobs:
        findings.append(
            Finding(
                id="pipeline_missing_test_before_deploy",
                severity="MEDIUM",
                rule_id="WEAK_PIPELINE_DESIGN",
                title="Deploy jobs found without explicit test jobs",
                description=(
                    "The workflow defines deployment jobs but does not contain any explicit test jobs. "
                    "This increases the risk of releasing untested changes."
                ),
                job_id=deploy_jobs[0].id if deploy_jobs else None,
                step_name=None,
            )
        )

    if not _workflow_has_quality_steps(workflow):
        findings.append(
            Finding(
                id="pipeline_missing_quality_checks",
                severity="LOW",
                rule_id="WEAK_PIPELINE_DESIGN",
                title="No explicit quality or security checks detected",
                description=(
                    "No steps mentioning test, lint, scan, security, or audit were detected. "
                    "Consider adding explicit quality and security checks in the pipeline."
                ),
                job_id=None,
                step_name=None,
            )
        )

    return findings
