"""Security rule stubs for the CI/CD security linter skeleton."""
from __future__ import annotations

import re

from models import Finding, WorkflowConfig


def _run_looks_like_secret(cmd: str) -> bool:
    """Return True if a run command appears to contain hard-coded secrets."""

    lowered = cmd.lower()
    if "api_key=" in lowered or "token=" in lowered or "password" in lowered:
        return True
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


def check_dangerous_commands(workflow: WorkflowConfig) -> list[Finding]:
    """
    Rule: detect dangerous command patterns such as curl|bash or wget|sh.
    """

    def _is_dangerous_command(run: str | None) -> bool:
        if not run:
            return False
        cmd = run.lower()
        return ("curl" in cmd and "bash" in cmd) or ("wget" in cmd and "sh" in cmd)

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


def check_pipeline_design(workflow: WorkflowConfig) -> list[Finding]:
    """
    Rule: check basic pipeline design issues: missing test jobs, missing security/audit steps, etc.
    Stub only in this step.
    """
    raise NotImplementedError()
