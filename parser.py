"""Workflow parsing utilities for the CI/CD security linter."""
from __future__ import annotations

from pathlib import Path
import yaml

from models import JobConfig, StepConfig, WorkflowConfig


def parse_workflow(workflow_path: str) -> WorkflowConfig:
    """Parse a GitHub Actions workflow YAML file into a WorkflowConfig object."""

    path = Path(workflow_path)
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    # Handle empty files or non-dict YAML roots
    if not isinstance(data, dict) or not data:
        return WorkflowConfig(name=None, jobs=[])

    workflow_name = data.get("name")
    jobs_data = data.get("jobs", {})

    # Jobs must be a dict; otherwise treat as empty
    if not isinstance(jobs_data, dict):
        jobs_data = {}

    job_configs: list[JobConfig] = []

    for job_id, job_body in jobs_data.items():
        if not isinstance(job_body, dict):
            # Skip malformed job entries
            continue

        steps_data = job_body.get("steps", [])
        if not isinstance(steps_data, list):
            steps_data = []

        step_configs: list[StepConfig] = []

        for step in steps_data:
            if not isinstance(step, dict):
                continue

            step_name = step.get("name")
            step_run = step.get("run")

            step_env = step.get("env", {})
            if not isinstance(step_env, dict):
                step_env = {}

            step_configs.append(
                StepConfig(
                    name=step_name,
                    run=step_run,
                    env=step_env,
                )
            )

        job_configs.append(
            JobConfig(
                id=job_id,
                name=job_body.get("name", job_id),
                steps=step_configs,
            )
        )

    return WorkflowConfig(name=workflow_name, jobs=job_configs)
