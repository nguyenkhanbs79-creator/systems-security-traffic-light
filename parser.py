"""Workflow parsing utilities for the CI/CD security linter skeleton."""
from __future__ import annotations

from pathlib import Path

import yaml

from models import JobConfig, StepConfig, WorkflowConfig


def parse_workflow(workflow_path: str) -> WorkflowConfig:
    """Parse a GitHub Actions workflow YAML file into a WorkflowConfig object."""

    path = Path(workflow_path)
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    # Handle empty files or files that do not parse into a dictionary
    if not data:
        return WorkflowConfig(name=None, jobs=[])

    workflow_name = data.get("name") if isinstance(data, dict) else None
    jobs_data = data.get("jobs", {}) if isinstance(data, dict) else {}

    job_configs: list[JobConfig] = []
    for job_id, job_body in jobs_data.items():
        steps_data = job_body.get("steps", []) if isinstance(job_body, dict) else []
        step_configs: list[StepConfig] = []

        for step in steps_data:
            if not isinstance(step, dict):
                continue

            step_name = step.get("name")
            step_run = step.get("run")
            step_env = step.get("env") if isinstance(step.get("env"), dict) else {}

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
                name=job_body.get("name", job_id) if isinstance(job_body, dict) else job_id,
                steps=step_configs,
            )
        )

    return WorkflowConfig(name=workflow_name, jobs=job_configs)
from models import WorkflowConfig


def parse_workflow(workflow_path: str) -> WorkflowConfig:
    """
    Parse a GitHub Actions workflow YAML file and return a normalized
    WorkflowConfig object.
    In this step, do NOT implement real parsing logic yet.
    """
    raise NotImplementedError()
