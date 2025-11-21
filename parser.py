"""Workflow parsing utilities for the CI/CD security linter skeleton."""
from models import WorkflowConfig


def parse_workflow(workflow_path: str) -> WorkflowConfig:
    """
    Parse a GitHub Actions workflow YAML file and return a normalized
    WorkflowConfig object.
    In this step, do NOT implement real parsing logic yet.
    """
    raise NotImplementedError()
