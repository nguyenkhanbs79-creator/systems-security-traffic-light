"""Security rule stubs for the CI/CD security linter skeleton."""
from models import Finding, WorkflowConfig


def check_secret_exposure(workflow: WorkflowConfig) -> list[Finding]:
    """
    Rule: detect potential secret exposure (hard-coded API keys, tokens, passwords).
    For now, this is just a stub with no real implementation.
    """
    raise NotImplementedError()


def check_dangerous_commands(workflow: WorkflowConfig) -> list[Finding]:
    """
    Rule: detect dangerous command patterns such as curl|bash or wget|sh.
    Stub only in this step.
    """
    raise NotImplementedError()


def check_pipeline_design(workflow: WorkflowConfig) -> list[Finding]:
    """
    Rule: check basic pipeline design issues: missing test jobs, missing security/audit steps, etc.
    Stub only in this step.
    """
    raise NotImplementedError()
