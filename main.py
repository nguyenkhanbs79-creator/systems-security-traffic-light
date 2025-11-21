"""Entry point for the CI/CD security linter."""
from __future__ import annotations

import argparse

from models import AnalysisResult
from parser import parse_workflow
from report import generate_markdown_report
from rules import check_dangerous_commands, check_pipeline_design, check_secret_exposure
from scorer import classify_risk, compute_score, traffic_light


def main() -> None:
    """Run the CI/CD security linter from the command line."""

    parser = argparse.ArgumentParser(description="CI/CD Security Linter")
    parser.add_argument(
        "--workflow",
        required=True,
        help="Path to the GitHub Actions workflow YAML file",
    )
    parser.add_argument(
        "--output",
        default="report.md",
        help="Path to the output Markdown report",
    )

    args = parser.parse_args()

    workflow = parse_workflow(args.workflow)

    findings = []
    findings += check_secret_exposure(workflow)
    findings += check_dangerous_commands(workflow)
    findings += check_pipeline_design(workflow)

    score = compute_score(findings)
    risk_level = classify_risk(score)
    emoji = traffic_light(risk_level)

    result = AnalysisResult(findings=findings, score=score, risk_level=risk_level)
    generate_markdown_report(result, args.output)

    print("CI/CD Security Linter Result")
    print(f"Score: {score}/100")
    print(f"Risk level: {risk_level} {emoji}")
    print(f"Total findings: {len(findings)}")
    print()

    for finding in findings:
        location = f" in job {finding.job_id}" if finding.job_id else ""
        if finding.step_name:
            location += f" (step: {finding.step_name})"
        print(f"- [{finding.severity}] {finding.rule_id}{location}")

    print(f"Report saved to: {args.output}")


if __name__ == "__main__":
    main()
