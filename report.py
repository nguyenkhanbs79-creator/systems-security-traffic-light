"""Markdown report generator for the CI/CD security linter."""
from __future__ import annotations

from typing import Iterable

from models import AnalysisResult, Finding
from scorer import traffic_light


def _format_findings_table(findings: Iterable[Finding]) -> str:
    lines = [
        "| Severity | Rule | Job | Step | Title | Description |",
        "|---|---|---|---|---|---|",
    ]

    for finding in findings:
        job = finding.job_id if finding.job_id is not None else "-"
        step = finding.step_name if finding.step_name is not None else "-"
        lines.append(
            "| {severity} | {rule} | {job} | {step} | {title} | {description} |".format(
                severity=finding.severity,
                rule=finding.rule_id,
                job=job,
                step=step,
                title=finding.title,
                description=finding.description,
            )
        )

    return "\n".join(lines)


def _build_recommendations(findings: Iterable[Finding]) -> list[str]:
    seen_rules: set[str] = set()
    recommendations: list[str] = []

    for finding in findings:
        if finding.rule_id in seen_rules:
            continue
        seen_rules.add(finding.rule_id)

        if finding.rule_id == "SECRET_EXPOSURE":
            recommendations.append(
                "- Use GitHub Secrets (e.g., `${{ secrets.MY_SECRET }}`) instead of hard-coding sensitive values."
            )
        elif finding.rule_id == "DANGEROUS_COMMAND":
            recommendations.append(
                "- Avoid piping remote scripts directly to shells; commit scripts to the repo and verify checksums before execution."
            )
        elif finding.rule_id == "WEAK_PIPELINE_DESIGN":
            recommendations.append(
                "- Add explicit test, lint, or security audit jobs before deployment to reduce release risk."
            )

    if not recommendations:
        recommendations.append("- No recommendations. Your pipeline looks good!")

    return recommendations


def generate_markdown_report(result: AnalysisResult, output_path: str) -> None:
    """Generate a Markdown report summarizing the CI/CD security analysis."""

    emoji = traffic_light(result.risk_level)

    summary_lines = [
        "# CI/CD Security Linter Report",
        "",
        "## Summary",
        f"- Score: {result.score}/100",
        f"- Risk level: {result.risk_level} {emoji}",
        f"- Total findings: {len(result.findings)}",
        "",
    ]

    findings_lines: list[str] = ["## Findings", ""]
    if not result.findings:
        findings_lines.append("No issues detected.")
    else:
        findings_lines.append(_format_findings_table(result.findings))
        findings_lines.append("")

    recommendations = _build_recommendations(result.findings)
    recommendation_lines = ["## Recommendations", ""]
    recommendation_lines.extend(recommendations)

    content = "\n".join(summary_lines + findings_lines + recommendation_lines) + "\n"

    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.write(content)
