"""Markdown report generator."""

from openapi_spec_validator.models.report import ValidationReport


def generate(report: ValidationReport) -> str:
    """Generate Markdown report."""
    lines = [
        f"# Validation Report: {report.spec_title}",
        f"\n**API Version:** {report.spec_version}",
        f"\n**Timestamp:** {report.timestamp.isoformat()}",
        f"\n**Status:** {'✓ PASSED' if report.passed else '✗ FAILED'}",
        f"\n**Total Findings:** {report.total_findings}",
        "\n---\n",
    ]

    if report.passed:
        lines.append("## Summary\nAll validations passed! ✓\n")
    else:
        lines.append("## Findings\n")
        lines.append("| Severity | Rule ID | Message |\n")
        lines.append("|----------|---------|----------|\n")

        for finding in report.findings:
            lines.append(
                f"| {finding.severity} | {finding.rule_id} | {finding.message} |\n"
            )

    return "".join(lines)
