"""Command-line interface for OpenAPI spec validation."""

import argparse
import sys
from pathlib import Path
import httpx
import yaml
from rich.console import Console
from rich.table import Table
from openapi_spec_validator.validator import SpecValidator
from openapi_spec_validator.reporters import json_reporter, markdown_reporter

console = Console()


def load_spec(spec_path: str) -> dict:
    """Load OpenAPI spec from file or URL."""
    if spec_path.startswith(("http://", "https://")):
        response = httpx.get(spec_path)
        response.raise_for_status()
        return yaml.safe_load(response.text) or {}
    else:
        with open(spec_path) as f:
            return yaml.safe_load(f) or {}


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Validate OpenAPI specs against OWASP API Security Top 10"
    )
    parser.add_argument("spec", help="Path to OpenAPI spec file or URL")
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file (default: stdout)",
    )

    args = parser.parse_args()

    try:
        console.print("[cyan]Loading OpenAPI spec...[/cyan]")
        spec = load_spec(args.spec)

        console.print("[cyan]Validating against rules...[/cyan]")
        validator = SpecValidator()
        report = validator.validate_spec(spec)

        # Generate output
        if args.format == "json":
            output = json_reporter.generate(report)
        elif args.format == "markdown":
            output = markdown_reporter.generate(report)
        else:
            output = _format_text_output(report)

        # Write output
        if args.output:
            Path(args.output).write_text(output)
            console.print(f"[green]✓ Report written to {args.output}[/green]")
        else:
            console.print(output)

        return 0 if report.passed else 1

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]", file=sys.stderr)
        return 1


def _format_text_output(report) -> str:
    """Format report as rich text table."""
    if report.passed:
        return "[green]✓ All validations passed![/green]"

    table = Table(title=f"Validation Report: {report.spec_title}")
    table.add_column("Severity", style="cyan")
    table.add_column("Rule", style="magenta")
    table.add_column("Message")

    for finding in report.findings:
        table.add_row(finding.severity, finding.rule_id, finding.message)

    return str(table)


if __name__ == "__main__":
    sys.exit(main())
