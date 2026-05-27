"""JSON report generator."""

import json
from openapi_spec_validator.models.report import ValidationReport


def generate(report: ValidationReport) -> str:
    """Generate JSON report."""
    report_dict = report.model_dump(mode="json")
    return json.dumps(report_dict, indent=2)
