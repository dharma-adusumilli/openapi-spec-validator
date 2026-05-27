"""Tests for report generators."""

import json
from datetime import datetime
from openapi_spec_validator.models.report import ValidationReport, Finding
from openapi_spec_validator.reporters import json_reporter, markdown_reporter


@pytest.fixture
def sample_report():
    return ValidationReport(
        spec_title="Test API",
        spec_version="1.0.0",
        findings=[
            Finding(rule_id="TEST_001", severity="HIGH", message="Test finding")
        ],
        total_findings=1,
        passed=False,
    )


def test_json_reporter(sample_report):
    output = json_reporter.generate(sample_report)
    data = json.loads(output)
    assert data["spec_title"] == "Test API"
    assert data["total_findings"] == 1


def test_markdown_reporter(sample_report):
    output = markdown_reporter.generate(sample_report)
    assert "Test API" in output
    assert "TEST_001" in output
