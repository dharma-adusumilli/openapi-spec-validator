"""Core validation engine."""

from typing import Any
from openapi_spec_validator.models.report import ValidationReport, Finding
from openapi_spec_validator.rules import owasp_api, governance
import yaml
import json


class SpecValidator:
    """Validates OpenAPI specifications against security and governance rules."""

    def __init__(self):
        self.owasp_rules = owasp_api.get_rules()
        self.governance_rules = governance.get_rules()

    def validate_spec(self, spec_content: dict | str) -> ValidationReport:
        """Validate an OpenAPI spec and return findings."""
        if isinstance(spec_content, str):
            spec_content = yaml.safe_load(spec_content) or {}

        findings = []

        # Run OWASP rules
        for rule in self.owasp_rules:
            rule_findings = rule.check(spec_content)
            findings.extend(rule_findings)

        # Run governance rules
        for rule in self.governance_rules:
            rule_findings = rule.check(spec_content)
            findings.extend(rule_findings)

        report = ValidationReport(
            spec_title=spec_content.get("info", {}).get("title", "Unknown"),
            spec_version=spec_content.get("info", {}).get("version", "Unknown"),
            findings=findings,
            total_findings=len(findings),
            passed=len(findings) == 0,
        )
        return report
