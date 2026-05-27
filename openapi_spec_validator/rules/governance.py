"""Custom governance rules."""

from dataclasses import dataclass
from openapi_spec_validator.models.report import Finding


@dataclass
class Rule:
    rule_id: str
    name: str
    description: str

    def check(self, spec: dict) -> list[Finding]:
        raise NotImplementedError


class RequiredContactInfo(Rule):
    """Governance: Contact information required."""

    def __init__(self):
        super().__init__(
            rule_id="GOV_001",
            name="Required Contact Information",
            description="API spec must include contact information",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        contact = spec.get("info", {}).get("contact")
        if not contact:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity="LOW",
                    message="Contact information missing in API spec",
                )
            )
        return findings


class RequiredLicense(Rule):
    """Governance: License information required."""

    def __init__(self):
        super().__init__(
            rule_id="GOV_002",
            name="Required License",
            description="API spec must include license information",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        license_info = spec.get("info", {}).get("license")
        if not license_info:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity="LOW",
                    message="License information missing in API spec",
                )
            )
        return findings


def get_rules() -> list[Rule]:
    """Return all governance rules."""
    return [
        RequiredContactInfo(),
        RequiredLicense(),
    ]
