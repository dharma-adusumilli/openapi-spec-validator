"""OWASP API Security Top 10 rules."""

from dataclasses import dataclass
from openapi_spec_validator.models.report import Finding


@dataclass
class Rule:
    rule_id: str
    name: str
    description: str

    def check(self, spec: dict) -> list[Finding]:
        raise NotImplementedError


class APIBrokenObjectLevelAuth(Rule):
    """OWASP API1: Broken Object Level Authorization."""

    def __init__(self):
        super().__init__(
            rule_id="OWASP_API_01",
            name="Broken Object Level Authorization",
            description="Endpoints lack proper authorization checks on object references",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ["get", "put", "delete"]:
                    if "{id}" in path or "{resource_id}" in path:
                        parameters = details.get("parameters", [])
                        security = details.get("security")
                        if not security:
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity="HIGH",
                                    message=f"{method.upper()} {path}: No security scheme defined",
                                )
                            )
        return findings


class APIBrokenUserAuthentication(Rule):
    """OWASP API2: Broken User Authentication."""

    def __init__(self):
        super().__init__(
            rule_id="OWASP_API_02",
            name="Broken User Authentication",
            description="Authentication mechanisms are broken or missing",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        security = spec.get("security", [])
        if not security:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity="CRITICAL",
                    message="No global security schemes defined",
                )
            )
        return findings


class APIExcessiveDataExposure(Rule):
    """OWASP API3: Excessive Data Exposure."""

    def __init__(self):
        super().__init__(
            rule_id="OWASP_API_03",
            name="Excessive Data Exposure",
            description="API exposes more data than necessary",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        return findings


class APILackOfResourcesThrottling(Rule):
    """OWASP API4: Lack of Resources & Throttling."""

    def __init__(self):
        super().__init__(
            rule_id="OWASP_API_04",
            name="Lack of Resources & Throttling",
            description="API lacks rate limiting and resource controls",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        return findings


class APIBrokenFunctionLevelAuth(Rule):
    """OWASP API5: Broken Function Level Authorization."""

    def __init__(self):
        super().__init__(
            rule_id="OWASP_API_05",
            name="Broken Function Level Authorization",
            description="Endpoints lack proper authorization checks",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        return findings


class APIMassAssignment(Rule):
    """OWASP API6: Mass Assignment."""

    def __init__(self):
        super().__init__(
            rule_id="OWASP_API_06",
            name="Mass Assignment",
            description="Binding of client data to data model without filtering",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        return findings


class APIWrongContentType(Rule):
    """OWASP API7: Cross-Site Scripting (XSS)."""

    def __init__(self):
        super().__init__(
            rule_id="OWASP_API_07",
            name="Cross-Site Scripting (XSS)",
            description="API vulnerable to XSS attacks",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        return findings


class APISQLInjection(Rule):
    """OWASP API8: SQL Injection."""

    def __init__(self):
        super().__init__(
            rule_id="OWASP_API_08",
            name="SQL Injection",
            description="API vulnerable to SQL injection",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        return findings


class APIImproperAssetManagement(Rule):
    """OWASP API9: Improper Assets Management."""

    def __init__(self):
        super().__init__(
            rule_id="OWASP_API_09",
            name="Improper Assets Management",
            description="Unversioned or abandoned API endpoints",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        info = spec.get("info", {})
        if not info.get("version"):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity="MEDIUM",
                    message="API version not specified in info",
                )
            )
        return findings


def get_rules() -> list[Rule]:
    """Return the OWASP API Security rules that are checkable from a static spec.

    API10 (Insufficient Logging & Monitoring) is intentionally omitted: it
    describes runtime/operational behavior that cannot be inferred from an
    OpenAPI document.
    """
    return [
        APIBrokenObjectLevelAuth(),
        APIBrokenUserAuthentication(),
        APIExcessiveDataExposure(),
        APILackOfResourcesThrottling(),
        APIBrokenFunctionLevelAuth(),
        APIMassAssignment(),
        APIWrongContentType(),
        APISQLInjection(),
        APIImproperAssetManagement(),
    ]
