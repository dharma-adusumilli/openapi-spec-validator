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


SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "ssn",
    "creditcard",
    "credit_card",
    "cvv",
}

PRIVILEGED_PATH_MARKERS = ("/admin", "/internal", "/debug", "/manage")


def _iter_operations(spec: dict):
    """Yield (path, method, details) for every HTTP operation in the spec."""
    for path, methods in spec.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.lower() in ("get", "post", "put", "patch", "delete"):
                yield path, method.lower(), details or {}


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
        for path, method, details in _iter_operations(spec):
            for status, response in (details.get("responses") or {}).items():
                if not status.startswith("2"):
                    continue
                for content_type, media in (response.get("content") or {}).items():
                    schema = media.get("schema", {})
                    props = schema.get("properties") or (
                        schema.get("items", {}).get("properties")
                    )
                    if not props:
                        continue
                    for field_name in props:
                        if field_name.lower().replace("_", "") in {
                            n.replace("_", "") for n in SENSITIVE_FIELD_NAMES
                        }:
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity="HIGH",
                                    message=(
                                        f"{method.upper()} {path}: response exposes "
                                        f"sensitive field '{field_name}' "
                                        f"({status} {content_type})"
                                    ),
                                    path=path,
                                )
                            )
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
        has_429 = any(
            "429" in (details.get("responses") or {})
            for _, _, details in _iter_operations(spec)
        )
        if not has_429:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity="MEDIUM",
                    message=(
                        "No operation defines a 429 Too Many Requests response — "
                        "rate limiting does not appear to be documented"
                    ),
                )
            )

        for path, method, details in _iter_operations(spec):
            if method != "get":
                continue
            for status, response in (details.get("responses") or {}).items():
                if not status.startswith("2"):
                    continue
                for media in (response.get("content") or {}).values():
                    schema = media.get("schema", {})
                    if schema.get("type") == "array":
                        params = {
                            p.get("name") for p in details.get("parameters", [])
                        }
                        if not params & {"limit", "page", "offset", "pageSize", "per_page"}:
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity="LOW",
                                    message=(
                                        f"GET {path}: returns an unbounded array "
                                        "with no pagination parameters "
                                        "(limit/page/offset)"
                                    ),
                                    path=path,
                                )
                            )
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
        global_security = spec.get("security")
        for path, method, details in _iter_operations(spec):
            if not any(marker in path.lower() for marker in PRIVILEGED_PATH_MARKERS):
                continue
            if not details.get("security") and not global_security:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity="HIGH",
                        message=(
                            f"{method.upper()} {path}: privileged-looking endpoint "
                            "defines no security requirement"
                        ),
                        path=path,
                    )
                )
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
        for path, method, details in _iter_operations(spec):
            if method not in ("post", "put", "patch"):
                continue
            body = details.get("requestBody", {})
            for content_type, media in (body.get("content") or {}).items():
                schema = media.get("schema", {})
                if schema.get("type", "object") != "object":
                    continue
                if "properties" in schema and schema.get("additionalProperties") is not False:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity="MEDIUM",
                            message=(
                                f"{method.upper()} {path}: request body schema does "
                                f"not set additionalProperties: false "
                                f"({content_type}), allowing unexpected fields to "
                                "bind to the model"
                            ),
                            path=path,
                        )
                    )
        return findings


class APISecurityMisconfiguration(Rule):
    """OWASP API7: Security Misconfiguration."""

    def __init__(self):
        super().__init__(
            rule_id="OWASP_API_07",
            name="Security Misconfiguration",
            description="Insecure defaults, unnecessary features, or permissive settings",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        for server in spec.get("servers", []):
            url = server.get("url", "")
            if url.startswith("http://"):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity="HIGH",
                        message=f"Server URL uses plaintext HTTP: {url}",
                    )
                )

        schemes = spec.get("components", {}).get("securitySchemes", {})
        for name, scheme in schemes.items():
            if scheme.get("type") == "apiKey" and scheme.get("in") == "query":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity="MEDIUM",
                        message=(
                            f"Security scheme '{name}' sends an API key via query "
                            "string, which gets logged in server/proxy access logs"
                        ),
                    )
                )
            if scheme.get("type") == "http" and scheme.get("scheme") == "basic":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity="LOW",
                        message=(
                            f"Security scheme '{name}' uses HTTP Basic auth, which "
                            "transmits credentials on every request"
                        ),
                    )
                )
        return findings


class APIInjection(Rule):
    """OWASP API8: Injection."""

    def __init__(self):
        super().__init__(
            rule_id="OWASP_API_08",
            name="Injection",
            description="Untrusted input reaches interpreters without validation",
        )

    def check(self, spec: dict) -> list[Finding]:
        findings = []
        for path, method, details in _iter_operations(spec):
            for param in details.get("parameters", []):
                if param.get("in") != "query":
                    continue
                schema = param.get("schema", {})
                if schema.get("type") != "string":
                    continue
                if not (schema.get("enum") or schema.get("pattern") or schema.get("format")):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity="MEDIUM",
                            message=(
                                f"{method.upper()} {path}: query parameter "
                                f"'{param.get('name')}' is an unconstrained string "
                                "(no pattern/enum/format), increasing injection risk"
                            ),
                            path=path,
                        )
                    )
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
        APISecurityMisconfiguration(),
        APIInjection(),
        APIImproperAssetManagement(),
    ]
