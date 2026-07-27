"""Tests for validation rules."""

from openapi_spec_validator.rules import governance, owasp_api


def test_broken_user_authentication_rule():
    rule = owasp_api.APIBrokenUserAuthentication()
    spec_without_security = {"openapi": "3.0.0", "info": {"title": "API"}}
    findings = rule.check(spec_without_security)
    assert len(findings) > 0


def test_excessive_data_exposure_flags_sensitive_field():
    rule = owasp_api.APIExcessiveDataExposure()
    spec = {
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "password": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    findings = rule.check(spec)
    assert len(findings) == 1
    assert "password" in findings[0].message


def test_excessive_data_exposure_passes_clean_schema():
    rule = owasp_api.APIExcessiveDataExposure()
    spec = {
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"id": {"type": "string"}},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert rule.check(spec) == []


def test_lack_of_resources_throttling_flags_missing_429_and_pagination():
    rule = owasp_api.APILackOfResourcesThrottling()
    spec = {
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {"schema": {"type": "array"}}
                            }
                        }
                    }
                }
            }
        }
    }
    findings = rule.check(spec)
    messages = " ".join(f.message for f in findings)
    assert "429" in messages
    assert "pagination" in messages


def test_lack_of_resources_throttling_passes_with_429_and_pagination():
    rule = owasp_api.APILackOfResourcesThrottling()
    spec = {
        "paths": {
            "/users": {
                "get": {
                    "parameters": [{"name": "limit", "in": "query"}],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {"schema": {"type": "array"}}
                            }
                        },
                        "429": {"description": "Too Many Requests"},
                    },
                }
            }
        }
    }
    assert rule.check(spec) == []


def test_broken_function_level_auth_flags_unprotected_admin_path():
    rule = owasp_api.APIBrokenFunctionLevelAuth()
    spec = {"paths": {"/admin/users": {"delete": {"responses": {"204": {}}}}}}
    findings = rule.check(spec)
    assert len(findings) == 1


def test_broken_function_level_auth_passes_when_secured():
    rule = owasp_api.APIBrokenFunctionLevelAuth()
    spec = {
        "paths": {
            "/admin/users": {
                "delete": {"security": [{"bearerAuth": []}], "responses": {"204": {}}}
            }
        }
    }
    assert rule.check(spec) == []


def test_mass_assignment_flags_open_request_schema():
    rule = owasp_api.APIMassAssignment()
    spec = {
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"name": {"type": "string"}},
                                }
                            }
                        }
                    },
                    "responses": {"201": {}},
                }
            }
        }
    }
    findings = rule.check(spec)
    assert len(findings) == 1


def test_mass_assignment_passes_with_additional_properties_false():
    rule = owasp_api.APIMassAssignment()
    spec = {
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"name": {"type": "string"}},
                                    "additionalProperties": False,
                                }
                            }
                        }
                    },
                    "responses": {"201": {}},
                }
            }
        }
    }
    assert rule.check(spec) == []


def test_security_misconfiguration_flags_http_server():
    rule = owasp_api.APISecurityMisconfiguration()
    spec = {"servers": [{"url": "http://api.example.com"}]}
    findings = rule.check(spec)
    assert any("HTTP" in f.message for f in findings)


def test_security_misconfiguration_flags_api_key_in_query():
    rule = owasp_api.APISecurityMisconfiguration()
    spec = {
        "components": {
            "securitySchemes": {
                "apiKeyAuth": {"type": "apiKey", "in": "query", "name": "api_key"}
            }
        }
    }
    findings = rule.check(spec)
    assert any("query string" in f.message for f in findings)


def test_injection_flags_unconstrained_query_param():
    rule = owasp_api.APIInjection()
    spec = {
        "paths": {
            "/search": {
                "get": {
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {}},
                }
            }
        }
    }
    findings = rule.check(spec)
    assert len(findings) == 1


def test_injection_passes_with_enum_constraint():
    rule = owasp_api.APIInjection()
    spec = {
        "paths": {
            "/search": {
                "get": {
                    "parameters": [
                        {
                            "name": "sort",
                            "in": "query",
                            "schema": {"type": "string", "enum": ["asc", "desc"]},
                        }
                    ],
                    "responses": {"200": {}},
                }
            }
        }
    }
    assert rule.check(spec) == []


def test_get_rules_excludes_logging_and_monitoring():
    rule_ids = {rule.rule_id for rule in owasp_api.get_rules()}
    assert "OWASP_API_10" not in rule_ids
    assert rule_ids == {
        "OWASP_API_01",
        "OWASP_API_02",
        "OWASP_API_03",
        "OWASP_API_04",
        "OWASP_API_05",
        "OWASP_API_06",
        "OWASP_API_07",
        "OWASP_API_08",
        "OWASP_API_09",
    }


def test_required_contact_info_rule():
    rule = governance.RequiredContactInfo()
    spec_without_contact = {"info": {"title": "API", "version": "1.0.0"}}
    findings = rule.check(spec_without_contact)
    assert len(findings) > 0


def test_required_license_rule():
    rule = governance.RequiredLicense()
    spec_without_license = {"info": {"title": "API", "version": "1.0.0"}}
    findings = rule.check(spec_without_license)
    assert len(findings) > 0
