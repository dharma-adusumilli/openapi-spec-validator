"""Tests for validation rules."""

from openapi_spec_validator.rules import owasp_api, governance


def test_broken_user_authentication_rule():
    rule = owasp_api.APIBrokenUserAuthentication()
    spec_without_security = {"openapi": "3.0.0", "info": {"title": "API"}}
    findings = rule.check(spec_without_security)
    assert len(findings) > 0


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
