"""Tests for the validator module."""

import pytest

from openapi_spec_validator.validator import SpecValidator


@pytest.fixture
def valid_spec():
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0",
            "contact": {"email": "support@example.com"},
            "license": {"name": "MIT"},
        },
        "paths": {
            "/users": {
                "get": {
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {}, "429": {"description": "Too Many Requests"}},
                }
            }
        },
        "security": [{"bearerAuth": []}],
    }


@pytest.fixture
def invalid_spec():
    return {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {},
    }


def test_validator_with_valid_spec(valid_spec):
    validator = SpecValidator()
    report = validator.validate_spec(valid_spec)
    assert report.passed is True


def test_validator_with_invalid_spec(invalid_spec):
    validator = SpecValidator()
    report = validator.validate_spec(invalid_spec)
    assert report.passed is False
    assert report.total_findings > 0
