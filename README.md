# OpenAPI Spec Validator

![Python Version](https://img.shields.io/badge/python-3.12+-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

A CLI tool that validates OpenAPI specifications against OWASP API Security Top 10 rules and governance standards, generating structured JSON and Markdown reports.

## Installation

```bash
pip install openapi-spec-validator
```

## Quick Start

### Validate a local OpenAPI file

```bash
osv specs/api.yaml
```

### Validate a remote OpenAPI spec from a URL

```bash
osv https://api.example.com/openapi.yaml --format json --output report.json
```

### Generate a Markdown report

```bash
osv specs/api.yaml --format markdown --output report.md
```

## Usage

```
usage: osv [-h] [--format {text,json,markdown}] [--output OUTPUT] spec

Validate OpenAPI specs against OWASP API Security Top 10

positional arguments:
  spec                  Path to OpenAPI spec file or URL

optional arguments:
  -h, --help           Show this help message and exit
  --format {text,json,markdown}
                       Output format (default: text)
  --output OUTPUT, -o OUTPUT
                       Output file (default: stdout)
```

## OWASP API Security Top 10

This tool statically analyzes an OpenAPI document against the OWASP API Security Top 10. 9 of the 10 risks are checked; **Insufficient Logging & Monitoring (API10)** is intentionally omitted because it describes runtime/operational behavior that cannot be inferred from a spec document alone.

| # | Rule ID | Rule | What is checked |
|---|---------|------|------------------|
| 1 | `OWASP_API_01` | **Broken Object Level Authorization** | `GET`/`PUT`/`DELETE` on `{id}`-style paths with no `security` requirement |
| 2 | `OWASP_API_02` | **Broken User Authentication** | No global `security` scheme defined for the API |
| 3 | `OWASP_API_03` | **Excessive Data Exposure** | 2xx response schemas that expose sensitive-looking fields (`password`, `token`, `ssn`, etc.) |
| 4 | `OWASP_API_04` | **Lack of Resources & Rate Limiting** | No operation defines a `429` response; list endpoints with no pagination parameters |
| 5 | `OWASP_API_05` | **Broken Function Level Authorization** | Privileged-looking paths (`/admin`, `/internal`, `/debug`, `/manage`) with no `security` requirement |
| 6 | `OWASP_API_06` | **Mass Assignment** | Request bodies whose schema doesn't set `additionalProperties: false` |
| 7 | `OWASP_API_07` | **Security Misconfiguration** | Plaintext HTTP servers, API keys sent via query string, HTTP Basic auth |
| 8 | `OWASP_API_08` | **Injection** | Unconstrained string query parameters (no `enum`/`pattern`/`format`) |
| 9 | `OWASP_API_09` | **Improper Assets Management** | Missing API version in `info` |

Rules 7 and 8 are renamed from earlier drafts ("XSS" and "SQL Injection") to match OWASP's actual API Security Top 10 naming — **Security Misconfiguration** and **Injection** — since the original names didn't reflect what can be checked from a static spec.

## Governance Rules

In addition to OWASP checks, the tool validates governance standards:

- **Required Contact Information** - API spec must include contact information
- **Required License** - API spec must include license information

## Sample JSON Report Output

```json
{
  "spec_title": "User API",
  "spec_version": "1.0.0",
  "findings": [
    {
      "rule_id": "OWASP_API_02",
      "severity": "CRITICAL",
      "message": "No global security schemes defined",
      "path": null,
      "line": null
    },
    {
      "rule_id": "GOV_001",
      "severity": "LOW",
      "message": "Contact information missing in API spec",
      "path": null,
      "line": null
    }
  ],
  "total_findings": 2,
  "passed": false,
  "timestamp": "2025-05-26T10:30:45.123456"
}
```

## Development

### Setup

```bash
git clone https://github.com/username/openapi-spec-validator.git
cd openapi-spec-validator
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
pytest --cov  # with coverage report
```

### Linting

```bash
ruff check .
ruff format .
```

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please submit issues and pull requests to the repository.
