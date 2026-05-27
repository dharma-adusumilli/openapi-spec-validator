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

This tool validates OpenAPI specifications against all 10 OWASP API Security risks:

| # | Rule | Description |
|---|------|-------------|
| 1 | **Broken Object Level Authorization** | Endpoints lack proper authorization checks on object references |
| 2 | **Broken User Authentication** | Authentication mechanisms are broken or missing |
| 3 | **Excessive Data Exposure** | API exposes more data than necessary |
| 4 | **Lack of Resources & Throttling** | API lacks rate limiting and resource controls |
| 5 | **Broken Function Level Authorization** | Endpoints lack proper authorization checks |
| 6 | **Mass Assignment** | Binding of client data to data model without filtering |
| 7 | **Cross-Site Scripting (XSS)** | API vulnerable to XSS attacks |
| 8 | **SQL Injection** | API vulnerable to SQL injection |
| 9 | **Improper Assets Management** | Unversioned or abandoned API endpoints |
| 10 | **Insufficient Logging & Monitoring** | API lacks logging and monitoring |

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
