# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for a security vulnerability in this tool.

Open an issue is not appropriate for security problems. Instead, contact the
maintainers via the repository's "Security" tab (GitHub security advisories), or
email `security@uprarlabs.dev` (a group inbox monitored by maintainers) with:

- A description of the vulnerability and the impact you expect.
- Steps to reproduce or a minimal proof of concept.
- Your contact details and availability.

We will acknowledge receipt within 48 hours and aim to triage within 5 business
days.

## Scope

This tool analyzes **source code statically** and makes no network calls to
Stellar during a scan. Relevant security considerations:

- A malformed or adversarial input file cannot escape the scanner; files are read
  as bytes and never executed.
- The JSON report is plain data; it is not interpreted or executed by the tool.
- The tool does not transmit findings off the host.

This project is **not** a Stellar node, wallet, or indexer and does not hold
keys, funds, or user data.

## Preferred languages

We prefer reports in English. Reports in Indonesian are also accepted.

## Policy

We follow a disclosure process and will credit reporters who request it after a
fix is released.
