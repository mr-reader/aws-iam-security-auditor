# AWS IAM Security Auditor

A Python-based security tool that audits AWS IAM configurations 
for common misconfigurations and generates a structured findings report.
Aligned with NIST CSF and CIS AWS Foundations Benchmark.

## What It Does

Performs 6 automated security checks across your AWS IAM environment:

| Check | Severity |
|---|---|
| Root account access keys exist | CRITICAL |
| User has AdministratorAccess directly attached | CRITICAL |
| MFA not enabled on IAM user | HIGH |
| Access key older than 90 days (stale key) | HIGH |
| Inactive user — no login in 90+ days | MEDIUM |
| Weak account password policy | MEDIUM |

## Output

- Console summary with findings grouped by severity
- `iam_security_report.json` — structured JSON report with metadata,
  summary counts, and detailed findings per resource

## Sample Output
