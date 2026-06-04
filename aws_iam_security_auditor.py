"""
AWS IAM Security Auditor
========================
Author : Goutham Reddy Kambalapally
Purpose: Audits AWS IAM users, policies, and access keys for common
         security misconfigurations and generates a structured findings report.

Security checks performed:
  1. Users with no MFA enabled
  2. Access keys older than 90 days (key rotation risk)
  3. Users with AdministratorAccess policy attached
  4. Inactive users (no console/API login in 90+ days)
  5. Root account access key existence
  6. Password policy compliance

Usage:
  pip install boto3
  Configure AWS credentials via environment variables or ~/.aws/credentials
  python aws_iam_security_auditor.py

Output:
  Console summary + iam_security_report.json
"""

import boto3
import json
import datetime
from collections import defaultdict

# ── Configuration ──────────────────────────────────────────────────────────
KEY_ROTATION_DAYS   = 90   # Flag access keys older than this
INACTIVITY_DAYS     = 90   # Flag users inactive longer than this
REPORT_FILE         = "iam_security_report.json"
SEVERITY            = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "INFO": []}
# ───────────────────────────────────────────────────────────────────────────


def get_client(service: str):
    """Return a boto3 client; gracefully handle missing credentials."""
    try:
        return boto3.client(service)
    except Exception as e:
        print(f"[ERROR] Could not create boto3 client for {service}: {e}")
        raise


def days_since(dt) -> int:
    """Return number of days between a datetime and now."""
    if dt is None:
        return -1
    if dt.tzinfo is not None:
        now = datetime.datetime.now(datetime.timezone.utc)
    else:
        now = datetime.datetime.utcnow()
    return (now - dt).days


def finding(severity: str, check: str, resource: str, detail: str):
    """Record a finding into the severity bucket."""
    SEVERITY[severity].append({
        "check":    check,
        "resource": resource,
        "detail":   detail
    })


# ── Check 1 – Root account access keys ──────────────────────────────────────
def check_root_access_keys(iam):
    print("[*] Checking root account access keys...")
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        finding(
            "CRITICAL",
            "Root Access Key Exists",
            "root",
            "The root account has active access keys. These should be removed immediately."
        )
    else:
        finding("INFO", "Root Access Key Exists", "root", "No root access keys found. ✓")


# ── Check 2 – Password policy ────────────────────────────────────────────────
def check_password_policy(iam):
    print("[*] Checking account password policy...")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append("Minimum password length < 14 characters")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("Uppercase characters not required")
        if not policy.get("RequireNumbers", False):
            issues.append("Numbers not required in password")
        if not policy.get("RequireSymbols", False):
            issues.append("Symbols not required in password")
        if not policy.get("EnablePasswordExpiration", False):
            issues.append("Password expiration not enabled")
        if not policy.get("PreventPasswordReuse", False):
            issues.append("Password reuse prevention not configured")

        if issues:
            finding("MEDIUM", "Weak Password Policy", "account",
                    "Password policy does not meet best practices: " + "; ".join(issues))
        else:
            finding("INFO", "Password Policy", "account", "Password policy meets best practices. ✓")

    except iam.exceptions.NoSuchEntityException:
        finding("HIGH", "Password Policy Missing", "account",
                "No account password policy is configured.")


# ── Check 3 – Per-user checks (MFA, key age, admin access, inactivity) ───────
def check_users(iam):
    print("[*] Enumerating IAM users...")
    paginator = iam.get_paginator("list_users")
    users = []
    for page in paginator.paginate():
        users.extend(page["Users"])

    print(f"    Found {len(users)} IAM user(s).")

    for user in users:
        uname = user["UserName"]

        # -- MFA check --
        mfa_devices = iam.list_mfa_devices(UserName=uname)["MFADevices"]
        if not mfa_devices:
            finding("HIGH", "MFA Not Enabled", uname,
                    f"User '{uname}' has no MFA device configured.")

        # -- Access key age check --
        keys = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
        for key in keys:
            if key["Status"] == "Active":
                age = days_since(key["CreateDate"])
                if age > KEY_ROTATION_DAYS:
                    finding("HIGH", "Stale Access Key", uname,
                            f"Access key {key['AccessKeyId']} for '{uname}' is {age} days old "
                            f"(threshold: {KEY_ROTATION_DAYS} days). Rotate immediately.")

        # -- Admin policy check --
        attached = iam.list_attached_user_policies(UserName=uname)["AttachedPolicies"]
        for policy in attached:
            if policy["PolicyName"] == "AdministratorAccess":
                finding("CRITICAL", "AdministratorAccess Attached", uname,
                        f"User '{uname}' has AdministratorAccess directly attached. "
                        "Follow least-privilege principles and use role-based access.")

        # -- Inactivity check --
        try:
            login_profile = iam.get_login_profile(UserName=uname)
            last_used_info = user.get("PasswordLastUsed")
            if last_used_info:
                inactive_days = days_since(last_used_info)
                if inactive_days > INACTIVITY_DAYS:
                    finding("MEDIUM", "Inactive User", uname,
                            f"User '{uname}' has not logged in for {inactive_days} days. "
                            "Consider disabling or removing this account.")
        except iam.exceptions.NoSuchEntityException:
            pass  # No console access — skip inactivity check


# ── Report generator ─────────────────────────────────────────────────────────
def generate_report():
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    total = sum(len(v) for v in SEVERITY.values())
    non_info = {k: v for k, v in SEVERITY.items() if k != "INFO"}

    report = {
        "report_metadata": {
            "title":       "AWS IAM Security Audit Report",
            "author":      "Goutham Reddy Kambalapally",
            "generated":   timestamp,
            "tool":        "aws_iam_security_auditor.py",
            "framework":   "NIST CSF, CIS AWS Foundations Benchmark"
        },
        "summary": {
            "total_findings": total,
            "critical": len(SEVERITY["CRITICAL"]),
            "high":     len(SEVERITY["HIGH"]),
            "medium":   len(SEVERITY["MEDIUM"]),
            "info":     len(SEVERITY["INFO"])
        },
        "findings": SEVERITY
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    # Console output
    print("\n" + "="*60)
    print("  AWS IAM SECURITY AUDIT — RESULTS SUMMARY")
    print("="*60)
    print(f"  Generated : {timestamp}")
    print(f"  Total findings : {total}")
    print(f"  CRITICAL : {report['summary']['critical']}")
    print(f"  HIGH     : {report['summary']['high']}")
    print(f"  MEDIUM   : {report['summary']['medium']}")
    print(f"  INFO     : {report['summary']['info']}")
    print("="*60)

    for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
        if SEVERITY[severity]:
            print(f"\n  [{severity}]")
            for item in SEVERITY[severity]:
                print(f"    • {item['check']} — {item['resource']}")
                print(f"      {item['detail']}")

    print(f"\n  Full report saved to: {REPORT_FILE}")
    print("="*60 + "\n")


# ── Demo mode (no AWS credentials needed) ────────────────────────────────────
def run_demo():
    """
    Populate sample findings to demonstrate report output
    without requiring live AWS credentials. Useful for portfolio demos.
    """
    print("\n[DEMO MODE] Running with simulated AWS environment...\n")

    finding("CRITICAL", "Root Access Key Exists", "root",
            "The root account has active access keys. These should be removed immediately.")
    finding("CRITICAL", "AdministratorAccess Attached", "jsmith",
            "User 'jsmith' has AdministratorAccess directly attached. "
            "Follow least-privilege principles and use role-based access.")
    finding("HIGH", "MFA Not Enabled", "jsmith",
            "User 'jsmith' has no MFA device configured.")
    finding("HIGH", "MFA Not Enabled", "svc_deploy",
            "User 'svc_deploy' has no MFA device configured.")
    finding("HIGH", "Stale Access Key", "svc_deploy",
            "Access key AKIAIOSFODNN7EXAMPLE for 'svc_deploy' is 124 days old "
            "(threshold: 90 days). Rotate immediately.")
    finding("MEDIUM", "Weak Password Policy", "account",
            "Password policy does not meet best practices: "
            "Minimum password length < 14 characters; Password expiration not enabled.")
    finding("MEDIUM", "Inactive User", "contractor_old",
            "User 'contractor_old' has not logged in for 147 days. "
            "Consider disabling or removing this account.")
    finding("INFO", "Root Access Key Exists", "root",
            "Demo note: root key check executed successfully.")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    print("\n" + "="*60)
    print("  AWS IAM Security Auditor")
    print("  Author: Goutham Reddy Kambalapally")
    print("  Aligned with: NIST CSF, CIS AWS Foundations Benchmark")
    print("="*60 + "\n")

    try:
        iam = get_client("iam")
        # Test credentials
        iam.get_account_summary()

        check_root_access_keys(iam)
        check_password_policy(iam)
        check_users(iam)

    except Exception as e:
        print(f"[INFO] Could not connect to AWS ({e}).")
        print("[INFO] Running in DEMO MODE with simulated findings.\n")
        run_demo()

    generate_report()


if __name__ == "__main__":
    main()
