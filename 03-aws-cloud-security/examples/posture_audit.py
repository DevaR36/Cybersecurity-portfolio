"""Offline AWS posture-check demonstration over fictional JSON snapshots.

This is NOT Scout Suite, an AWS audit, or an AWS API client. It only checks
predefined fields in hand-written, non-sensitive example JSON files.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys
from typing import Any

MAX_BYTES = 256_000


@dataclass(frozen=True)
class Check:
    key: str
    service: str
    description: str
    path: tuple[str, ...]
    expected: bool | int
    guidance: str


CHECKS: tuple[Check, ...] = (
    Check("IAM-01", "IAM", "Root MFA configured", ("iam", "root_mfa"), True, "Enable strong authentication for the root user."),
    Check("IAM-02", "IAM", "IAM console user MFA configured", ("iam", "analyst_mfa"), True, "Require MFA for the lab IAM console identity."),
    Check("IAM-03", "IAM", "Password minimum length at least 14", ("iam", "password_min_length"), 14, "Review the IAM account password policy."),
    Check("EC2-01", "EC2/EBS", "EBS default encryption enabled", ("ec2", "ebs_default_encryption"), True, "Enable EBS encryption by default for the Region; check existing volumes separately."),
    Check("S3-01", "S3", "Audit bucket blocks public access", ("s3", "audit_bucket_block_public_access"), True, "Enable all applicable S3 Block Public Access settings."),
    Check("S3-02", "S3", "Audit bucket requires TLS", ("s3", "audit_bucket_tls_required"), True, "Consider a bucket policy enforcing secure transport after testing service compatibility."),
    Check("S3-03", "S3", "Audit bucket versioning enabled", ("s3", "audit_bucket_versioning"), True, "Evaluate versioning and retention requirements for the audit bucket."),
    Check("CT-01", "CloudTrail", "Management-event logging active", ("cloudtrail", "management_logging"), True, "Enable CloudTrail management-event delivery."),
    Check("CT-02", "CloudTrail", "Multi-Region trail", ("cloudtrail", "multi_region"), True, "Review organization and Region-wide management-event coverage."),
    Check("CT-03", "CloudTrail", "Log-file validation enabled", ("cloudtrail", "log_file_validation"), True, "Enable validation and verify delivered log files as appropriate."),
    Check("CFG-01", "AWS Config", "Configuration recorder enabled", ("config", "recorder_enabled"), True, "Enable recording and separately review permissions and recording coverage."),
)


@dataclass(frozen=True)
class Result:
    key: str
    service: str
    description: str
    passed: bool
    observed: bool | int | str | None
    guidance: str


def _nested(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def check_snapshot(snapshot: dict[str, Any]) -> list[Result]:
    """Evaluate only explicitly modeled, illustrative fields; never call AWS."""
    if not isinstance(snapshot, dict):
        raise ValueError("Snapshot must be a JSON object")
    results = []
    for check in CHECKS:
        observed = _nested(snapshot, check.path)
        if isinstance(check.expected, bool):
            passed = isinstance(observed, bool) and observed is check.expected
        else:
            passed = isinstance(observed, int) and not isinstance(observed, bool) and observed >= check.expected
        if isinstance(observed, (dict, list)):
            display: bool | int | str | None = "invalid type"
        elif isinstance(observed, (bool, int, str)) or observed is None:
            display = observed
        else:
            display = "invalid type"
        results.append(Result(check.key, check.service, check.description, passed, display, check.guidance))
    return results


def load_snapshot(path: str | Path) -> dict[str, Any]:
    f = Path(path)
    if not f.is_file():
        raise ValueError("Input is not an existing file")
    if f.stat().st_size > MAX_BYTES:
        raise ValueError("Example JSON file is too large")
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Input must contain valid UTF-8 JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("Snapshot root must be a JSON object")
    return data


def summarize(results: list[Result]) -> dict[str, Any]:
    return {"checks": len(results), "passed": sum(x.passed for x in results), "flagged": sum(not x.passed for x in results),
            "flagged_checks": [x.key for x in results if not x.passed]}


def compare(before: list[Result], after: list[Result]) -> dict[str, Any]:
    old = {x.key: x.passed for x in before}
    new = {x.key: x.passed for x in after}
    if old.keys() != new.keys():
        raise ValueError("Cannot compare different check sets")
    return {"before": summarize(before), "after": summarize(after),
            "resolved": sorted(k for k in old if not old[k] and new[k]),
            "newly_flagged": sorted(k for k in old if old[k] and not new[k]),
            "still_flagged": sorted(k for k in old if not old[k] and not new[k])}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline checks of fictional AWS posture JSON snapshots; no AWS access")
    parser.add_argument("before", help="Path to fictional baseline JSON")
    parser.add_argument("after", nargs="?", help="Path to fictional follow-up JSON")
    parser.add_argument("--json", action="store_true", help="Print results as structured JSON")
    args = parser.parse_args(argv)
    try:
        before = check_snapshot(load_snapshot(args.before))
        if args.after:
            after = check_snapshot(load_snapshot(args.after))
            report = compare(before, after)
        else:
            report = {"snapshot": summarize(before)}
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("Offline training demonstration — NOT an AWS scan")
        for label in ("before", "after") if args.after else ("snapshot",):
            item = report[label]
            print(f"{label.title()}: {item['passed']}/{item['checks']} passed; {item['flagged']} flagged")
            print("  Flagged controls: " + (", ".join(item["flagged_checks"]) or "none"))
        if args.after:
            print("Resolved: " + (", ".join(report["resolved"]) or "none"))
            print("Newly flagged: " + (", ".join(report["newly_flagged"]) or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
