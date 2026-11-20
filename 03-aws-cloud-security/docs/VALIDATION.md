# Validation report — independent offline AWS posture demonstration

## Scope

This document evaluates the repository's **fictional JSON control checker**, not the original internship Scout Suite scan or a live AWS environment. No AWS credentials, AWS SDK packages, access to an AWS account, or internet connectivity are required.

## Environment and commands

- Python: **3.10 or later**, standard library only.
- Working directory: `03-aws-cloud-security/`.

```bash
python examples/posture_audit.py data/fictional_before.json data/fictional_after.json
python examples/posture_audit.py data/fictional_before.json data/fictional_after.json --json
python -m unittest discover -s tests -v
```

## Verified results

All **31 automated tests passed** in local validation. The tests cover normal and abnormal settings, missing keys, type checking, minimum-password-length boundaries, before/after counts, a deliberately malformed JSON file, oversize input, mismatched check sets, and both text and JSON command-line output.

The fictional baseline and follow-up snapshots produce:

```text
Offline training demonstration — NOT an AWS scan
Before: 6/11 passed; 5 flagged
  Flagged controls: IAM-02, IAM-03, EC2-01, S3-02, S3-03
After: 8/11 passed; 3 flagged
  Flagged controls: IAM-03, S3-02, S3-03
Resolved: EC2-01, IAM-02
Newly flagged: none
```

**Interpretation:** Two modeled controls changed from failed to passed: an IAM user MFA flag and regional default EBS encryption. This is a fictional example of remediation verification, with three intentionally unresolved findings. These numbers **do not represent** the real Scout Suite findings documented in the README.

## What was tested

| Test area | Validation objective |
|:--|:--|
| Deterministic control catalog | No duplicate control IDs; 11 modeled checks |
| Baseline vs follow-up | Five fictional failures initially; three afterward |
| Remediation tracking | Exactly IAM-02 and EC2-01 become passing checks |
| Missing data | Missing keys cannot silently pass a check |
| Data-type checks | A JSON `1` or `"true"` is not accepted as a Boolean `true` |
| Password policy | Boundary condition at an illustrative 14-character minimum |
| Input handling | Invalid JSON, invalid root types, absent files and oversize inputs fail |
| Comparison consistency | Reports with different modeled checks cannot be combined |
| Command-line interface | Plain-text and structured-JSON output are consistent |

## Limitations

- The eleven checks are deliberately simplified and hard-coded. They do not cover IAM policy evaluation, effective permissions, service-specific exceptions, multiple Regions, detailed policy statements, CloudTrail delivery errors or AWS Config's resource-level recording gaps.
- Input values are **asserted fictional values**, not independently collected or verified cloud settings.
- A passed check is not proof of organizational compliance, effective security or absence of exploitation.
- The program is not a replacement for AWS Config, Scout Suite, AWS Security Hub, policy-as-code solutions or a professional risk assessment.
- No real AWS APIs were called, and no production platform integration was tested.

See [assessment checklist](ASSESSMENT_CHECKLIST.md) and [responsible sharing notes](SECURITY_NOTES.md).
