# Cloud security assessment checklist

This is a **general educational checklist** for a reviewer. It does not certify compliance with AWS or any security framework, and not every item is applicable to every account.

| Area | Review question | Evidence to seek | Typical follow-up |
|---|---|---|---|
| IAM access | Are identities individually assigned and privileges restricted? | Role/policy inventory with account IDs redacted | Reduce permissions and use roles where appropriate |
| MFA | Are root and console users protected by MFA? | Redacted MFA status | Enable and verify MFA; manage break-glass access |
| Authentication | Does the account password policy meet organizational needs? | Redacted policy settings | Review minimum length and password controls |
| Logging | Is CloudTrail management-event logging enabled as intended? | Redacted trail configuration, delivery checks | Review coverage and log destinations |
| Log integrity | Is log-file validation enabled and used? | Validation configuration / approved output | Confirm logs are retrievable and validation can run |
| Configuration tracking | Is AWS Config enabled, and is recording complete? | Recorder state plus permission/coverage checks | Resolve recording errors and validate scope |
| EBS | Is encryption by default enabled in intended Regions? | Redacted regional setting | Also review existing EBS volumes separately |
| S3 | Are public access settings, TLS policies and retention suitable? | Redacted bucket-level settings | Test bucket policy changes against service delivery |
| Detection | Are meaningful events visible to analysts? | Authorized alerts/dashboards | Tune alerting and reduce false positives |
| Remediation | Were changes independently verified and rescanned? | Before/after control snapshots | Track unresolved findings and ownership |

**Important nuances:** S3 Block Public Access being enabled does not prove all storage is safe, while an S3 control gap does not by itself mean that a bucket is publicly exposed. AWS Config recorder status does not guarantee every resource was recorded successfully. Enabling *default* EBS encryption does not retroactively encrypt existing volumes. Findings from automated scanners require manual validation and prioritization.

Never publish real account IDs, access keys, session tokens, full policy dumps, production inventory, or organizational findings without authorization.
