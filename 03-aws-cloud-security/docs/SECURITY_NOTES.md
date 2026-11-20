# Portfolio scope, source separation and responsible disclosure

## Two intentionally separate sources of content

1. **Internship case-study summaries**: high-level, individually performed, authorized AWS security exercises documented in internship reports. The reports themselves, screenshots of account inventories, exported Scout Suite results, and exact solution steps are **not published here**.
2. **Independent demonstration**: brand-new, fictional JSON snapshots and a standard-library Python script. These do not connect to AWS, use credentials or reproduce the original Scout Suite report. The demonstration models only eleven illustrative control checks, so its findings must not be compared numerically with Scout Suite's larger assessment.

## What the real internship results do and do not prove

- The lab Scout Suite run evaluated **243 check results** across IAM, EC2, S3 and CloudTrail, with **22 initially flagged**; a follow-up run reported **20 flagged** after enabling IAM user MFA and EBS default encryption.
- The reduced count shows an improvement on those assessed checks, **not comprehensive AWS security or compliance**.
- IAM user MFA was separately verified and EBS default encryption was enabled in the assessed Region; neither step establishes remediation of all other risks.
- The storage-bucket Block Public Access setting was enabled in the lab, and the assessment did **not** establish publicly exposed S3 buckets.
- AWS Config was enabled but some resource-recording permission errors appeared; its coverage should not be overstated.
- Findings represented configuration/monitoring gaps, not successful exploitation.

## Publication precautions

- No AWS access keys, secret keys, account numbers, resource ARNs, user names, policy exports, raw scanner output or sensitive screenshots.
- No live AWS API calls are made by repository code.
- No internship-issued confidential reports, assessment keys, or complete task solutions are published.
- Sharing remains subject to EncryptEdge Labs' guideline to publish selected summaries when the relevant task/cohort is concluded and no sensitive material is included.
- Any future changes must be reviewed for leaks, including Git commit history.
