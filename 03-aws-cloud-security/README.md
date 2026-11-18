
# AWS Cloud Security Assessment

## Project Overview

This project documents a hands-on AWS cloud security assessment conducted during my Junior Cybersecurity Analyst Internship at EncryptEdge Labs.

The assessment focused on Identity and Access Management (IAM), cloud activity monitoring, configuration security, automated security auditing, and risk-based remediation.

All activities were conducted in an authorized personal AWS laboratory environment.

## Tools & Technologies

**AWS Services:** IAM, CloudTrail, AWS Config, EC2, S3

**Security Assessment:** Scout Suite v5.14.0

**Command-Line Tools:** AWS CLI, AWS CloudShell

**Risk Assessment:** Microsoft Excel, CIS Controls, NIST Security Frameworks

---

## Case Study 1: AWS Security Configuration & Monitoring

### Objective
Configure fundamental AWS security controls and establish visibility into account activities and resource configurations.

### Methodology
- Configured an AWS laboratory environment with IAM identities and appropriate access permissions.
- Reviewed IAM users, attached policies, and least-privilege access principles.
- Configured AWS CloudTrail for multi-Region management-event logging.
- Enabled CloudTrail log file validation and verified active logging.
- Enabled AWS Config for resource configuration monitoring.
- Used AWS CLI to verify security configurations and account settings.

### Results
- Established a working AWS security monitoring environment.
- Verified CloudTrail management-event logging and log delivery.
- Enabled AWS Config continuous recording, while documenting resource-level permission limitations.
- Reviewed authentication and access-control configurations.

---

## Case Study 2: Automated Cloud Security Assessment

### Objective
Identify AWS security misconfigurations and potential security control gaps using automated assessment tools.

### Methodology
- Installed and configured Scout Suite v5.14.0.
- Conducted an AWS security assessment using AWS CloudShell.
- Examined IAM, EC2, S3, and CloudTrail configurations.
- Reviewed automated findings and distinguished configuration gaps from confirmed vulnerabilities.
- Classified security concerns and documented remediation recommendations.

### Results
- Evaluated 243 security check results.
- Identified 22 initially flagged checks across four AWS services.
- Consolidated relevant observations into a risk assessment covering 12 security concerns.
- Identified opportunities to improve authentication, encryption, logging, and storage security.

The findings represented configuration weaknesses or monitoring gaps, not confirmed exploitation or security breaches.

---

## Case Study 3: Security Remediation & Verification

### Objective
Implement selected security improvements and verify their effectiveness through reassessment.

### Methodology
- Enabled Multi-Factor Authentication (MFA) for an IAM user.
- Enabled default EBS encryption in the assessed AWS Region.
- Verified both configuration changes using AWS CLI.
- Re-ran Scout Suite using the original assessment scope.
- Compared baseline and updated security findings.

### Results

| Assessment Metric | Initial Scan | Rescan |
|-------------------|-------------:|-------:|
| Flagged Security Checks | 22 | 20 |
| IAM Findings | 6 | 5 |
| EC2 Findings | 5 | 4 |

**Outcome:** Reduced the number of flagged checks from 22 to 20, representing a 9.1% decrease in the original flagged count.

The remaining flagged checks required further review and remediation.

---

## Key Skills Demonstrated

- AWS Identity and Access Management
- Least-Privilege Security
- Cloud Security Assessment
- CloudTrail Logging and Monitoring
- AWS Config
- Security Misconfiguration Analysis
- Risk Assessment and Prioritization
- Remediation and Verification
- Technical Security Reporting

## Project Disclaimer

This project was conducted in an authorized personal AWS laboratory environment.

The case study summarizes security assessment methodologies and verified outcomes for educational and portfolio purposes.

Cloud credentials, account identifiers, restricted assessment files, confidential internship reports, and sensitive configurations are excluded.
