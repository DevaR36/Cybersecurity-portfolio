# SOC Monitoring & Threat Detection

## Project Overview

This project documents selected Security Operations Center (SOC) investigations and detection engineering exercises completed during my Junior Cybersecurity Analyst Internship at EncryptEdge Labs.

The work focused on security event monitoring, log correlation, network traffic analysis, threat detection, and incident response within authorized virtual laboratory environments.

## Tools & Technologies

**SIEM:** Wazuh, Splunk, Elasticsearch, Kibana

**Network Security:** Suricata, Zeek, Wireshark

**Endpoint Monitoring:** Sysmon, Windows Event Logs

**Environment & Automation:** Ubuntu Linux, Windows 10, VMware, Docker, Python

## Case Study 1: Authentication Monitoring & SIEM Analysis

**Objective:** Identify suspicious authentication activity and improve detection through log correlation.

### Methodology

- Configured Windows endpoint event monitoring using Sysmon and Wazuh.
- Analyzed Windows authentication events, including failed-login Event ID 4625 and privileged-logon Event ID 4672.
- Developed custom Wazuh correlation rules to identify repeated authentication failures and privileged-login activity.
- Used Splunk to examine authentication, endpoint, and network event patterns in controlled training datasets.

### Results

- Successfully generated a Wazuh Level 10 alert for three failed login attempts within 60 seconds.
- Validated additional Level 8 detection for privileged-logon activity.
- Demonstrated how event correlation improves visibility into potentially suspicious authentication behavior.

## Case Study 2: Network Incident Investigation & Detection Engineering

**Objective:** Investigate suspicious network activity and improve detection coverage using network security monitoring tools.

### Methodology

- Analyzed a historical network capture containing 22,473 packets.
- Examined Suricata alerts and correlated relevant network activity using Zeek and Wireshark.
- Investigated suspicious HTTP communications and identified candidate indicators of compromise.
- Developed and validated a custom Suricata detection rule for a recurring HTTP POST pattern.
- Integrated the custom detection with Wazuh and verified alert indexing in the SIEM dashboard.

### Results

- Identified 51 alerts using the original Suricata ruleset.
- Generated 113 additional alerts using the new detection rule during offline analysis.
- Increased observed alert coverage from 51 to 164 alerts in the combined ruleset.
- Successfully validated the corresponding Wazuh detection through a controlled test event.

These results demonstrate improved detection coverage for the specific traffic pattern. They do not establish confirmed malware execution, successful data exfiltration, or a measured false-positive rate.

## Key Skills Demonstrated

- SOC Monitoring & Alert Triage
- SIEM Configuration & Log Correlation
- Network Traffic Analysis
- Detection Engineering
- Security Event Investigation
- MITRE ATT&CK Mapping
- Incident Response Documentation

## Project Scope & Disclaimer

All activities were performed in authorized laboratory environments using controlled or historical training datasets.

This portfolio presents original summaries of technical methods and findings. Confidential internship reports, sensitive evidence, credentials, and restricted materials are excluded.
