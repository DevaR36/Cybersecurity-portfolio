
# Digital Forensics & Malware Analysis

## Project Overview

This project highlights selected digital forensics and malware analysis investigations completed during my Junior Cybersecurity Analyst Internship at EncryptEdge Labs.

The investigations focused on forensic evidence examination, Windows memory analysis, malware indicators, suspicious network activity, and incident timeline reconstruction.

All exercises were conducted using authorized laboratory environments and training datasets.

## Tools & Technologies

**Digital Forensics:** FTK Imager, Autopsy, Volatility 3, Sleuth Kit, Plaso

**Malware Analysis:** REMnux, YARA, INetSim, ExifTool, strings

**Network Analysis:** Wireshark, TShark

**Environment:** Ubuntu Linux, Windows, VMware Workstation

---

## Case Study 1: Disk & Memory Forensics

### Objective
Examine forensic evidence to identify suspicious processes, persistence mechanisms, and potentially malicious system activity.

### Methodology
- Used FTK Imager to examine a Windows forensic image and extract event logs in an endpoint security exercise.
- Imported and examined an NTFS forensic test image using Autopsy, verifying image integrity.
- Analyzed Windows memory artifacts using Volatility 3.
- Investigated process relationships, network connections, and Registry persistence indicators.
- Examined Windows event logs and filesystem timestamps to support investigation findings.

### Results
- Successfully verified and examined forensic disk image contents.
- Identified suspicious process activity and potential Registry-based persistence in a training memory image.
- Documented relevant network artifacts and investigation limitations.
- Demonstrated forensic analysis without modifying original evidence.

---

## Case Study 2: Malware Traffic & Static Analysis

### Objective
Identify suspicious executable delivery, investigate potential malware-related communications, and develop detection indicators.

### Methodology
- Configured an isolated REMnux malware analysis environment.
- Examined a historical packet capture containing 42,497 packets.
- Recovered a suspicious Windows executable transferred over HTTP.
- Performed static analysis using file metadata, SHA-256 hashing, ExifTool, and embedded strings.
- Developed and tested a sample-specific YARA detection rule.
- Tested INetSim network-service emulation using a harmless HTTP request.

### Results
- Identified suspicious executable delivery and investigated potential command-and-control communication.
- Successfully extracted and examined a Windows PE executable without executing it.
- Validated a custom YARA rule against the recovered sample and a negative control.
- Documented indicators of compromise and containment recommendations.

**Limitation:** Live malware execution was not performed. Suspected command-and-control behavior was not independently confirmed.

---

## Case Study 3: Forensic Timeline & Incident Investigation

### Objective
Reconstruct security-relevant events by analyzing disk, memory, and network evidence from a historical DFIR training dataset.

### Methodology
- Used Plaso (log2timeline and psort) to generate and examine a forensic timeline from a Windows disk image.
- Analyzed Windows security events, authentication activity, and system changes.
- Investigated a network capture using Wireshark.
- Used Volatility 3 to analyze Windows processes and network artifacts.
- Correlated available timestamps and documented candidate indicators.

### Results
- Generated a forensic timeline containing 1,035,505 extracted events.
- Examined a network capture containing 411,797 packets.
- Investigated suspicious RDP activity and process-related artifacts.
- Prepared structured forensic findings, risk assessments, and response recommendations.

**Limitation:** Timeline extraction generated 1,211 parser warnings. Some evidence sources could not be conclusively linked into a single attack sequence.

---

## Key Skills Demonstrated

- Digital Evidence Examination
- Windows Memory Forensics
- Forensic Timeline Reconstruction
- Malware Static Analysis
- YARA Detection Rules
- Network Traffic Investigation
- Incident Response Documentation
- Evidence Integrity Verification

## Project Disclaimer

These case studies summarize independent investigations conducted in authorized training environments.

Findings are presented with their technical limitations and should not be interpreted as confirmed incidents affecting real organizations.

Confidential internship reports, sensitive evidence, and restricted materials are not included.
