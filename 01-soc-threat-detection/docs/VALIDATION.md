# Validation & Reproducibility

This document records tests performed against **independent educational code**, not original internship solutions.

## Environment

- Runtime: Python 3.13 used for the recorded test run (code is compatible with Python 3.10+)
- Dependencies: Python standard library only for the detector and its tests
- Dataset: `data/synthetic_auth_events.csv` (fictional identities and documentation-only IP addresses)
- Network access: not required

## Reproduce the Python results

Run these commands from `01-soc-threat-detection/`:

```bash
python log_analyzer.py
python -m unittest -v test_log_analyzer.py
```

Default script output:

```text
[ALERT] 192.0.2.10: 3 failed logins between 2026-10-01T10:00:00Z and 2026-10-01T10:00:50Z
Analysis complete: 1 source(s) flagged.
```

**Recorded result:** 17 automated unit tests passed.

## Covered test scenarios

| Area | What is checked |
|---|---|
| Detection | Three failures from the same IP inside one minute |
| Noise handling | Two failures do not trigger |
| Time logic | Events outside one minute do not trigger |
| Grouping | Different source IPs are evaluated separately |
| Status | Successful logins are excluded |
| Ordering | Unsorted events produce the same detection |
| Boundary | Exactly sixty seconds is included |
| Multiple sources | Two qualifying IPs produce independent alerts |
| Empty input | Empty event list returns no alerts |
| Parameter validation | Nonpositive threshold and negative time window rejected |
| Time zones | Explicit UTC offsets normalized; missing zones rejected |
| CSV validation | Missing columns and invalid IP addresses rejected |
| Integration | Synthetic CSV and command-line output verified |

## How the Python detector works

1. Read explicit-timezone authentication events from the fictional CSV.
2. Retain failed events and group by source IP address.
3. Sort timestamps and maintain an inclusive sliding time window.
4. Emit the first qualifying alert per source IP, avoiding repeated demonstration alerts.

This is a minimal learning example: it does not account for user identity context, NAT sharing, approved scanners, account lockout policy, ingestion gaps, or event enrichment. Review alert context before interpreting failures as malicious activity.

## Sigma YAML check

The file `sigma/windows_failed_logon_burst.yml` was parsed successfully as **two YAML documents** using PyYAML in the package validation environment. Structural checks confirmed that:

- The base rule selects `EventID: 4625` from Windows Security logs.
- The correlation references the base rule's `name`.
- The correlation specifies `type: event_count`, `group-by: [IpAddress]`, `timespan: 1m`, and `condition: {gte: 3}`.

These checks verify YAML readability and intended structure, **not** full Sigma schema conformance, conversion by a particular backend, detection accuracy, or successful deployment. Validate and map fields with a supported Sigma converter and your own target SIEM before operational use.

**Semantic difference:** The Python script uses an inclusive sliding window; Sigma `event_count` correlations may compile into time buckets. Result counts can differ at bucket boundaries.

Further reading: [Sigma correlation documentation](https://sigmahq.io/docs/meta/correlations.html).

## Publication boundaries

Only generic training summaries and new fictional demonstrations are shared here. No original confidential task code, full task solutions, sensitive real logs, or executable samples are included.
