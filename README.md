# ALERTIQ

AI-powered SOC Analyst for automated security alert triage, correlation, and incident response.

## Overview

ALERTIQ is an intelligent Security Operations Center (SOC) analyst that automates the triage of security alerts using MITRE ATT&CK framework mapping, correlates related alerts into incidents, and generates response playbooks for containment and remediation.

## Features

- **Alert Classification** - Categorizes alerts into malware, phishing, brute force, data exfiltration, insider threat, denial of service, and lateral movement
- **Priority Scoring** - Uses MITRE ATT&CK tactics to compute severity scores with contextual weighting
- **Alert Deduplication** - Groups related alerts to reduce noise and analyst fatigue
- **Correlation Engine** - Links alerts by IP address, user identity, and timeframe into unified incidents
- **Correlation Rules** - Detects same-source multi-type attacks, kill chain progression, and repeated failure patterns
- **Attack Timeline** - Builds narrative timelines from correlated alerts to visualize attack progression
- **Incident Playbooks** - Provides step-by-step response procedures per alert type
- **Response Automation** - Executes containment actions (block IP, disable account, isolate host)
- **Alert Simulation** - Generates realistic alert scenarios for testing and demos
- **Rich Reporting** - Produces formatted incident reports with MITRE ATT&CK mappings

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Simulate alerts and run triage
alertiq simulate --count 20

# Triage a batch of alerts
alertiq triage --input alerts.json

# Correlate alerts into incidents
alertiq correlate --input alerts.json --window 3600

# Generate incident report
alertiq report --incident-id INC-001

# Run full pipeline: simulate -> triage -> correlate -> respond -> report
alertiq run --simulate --count 30
```

## MITRE ATT&CK Coverage

ALERTIQ maps alerts to the following MITRE ATT&CK tactics:

| Tactic | ID | Description |
|---|---|---|
| Initial Access | TA0001 | Entry vectors into the network |
| Execution | TA0002 | Running malicious code |
| Persistence | TA0003 | Maintaining foothold |
| Privilege Escalation | TA0004 | Gaining higher permissions |
| Defense Evasion | TA0005 | Avoiding detection |
| Credential Access | TA0006 | Stealing credentials |
| Discovery | TA0007 | Exploring the environment |
| Lateral Movement | TA0008 | Moving through the network |
| Collection | TA0009 | Gathering target data |
| Exfiltration | TA0010 | Stealing data |
| Command and Control | TA0011 | Communicating with compromised systems |
| Impact | TA0040 | Disrupting availability or integrity |

## Architecture

```
src/alertiq/
  models.py          # Pydantic data models (Alert, Incident, MITRETactic, Playbook)
  cli.py             # Click CLI entry point
  simulator.py       # Alert simulation engine
  report.py          # Rich incident reporting
  triage/
    classifier.py    # AlertClassifier - ML-based alert categorization
    priority.py      # PriorityEngine - MITRE ATT&CK severity scoring
    dedup.py         # AlertDeduplicator - related alert grouping
  correlator/
    engine.py        # CorrelationEngine - multi-signal alert linking
    rules.py         # CorrelationRule definitions
    timeline.py      # AttackTimeline narrative builder
  responder/
    playbook.py      # IncidentPlaybook - response procedures
    automator.py     # ResponseAutomator - containment execution
```

## Author

Mukunda Katta

## License

MIT
