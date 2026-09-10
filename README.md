# Network Remediation Validation Lab

A defensive network-security engineering project that validates whether remediation work actually changed the effective control state. The lab focuses on **post-remediation assurance**: comparing an approved target state with observed results, retaining validation evidence, measuring residual risk, and preventing administrative closure of controls that have not been independently verified.

This repository uses **synthetic data only** and performs no live scanning, exploitation, credential collection, packet injection, or production changes.

## Why this project exists

Network remediation frequently fails at the final control-assurance step. A firewall ticket can be closed even though a broader rule still exists. A segmentation change can be deployed without confirming denied paths. A remote-access restriction can be marked complete even though the effective rule set does not match the approved design. Temporary exceptions can also remain in place after their expiry date.

This project models a stronger lifecycle:

```text
Finding / requirement
        |
        v
Approved target state
        |
        v
Technical implementation
        |
        v
Independent validation
        |
        +---- mismatch / missing evidence ----> remediation re-opened
        |
        v
Evidence-backed closure
```

The operating principle is simple:

> **Implementation is not equivalent to validation. Validation is not complete until the observed control state matches the approved target and evidence is retained.**

## Security engineering capabilities demonstrated

- Network remediation governance
- Post-change control validation
- Firewall and ACL assurance
- Segmentation validation
- Remote-access exposure review
- TLS, DNS, and network-service control modelling
- Exception-expiry governance
- Residual-risk scoring
- Evidence-preserving findings
- Deterministic finding identifiers
- Defensive MITRE ATT&CK contextual mapping
- Data validation and fail-closed ingestion
- Portfolio security metrics
- Executive and technical reporting
- Unit-test-driven control logic
- Least-privilege CI/CD

## Repository structure

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml
├── data/
│   └── synthetic_remediation_cases.json
├── docs/
│   └── architecture-methodology.md
├── reports/
│   └── example-assessment.md
├── src/
│   ├── __init__.py
│   ├── cli.py
│   ├── io_utils.py
│   ├── models.py
│   ├── reporting.py
│   └── validator.py
└── tests/
    └── test_validator.py
```

## Core workflow

### 1. Ingest remediation cases

`src/io_utils.py` loads an offline JSON dataset and applies fail-closed validation. Duplicate case identifiers, malformed timestamps, invalid CIDRs, and unsupported lifecycle values are rejected rather than silently normalized into misleading results.

### 2. Build validated domain objects

`src/models.py` defines immutable remediation and finding models. Lifecycle constraints prevent contradictory records, such as validation occurring before implementation or a validated case having no supporting evidence.

### 3. Compare expected and observed state

`src/validator.py` evaluates each case for:

- missing accountable ownership;
- implementation without independent validation evidence;
- target-state versus observed-state mismatch;
- expired risk acceptance;
- residual exposure after a reported remediation change.

### 4. Prioritize residual risk

The engine assigns a bounded **0–100 residual-risk score** using explainable factors:

- original remediation severity;
- current lifecycle state;
- expected/observed mismatch;
- missing validation evidence;
- missing owner;
- expired exception.

The score supports prioritization but does not replace engineering judgment or formal risk acceptance.

### 5. Produce governance metrics and reporting

`src/reporting.py` produces portfolio metrics including:

- total remediation cases;
- independently validated cases;
- validation rate;
- open validation gaps;
- critical/high validation gaps;
- highest residual-risk score;
- lifecycle distribution;
- finding-severity distribution.

It can then render an executive-style Markdown report with technical rationale, ATT&CK context, remediation actions, and revalidation requirements.

## Example synthetic scenarios

The included dataset contains four fictional network remediation cases:

| Case | Control | Scenario | Validation state |
|---|---|---|---|
| `NET-001` | Remote access | RDP restriction reported implemented, but evidence is missing and observed state still differs from target | Gap |
| `NET-002` | Segmentation | PostgreSQL access restricted to approved application subnet and independently re-tested | Validated |
| `NET-003` | Network service | Broader SMB access remains under a temporary exception that has expired | Gap |
| `NET-004` | Firewall | Public API edge permits only approved HTTPS exposure and evidence is retained | Validated |

All assets, addresses, owners, evidence references, and observations are synthetic.

## MITRE ATT&CK context

The project uses ATT&CK mappings as defensive context for why a control matters:

| Technique | Relevance |
|---|---|
| T1190 — Exploit Public-Facing Application | Internet-facing exposure and firewall validation |
| T1133 — External Remote Services | Remote-access restriction and administrative exposure |
| T1021 — Remote Services | Segmentation and lateral-access control |
| T1210 — Exploitation of Remote Services | Reachability of vulnerable or sensitive network services |
| T1078 — Valid Accounts | Authentication context around remote administrative access |
| T1557 — Adversary-in-the-Middle | TLS and transport-control context |
| T1071.004 — DNS | DNS security-control context |

ATT&CK mappings are not evidence that a technique occurred and are not proof of compromise.

## Running the lab

Requires Python 3.12 or a compatible modern Python 3 release.

```bash
python -m unittest discover -s tests -v
```

Generate a report from the synthetic dataset:

```bash
python -m src.cli data/synthetic_remediation_cases.json --report reports/generated-report.md
```

The CLI performs no network activity. It only evaluates the supplied local dataset.

## Validation standard

A remediation case should only be treated as validated when:

1. the approved target state is documented;
2. the change was implemented by an accountable owner;
3. the effective observed state matches the approved target;
4. validation evidence is dated and retained;
5. no material unintended access path was introduced;
6. any risk acceptance remains explicitly approved and unexpired;
7. failed validation is returned to remediation rather than administratively closed.

## Example output

The committed example report demonstrates how validation gaps can be communicated to both technical owners and security leadership. The synthetic assessment shows a 50% independently validated case rate and highlights missing validation evidence, target-state mismatch, and expired exception governance.

See [`reports/example-assessment.md`](reports/example-assessment.md).

## CI/CD

The GitHub Actions workflow uses read-only repository permissions and performs:

- Python source compilation;
- unit-test discovery and execution;
- an offline synthetic CLI smoke test.

The workflow does not connect to external infrastructure or require secrets.

## Design decisions

### Evidence before closure

A change ticket, configuration claim, or implementation timestamp is not treated as proof that a control now behaves correctly.

### Fail closed on bad input

Invalid CIDRs, duplicate case IDs, unsupported states, and contradictory lifecycle dates raise errors instead of being ignored.

### Deterministic findings

Finding identifiers are derived deterministically from the remediation case and validation condition. This supports repeatable reporting and easier reconciliation across repeated assessments.

### Separate risk acceptance from validation

An accepted risk is not represented as a validated control. Exceptions remain a distinct lifecycle state and are checked for expiry.

### Synthetic, defensive scope

The repository demonstrates security-engineering reasoning without performing active discovery or exploitation. It is designed for safe portfolio demonstration and controlled enterprise-style methodology.

## Skills demonstrated

This project is intended to demonstrate practical capability relevant to roles such as:

- Security Engineer
- Network Security Engineer
- Vulnerability / Exposure Management Analyst
- Security Assurance Engineer
- Purple Team Engineer
- Detection / Response Engineer
- Cyber Risk Engineer

The emphasis is on **control effectiveness, measurable remediation, evidence-backed closure, and defensible risk communication** rather than repository volume.

## Roadmap

Potential future enhancements include:

- policy-as-code import adapters for synthetic firewall exports;
- change-ticket correlation using offline fixtures;
- validation SLA metrics;
- remediation aging and reopen-rate analytics;
- compensating-control scoring;
- network-zone dependency graphing;
- trend reporting across repeated validation cycles;
- JSON and CSV report exporters.

## Safety and ethics

Use network testing only against systems you own or have explicit authorization to assess. This repository does not contain exploit payloads, credential attacks, packet-injection logic, live scanning, bypass automation, or production targeting. The included data and reports are fictional and synthetic.
