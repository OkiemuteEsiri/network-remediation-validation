# Architecture and Methodology

## Purpose

This project demonstrates a defensive workflow for validating whether network-security remediation has actually reduced exposure. It is intentionally offline and uses synthetic data only. The core principle is that **implementation is not closure**: a firewall, segmentation, remote-access, TLS, DNS, or network-service change should remain in a validation state until the intended control behavior is independently re-tested and evidence is retained.

## Architecture

```text
Synthetic JSON remediation cases
        |
        v
src/io_utils.py
  - schema checks
  - timestamp normalization
  - duplicate case rejection
        |
        v
src/models.py
  - immutable remediation cases
  - lifecycle validation
  - CIDR validation
        |
        v
src/validator.py
  - expected vs observed comparison
  - evidence checks
  - exception-expiry checks
  - deterministic finding IDs
  - contextual residual-risk scoring
        |
        v
src/reporting.py
  - portfolio metrics
  - executive Markdown report
        |
        v
src/cli.py
  - offline command-line execution
```

## Validation lifecycle

1. **Open** — a network control weakness or remediation requirement is recorded.
2. **Implemented** — the technical owner reports that the approved change has been applied.
3. **Validated** — an independent check demonstrates that observed behavior matches the approved target state and evidence is retained.
4. **Accepted** — remediation is deferred under an approved exception with an owner, compensating controls, and expiry date.

The model intentionally avoids treating an implementation timestamp as proof that risk is closed.

## Control validation examples

### Firewall and ACL changes

Validation should compare the approved rule intent with the resulting effective policy. Typical evidence includes an exported rule review, a controlled connectivity test from an approved test point, and a timestamped change record.

### Segmentation changes

Validation should confirm that only approved source zones can reach the protected destination and required service. Testing should include both allowed and expected-denied paths in an authorized lab or approved enterprise validation process.

### Remote access

Validation should confirm that administrative protocols are restricted to approved management paths such as VPN or privileged-access networks, with authentication and ownership controls separately reviewed.

### TLS and DNS

Validation should confirm the approved security configuration without actively probing unknown or unauthorized infrastructure. This repository models those results as imported observations rather than performing live scanning.

## Residual-risk scoring

The engine produces an explainable score from 0–100 using bounded factors:

- original severity,
- remediation lifecycle state,
- expected-versus-observed mismatch,
- missing validation evidence,
- missing accountable owner,
- expired risk acceptance.

The score is a prioritization aid, not a replacement for engineering judgment or formal risk acceptance.

## ATT&CK context

Mappings provide defensive threat context only:

- **T1190 — Exploit Public-Facing Application**
- **T1133 — External Remote Services**
- **T1021 — Remote Services**
- **T1210 — Exploitation of Remote Services**
- **T1078 — Valid Accounts**
- **T1557 — Adversary-in-the-Middle**
- **T1071.004 — DNS**

A mapped technique does not mean the technique occurred and is not evidence of compromise.

## Remediation closure standard

A case should move to validated only when all applicable conditions are met:

- approved target state is documented;
- change is implemented by the accountable owner;
- observed state matches the target;
- evidence is retained and dated;
- no material unintended exposure is introduced;
- temporary exceptions are still approved and unexpired;
- failed validation is returned to remediation rather than administratively closed.

## Safety boundary

The project contains no exploit code, live scanning, credential collection, packet injection, bypass automation, or production infrastructure. All examples are synthetic and intended for defensive engineering, governance, and portfolio demonstration.
