STATUS: NON-CANON
ROLE: SECURITY / VULNERABILITY DISCLOSURE
SCOPE: Reporting and disclosure metadata. Not part of canonical law.

# Security & Vulnerability Disclosure — SAFA

This file is non-canonical metadata describing how to report security
vulnerabilities affecting this repository.

## Reporting

- To report a vulnerability, contact: **corexalt@proton.me**
- Please include:
  - Affected version (release tag or commit SHA).
  - Reproduction steps, ideally with a minimal proof-of-concept.
  - Assessed impact and any known mitigations.
- We will acknowledge receipt within **5 business days**.

## Coordinated Disclosure

We follow a coordinated disclosure model:

- Default disclosure window: **90 days** from acknowledgement.
- Extendable by mutual agreement for complex issues that require upstream
  coordination (Rust crates, Linux kernel, HSM vendors, etc.).
- Public disclosure prior to remediation is discouraged unless safety
  considerations require otherwise.

## Scope

Policy evaluation engine (safa-core), HTTP daemon (safa-daemon), and post-authorization actuators. Reports concerning verdict bypass, transport (mTLS) attacks, or actuator escalation are in scope.

Vulnerabilities in third-party dependencies declared in this repository's
manifests are also welcome; we will coordinate upstream where applicable.

## Out of Scope

- Issues already disclosed publicly without coordination.
- Social engineering of maintainers.
- Denial-of-service against public test infrastructure.
- Findings that violate applicable law or this project's NOTICE / LICENSE
  terms (e.g., unauthorized access to non-public infrastructure).

## Provenance and Maintainer

This Work is the property of **Technologies CoreXalt Inc.** (Québec, Canada);
see the repository's `NOTICE` file for full provenance and attribution
(SYF Core Foundation stewardship 2025 → CoreXalt assignment 2026).

---

This document is non-canonical informational metadata. It does not modify
license, contract, or warranty terms.
