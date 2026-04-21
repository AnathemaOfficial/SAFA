# SAFA

**SAFA** is a policy evaluation engine designed for **autonomous AI agents and LLM tool-use systems**.

It provides a deterministic, composable way to decide whether an action is authorized — without executing it.

---

## Overview

SAFA answers a single question:

> **"Can this action happen?"**

Given:
- structured input
- explicit policy
- validated context

SAFA produces a **canonical authorization verdict**:

- `Authorized`
- `Impossible`

This binary outcome is the core guarantee of the system.

---

## Repository Structure

This repository intentionally contains three distinct layers:

### 1. `safa-core` — Policy Engine (Canonical Layer)

The core evaluation engine.

Responsibilities:
- policy evaluation
- rule application
- canonical verdict generation
- deterministic decision logic

Properties:
- no runtime dependencies
- no network access
- no side effects
- no product knowledge

---

### 2. `safa-daemon` — Reference Implementation (Transport Layer)

A minimal HTTP daemon exposing SAFA to external systems.

Purpose:
- demonstrate real-world usage
- enable agent/LLM integration
- provide a testable standalone surface

Important:
- this is a **reference implementation**, not a product runtime
- it does not define product workflows
- it does not implement business logic

---

### 3. `actuators` — Generic Effect Adapters (Post-Authorization Layer)

Optional components that execute actions **after authorization**.

Examples:
- file operations
- shell execution
- HTTP calls

Properties:
- generic and product-agnostic
- invoked only after a valid `Authorized` verdict
- exist for demonstration and integration purposes

---

## What SAFA Does NOT Do

SAFA explicitly does **not**:

- define product behavior
- implement user-facing workflows
- manage credentials or OAuth flows
- encode provider-specific business logic
- act as a full runtime system
- function as a product "membrane"

Execution, orchestration, and product logic must live **outside SAFA**.

---

## Core Properties

### Binary Canonical Verdict

All authorization decisions resolve to:

- `Authorized`
- `Impossible`

Transport errors, validation failures, or system issues are **not** canonical verdicts.

---

### No Effectful I/O Before Authorization

SAFA performs:

- no network calls
- no filesystem writes
- no external execution

before producing a verdict.

Read-only validation is allowed.

---

### Deterministic & Composable

- same input → same verdict
- no hidden state
- safe to embed in larger systems

---

### Product-Agnostic by Design

SAFA contains:
- no product names
- no provider integrations
- no UX assumptions

It is designed to integrate into:
- agent runtimes
- LLM toolchains
- automation systems
- custom execution layers

---

## Example (Conceptual)

```rust
let verdict = safa.evaluate(policy, input);

match verdict {
    Authorized => {
        // proceed with execution (outside SAFA)
    }
    Impossible => {
        // reject action
    }
}
```

---

## Doctrinal Integrity

SAFA is governed by strict architectural rules:

- **Binary verdict purity** — Canonical authorization is strictly `Authorized | Impossible`
- **No effectful I/O before authorization** — No side effects occur before a decision is made
- **Separation of concerns** — Policy (SAFA) ≠ Execution (external systems)
- **Product isolation** — SAFA must not "know" what it is used for

> If a policy engine starts to know what it is used for, it is already broken.

See:
- [`docs/doctrine/SAFA_DOCTRINAL_AMENDMENTS.md`](docs/doctrine/SAFA_DOCTRINAL_AMENDMENTS.md)
- [`docs/doctrine/SAFA_COMPLIANCE_SCORE.md`](docs/doctrine/SAFA_COMPLIANCE_SCORE.md)

---

## Positioning

SAFA is intended for:

- autonomous AI agents
- LLM tool-use systems
- secure automation pipelines
- deterministic authorization layers

It is **not**:

- a product backend
- a workflow engine
- an execution runtime
- a system membrane

---

## Reference vs Product Systems

This repository demonstrates **how SAFA can be used**, not how a full system should be built.

- `safa-core` → canonical engine
- `safa-daemon` → reference transport layer
- `actuators` → generic execution adapters

Production systems are expected to:

- implement their own runtime
- define their own orchestration
- enforce their own boundaries

---

## Status

Active development.

SAFA is evolving as a foundational component for safe, deterministic authorization in agent-driven systems.

---

## Philosophy

Keep the decision engine small, strict, and predictable.

Everything else belongs outside.
