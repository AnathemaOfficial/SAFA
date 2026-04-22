<img width="1199" height="349" alt="SAFA" src="https://github.com/user-attachments/assets/6ea5070d-c4da-47b8-80db-3c7c93acae82" />

# SAFA

### SLIME Adaptor For Agents

**SAFA** is a policy evaluation engine for **autonomous AI agents and LLM tool-use systems**.

It provides a deterministic, composable way to decide whether an action is authorized — without executing it.

---

## Overview

SAFA answers a single question:

> **Can this action happen?**

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

### 1. `safa-core` — Canonical Policy Engine

The core evaluation layer.

Responsibilities:
- policy evaluation
- rule application
- canonical verdict generation
- deterministic decision logic

Properties:
- no product semantics
- no workflow semantics
- no provider-specific behavior
- no effectful I/O before authorization

---

### 2. `safa-daemon` — Reference HTTP Surface

A minimal daemon exposing SAFA to external systems.

Purpose:
- demonstrate standalone usage
- provide an agent/LLM-facing transport layer
- support testing and integration

Important:
- `safa-daemon` is a **reference implementation**
- it is not a product runtime
- it does not define product workflows
- it does not act as a product membrane

---

### 3. `actuators` — Generic Post-Authorization Adapters

Optional generic adapters that execute effects **after** authorization.

Examples may include:
- file operations
- shell execution
- HTTP calls

Properties:
- generic
- post-authorization only
- not product-specific
- intended for demonstration and integration

---

## What SAFA Does NOT Do

SAFA does **not**:

- define product behavior
- implement user-facing workflows
- manage provider-specific business logic
- encode product semantics
- function as a product membrane
- replace a runtime system

Execution, orchestration, and product-specific runtime behavior must live **outside SAFA**.

---

## Core Properties

### Binary Canonical Verdict

All canonical authorization decisions resolve to:

- `Authorized`
- `Impossible`

Transport errors, validation failures, or system faults are **not** canonical verdicts.

---

### No Effectful I/O Before Authorization

SAFA performs no effectful I/O before canonical authorization:

- no external network side effects
- no writes
- no execution

Read-only validation is allowed where required for containment or input validation.

---

### Product-Agnostic by Design

SAFA contains:
- no product vocabulary
- no provider-specific workflows
- no UX assumptions

It is designed to remain understandable and usable without knowledge of any particular product.

---

## Example (Conceptual)

```rust
let verdict = safa.evaluate(policy, input);

match verdict {
    Authorized => {
        // execution happens outside SAFA
    }
    Impossible => {
        // reject action
    }
}
Doctrinal Integrity

SAFA is governed by strict architectural rules:

Binary verdict purity at the canonical authorization layer
No effectful I/O before authorization
Strict separation between policy and execution
Product isolation

If a policy engine starts to know what it is used for, it is already broken.

See:

docs/doctrine/SAFA_DOCTRINAL_AMENDMENTS.md
docs/doctrine/SAFA_COMPLIANCE_SCORE.md
Positioning

SAFA is intended for:

autonomous AI agents
LLM tool-use systems
secure automation pipelines
deterministic authorization layers

It is not:

a product backend
a workflow engine
an execution runtime
a product-specific membrane
Standalone Use

SAFA is designed to remain useful as a standalone component.

A developer should be able to:

read this repository
understand its role
build it
evaluate policy
integrate it into a larger system

without needing any knowledge of closed or product-specific runtimes.

Status

Active development.

SAFA is evolving as a foundational authorization component for agent-driven systems.

Philosophy

Keep the judgment engine small, strict, and predictable.
Everything else belongs outside.
