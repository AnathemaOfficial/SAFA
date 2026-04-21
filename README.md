# SAFA

**SAFA** is a policy evaluation engine designed for autonomous agents and LLM-driven systems.

It provides a deterministic way to decide whether a given action is authorized, based on explicit policy and validated input.

---

## What SAFA Does

SAFA evaluates:

- structured input
- policy rules
- contextual constraints

And produces a **canonical authorization verdict**:

- `Authorized`
- `Impossible`

This binary outcome is the core guarantee of SAFA.

---

## What SAFA Does NOT Do

SAFA does **not**:

- perform network requests
- execute actions
- manage credentials
- store state or logs
- implement product-specific workflows
- integrate with external providers

SAFA is **not a runtime**.
It is a **decision engine**.

---

## Why SAFA Exists

Autonomous systems (agents, LLM tools, automation pipelines) need:

- predictable authorization
- explicit policy boundaries
- deterministic outcomes
- safe composition with external systems

SAFA provides a minimal, composable layer for:

> **"Can this action happen?"**

It does not answer:

> **"How is this action executed?"**

---

## Core Properties

### Binary Verdict

All canonical decisions reduce to:

- `Authorized`
- `Impossible`

Transport or validation errors are **not** verdicts.

---

### No Effectful I/O

SAFA performs **no effectful I/O** before authorization:

- no network calls
- no writes
- no execution

Read-only validation is allowed (e.g. structure, metadata).

---

### Product-Agnostic

SAFA has:

- no knowledge of products
- no provider-specific logic
- no UI or UX assumptions

It is designed to be embedded in any system.

---

## Example (Conceptual)

```rust
let verdict = safa.evaluate(policy, input);

match verdict {
    Authorized => {
        // proceed to execution (outside SAFA)
    }
    Impossible => {
        // reject action
    }
}
```

---

## Composition

SAFA is designed to be composed with:

- agent runtimes
- LLM toolchains
- automation systems
- execution layers

It can be used standalone or as part of a larger architecture.

---

## Doctrine

SAFA is governed by explicit doctrinal rules:

- binary canonical verdicts
- no effectful I/O before authorization
- strict separation between policy and execution
- product-agnostic design

See:

- `docs/doctrine/SAFA_DOCTRINAL_AMENDMENTS.md`
- `docs/doctrine/SAFA_COMPLIANCE_SCORE.md`

---

## CI & Integrity

SAFA includes automated checks to prevent architectural drift:

- doctrinal CI checks
- compliance scoring
- invariant enforcement

These ensure SAFA remains:

- deterministic
- composable
- product-independent

---

## Design Philosophy

> If a policy engine starts to know what it is used for, it is already broken.

SAFA exists to remain small, strict, and predictable.

---

## Status

Active development - designed for integration with modern autonomous systems and LLM-based tooling.
