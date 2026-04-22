# Architecture Boundaries v0.2

**Status:** Canonical draft
**Scope:** SYF foundations and derived systems
**Principle:** *boundaries define the system*

---

## 1. Core Principle

A system is defined by its boundaries, not by the number of components it contains.

If a responsibility cannot be assigned to one layer only, the architecture is already drifting.

---

## 2. Layer Model

The model is four-layered:

| Layer | Question it answers |
|---|---|
| **SLIME-Core** | What can exist? |
| **SAFA** | What is allowed? |
| **Runtime** | What executes? |
| **Surface** | What is shown? |

---

## 3. Ownership Map

| Responsibility | Owner |
|---|---|
| Canon / invariants / representability | **SLIME-Core** |
| Policy judgment / authorization | **SAFA** |
| Actuation / transport / custody / journal / readiness | **Runtime** |
| UX / user projection / interaction | **Surface** |

No other layer may assume these responsibilities.

---

## 4. Layer Definitions

### 4.1 SLIME-Core

SLIME-Core is the canonical kernel.

It defines:
- structural invariants
- representability boundaries
- canonical forms
- impossibility conditions

It does **not**:
- execute actions
- evaluate product policy
- expose product/runtime behavior
- carry provider semantics

---

### 4.2 SAFA

SAFA is the judgment layer.

It evaluates:
- validated input
- explicit policy
- contextual constraints

It produces canonical authorization outcomes.

It does **not**:
- execute actions
- call providers
- define UX
- own product workflows

---

### 4.3 Runtime

The runtime executes authorized actions.

It owns:
- ingress
- transport
- custody
- idempotency
- journal
- readiness
- actuation

It does **not**:
- define canon
- redefine policy
- project UX truth by itself

---

### 4.4 Surface

The surface is what the user sees.

It owns:
- user interaction
- projection of state
- messages
- visibility of readiness
- experience-level truthfulness

It does **not**:
- actuate providers directly
- decide authorization
- recalculate canonical truth locally

---

## 5. Hard Invariants

### I1 — No Cross-Layer Authority

No layer may exercise the authority of another.

### I2 — No Effect Before Judgment

No side effect may occur before canonicalization, identity/context validation, and policy verdict.

### I3 — Canon Is Pure

SLIME-Core must remain free of product, runtime, and provider semantics.

### I4 — Judgment Is Isolated

SAFA must not execute, store runtime state, or call external providers.

### I5 — Runtime Executes, It Does Not Judge

Runtime applies verdicts but does not define them.

### I6 — Surface Cannot Actuate

No direct provider I/O may originate from the user-facing surface.

---

## 6. Dependency Graph

### Allowed conceptual direction

```
Surface → Runtime → SAFA → SLIME-Core
```

### Forbidden conceptual direction

```
SAFA → Runtime
SLIME-Core → Runtime
Surface → Provider
Surface → Canon
Runtime → redefine Policy
```

---

## 7. Truth-First Rule

If the system claims something, the architecture must enforce it.

Examples:

- "authorized" means a policy layer judged it
- "idempotent" means runtime proves it
- "audited" means a journal exists
- "ready" means readiness is real, not inferred cosmetically

---

## 8. Failure Modes

| Failure | Meaning |
|---|---|
| Dual ownership | boundary violation |
| Hidden dependency | coupling leak |
| Side effect before verdict | critical architectural bug |
| Recomputed truth in surface | truth drift |
| Runtime policy logic | SAFA bypass |
| Product semantics in foundations | contamination |

---

## 9. Public vs Closed Layers

Public foundations may remain open if they are still comprehensible without product knowledge.

A layer becomes unsuitable for public exposure when it contains:

- product vocabulary
- runtime membranes
- provider-specific workflows
- private system narratives

This implies:

- **SLIME-Core** may be public
- **SAFA** may be public
- product membranes remain closed where required

---

## 10. Exception Rule

Exceptions are allowed only if they are:

- explicit
- documented
- bounded in scope
- time-limited

An undocumented exception is a bug.

---

## 11. Final Test

A refactor is acceptable only if **all four layers remain distinguishable in code**, not just in directory names.

If the boundary only exists in naming, the system is already collapsing.

---

## 12. Control Phrases

- **Canon fixes what can exist**
- **SAFA judges what is allowed**
- **Runtime executes what is authorized**
- **Surface shows what is true**

These phrases are not metaphors; they are boundary tests.
