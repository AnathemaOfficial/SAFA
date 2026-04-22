# Contributing to SAFA

---

## ⚠️ Boundary-Critical Repository

SAFA enforces strict architectural boundaries.

Most contributions are rejected not because of code quality,
but because they violate separation between:

- judgment (SAFA)
- execution (external systems)

Read this document fully before contributing.

---

SAFA is a **policy evaluation engine**.

Its value depends on **strict architectural boundaries**.  
Contributions are accepted only if they preserve those boundaries.

---

## Core Principle

> SAFA is the **judgment layer**, not a runtime system.

It determines whether an action is authorized.  
It does not execute, orchestrate, or define workflows.

---

## Architecture Overview

SAFA is intentionally split into:

- `safa-core` → canonical policy engine (judgment)
- `safa-daemon` → reference transport surface
- `actuators` → generic post-authorization adapters

Each layer has strict responsibilities.

---

## Non-Negotiable Rules

### 1. No Runtime Logic in `safa-core`

Forbidden in `safa-core`:
- network calls
- filesystem writes
- process execution
- async runtimes (`tokio`, `async-std`, etc.)
- HTTP frameworks

Allowed:
- pure evaluation logic
- deterministic transformations
- read-only validation

---

### 2. SAFA Does Not Execute Actions

SAFA must never:
- call external providers
- perform business operations
- trigger workflows

Execution always belongs **outside SAFA**.

---

### 3. `safa-daemon` Is a Reference Implementation

The daemon exists to:
- expose SAFA over HTTP
- demonstrate usage
- support testing

It must **not evolve into a product runtime**.

Forbidden:
- business logic
- provider-specific flows
- product semantics
- orchestration logic

---

### 4. Actuators Are Not the Core

Actuators:
- run **after authorization**
- are generic and minimal

They must not:
- contain product-specific integrations
- define workflows
- become feature-rich subsystems

---

### 5. No Product or Provider Semantics

Forbidden anywhere in the repo:
- product names
- provider-specific logic (e.g. social APIs, SaaS workflows)
- domain-specific vocabulary tied to a product

SAFA must remain:
> understandable without knowledge of any specific system

---

### 6. Binary Verdict Is Canonical

The policy layer must preserve:

```text
Authorized | Impossible

Do not:

extend the canonical verdict model
encode business states as verdicts

Transport-level errors are allowed outside the canonical layer.

7. No Effectful I/O Before Authorization

Before a verdict:

no network calls
no writes
no execution

Read-only validation is allowed.

Contribution Test (Required)

Before submitting a PR, ask:

Boundary Test
Does this belong to judgment, or to execution?
If execution → it does not belong in SAFA
Contamination Test
Does this introduce product vocabulary?
Does it assume a specific system or workflow?

If yes → reject or refactor

Simplicity Test
Does this make SAFA more general, or more vague?

If more vague → reject

Red Flags (Automatic Rejection)

PRs will be rejected if they introduce:

provider integrations
OAuth / credential handling
workflow orchestration
background jobs / schedulers
business rules tied to a product
runtime state management
“temporary” hacks that cross boundaries
Acceptable Contributions
improvements to policy evaluation
stronger typing / canonical structures
validation and containment logic (read-only)
test coverage
documentation clarifications
minimal, generic actuators
improvements to the reference daemon (without adding product semantics)
Design Philosophy

SAFA must remain:

small — minimal surface area
strict — strong constraints
predictable — deterministic behavior
isolated — no runtime coupling

If SAFA starts to absorb responsibilities, it is already failing.

Final Rule

If you cannot clearly explain why a change belongs inside SAFA
it does not belong in SAFA.