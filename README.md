<img width="1199" height="349" alt="SAFA" src="https://github.com/user-attachments/assets/6ea5070d-c4da-47b8-80db-3c7c93acae82" />

# SAFA

**SAFA — SLIME Adaptor For Agents**

A policy evaluation engine for **autonomous AI agents and LLM tool-use systems**.

SAFA is the **judgment layer** between intent and execution:
it determines whether an action is authorized — without executing it.

---

## Acronym

**SAFA** stands for:

> **SLIME Adaptor For Agents**

- **SLIME** → structural model defining what can exist  
- **Adaptor** → bridges structured intent to executable systems  
- **Agents** → autonomous systems and LLM tool-use environments  

SAFA is a **policy engine**, not a runtime system.

---

## Core Role

SAFA answers a single question:

> **Can this action happen?**

It does **not**:
- execute actions  
- perform orchestration  
- define workflows  

Execution always happens **outside SAFA**.

---

## Repository Structure

This repository contains three layers:

### 1. `safa-core` — Canonical Policy Engine

The core judgment engine.

Responsibilities:
- policy evaluation  
- rule application  
- canonical verdict generation  

Properties:
- deterministic  
- no product semantics  
- no provider logic  
- no effectful I/O before authorization  

---

### 2. `safa-daemon` — Reference Transport Surface

A minimal HTTP interface exposing SAFA.

Purpose:
- demonstrate real usage  
- enable agent/LLM integration  
- support testing  

Important:

> `safa-daemon` is a **reference implementation**, not a product runtime.

It does **not**:
- implement business logic  
- define workflows  
- act as a system membrane  

---

### 3. `actuators` — Post-Authorization Adapters

Generic components that execute effects **after authorization**.

Examples:
- file operations  
- shell execution  
- HTTP calls  

Important:

> Actuators are **adapters**, not the core system.

They exist for:
- demonstration  
- integration  

They are not:
- product integrations  
- workflow engines  

---

## What SAFA Is NOT

SAFA is **not**:

- a product backend  
- a workflow engine  
- a runtime system  
- a system membrane  
- a provider integration layer  

SAFA does not replace system architecture.

It only provides **authorization judgment**.

---

## Core Properties

### Binary Canonical Verdict

All canonical decisions resolve to:

- `Authorized`  
- `Impossible`  

Transport or validation errors are **not** canonical verdicts.

---

### No Effectful I/O Before Authorization

SAFA performs no side effects before judgment:

- no network calls  
- no writes  
- no execution  

Read-only validation is allowed.

---

### Deterministic

Same input → same verdict.

No hidden state. No implicit behavior.

---

### Product-Agnostic

SAFA contains:
- no product vocabulary  
- no provider-specific logic  
- no UX assumptions  

It is designed to remain usable **without knowledge of any product**.

---

## Execution Boundary

SAFA defines a strict boundary:

```text
Intent → SAFA → Verdict → Execution (external)

SAFA stops at the verdict.

Execution belongs to another system.

Example (Conceptual)
let verdict = safa.evaluate(policy, input);

if verdict == Authorized {
    // execution handled outside SAFA
} else {
    // reject action
}
Doctrinal Integrity

SAFA enforces:

Binary verdict at the canonical layer
No effectful I/O before authorization
Strict separation: judgment ≠ execution
Product isolation

If a policy engine starts to know what it is used for, it is already broken.

Relationship to SLIME-Core
SLIME-Core → defines what can exist
SAFA → determines what is allowed

SAFA operates on top of structural constraints defined elsewhere.

Intended Use

SAFA is designed for:

autonomous AI agents
LLM tool-use systems
automation pipelines requiring strict authorization
systems needing deterministic policy evaluation
Important Clarification

SAFA is a judgment engine with a reference transport surface.

It is not:

a complete system
a runtime platform
a security solution by itself
Status

Active development.

Philosophy

Keep the judgment engine small, strict, and predictable.
Everything else belongs outside.
