# SAFA Doctrinal Amendments

This document defines the public doctrinal contract for SAFA as a standalone policy evaluation engine.

## 1. Canonical Role

SAFA answers one question:

> Can this action happen under the declared policy?

It is not responsible for transport, orchestration, provider integration, or execution.

## 2. Canonical Verdict

The canonical authorization surface is binary:

- `Authorized`
- `Impossible`

Anything outside that binary shape belongs to transport, validation, or hosting layers and must not redefine the core policy verdict.

## 3. Evaluation Boundary

SAFA may perform read-only validation needed to normalize input and confirm structural safety.

Before authorization, SAFA must not perform effectful I/O such as:

- outbound network mutation
- filesystem mutation
- process execution
- credential brokerage

## 4. Product Neutrality

SAFA must remain product-agnostic:

- no product names in public-facing doctrine
- no provider-specific policy semantics
- no workflow assumptions tied to a single application

If a downstream system needs product behavior, that behavior belongs outside SAFA.

## 5. Separation Of Concerns

Policy evaluation and execution are separate concerns.

- SAFA decides whether an action is allowed.
- External systems decide how to carry out allowed actions.

This boundary preserves determinism, auditability, and reusability.

## 6. Public Repository Standard

The public repository should present SAFA as a generic engine suitable for autonomous agents, LLM tooling, and automation systems.

Public documentation should therefore prefer:

- generic terminology
- doctrinal clarity
- architecture-neutral examples

And avoid:

- private roadmap artifacts
- product-specific implementation narratives
- internal naming that leaks unrelated systems
