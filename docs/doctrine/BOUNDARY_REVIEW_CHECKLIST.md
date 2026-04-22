# Boundary Review Checklist

This checklist is used during architectural review to verify that SAFA — and systems derived from the SYF foundation layers — preserve their canonical boundaries.

Each reviewed change MUST pass every item below. A single failure is an architectural regression.

---

## Canon

- [ ] No product semantics in foundational repos
- [ ] No runtime/framework imports in judgment/core
- [ ] No provider/business vocabulary in public types

---

## Ownership

- [ ] Canon lives in kernel only
- [ ] Judgment lives in SAFA only
- [ ] Runtime lives outside SAFA
- [ ] Surface does not actuate

---

## Truth

- [ ] README matches actual role
- [ ] Docs do not overclaim
- [ ] Public examples are generic

---

## Drift

- [ ] No reintroduction of product terms
- [ ] No hidden coupling through trait names
- [ ] No runtime logic creeping into policy layer

---

## Failure Policy

Any failure is treated as an architectural regression. Fix is required before merge. Undocumented exceptions are bugs.

See [`ARCHITECTURE_BOUNDARIES_v0.2.md`](ARCHITECTURE_BOUNDARIES_v0.2.md) for the canonical doctrine this checklist enforces.
