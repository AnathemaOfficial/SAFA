# SAFA Compliance Score

This document records the public-facing doctrinal compliance target for SAFA.

## Public Positioning Score

| Area | Target | Status |
|---|---|---|
| Binary authorization vocabulary | `Authorized` / `Impossible` only at the doctrinal layer | Aligned |
| Product neutrality in public docs | No product-specific language | Aligned |
| Execution/policy separation | Policy engine described independently from execution layers | Aligned |
| Public documentation scope | Generic and publishable without private ecosystem context | Aligned |

## Publication Checklist

- README describes SAFA as a policy evaluation engine.
- Public doctrine documents use generic language.
- Product-specific wording is removed from public docs and examples.
- Internal planning and private implementation notes are excluded from the public repo surface.

## Ongoing Review Rules

When updating public materials, reject changes that:

- reintroduce product naming
- turn SAFA into a workflow narrative
- blur the boundary between policy and execution
- assume knowledge of a private ecosystem

## Review Outcome

The public repository should remain understandable to an external engineer who has never seen the surrounding ecosystem.

If a reader must know an internal product to understand SAFA, the public surface has drifted and should be corrected.
