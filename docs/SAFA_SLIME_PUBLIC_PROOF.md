# SAFA -> SLIME Public Proof Boundary

## Statement This Proof Is Intended To Support

This integration demonstrates that the cleaned SAFA decision surface can hand
off one bounded action mapping to the cleaned public SLIME harness under
explicit demo assumptions.

More precisely, the proof covers:

- SAFA `ActionRequest` parsing and validation
- SAFA action-to-domain mapping through a dedicated demo config fixture
- handoff of the mapped `(domain, magnitude)` pair into the public SLIME
  ingress shape
- one observed `AUTHORIZED` outcome
- one observed `IMPOSSIBLE` outcome

## What This Proof Does Not Claim

This proof does not demonstrate:

- production readiness
- enterprise or private AB-S integration
- canonical-law completeness
- semantic equivalence between SAFA domains and SLIME canon domains
- Unix socket deployment parity on every platform

## Demo Assumptions

The integration proof is intentionally narrow and uses the following explicit
assumptions:

1. SAFA uses a demo fixture whose domain mappings are chosen only to exercise
   the handoff shape into the public SLIME harness.
2. The public SLIME harness runs with `stub_ab`.
3. On non-Unix platforms, the proof uses a demo-only egress sink so that an
   authorized path can be observed without claiming Unix deployment parity.

## Reading Rule

If the demo succeeds, the truthful conclusion is:

> The cleaned public SAFA and the cleaned public SLIME harness can participate
> in one bounded end-to-end handoff path under explicit demo assumptions.

If stronger claims are needed, they must be proven separately.
