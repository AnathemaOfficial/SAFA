# SAFA P3 — Agent Containment & Verifiable Identity

> Phase: **HELD** (v0.3.0-p3-held)
> Predecessor: P2 HELD (v0.2.0-p2-held)
> Tag: `v0.3.0-p3-held`

---

## Definition

SAFA P3 transforms the system from a multi-agent constraint engine with
header-based routing into a system where each agent is **identified,
contained, and verifiable**.

P3 is purely structural. No product features, no UX, no new business
domains.

---

## Scope Statement

> P3 delivers identity binding, capability manifests, and per-agent
> workspace isolation. After P3, an agent cannot impersonate another,
> cannot access another's workspace, and its constraints are verifiable
> by a public hash.

---

## Three Pillars

### Pillar 1 — Identity Binding

**Problem:** `X-Agent-Id` is a free-text header. Any caller can claim to
be any agent. In P2 this is acceptable because SAFA runs on localhost,
but for any networked or multi-tenant deployment this is a structural
gap.

**Deliverable:** Agent identity verified via HMAC signature or
pre-shared token. The daemon rejects requests where the claimed
`X-Agent-Id` does not match the presented credential.

**Minimal implementation:**
- Each agent config (`config/agents/*.toml`) gains a `secret` field
  (HMAC shared secret, stored as SHA-256 hash).
- Requests must include three headers:
  - `X-Agent-Id: <agent_id>`
  - `X-Agent-Timestamp: <unix_epoch_secs>`
  - `X-Agent-Signature: HMAC-SHA256(secret, agent_id + timestamp + request_body_hash)`
- Middleware verifies:
  1. Timestamp is within acceptable window (e.g., ±300s) — prevents replay.
  2. HMAC signature matches — binds identity to the specific request.
  3. Agent ID exists in registry.
- Failure → `403 Forbidden` (not `400`).

**Why HMAC over static secret:**
- Static `X-Agent-Secret` is vulnerable to replay attacks.
- HMAC binds identity to the specific request content and timestamp.
- Replay window is bounded by timestamp tolerance.
- No additional infrastructure required (no PKI, no token server).

**What this is NOT:**
- Not OAuth, not JWT, not PKI. Minimal trust binding only.
- Full authentication is out of scope (reverse proxy / mTLS concern).
- Secret rotation requires process restart (documented, not hot-reloadable).

---

### Pillar 2 — Capability Manifest & Proof-of-Constraint

**Problem:** Agent capabilities are defined in TOML config files but are
not versioned, hashed, or externally verifiable. There is no way for an
external observer to confirm what rules constrain a given agent.

**Deliverable:** Each agent's capability manifest is hashed at boot. The
hash is exposed in HTTP responses and via a dedicated endpoint.

**Minimal implementation:**
- At boot, compute `SHA-256(canonical_json(agent_config))` for each
  registered agent. Canonical JSON = keys sorted alphabetically, no
  extra whitespace, deterministic serialization. Store as `manifest_hash`
  in `AgentRegistry`.
- Every `ActionResponse` includes header `X-Safa-Policy-Hash`.
- New endpoint: `GET /ama/manifest/{agent_id}` returns a `PublicManifest`
  (never exposes `secret` or internal fields):
  ```json
  {
    "agent_id": "default",
    "manifest_hash": "sha256:abc123...",
    "domains": { "fs.read.workspace": { "enabled": true, "max_magnitude": 1000 } },
    "max_capacity": 10000,
    "rate_limit": { "per_window": 60, "window_secs": 60 }
  }
  ```
- **Security note:** `PublicManifest` is a distinct type from
  `AgentConfig`. It MUST NOT include `secret`, `secret_hash`, or any
  internal implementation details. Only constraint-relevant fields are
  exposed.
- New endpoint: `GET /ama/proof/{request_id}` returns:
  ```json
  {
    "request_id": "uuid",
    "verdict": "AUTHORIZED",
    "manifest_hash": "sha256:abc123...",
    "timestamp": "ISO8601"
  }
  ```

**Why this matters:**
- This is the "Proof-of-Constraint" that can be displayed in any future
  product ("This action was verified by SAFA. [View proof]").
- Manifest hash changes if config changes → tamper-evident.

---

### Pillar 3 — Per-Agent Workspace Isolation

**Problem:** All agents share the same `workspace_root`. Agent "ci-bot"
can read/write files created by agent "developer". There is no
filesystem isolation between agents.

**Deliverable:** Each agent is confined to `workspace_root/{agent_id}/`.
WorkspacePath validation enforces this boundary.

**Minimal implementation:**
- `WorkspacePath::new()` accepts an `agent_id` parameter.
- Resolved path must start with `workspace_root/{agent_id}/`.
- Symlink/junction resolution before boundary check (fixes C1).
- Agent "default" uses `workspace_root/default/`.
- Cross-agent path access → `Impossible`.

**Prerequisite:** Resolves C1 (TOCTOU/symlink race on Windows) as part
of the implementation, since proper canonicalization is required anyway.

---

## Explicitly Out of Scope

| Item | Why | Target Phase |
|------|-----|-------------|
| New domains (email, calendar, news) | Product concern, not structural | P4 |
| Claw aliases (mail-it, news-it) | Product naming, not constraint | P4 |
| Consumer/mobile agent profiles | Product config, not structural | P4 |
| Session tracking / cumulative context | Requires design work | P5 |
| Policy Editor | Requires UX design | P5+ |
| Endpoint migration /ama/ → /safa/ | Cosmetic, non-breaking | P4 |
| Lobster / Snapy Clapy / mobile app | Entirely separate product | N/A |
| Scoring, probabilities, fallbacks | Anti-pattern — violates binary verdict | Never |

---

## Success Criteria

P3 is HELD when ALL of the following are true:

1. **Identity:** An agent cannot execute actions under another agent's
   identity. Requests with invalid credentials are rejected.

2. **Containment (file_read / file_write):** An agent cannot read or
   write files outside its own workspace subdirectory through the file
   actuator. Cross-agent filesystem access via `WorkspacePath` is
   structurally impossible.
   **Containment (shell_exec):** `shell_exec` intents whose
   `working_dir` uses `{{agent_workspace}}` are also confined per-agent.
   Intents that explicitly opt into `{{workspace_root}}` share the
   global workspace root and do NOT provide per-agent isolation; the
   config loader emits a warning when this pattern is detected so
   operators cannot enable it silently. (Codex adversarial audit fix.)

3. **Verifiability:** Every agent's capability manifest is hashed at
   boot. The hash is exposed in responses and queryable via endpoint.
   Changes to the *effective policy surface* — `domains.toml`,
   `intents.toml`, `allowlist.toml`, and per-agent capabilities —
   produce a different hash. `config.toml` is INTENTIONALLY excluded
   from the policy bundle hash because its fields (`workspace_root`,
   `bind_host`, `bind_port`, log settings) are deployment metadata,
   not policy: an operator moving the daemon from one host to another
   should not flip every existing manifest hash. Operators who need
   that specific field to be attested should pin it out-of-band
   (infrastructure-as-code, immutable image, etc.).
   (Kimi + MiniMax + Codex adversarial convergence.)

4. **Non-bypass:** Adversarial tests confirm that identity spoofing,
   workspace escape via `file_*` actuators, and manifest tampering are
   structurally prevented. Cross-agent reads via `shell_exec` intents
   that use the global `{{workspace_root}}` without per-agent scoping
   are NOT structurally prevented — the warning at boot is the operator
   signal that this trade-off has been made.

5. **C1 resolved on Unix:** WorkspacePath TOCTOU/symlink race is
   closed on Unix by `canonicalize()` + explicit `verify_no_symlinks`
   on every path component, plus a post-`create_dir_all` re-validation
   that catches an intermediate directory symlink-swap between
   validation and directory creation (Codex adversarial audit fix).
   **On Windows**, `verify_no_symlinks` is a no-op and the race is
   NOT fully closed — see `THREAT_MODEL.md` for the residual
   limitation. Production deployments SHOULD target Unix.

6. **Tests pass:** All existing tests continue to pass. New P3
   tests added for identity, workspace isolation, and bypass attempts.

---

## Test Plan (P3-specific)

### Identity Binding Tests
- Valid agent + valid HMAC signature → routed correctly
- Valid agent + wrong signature → 403
- Valid agent + missing signature header → 403
- Valid agent + expired timestamp (>300s) → 403 (replay prevention)
- Valid agent + future timestamp (>300s ahead) → 403
- Unknown agent + any signature → 400
- Valid signature but tampered request body → 403
- Replay of exact same request (same timestamp+signature) → 403

### Workspace Isolation Tests
- Agent writes to own workspace → AUTHORIZED
- Agent reads from own workspace → AUTHORIZED
- Agent attempts to read another agent's workspace → IMPOSSIBLE
- Agent attempts path traversal (`../other-agent/`) → IMPOSSIBLE
- Symlink pointing outside agent workspace → IMPOSSIBLE (C1 fix)
- Junction on Windows pointing outside → IMPOSSIBLE (C1 fix)
- Cross-agent symlink attack (Agent A symlinks to Agent B's workspace) → IMPOSSIBLE

### Proof-of-Constraint Tests
- Manifest hash changes when config changes
- Manifest hash is deterministic (same config → same hash)
- `/ama/manifest/{id}` returns correct hash
- `/ama/proof/{id}` returns correct verdict + hash
- `X-Safa-Policy-Hash` header present in all responses

### Bypass Attempt Tests
- Agent sends unexpected fields in JSON → rejected
- Agent attempts capability escalation (readonly → write) → IMPOSSIBLE
- Agent replays idempotency key from another agent → rejected
- Agent sends magnitude=0 or magnitude=1001 → rejected
- Agent sends empty domain or capability → rejected

---

## Estimated Scope

| Pillar | Files Affected | New Files | Estimated LOC |
|--------|---------------|-----------|---------------|
| Identity Binding | `server.rs`, `config.rs`, agent TOMLs | — | ~150 |
| Capability Manifest | `slime.rs`, `server.rs`, `audit.rs` | — | ~200 |
| Workspace Isolation | `newtypes.rs`, `pipeline.rs`, `actuator/file.rs` | — | ~200 |
| Tests | — | `p3_identity.rs`, `p3_workspace.rs`, `p3_proof.rs`, `p3_bypass.rs` | ~400 |
| Docs | — | `P3_SCOPE.md`, `P3_GAP_ANALYSIS.md` | ~300 |
| **Total** | | | **~1250** |

---

## References

- [ARCHITECTURE.md](ARCHITECTURE.md) — P3 defined at line 192
- [KNOWN_ISSUES_P1.md](KNOWN_ISSUES_P1.md) — C1 to be resolved in P3
- [CAPACITY_MODEL.md](CAPACITY_MODEL.md) — Thermodynamic model unchanged
- [THREAT_MODEL.md](THREAT_MODEL.md) — P3 closes identity threat vector
