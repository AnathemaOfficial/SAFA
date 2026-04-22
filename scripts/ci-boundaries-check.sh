#!/usr/bin/env bash
# SAFA Boundary Check
# Enforces the canonical boundaries defined in docs/doctrine/ARCHITECTURE_BOUNDARIES_v0.2.md
# and docs/doctrine/SAFA_DOCTRINAL_AMENDMENTS.md.
#
# Scope conventions:
#   - safa-core/src/*             = policy layer (strict)
#   - safa-core/src/actuator/*    = POST-authorization effects (runtime-allowed)
#   - safa-daemon/*               = reference HTTP daemon (runtime-allowed)
#
# FAIL conditions stop the build. WARN conditions surface drift risk for review.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAILURES=0
WARNINGS=0

pass() { echo -e "${GREEN}PASS${NC} $1"; }
fail() { echo -e "${RED}FAIL${NC} $1"; FAILURES=$((FAILURES + 1)); }
warn() { echo -e "${YELLOW}WARN${NC} $1"; WARNINGS=$((WARNINGS + 1)); }

# zero_match "label" "pattern" path...
zero_match() {
  local label="$1"
  local pattern="$2"
  shift 2
  if rg -n -i "$pattern" "$@" >/tmp/safa_boundary_match.txt 2>/dev/null; then
    fail "$label"
    head -20 /tmp/safa_boundary_match.txt
  else
    pass "$label"
  fi
}

# zero_match_glob "label" "pattern" path exclude_glob
zero_match_glob() {
  local label="$1"
  local pattern="$2"
  local path="$3"
  local exclude="$4"
  if rg -n "$pattern" "$path" --glob "$exclude" >/tmp/safa_boundary_match.txt 2>/dev/null; then
    fail "$label"
    head -20 /tmp/safa_boundary_match.txt
  else
    pass "$label"
  fi
}

# warn_match_glob "label" "pattern" path exclude_glob
warn_match_glob() {
  local label="$1"
  local pattern="$2"
  local path="$3"
  local exclude="$4"
  if rg -n "$pattern" "$path" --glob "$exclude" >/tmp/safa_boundary_warn.txt 2>/dev/null; then
    warn "$label"
    head -10 /tmp/safa_boundary_warn.txt
  else
    pass "$label"
  fi
}

echo "== SAFA Boundary Check =="
echo

# ============================================================
# I5 — Zero product leakage in public foundations
# Strict unique product identifiers that must never appear in SAFA
# ============================================================
TARGETS=(safa-core/src safa-core/tests safa-daemon/src safa-daemon/tests docs examples README.md Cargo.toml config)
EXISTING_TARGETS=()
for t in "${TARGETS[@]}"; do
  [ -e "$t" ] && EXISTING_TARGETS+=("$t")
done

zero_match "I5: No product leakage (slapy|bluesky|slime-app|slapybot|j5|j6a|j6b)" \
  'slapy|bluesky|slime-app|slapybot|j5|j6a|j6b' \
  "${EXISTING_TARGETS[@]}"

# ============================================================
# I2/I6 — No HTTP server setup in policy layer
# safa-core must not embed an HTTP server; safa-daemon is the
# designated reference transport layer.
# ============================================================
zero_match_glob "I2/I6: No HTTP server setup in safa-core/src (excluding actuator/)" \
  'axum::serve|axum::Server|hyper::Server|warp::serve|actix_web::HttpServer' \
  safa-core/src \
  '!**/actuator/**'

# ============================================================
# I7 — No socket primitives in policy layer
# ============================================================
zero_match_glob "I7: No socket primitives in safa-core/src (excluding actuator/)" \
  'TcpListener|TcpStream|UdpSocket|UnixStream' \
  safa-core/src \
  '!**/actuator/**'

# ============================================================
# Public README sanity
# ============================================================
if [ -f README.md ]; then
  zero_match "README public positioning is clean" \
    'slapy|bluesky|slime-app|j6a|j6b' \
    README.md
else
  fail "README.md missing"
fi

# ============================================================
# WARN-only: potential runtime embedding in policy layer
# Allowed: tokio::time, tokio::net::lookup_host (used in actuation coordination)
# Watch: tokio::runtime, #[tokio::main], tokio::spawn in policy code
# ============================================================
warn_match_glob "WARN: tokio::runtime or #[tokio::main] in safa-core (review for runtime embedding)" \
  'tokio::runtime::Runtime|#\[tokio::main\]' \
  safa-core/src \
  '!**/actuator/**'

warn_match_glob "WARN: provider-suggestive public symbols in safa-core (manual review)" \
  'pub\s+(struct|enum|trait|type|fn)\s+.*(Publish|Schedule|Provider|Bluesky|PostAction)' \
  safa-core/src \
  '!**/actuator/**'

# ============================================================
# Build & test (standalone usability)
# ============================================================
if cargo build --workspace --quiet 2>/dev/null; then
  pass "cargo build --workspace"
else
  fail "cargo build --workspace"
fi

if cargo test --workspace --quiet >/dev/null 2>&1; then
  pass "cargo test --workspace"
else
  fail "cargo test --workspace"
fi

# ============================================================
# Summary
# ============================================================
echo
echo "== Summary =="
echo "Failures: $FAILURES"
echo "Warnings: $WARNINGS"

if [ "$FAILURES" -gt 0 ]; then
  echo -e "${RED}SAFA boundary check FAILED${NC}"
  exit 1
fi

echo -e "${GREEN}SAFA boundary check PASSED${NC}"
exit 0
