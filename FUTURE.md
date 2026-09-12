# Future Work / Deferred Items

This document tracks intentionally deferred work that can be revisited when needed.

---

## 🔬 Fuzz Testing

**Status:** ⏸️ Deferred  
**Priority:** Low  
**Reason:** Low ROI for an ephemeral test tool; the attack surface is small and well-tested via unit tests.

**When to revisit:**
- If the tool gains complexity (more parsers, more input formats)
- If a vulnerability class is discovered in similar JWT libraries
- As a learning exercise for the team

**Implementation:**
```bash
# Install go-fuzz
go install github.com/dvyukov/go-fuzz/go-fuzz@latest
go install github.com/dvyukov/go-fuzz/go-fuzz-build@latest

# Target areas:
# - internal/tokenfactory: ParseTimeValue (duration, RFC3339, epoch parsing)
# - internal/server: JSON body decoding, claim validation
# - internal/keyring: JWK parsing (though jwx handles this)
```

---

## 📦 SBOM Generation

**Status:** ⏸️ Deferred  
**Priority:** Low  
**Reason:** Supply chain transparency is valuable but not critical for a test-only tool with minimal dependencies (3 direct deps).

**When to revisit:**
- If compliance requirements mandate SBOMs
- If the dependency graph grows significantly
- When GoReleaser v2 adds native SBOM support

**Implementation (when needed):**
```yaml
# .github/workflows/release.yml - add to publish job
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    path: .
    format: spdx-json
    output-file: sbom.spdx.json

- name: Attach SBOM to release
  uses: softprops/action-gh-release@v2
  with:
    files: sbom.spdx.json
```

**Alternative:** Use `syft` + `cosign` for signed SBOMs:
```bash
syft packages dir:. -o spdx-json=sbom.spdx.json
cosign attest --predicate sbom.spdx.json --type spdxjson ghcr.io/larryf1/jwtoken-tester:v1.2.3
```

---

## 📝 OpenAPI Spec Versioning

**Status:** ✅ Automated  
**Mechanism:** `make docs-openapi` target regenerates `docs/openapi.yaml` with current git-describe version.

**Version Scheme:** Matches binary/Docker image versioning:
- Release tag `vX.Y.Z` → version `X.Y.Z`
- Dev build → `X.Y.Z-<n>-<short-sha>` (e.g., `1.1.0-1-81a0fb8`)
- No tags → `0.0.0-<n>-<short-sha>`

**Usage:**
```bash
make docs-openapi  # Updates docs/openapi.yaml version field
```

---

## 🔮 Other Potential Enhancements

| Item | Effort | Value | Notes |
|------|--------|-------|-------|
| Configurable log format (JSON vs text) | Low | Medium | Useful for CI log aggregation |
| Prometheus metrics endpoint | Medium | Medium | `/metrics` with token_minted_total, rate_limit_exceeded_total, active_keys gauge |
| Admin API (key rotation trigger, manual prune) | Low | Low | Protected by separate flag/env; useful for integration tests |
| JWKS caching headers (ETag, Cache-Control) | Low | Medium | Reduces consumer polling load |
| Multiple issuer support | High | Low | Not needed for test tool scope |

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-09-12 | Deferred fuzz testing | 3 direct deps, well-covered by unit tests, test-tool threat model |
| 2026-09-12 | Deferred SBOM | Minimal deps, test-only tool, can add when compliance requires |
| 2026-09-12 | Automated OpenAPI versioning | `make docs-openapi` uses same git-describe scheme as binary/Docker |