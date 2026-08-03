# Ubuntu Vault Conformance (v1)

**Adapter**: `ubuntu-secret-service-v1` — FEAT-005
**Status**: Skeleton (Phase 2) — additive digest-only evidence lands in Phases 3–8
**Normative sources**: FEAT-005 FeatureDescription; FEAT-001 identity corpus v1; FEAT-003 vault corpus v1

This directory is the additive, digest-only conformance surface for the Ubuntu
native vault adapter. It never edits or duplicates the immutable FEAT-001
identity corpus or FEAT-003 vault corpus — those are replayed unchanged by the
native implementation and referenced by digest only.

## What lives here (and when)

| Artifact | Phase | Content |
|---|---|---|
| `README.md` (this file) | 2 | Contract and evidence rules |
| `HANDOFF.md` | 2 (skeleton), 8 (final) | Native contract for downstream FEAT-007–011 consumers |
| `reports/` | 3–8 | Deterministic digest-only reports (crypto replay, storage fault matrix, Secret Service integration, package/lifecycle, a11y, performance, security) |
| `schemas/` | 3 | Native wrapper/envelope schemas (digest-pinned, no secrets) |
| `manifest.json` | 3 | Immutable corpus manifest for the Ubuntu adapter (digest-pinned) |

## Rules

- **Additive only**: native reports append; they never modify upstream corpus.
- **Digest-only**: reports contain digests, closed typed codes, and coarse
  timing — never ciphertext, item values, paths, usernames, aliases,
  addresses, keys, mnemonics, or free-form errors.
- **No real credentials**: only declared public synthetic fixtures participate.
- **Provider name is never proof**: qualification evidence requires the
  build-pinned bundle version plus live capability checks (see
  `src-tauri/src/ubuntu_vault/item_model.rs`).

## Pinned inputs (unchanged from `FeatureTasks.md`)

- FEAT-001 identity corpus manifest SHA-256: `f1bec7741de20efc3e488d0736ab61e745f3739032daaf50d955a83878d4f124`
- FEAT-003 vault corpus manifest SHA-256: `e8dfdfa49b9e33cfc8a47b1266c5a14cb978c4be28f21d87cc2f034d435582e5`
- HushServerNode protocol revision: `fb789bd1c2b353387183300a370de2960bc71795`
