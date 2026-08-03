# Pinned Protocol Artifacts (FEAT-005)

**Purpose**: exact, digest-pinned HushServerNode Protocol Buffer sources used
by the native gRPC codegen (`src-tauri/build.rs`). The adapter exposes ONLY
the EPIC-001 identity lookup/submission surface generated from these files.

## Provenance

| File | Source revision | SHA-256 |
|------|----------------|---------|
| `hushIdentity.proto` | HushServerNode `fb789bd1c2b353387183300a370de2960bc71795` | `df3a2d9b128335dc3c92f0ef2b246655ed4c95f53f7ce058d438d945724f8ffa` |
| `hushBlockchain.proto` | HushServerNode `fb789bd1c2b353387183300a370de2960bc71795` | `e0625d52e4227ed77b6eb0e7d74b2990b7a8d3e8ecd77bd308371797275dc04b` |

## Immutability gate

`src-tauri/build.rs` verifies each file's SHA-256 against the digests above
BEFORE `tonic-build` codegen. An edited or replaced file fails the build —
the digest gate makes this set effectively read-only even though it is stored
in this repository (the "no editable copied proto set" rule from the target).

## Regeneration

Update from the pinned server revision:

```bash
cd ../hush-server-node   # at revision fb789bd1c2b353387183300a370de2960bc71795
cp Protos/hushIdentity.proto Protos/hushBlockchain.proto \
   ../hush-voting-web-client/conformance/protocol/
cd ../hush-voting-web-client && sha256sum conformance/protocol/*.proto
```

Any revision change requires a separately reviewed compatibility migration
(Protocol Omega version/field-number rules) and a manifest digest update here,
in `FeatureTasks.md`, and in `conformance/ubuntu-vault/v1/README.md`.
