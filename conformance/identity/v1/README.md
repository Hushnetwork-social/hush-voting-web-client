# HushVoting Identity Compatibility Corpus — `conformance/identity/v1`

Versioned, non-secret conformance evidence for **FEAT-001: Canonical Identity
Compatibility Contract** (EPIC-001). This package is the single canonical source
of compatibility truth for Hush identities; both the TypeScript production API
and the .NET conformance adapter execute it and must produce equivalent results.

**This corpus contains PUBLIC TEST MATERIAL ONLY.** Every mnemonic, `.dat`
password, private key, and signature is synthetic, fixed, and clearly labelled
test-only. It must never be registered, funded, associated with real users, or
used outside conformance tooling.

---

## Layout

```text
conformance/identity/v1/
├── README.md                       ← this file
├── manifest.json                   ← deterministic integrity manifest (generated)
├── inventory.json                  ← complete attested producer inventory P-01..P-12
├── schemas/                        ← local JSON Schema 2020-12 documents (no remote refs)
│   ├── manifest.schema.json
│   ├── inventory.schema.json
│   ├── producer.schema.json
│   ├── mnemonic-vectors.schema.json
│   ├── key-vectors.schema.json
│   ├── dat-vectors.schema.json
│   ├── canonical-byte-vectors.schema.json
│   ├── signature-vectors.schema.json
│   ├── negative-vectors.schema.json
│   ├── lookup-outcomes.schema.json
│   └── report.schema.json
├── producers/                      ← version-controlled inventory records (P-01..P-08)
├── vectors/                        ← positive, negative, and tamper vectors
│   ├── mnemonic-vectors.json       ← C-A/C-B derivation, 12-word and 24-word
│   ├── key-vectors.json            ← encodings, decode, scalar validity
│   ├── dat-vectors.json            ← .dat v1 envelope + JSON structure
│   ├── canonical-byte-vectors.json ← exact transaction bytes + tamper variants
│   ├── signature-vectors.json      ← ECDSA-SHA256 fixtures (compact + DER)
│   └── negative-vectors.json       ← unsupported inputs and rejections
├── lookup/outcomes.json            ← controlled identity lookup evidence
├── scripts/                        ← deterministic integrity tooling
│   ├── generate-manifest.mjs       ← manifest generator (+ --check mode)
│   ├── validate.mjs                ← schema + integrity + completeness validation
│   ├── derive-vectors.mjs          ← provenance: how vectors were produced
│   ├── create-release-archive.mjs  ← deterministic immutable release archive
│   └── vendor/ajv-bundle.mjs       ← self-contained JSON Schema 2020-12 engine
└── tests/                          ← node:test suites (framework-independent)
    ├── manifest-integrity.test.mjs
    ├── negative-matrix.test.mjs
    ├── schema-boundaries.test.mjs
    ├── documentation.test.mjs      ← consumer/contributor doc checks
    └── release-archive.test.mjs    ← archive reproducibility gate
```

## Versioning

Semantic versioning on the contract and corpus (`contractVersion`):

- **Major**: changes derivation behavior, candidate ordering, encodings, or an
  existing expected output.
- **Minor**: adds an approved producer/vector without changing existing behavior.
- **Patch**: adds documentation, diagnostics, or negative vectors without
  changing behavior.

Producer IDs are immutable. Every supported release permanently replays all prior
approved corpus versions. An approved producer cannot be removed or changed
without separate migration/security work addressing affected identities.

## Integrity

`manifest.json` lists every schema, inventory, producer, vector, and lookup file
in stable sorted order with relative path, byte length, and SHA-256 digest over
the exact corpus bytes. The expected SHA-256 of `manifest.json` itself is
supplied separately by pinned CI/release configuration.

Consumers reject missing, changed, and unexpected files. Contributors never
hand-edit integrity metadata:

```bash
node scripts/generate-manifest.mjs          # regenerate manifest.json
node scripts/generate-manifest.mjs --check  # verify no drift (CI)
node scripts/validate.mjs                   # schema + integrity + completeness
node --test "tests/*.test.mjs"              # boundary, negative-matrix, integrity suites
```

Formatting rules (enforced): UTF-8 without BOM, LF line endings,
lexicographically stable object-key ordering, two-space indentation, one final
newline.

## Security guidance

- All fixtures are public test material. They are allowlisted in secret scanning
  **only** on these exact corpus paths.
- Runtime/conformance diagnostics must never echo mnemonics, passwords, private
  keys, decrypted `.dat` content, or ciphertext — even though the fixtures are
  public. Failure records carry digests and stable error codes only
  (see `schemas/report.schema.json`).
- No real user mnemonic, password, private key, portable credential file, or
  recoverable production secret may ever be added here.

## Consumers

- **TypeScript production API** (`src/lib/identity-compatibility/`, Phase 3):
  framework-neutral; derives ordered public candidate descriptors, resolves
  caller-supplied lookup outcomes, and derives private material only for a
  selected producer.
- **.NET conformance runner** (`hush-server-node/Tools/HushIdentityCompatibilityConformance`,
  Phase 4): non-production adapter wrapping `Olimpo.KeyDerivation`,
  `Olimpo.CredentialsManager`, transaction serialization, and
  `Olimpo.DigitalSignature`. Pinned CI checkout; never an editable copy.
- **Controlled identity lookup** (Phase 6): one focused HushServerNode TwinTest
  using `lookup/outcomes.json` with controlled identities only.
- **Downstream features**: FEAT-002/003/007/008/009 and future Rust adapters
  (FEAT-005/006) must replay every applicable corpus version.

## Consumer contract

Consumers interact with the compatibility boundary in exactly this order
(defined and implemented by Phase 3/4):

1. **Normalize and validate** the supplied compatibility input (mnemonic words,
   word count, checksum, `.dat` envelope, key encoding) against the Approved
   producer contracts.
2. **Derive ordered public candidate descriptors** with producer provenance,
   in frozen manifest precedence order. Candidates with exactly identical
   encoded signing+encryption address pairs are deduplicated while retaining
   every contributing producer ID; compressed and uncompressed encodings of
   the same curve point remain distinct candidates.
3. **Resolve candidates** against caller-supplied deterministic lookup
   outcomes (zero, one, or multiple matches; never silently choose among
   distinct matching identities).
4. **Derive private credential material only for the selected producer** after
   lookup/selection. The API never returns every candidate's private keys to
   application state simultaneously.

Expected failures are typed data with stable machine-readable codes; they do
not throw. Diagnostics never contain mnemonics, passwords, private keys,
decrypted credentials, or ciphertext.

| Code | Meaning |
|---|---|
| `INVALID_WORD_COUNT` / `UNKNOWN_WORD` / `INVALID_CHECKSUM` / `INVALID_MNEMONIC` | Mnemonic rejection (producer-specific) |
| `UNSUPPORTED_PRODUCER` / `UNSUPPORTED_VERSION` / `UNSUPPORTED_PASSPHRASE` | Unsupported contract selection |
| `INVALID_KEY_ENCODING` / `INVALID_PRIVATE_SCALAR` | Key/encoding rejection |
| `DAT_INVALID_MAGIC` / `DAT_UNSUPPORTED_VERSION` / `DAT_MALFORMED` / `DAT_WRONG_PASSWORD` | Envelope rejection |
| `DAT_MISSING_FIELD` / `DAT_UNKNOWN_FIELD` / `DAT_DUPLICATE_FIELD` / `DAT_INVALID_FIELD` | Strict record parse rejection |
| `DAT_KEY_MISMATCH` / `DAT_MNEMONIC_KEY_MISMATCH` | Key consistency rejection |
| `SIGNATURE_MALFORMED` | Signature encoding rejection |
| `DERIVATION_FAILURE` / `CANONICAL_MISMATCH` | Derivation/internal contract failure |

Consumption rules:

- Pin a **tagged HushVoting release** (never a mutable default branch) and the
  **expected `manifest.json` SHA-256** from its release evidence.
- Every supported release permanently replays all prior approved corpus
  versions; consumers must keep the replay path.
- Runtime/conformance output must never echo fixture material (see Security).

## Contributor contract

Adding a producer, vector, schema, or expected output requires:

1. **Evidence**: reproducible derivation from an approved historical producer,
   or a documented migration/security decision for changed behavior.
2. **Semantic version bump** (major for behavior/ordering/encoding/expected
   output changes; minor for additive producers/vectors; patch for docs,
   diagnostics, or negative vectors).
3. **Dual-owner review**: HushVoting + HushNetwork platform review for any
   producer, algorithm, precedence, expected-output, or schema change
   (see Review ownership).
4. **Deterministic formatting**: UTF-8 without BOM, LF endings, lexicographic
   object-key order, two-space indent, one final newline — then regenerate:
   ```bash
   node scripts/generate-manifest.mjs && node scripts/generate-manifest.mjs --check
   node scripts/validate.mjs
   node --test "tests/*.test.mjs"
   ```
5. **Public-test warnings**: any new fixture mnemonic/password/private key is
   synthetic, clearly labelled test-only, and prohibited from production use.
   Secret scanning allows fixtures only on exact corpus paths.
6. **Cross-runtime obligations**: TypeScript and .NET conformance must pass on
   every applicable corpus version; future Rust/native implementations must
   replay every applicable version and must not derive from a separate
   undocumented algorithm.
7. **Server-runtime exclusion**: HushServerNode runtime DI never references the
   corpus or derives user private keys from it; the .NET runner is
   non-production tooling only.

Producer IDs are immutable. Incomplete evidence must never be silently
converted to Unsupported or omitted; an Unverified producer that may have
created recoverable identities blocks release.

## Release archive

Each approved corpus version is published as a deterministic immutable archive
attached to a tagged HushVoting release:

```bash
node scripts/create-release-archive.mjs \
  --version 1.0.0 \
  --output release/ \
  [--ts-report conformance/reports/typescript-identity-report.json] \
  [--dotnet-report <path-to-dotnet-identity-report.json>]
```

The archive contains the exact corpus bytes, `manifest.json` digest,
`contractVersion`/`schemaVersion` (report fields per `schemas/report.schema.json`),
inventory attestation reference, optional TS/.NET conformance reports, and a
`release-evidence.json` recording both repository SHAs and the manifest digest. Two builds from identical inputs produce
byte-identical archives (deterministic ordering and fixed timestamps). See
`tests/release-archive.test.mjs` for the reproducibility gate.

## Attestation

Producer classifications and precedence are frozen by the FEAT-001 attestation
record (decision record in `hush-voting-memory-bank`,
`Features/03_IN_PROGRESS/FEAT-001-.../attestation-record.md`). Classification
changes require a semantic version bump and dual-owner (HushVoting + HushNetwork
platform) review.

## Review ownership

- **Dual-owner review is mandatory** for any change to a producer, algorithm,
  precedence, schema, or expected output: one HushVoting owner and one
  HushNetwork platform owner, recorded on the pull request with evidence
  references.
- **Release evidence** records the HushVoting SHA, HushServerNode SHA,
  contract/schema versions, and the `manifest.json` digest in
  `release-evidence.json` inside the immutable archive.
- The attestation record's reviewer roles, dates, evidence references, and
  conclusion provide the approval trail; fixtures never embed personal
  signatures.
