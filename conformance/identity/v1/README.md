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
│   └── vendor/ajv-bundle.mjs       ← self-contained JSON Schema 2020-12 engine
└── tests/                          ← node:test suites (framework-independent)
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

## Attestation

Producer classifications and precedence are frozen by the FEAT-001 attestation
record (decision record in `hush-voting-memory-bank`,
`Features/03_IN_PROGRESS/FEAT-001-.../attestation-record.md`). Classification
changes require a semantic version bump and dual-owner (HushVoting + HushNetwork
platform) review.
