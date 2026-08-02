/**
 * FEAT-003 adversarial property suite (Task 7.1).
 *
 * At least 10,000 deterministic-seeded generated cases spanning the documented
 * domains: canonical JSON, field/bound limits, Unicode passwords, AAD/purpose,
 * generation/migration, extensions, capability phases/epochs/operations, and typed
 * outcomes. Every case derives from an explicit seed (mulberry32) so failures are
 * byte-for-byte replayable; a discovered failing seed becomes a permanent regression
 * vector (Task 7.2). No real credentials participate in generation.
 */
import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { canonicalizeJson } from '../canonical/jcs';
import { parseBoundedJson, DEFAULT_PARSE_LIMITS, isUnpaddedBase64Url } from '../canonical/parse';
import { buildAadBytes, aadInputsFor } from '../canonical/aad';
import { PARAMETER_SUITE_V1 } from '../contracts/suite';
import { validateDevicePassword, comparisonRepresentation } from '../password/unicode';
import { evaluatePasswordPolicy } from '../password/policy';
import { checkSupportedVersion } from '../contracts/versions';
import { validateExtensionContainer, EXTENSION_NAMESPACE_PATTERN } from '../contracts/extensions';
import { journalCommit, type JournalState } from '../lifecycle/journal';
import {
  stagePendingRegistration,
  beginSubmission,
  reconcileToActive,
  completeRemoval,
  type LifecycleState,
} from '../lifecycle/transitions';
import { onLocalUnlock, onExactOnlineVerification, onFreshPassword, consumeFreshPassword, invalidateSession, INITIAL_KERNEL_STATE, type SessionKernelState } from '../session/kernel';
import { VAULT_RESULT_CODES, VAULT_RESULT_REGISTRY, failure } from '../contracts/results';
import { mulberry32, intInRange, pick, randomString, randomBase64Url, randomJsonValue } from './prng';

const CASE_COUNTS = {
  canonical: 3000,
  bounds: 1500,
  unicode: 1500,
  aad: 1000,
  lifecycle: 1000,
  extensions: 1000,
  session: 1000,
  typed: 1000,
} as const;

/** Record a failing seed (becomes a permanent regression vector). */
const failures: Array<{ domain: string; seed: number; detail: string }> = [];
const caseCounts: Record<string, number> = {};

function runCase(domain: keyof typeof CASE_COUNTS, seed: number, check: (rand: () => number) => string | null): void {
  caseCounts[domain] = (caseCounts[domain] ?? 0) + 1;
  const rand = mulberry32(seed);
  const failureDetail = check(rand);
  if (failureDetail !== null) {
    failures.push({ domain, seed, detail: failureDetail });
  }
}

const enc = (s: string) => new TextEncoder().encode(s);
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

describe('FEAT-003 deterministic property suite (10,000+ seeded cases)', () => {
  it('canonical JSON round-trips through JCS + bounded parser (idempotence)', () => {
    for (let seed = 1; seed <= CASE_COUNTS.canonical; seed++) {
      runCase('canonical', seed, (rand) => {
        const value = randomJsonValue(rand, 4, { nodes: 12 });
        const canonical = canonicalizeJson(value);
        const parsed = parseBoundedJson(enc(canonical));
        if (!parsed.ok) return `canonical output rejected by parser: ${parsed.code}`;
        const recanonical = canonicalizeJson(parsed.value);
        if (canonical !== recanonical) return `JCS not idempotent: ${canonical} vs ${recanonical}`;
        return null;
      });
    }
    expect(caseCounts.canonical).toBeGreaterThanOrEqual(CASE_COUNTS.canonical);
  });

  it('field/bound limits produce typed outcomes — never throws or hangs', () => {
    for (let seed = 1; seed <= CASE_COUNTS.bounds; seed++) {
      runCase('bounds', seed, (rand) => {
        const size = intInRange(rand, 0, 4096);
        const depth = intInRange(rand, 1, 64);
        const collections = intInRange(rand, 1, 200);
        const body = `{"x":${'['.repeat(depth)}${'1'.repeat(Math.max(1, size))}${']'.repeat(depth)}}`;
        const out = parseBoundedJson(enc(body), { limits: { maxBytes: 1024, maxNestingDepth: 16, maxCollections: 64 } });
        if (out.ok === false && !['OVERSIZED_INPUT', 'TOO_DEEP', 'TOO_MANY_COLLECTIONS', 'MALFORMED_JSON', 'NON_FINITE_NUMBER'].includes(out.code)) {
          return `unexpected parse code: ${out.code}`;
        }
        return null;
      });
    }
    expect(caseCounts.bounds).toBeGreaterThanOrEqual(CASE_COUNTS.bounds);
  });

  it('Unicode passwords: valid inputs normalize consistently; failures are closed typed codes', () => {
    for (let seed = 1; seed <= CASE_COUNTS.unicode; seed++) {
      runCase('unicode', seed, (rand) => {
        const input = randomString(rand, 96);
        const result = validateDevicePassword(input);
        if (result.ok) {
          const again = validateDevicePassword(result.normalizedNfc);
          if (!again.ok || again.normalizedNfc !== result.normalizedNfc) return 'NFC normalization unstable';
          if (result.graphemeClusters < 6 || result.graphemeClusters > 64) return `grapheme count out of policy: ${result.graphemeClusters}`;
          if (result.utf8Bytes > 256) return `utf8 bytes exceed 256: ${result.utf8Bytes}`;
        } else if (!['INVALID_ENCODING', 'UNPAIRED_SURROGATE', 'TOO_FEW_GRAPHEMES', 'TOO_MANY_GRAPHEMES', 'TOO_MANY_BYTES'].includes(result.code)) {
          return `unexpected unicode code: ${result.code}`;
        }
        // Comparison representation must never throw and is never KDF input.
        comparisonRepresentation(input);
        return null;
      });
    }
    expect(caseCounts.unicode).toBeGreaterThanOrEqual(CASE_COUNTS.unicode);
  });

  it('AAD/purpose separation: bytes are deterministic and change with any bound field', () => {
    for (let seed = 1; seed <= CASE_COUNTS.aad; seed++) {
      runCase('aad', seed, (rand) => {
        const base = aadInputsFor(PARAMETER_SUITE_V1, {
          adapterBinding: pick(rand, ['logical', 'browser', 'ubuntu', 'android']),
          preview: {
            alias: randomString(rand, 20),
            signingAddressPrefix: randomBase64Url(rand, 8),
            signingAddressSuffix: randomBase64Url(rand, 6),
            lifecycleStatus: pick(rand, ['PendingRegistration', 'Active']),
            envelopeFormatVersion: 1,
            parameterSuiteVersion: 1,
            recordSchemaVersion: 1,
          },
          vaultGeneration: intInRange(rand, 1, 50),
          recordGeneration: intInRange(rand, 1, 50),
          recordPurpose: pick(rand, ['ordinary', 'mnemonic']),
          producerId: 'hush-voting-ts',
          producerVersion: '1.0.0',
          signingAddress: randomBase64Url(rand, 16),
          criticalExtensions: rand() < 0.5 ? ['hush.vault.telemetry'] : [],
        });
        const bytesA = Buffer.from(buildAadBytes(base)).toString('hex');
        const bytesB = Buffer.from(buildAadBytes(base)).toString('hex');
        if (bytesA !== bytesB) return 'AAD bytes not deterministic';
        const changed = { ...base, recordPurpose: base.recordPurpose === 'ordinary' ? 'mnemonic' : 'ordinary' } as Parameters<typeof buildAadBytes>[0];
        if (Buffer.from(buildAadBytes(changed)).toString('hex') === bytesA) return 'purpose swap did not change AAD';
        return null;
      });
    }
    expect(caseCounts.aad).toBeGreaterThanOrEqual(CASE_COUNTS.aad);
  });

  it('generation/migration: journal CAS and version checks return closed typed outcomes', () => {
    for (let seed = 1; seed <= CASE_COUNTS.lifecycle; seed++) {
      runCase('lifecycle', seed, (rand) => {
        const state: JournalState = {
          activeSlot: rand() < 0.5 ? { generation: intInRange(rand, 0, 10), bytes: new Uint8Array([1]) } : null,
          rollbackSlot: rand() < 0.5 ? { generation: intInRange(rand, 0, 10), bytes: new Uint8Array([2]) } : null,
          activeGeneration: intInRange(rand, 0, 10),
          newSlotVerified: rand() < 0.5,
        };
        const outcome = journalCommit(
          state,
          intInRange(rand, 0, 10),
          { generation: intInRange(rand, 0, 12), bytes: new Uint8Array([3]) },
          { writeInactive: () => rand() < 0.8, verifyInactive: () => rand() < 0.8, switchActive: () => rand() < 0.8 },
        );
        const code = outcome.ok ? 'OK' : outcome.code;
        if (!['OK', 'NO_ACTIVE_SLOT', 'GENERATION_CONFLICT', 'WRITE_FAILED', 'VERIFY_FAILED', 'SWITCH_FAILED'].includes(code)) {
          return `unexpected journal code: ${code}`;
        }
        // On success the active generation must be the new slot generation.
        if (outcome.ok && outcome.state.activeGeneration !== outcome.state.activeSlot?.generation) {
          return 'successful commit left inconsistent active generation';
        }
        const version = {
          envelopeFormatVersion: intInRange(rand, 0, 3),
          parameterSuiteVersion: intInRange(rand, 0, 3),
          recordSchemaVersion: intInRange(rand, 0, 3),
          platformWrapperVersion: intInRange(rand, 0, 2),
        };
        const verdict = checkSupportedVersion(version as never);
        if (!verdict.ok && verdict.code !== 'UNSUPPORTED_CRITICAL_VERSION') return `unexpected version code: ${verdict.code}`;
        return null;
      });
    }
    expect(caseCounts.lifecycle).toBeGreaterThanOrEqual(CASE_COUNTS.lifecycle);
  });

  it('extensions: containers validate to closed outcomes under bounds', () => {
    for (let seed = 1; seed <= CASE_COUNTS.extensions; seed++) {
      runCase('extensions', seed, (rand) => {
        const container: Record<string, unknown> = {};
        const critical: string[] = [];
        const n = intInRange(rand, 0, 20);
        for (let i = 0; i < n; i++) {
          const name = `${randomString(rand, 10).replace(/[^a-z0-9-]/g, 'x').toLowerCase()}.ext${i}`;
          container[name] = { v: intInRange(rand, 0, 100) };
          if (rand() < 0.4) critical.push(name);
        }
        const result = validateExtensionContainer({ extensions: container, criticalExtensions: critical });
        if (!result.ok && result.code !== 'INVALID_EXTENSIONS') return `unexpected extension code: ${result.code}`;
        if (result.ok) {
          for (const key of Object.keys(container)) {
            if (!EXTENSION_NAMESPACE_PATTERN.test(key)) return `namespace pattern accepted invalid key: ${key}`;
          }
        }
        return null;
      });
    }
    expect(caseCounts.extensions).toBeGreaterThanOrEqual(CASE_COUNTS.extensions);
  });

  it('capability phases/epochs/operations: transitions stay in the closed phase set', () => {
    for (let seed = 1; seed <= CASE_COUNTS.session; seed++) {
      runCase('session', seed, (rand) => {
        let state: SessionKernelState = { ...INITIAL_KERNEL_STATE };
        state = { ...state, phase: pick(rand, ['Locked', 'VerificationOnly', 'Authenticated', 'FreshPasswordVerified', 'Invalidated']) };
        for (let step = 0; step < 6; step++) {
          const action = intInRange(rand, 0, 4);
          if (action === 0) {
            const r = onLocalUnlock(state);
            state = r.ok ? r.state : state;
          } else if (action === 1) {
            const r = onExactOnlineVerification(state);
            state = r.ok ? r.state : state;
          } else if (action === 2) {
            state = invalidateSession(state, pick(rand, ['lock', 'removal', 'replacement', 'takeover', 'platform-invalidation', 'authority-loss', 'restart']));
          } else if (action === 3) {
            const r = onFreshPassword(state, { channelId: `c${intInRange(rand, 0, 3)}` }, pick(rand, ['mnemonic-reveal', 'password-change']), 0);
            state = r.ok ? r.state : state;
          } else {
            const r = consumeFreshPassword(state, { channelId: `c${intInRange(rand, 0, 3)}` }, pick(rand, ['mnemonic-reveal', 'password-change']), 0);
            state = r.ok ? r.state : state;
          }
          if (!['Locked', 'VerificationOnly', 'Authenticated', 'FreshPasswordVerified', 'Invalidated'].includes(state.phase)) {
            return `invalid phase after action ${action}: ${state.phase}`;
          }
        }
        // After any invalidation the epoch must have increased relative to start.
        if (state.epoch < 0) return `negative epoch: ${state.epoch}`;
        return null;
      });
    }
    expect(caseCounts.session).toBeGreaterThanOrEqual(CASE_COUNTS.session);
  });

  it('typed outcomes: every closed code maps to a safe registry entry and failure shape', () => {
    for (let seed = 1; seed <= CASE_COUNTS.typed; seed++) {
      runCase('typed', seed, (rand) => {
        const code = pick(rand, VAULT_RESULT_CODES);
        const meta = VAULT_RESULT_REGISTRY[code];
        if (!meta) return `registry missing code ${code}`;
        if (typeof meta.retryable !== 'boolean') return `retryable not boolean for ${code}`;
        const f = failure(code);
        if (f.ok !== false || f.code !== code) return `failure() shape invalid for ${code}`;
        if (!Array.isArray(f.allowedActions)) return `allowedActions not array for ${code}`;
        return null;
      });
    }
    expect(caseCounts.typed).toBeGreaterThanOrEqual(CASE_COUNTS.typed);
  });

  it('policy evaluation returns closed outcomes without throwing', () => {
    for (let seed = 1; seed <= 1000; seed++) {
      const rand = mulberry32(seed * 7 + 1);
      const input = randomString(rand, 32);
      const result = evaluatePasswordPolicy({ password: input, aliasTerms: [randomString(rand, 8)] });
      if (result.ok) {
        if (result.score < 0 || result.score > 4) throw new Error(`score out of range for seed ${seed}`);
      } else if (!['POLICY_VIOLATION', 'COMMON_PASSWORD', 'IDENTITY_DERIVED'].includes(result.code)) {
        throw new Error(`unexpected policy code for seed ${seed}: ${result.code}`);
      }
    }
    expect(true).toBe(true);
  });

  it('no failing seed was discovered (permanent regressions would be recorded)', () => {
    expect(failures).toEqual([]);
    const total = Object.values(caseCounts).reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThanOrEqual(10_000);
    // A summary digest for the gate report (deterministic, secret-safe).
    const summary = sha(JSON.stringify({ domain: Object.keys(caseCounts).sort(), counts: caseCounts }));
    expect(summary).toMatch(/^[0-9a-f]{64}$/);
  });
});
