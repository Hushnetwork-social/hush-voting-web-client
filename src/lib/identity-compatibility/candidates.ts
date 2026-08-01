/**
 * FEAT-001 identity compatibility API — candidate derivation and lookup.
 *
 * Step 1 of the two-step contract: derive ordered PUBLIC candidate descriptors
 * with producer provenance. No private material is produced here. Resolution
 * against caller-supplied controlled lookup outcomes never silently chooses
 * among distinct matching identities.
 */
import { APPROVED_DERIVATION_PRODUCERS, deriveProducerKeys, getProducer } from './producers.js';
import { validateMnemonicForProducer, validateInput } from './mnemonic.js';
import type {
  CompatibilityResult,
  CompatibilityFailure,
  DerivedCandidates,
  LookupResult,
  PublicCandidateDescriptor,
  RegistryEntry,
} from './types.js';

const failure = (code: CompatibilityFailure['code'], message: string): CompatibilityFailure => ({ ok: false, code, message });

/**
 * Derive ordered public candidate descriptors for a compatibility input.
 * Deduplicates candidates with identical exact encoded address pairs while
 * retaining every contributing producer ID; distinct encodings of the same
 * curve point remain distinct candidates.
 */
export function deriveCandidates(mnemonic: string, passphrase?: string): CompatibilityResult<DerivedCandidates> {
  const input = validateInput(mnemonic, passphrase);
  if (!input.ok) return input;

  const candidates: PublicCandidateDescriptor[] = [];
  const rejectedProducers: Array<{ producerId: string; code: CompatibilityFailure['code'] }> = [];

  for (const producer of APPROVED_DERIVATION_PRODUCERS) {
    const validation = validateMnemonicForProducer(mnemonic, producer.producerId);
    if (!validation.valid) {
      rejectedProducers.push({ producerId: producer.producerId, code: validation.code });
      continue;
    }
    const derived = deriveProducerKeys(producer.producerId, mnemonic);
    if (!derived.ok) {
      rejectedProducers.push({ producerId: producer.producerId, code: derived.code });
      continue;
    }
    candidates.push({
      producerId: producer.producerId,
      producerName: producer.name,
      precedence: producer.precedence,
      producerIds: [producer.producerId],
      signingAddress: derived.value.signingAddress,
      encryptionAddress: derived.value.encryptionAddress,
      publicKeyEncoding: derived.value.publicKeyEncoding,
    });
  }

  if (candidates.length === 0) {
    const firstRejection = rejectedProducers[0];
    return failure(firstRejection?.code ?? 'INVALID_MNEMONIC', 'no approved producer accepted the input');
  }

  return { ok: true, value: { candidates: dedupeCandidates(candidates), rejectedProducers } };
}

/** Merge candidates with identical exact encoded address pairs (keep producer IDs). */
export function dedupeCandidates(candidates: readonly PublicCandidateDescriptor[]): PublicCandidateDescriptor[] {
  const byKey = new Map<string, PublicCandidateDescriptor>();
  const order: string[] = [];
  for (const c of candidates) {
    const key = `${c.signingAddress}|${c.encryptionAddress}`;
    const existing = byKey.get(key);
    if (existing) {
      const producerIds = [...new Set([...existing.producerIds, ...c.producerIds])];
      byKey.set(key, {
        ...existing,
        ...(c.precedence < existing.precedence
          ? { precedence: c.precedence, producerName: c.producerName, producerId: c.producerId }
          : {}),
        producerIds,
      });
      continue;
    }
    byKey.set(key, { ...c, producerIds: [...c.producerIds] });
    order.push(key);
  }
  return order.map((k) => byKey.get(k)).filter((c): c is PublicCandidateDescriptor => c !== undefined);
}

/**
 * Resolve candidates against caller-supplied controlled registry entries.
 * Returns zero, one, or multiple matches with an explicit ambiguous flag;
 * never selects an identity on the caller's behalf.
 */
export function resolveLookup(candidates: readonly PublicCandidateDescriptor[], registry: readonly RegistryEntry[]): LookupResult {
  const matches: Array<{ registryId: string; profileAlias: string; producerIds: string[] }> = [];
  registry.forEach((entry, index) => {
    const matching = candidates.filter((c) => c.signingAddress === entry.signingAddress && c.encryptionAddress === entry.encryptionAddress);
    if (matching.length > 0) {
      const producerIds = [...new Set(matching.flatMap((m) => m.producerIds))];
      matches.push({ registryId: String(index + 1).padStart(3, '0'), profileAlias: entry.profileAlias, producerIds });
    }
  });
  return {
    matchCount: matches.length,
    ambiguous: matches.length > 1,
    matches,
  };
}

export { getProducer };
