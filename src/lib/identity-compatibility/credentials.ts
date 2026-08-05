/**
 * FEAT-001 identity compatibility API — step 2: private credential access.
 *
 * Private material is derived ONLY for one selected producer after public
 * candidate derivation and lookup/selection. The API never returns every
 * candidate's private keys to application state simultaneously.
 */
import { APPROVED_DERIVATION_PRODUCERS, deriveProducerKeys, getProducer } from './producers';
import { validateMnemonicForProducer, validateInput } from './mnemonic';
import type { CompatibilityResult, CompatibilityFailure, SelectedCredentials } from './types';

const failure = (code: CompatibilityFailure['code'], message: string): CompatibilityFailure => ({ ok: false, code, message });

/**
 * Derive private credential material for a single selected producer.
 * Re-validates the mnemonic for that producer; returns only that producer's
 * credentials.
 */
export function deriveSelectedCredentials(mnemonic: string, producerId: string, passphrase?: string): CompatibilityResult<SelectedCredentials> {
  const producer = getProducer(producerId);
  if (!producer || !APPROVED_DERIVATION_PRODUCERS.some((p) => p.producerId === producerId)) {
    return failure('UNSUPPORTED_PRODUCER', `producer ${producerId} has no derivation adapter`);
  }
  const input = validateInput(mnemonic, passphrase);
  if (!input.ok) return input;
  const validation = validateMnemonicForProducer(mnemonic, producerId);
  if (!validation.valid) return failure(validation.code, 'mnemonic rejected by the selected producer');
  const derived = deriveProducerKeys(producerId, mnemonic);
  if (!derived.ok) return derived;
  return {
    ok: true,
    value: {
      producerId: producer.producerId,
      producerName: producer.name,
      signingPrivateKey: derived.value.signingPrivateKey,
      encryptionPrivateKey: derived.value.encryptionPrivateKey,
      signingAddress: derived.value.signingAddress,
      encryptionAddress: derived.value.encryptionAddress,
      publicKeyEncoding: derived.value.publicKeyEncoding,
    },
  };
}
