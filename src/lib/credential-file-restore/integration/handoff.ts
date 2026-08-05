/**
 * FEAT-009 credential-file restore integration — immutable downstream
 * handoff (Task 6.9).
 *
 * Versioned, pinned, secret-free handoff consumed by FEAT-010 (returning
 * unlock/lifecycle) and FEAT-011 (portable export). Carries only safe
 * lifecycle/protection/import-compatibility contract surfaces; never
 * source identifiers, passwords, mnemonics, private keys, or generic
 * capabilities.
 *
 * Normative source: FEAT-009 FeatureDescription "Cross-Feature and Release
 * Dependencies", "Definition of Done"; planning report §14 downstream
 * obligations.
 */
import { validateFileRestoreHandoff } from '../contracts/evidence';
import type { FileRestoreHandoff } from '../contracts/evidence';

/** Immutable FEAT-009 → FEAT-010/011 downstream handoff (version 1). */
export function createFileRestoreHandoff(pins: Readonly<Record<string, string>>, generatedAt: string): FileRestoreHandoff {
  const handoff: FileRestoreHandoff = {
    handoffVersion: 1,
    featureId: 'FEAT-009',
    contractPins: pins,
    exportedContracts: [
      'credential-file-restore/contracts/lifecycle',
      'credential-file-restore/contracts/custody',
      'credential-file-restore/contracts/projection',
      'credential-file-restore/contracts/import',
      'credential-file-restore/contracts/resolution',
      'credential-file-restore/contracts/protection',
      'credential-file-restore/contracts/staging',
      'credential-file-restore/contracts/evidence',
    ],
    prohibitedSurfaces: [
      'sourceIdentifier',
      'sourceBytes',
      'backupPassword',
      'plaintext',
      'mnemonic',
      'seed',
      'privateKey',
      'fullAddress',
      'exactTransaction',
      'genericCapability',
    ],
    generatedAt,
  };
  const validated = validateFileRestoreHandoff(handoff);
  if (!validated.ok) {
    throw new Error(`handoff integrity failed: ${validated.reasons.join('; ')}`);
  }
  return handoff;
}
