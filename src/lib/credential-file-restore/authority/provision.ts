/**
 * FEAT-009 credential-file restore authority — protection, staging, exact
 * activation, recreation, and resume policy (Task 3.7).
 *
 * Framework-neutral. Reuses FEAT-008 protection selection and selected-key
 * staging semantics for validated file credentials, FEAT-007 exact-key
 * missing-profile registration, and implements persistent/session
 * activation and restart reconciliation without source dependency. The
 * Backup-file password component/state is already destroyed before any
 * protection contract is produced; stage read-back is not authentication.
 *
 * SECRET BOUNDARY: exact public addresses and opaque validated-key
 * references only. No password, source, plaintext, mnemonic, or private
 * key is representable; the sealed platform authority performs all
 * encryption/read-back.
 *
 * Normative source: FEAT-009 FeatureDescription "Initial Local
 * Protection", "Persistent Staging and Activation", "Session-Only Import",
 * "Restart and Resume", "Missing-Profile Transaction"; FEAT-008
 * protection/activation; FEAT-007 registration.
 */
import type { RestoreResult } from '../contracts/lifecycle';
import type { ProtectionMode } from '../contracts/protection';
import type { ActivationOutcome, ResumeOutcome, SessionOnlyOutcome, StageState, StageVerification, StagedRestoreRecordMetadata } from '../contracts/protection';
import type { RecreationOutcome, ResolvedChainProfile } from '../contracts/resolution';

/** Protection qualification port (sealed capability probe). */
export interface ProtectionCapabilityPort {
  qualify(mode: ProtectionMode): Promise<'qualified' | 'unavailable' | 'unsupported'>;
}

/** Sealed staging port — two-slot journal, generation CAS, authenticated read-back. */
export interface StagingPort {
  writeStage(input: { readonly protectionMode: ProtectionMode; readonly generation: number }): Promise<RestoreResult<{ readonly state: StageState }>>;
  verifyStage(generation: number): Promise<StageVerification>;
}

/** Sealed FEAT-007 registration port (unchanged lifecycle). */
export interface RegistrationPort {
  submitMissingProfile(input: {
    readonly signingAddress: string;
    readonly encryptionAddress: string;
    readonly alias: string;
    readonly isPublic: boolean;
  }): Promise<RecreationOutcome>;
}

/** Sealed fresh-verification port (exact online GetIdentity). */
export interface FreshVerificationPort {
  freshLookup(signingAddress: string, encryptionAddress: string): Promise<
    | { readonly kind: 'exactExisting'; readonly profile: ResolvedChainProfile }
    | { readonly kind: 'authoritativeAbsent' }
    | { readonly kind: 'transportFailure' }
    | { readonly kind: 'mismatch' }
  >;
}

/**
 * Protection selection policy: Device-password default; alternatives only
 * when qualified; capability loss fails closed without downgrade.
 */
export async function selectProtection(
  port: ProtectionCapabilityPort,
  requested: ProtectionMode,
): Promise<RestoreResult<{ readonly mode: ProtectionMode; readonly qualified: boolean }>> {
  const qualification = await port.qualify(requested);
  if (qualification === 'unavailable' || qualification === 'unsupported') {
    return {
      ok: false,
      code: 'PROTECTION_CANCELLED',
      message: 'selected protection mode is not available; choose another mode or cancel',
      supportCode: 'PROT-UNAVAIL',
    };
  }
  return { ok: true, value: { mode: requested, qualified: true } };
}

/**
 * Staging policy: write → read-back → CAS → committed. A committed stage is
 * never authentication; exact online verification is mandatory afterward.
 */
export async function stageValidatedCredentials(
  port: StagingPort,
  input: { readonly protectionMode: ProtectionMode; readonly generation: number },
): Promise<RestoreResult<{ readonly state: 'committed'; readonly verification: 'verified' }>> {
  const write = await port.writeStage({ protectionMode: input.protectionMode, generation: input.generation });
  if (!write.ok) {
    return { ok: false, code: 'STAGE_WRITE_FAILURE', message: 'encrypted stage write failed', supportCode: 'STAGE-WRITE' };
  }
  const verification = await port.verifyStage(input.generation);
  if (verification.kind !== 'verified') {
    return { ok: false, code: 'STAGE_WRITE_FAILURE', message: 'stage read-back verification failed', supportCode: 'STAGE-READBACK' };
  }
  return { ok: true, value: { state: 'committed', verification: 'verified' } };
}

/**
 * Existing-profile activation: fresh exact online verification only; never
 * local-state activation. Transport failure preserves the stage.
 */
export async function activateExistingProfile(
  port: FreshVerificationPort,
  signingAddress: string,
  encryptionAddress: string,
): Promise<RestoreResult<ActivationOutcome>> {
  const outcome = await port.freshLookup(signingAddress, encryptionAddress);
  switch (outcome.kind) {
    case 'exactExisting':
      return { ok: true, value: { kind: 'activatedExisting' } };
    case 'authoritativeAbsent':
      return { ok: true, value: { kind: 'notYetActive' } }; // missing-profile path required
    case 'mismatch':
      return { ok: false, code: 'UNKNOWN_OUTCOME', message: 'fresh verification did not match both keys', supportCode: 'ACT-MISMATCH' };
    case 'transportFailure':
      return { ok: true, value: { kind: 'connectivityFailure' } }; // stage preserved; never shell
    default:
      return { ok: false, code: 'UNKNOWN_OUTCOME', message: 'fresh verification outcome unknown', supportCode: 'ACT-UNKNOWN' };
  }
}

/**
 * Missing-profile creation: reuse FEAT-007 exact-key registration; only
 * exact block confirmation (CONFIRMED) activates.
 */
export async function createMissingProfile(
  port: RegistrationPort,
  input: { readonly signingAddress: string; readonly encryptionAddress: string; readonly alias: string; readonly isPublic: boolean },
): Promise<RestoreResult<RecreationOutcome>> {
  const outcome = await port.submitMissingProfile(input);
  switch (outcome.kind) {
    case 'confirmed':
      return { ok: true, value: { kind: 'confirmed' } };
    case 'accepted':
      return { ok: true, value: { kind: 'accepted' } }; // mempool acceptance is NOT success
    case 'pending':
      return { ok: true, value: { kind: 'pending' } };
    case 'alreadyExists':
      return { ok: true, value: { kind: 'alreadyExists' } };
    case 'invalidProof':
      return { ok: false, code: 'SERVER_PROOF_REJECTED', message: 'HushServerNode rejected the identity proof', supportCode: 'SRV-PROOF' };
    case 'rejected':
      return { ok: false, code: 'SERVER_PROOF_REJECTED', message: 'HushServerNode rejected the identity proof', supportCode: 'SRV-REJECT' };
    case 'timeout':
      return { ok: true, value: { kind: 'timeout' } };
    case 'unknown':
      return { ok: false, code: 'UNKNOWN_OUTCOME', message: 'registration outcome unknown', supportCode: 'SRV-UNKNOWN' };
    default:
      return { ok: false, code: 'UNKNOWN_OUTCOME', message: 'registration outcome unknown', supportCode: 'SRV-UNKNOWN' };
  }
}

/**
 * Resume policy after persistent staging: unlock → lookup-first
 * reconciliation. Corruption/version/key mismatch fails closed; connectivity
 * preserves the stage; cancellation requires source re-import later.
 */
export function evaluateResume(verification: StageVerification, metadata: StagedRestoreRecordMetadata): RestoreResult<ResumeOutcome> {
  if (verification.kind === 'verified') {
    return { ok: true, value: { kind: 'resume', stage: metadata } };
  }
  // Every other verification state (tampered/corrupt/versionMismatch/
  // addressMismatch/unknown) fails closed: the stage cannot be trusted.
  return { ok: false, code: 'STAGED_RESTART_FAILURE', message: 'staged restore failed closed verification', supportCode: 'RESUME-FAIL' };
}

/** Session-only lifecycle: nothing persists; authority loss requires re-import. */
export function evaluateSessionOnly(sessionAlive: boolean): RestoreResult<SessionOnlyOutcome> {
  if (sessionAlive) {
    return { ok: true, value: { kind: 'active' } };
  }
  return { ok: true, value: { kind: 'ended' } };
}

export type { ProtectionMode };
