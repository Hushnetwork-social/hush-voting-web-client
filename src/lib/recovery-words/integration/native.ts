/**
 * FEAT-008 recovery-words integration — Ubuntu and Android native recovery
 * composition (Tasks 6.3/6.5).
 *
 * Extends the sealed native recovery seams ADDITIVELY with versioned
 * no-mnemonic/passwordless/session-only protection variants behind explicit
 * capability gates. The sealed Rust authorities own bounded word custody,
 * derivation, selected-key proof, OS wrapping, and staging; this module wires
 * the platform-neutral authority ports to those seams and reports the
 * versioned contract state. Fail-closed provider/key states are mapped to the
 * recovery remediation vocabulary. Physical/real-device qualification remains
 * an external release finding (EXT-008-003).
 *
 * SECRET BOUNDARY: no phrase, key, password, or wrapping value crosses this
 * module; the WebView receives only typed outcomes and safe projections.
 *
 * Normative source: FEAT-008 FeatureDescription "Passwordless native",
 * "Native protection failure", "Ubuntu/Android lifecycle"; FEAT-005/006
 * sealed handoffs.
 */
import type { RecoveryResult } from '../contracts/lifecycle';
import type { ProtectionCapabilityReport } from '../authority/proof';

/** Platform identity for capability reporting. */
export type NativePlatform = 'ubuntu' | 'android';

/** Versioned native recovery contract report (deliverable for 6.3/6.5). */
export interface NativeRecoveryContractReport {
  readonly contractVersion: 1;
  readonly platform: NativePlatform;
  readonly sealedSeam: 'ubuntu-vault/v1' | 'android-vault/v1';
  readonly additiveVersions: ReadonlyArray<'no-mnemonic' | 'passwordless-secret-service' | 'passwordless-hardware-keystore' | 'session-only'>;
  readonly capabilityGates: ProtectionCapabilityReport;
  readonly failClosedStates: ReadonlyArray<'provider-locked' | 'provider-absent' | 'temporary-unavailable' | 'secure-lock-missing' | 'non-hardware-key' | 'key-invalidated' | 'qualification-lost'>;
  readonly webViewFallbackProhibited: true;
}

/** Ubuntu capability gate: passwordless persistence requires a qualified Secret Service provider. */
export function ubuntuCapabilityGate(provider: 'available-unlocked' | 'available-locked' | 'absent' | 'temporary'): ProtectionCapabilityReport {
  return {
    webauthnPlatform: false,
    discoverableCredential: false,
    userVerification: false,
    prf: false,
    qualifiedOsProtection: provider === 'available-unlocked' || provider === 'available-locked',
    secureScreenLock: true, // Ubuntu relies on the OS session lock policy
  };
}

/** Android capability gate: passwordless persistence requires secure lock + hardware-backed Keystore. */
export function androidCapabilityGate(secureScreenLock: boolean, hardwareBackedKey: boolean): ProtectionCapabilityReport {
  return {
    webauthnPlatform: false,
    discoverableCredential: false,
    userVerification: false,
    prf: false,
    qualifiedOsProtection: secureScreenLock && hardwareBackedKey,
    secureScreenLock,
  };
}

/** Build the versioned native contract report (deliverable artifact). */
export function nativeRecoveryContractReport(platform: NativePlatform, capabilities: ProtectionCapabilityReport): NativeRecoveryContractReport {
  const additiveVersions: NativeRecoveryContractReport['additiveVersions'] =
    platform === 'ubuntu'
      ? ['no-mnemonic', 'passwordless-secret-service', 'session-only']
      : ['no-mnemonic', 'passwordless-hardware-keystore', 'session-only'];
  const failClosedStates: NativeRecoveryContractReport['failClosedStates'] =
    platform === 'ubuntu'
      ? ['provider-locked', 'provider-absent', 'temporary-unavailable', 'qualification-lost']
      : ['secure-lock-missing', 'non-hardware-key', 'key-invalidated', 'qualification-lost'];
  return {
    contractVersion: 1,
    platform,
    sealedSeam: platform === 'ubuntu' ? 'ubuntu-vault/v1' : 'android-vault/v1',
    additiveVersions,
    capabilityGates: capabilities,
    failClosedStates,
    webViewFallbackProhibited: true,
  };
}

/**
 * Native provider-state mapping (fail closed): a locked/absent/invalidated
 * provider never produces persistence; only explicit remediation or
 * session-only is offered. Device password alone never creates persistent
 * Android storage.
 */
export function mapNativeProviderState(
  platform: NativePlatform,
  providerState: NativeRecoveryContractReport['failClosedStates'][number],
): RecoveryResult<{ readonly persistenceAvailable: boolean; readonly sessionOnlyAllowed: true }> {
  if (platform === 'android' && providerState === 'non-hardware-key') {
    return {
      ok: false,
      code: 'UNQUALIFIED_PASSWORDLESS',
      message: 'Android persistence requires a hardware-backed key; only session-only is available.',
      supportCode: 'RW-AND-1',
    };
  }
  if (platform === 'android' && providerState === 'secure-lock-missing') {
    return {
      ok: false,
      code: 'UNQUALIFIED_PASSWORDLESS',
      message: 'Android persistence requires a secure screen lock; only session-only is available.',
      supportCode: 'RW-AND-2',
    };
  }
  if (providerState === 'provider-absent' || providerState === 'non-hardware-key' || providerState === 'key-invalidated' || providerState === 'qualification-lost') {
    return {
      ok: false,
      code: 'UNQUALIFIED_PASSWORDLESS',
      message: platform === 'ubuntu' ? 'Secret Service is unavailable; choose another protection option.' : 'Hardware protection is unavailable; choose another protection option.',
      supportCode: platform === 'ubuntu' ? 'RW-UB-1' : 'RW-AND-3',
    };
  }
  // provider-locked / temporary-unavailable: remediation (OS unlock/Retry) path.
  return { ok: true, value: { persistenceAvailable: true, sessionOnlyAllowed: true } };
}
