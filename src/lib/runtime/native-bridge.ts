/**
 * FEAT-010 runtime — trusted native bridge invocation (Task 6.1).
 *
 * Invokes the Rust-owned `native_target_descriptor` startup command. The
 * result is a closed discriminated outcome:
 * - `absent` — no Tauri bridge at all (plain browser context) → Browser
 *   composition may be selected;
 * - `descriptor` — a validated-shaped descriptor for the composition builder
 *   to check against the deployment manifest;
 * - `failed` — a Tauri bridge EXISTS but the command failed or produced a
 *   malformed/unknown payload → composition FAILS CLOSED; a recognized
 *   native target never falls back to Browser (AC-010-006).
 *
 * Framework-neutral; the Tauri invoke surface is probed lazily and never
 * imports the Tauri package eagerly.
 */
import type { TrustedTargetDescriptor, NativePlatform, NativeCapabilityClass } from './target';

/** Raw payload shape expected from the native command. */
interface RawDescriptor {
  readonly platform?: unknown;
  readonly buildIdentity?: unknown;
  readonly adapterContractVersion?: unknown;
  readonly capabilityClasses?: unknown;
  readonly deploymentConfigurationId?: unknown;
}

export type NativeBridgeOutcome =
  | { readonly kind: 'absent' }
  | { readonly kind: 'descriptor'; readonly descriptor: TrustedTargetDescriptor }
  | { readonly kind: 'failed' };

/** Lazy probe: is a Tauri invoke surface present? (overridable in tests). */
let bridgeProbe: (() => boolean) | null = null;

function hasTauriBridge(): boolean {
  if (bridgeProbe !== null) {
    return bridgeProbe();
  }
  const globalThisValue = globalThis as Record<string, unknown>;
  const internals = globalThisValue.__TAURI_INTERNALS__ as { invoke?: unknown } | undefined;
  return typeof internals?.invoke === 'function';
}

function isPlatform(value: unknown): value is NativePlatform {
  return value === 'ubuntu' || value === 'android';
}

function isCapabilityClass(value: unknown): value is NativeCapabilityClass {
  return (
    value === 'secret-service' ||
    value === 'android-keystore' ||
    value === 'native-transport' ||
    value === 'native-lifecycle'
  );
}

/** Validate the raw payload shape (closed; unknown values fail). */
function toDescriptor(raw: unknown): TrustedTargetDescriptor | null {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return null;
  }
  const record = raw as RawDescriptor;
  if (
    !isPlatform(record.platform) ||
    typeof record.buildIdentity !== 'string' ||
    record.buildIdentity.length === 0 ||
    typeof record.adapterContractVersion !== 'string' ||
    !/^\d+\.\d+\.\d+$/.test(record.adapterContractVersion) ||
    !Array.isArray(record.capabilityClasses) ||
    record.capabilityClasses.length === 0 ||
    !record.capabilityClasses.every(isCapabilityClass) ||
    typeof record.deploymentConfigurationId !== 'string' ||
    record.deploymentConfigurationId.length === 0
  ) {
    return null;
  }
  return {
    platform: record.platform,
    buildIdentity: record.buildIdentity,
    adapterContractVersion: record.adapterContractVersion,
    capabilityClasses: record.capabilityClasses as readonly NativeCapabilityClass[],
    deploymentConfigurationId: record.deploymentConfigurationId,
  };
}

/**
 * Read the trusted native descriptor once at composition time.
 * - no bridge → `absent` (Browser selection allowed);
 * - bridge + valid descriptor → `descriptor`;
 * - bridge + failure/malformed/unknown → `failed` (never Browser fallback).
 */
export async function readNativeTargetDescriptor(): Promise<NativeBridgeOutcome> {
  if (!hasTauriBridge()) {
    return { kind: 'absent' };
  }
  try {
    const invoke = (globalThis as unknown as { __TAURI_INTERNALS__: { invoke: (command: string) => Promise<unknown> } }).__TAURI_INTERNALS__.invoke;
    const raw = await invoke('native_target_descriptor');
    const descriptor = toDescriptor(raw);
    if (descriptor === null) {
      return { kind: 'failed' };
    }
    return { kind: 'descriptor', descriptor };
  } catch {
    return { kind: 'failed' };
  }
}

/** Test hook: force the bridge presence probe (framework-neutral tests). */
export function __setBridgeProbeForTests(probe: (() => boolean) | null): void {
  bridgeProbe = probe;
}
