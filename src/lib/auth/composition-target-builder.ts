/**
 * FEAT-010 integration — central target-aware production composition
 * (Task 6.1).
 *
 * One builder resolves the trusted runtime target (Browser, or Ubuntu/Android
 * via the Rust-owned handshake), validates the complete actor set ATOMICALLY
 * against the Phase 2 contracts (missing/duplicate/synthetic/incompatible/
 * partial/target-contradictory/unknown fail the whole set before secret
 * entry), and assembles the FEAT-002 `AuthActors` graph from real providers.
 * Ordinary development and production share this real composition; synthetic
 * composition is reachable only through the separately named test-harness
 * entry (AC-010-001/002).
 *
 * Framework-neutral except for the FEAT-002 ports it assembles.
 */
import type { DeploymentManifest } from '../runtime/deployment';
import type { TrustedTargetDescriptor, ResolvedRuntimeTarget } from '../runtime/target';
import { resolveRuntimeTarget } from '../runtime/target';
import {
  MANDATORY_TARGET_CAPABILITIES,
  validateTargetAwareActorSet,
  type SettingsExtensionState,
  type TargetAwareActorRegistration,
  type TargetClass,
} from './composition-target';
import {
  createProductionComposition,
  type CompositionResult,
} from './composition';
import type { CapabilityRegistration } from './ports';
import type { AuthActors } from './ports';

/** Inputs for the central composition builder. */
export interface TargetCompositionInput {
  readonly manifest: DeploymentManifest;
  /** Native handshake descriptor, or null in a plain browser context. */
  readonly handshake: TrustedTargetDescriptor | null;
  /** Exact pinned contract version for every registration. */
  readonly pinnedContractVersion: string;
  /** FEAT-011 settings-extension state (absent until a real capability registers). */
  readonly extension: SettingsExtensionState;
  /** Real target-aware actor registrations (provenance: real, non-synthetic). */
  readonly registrations: readonly TargetAwareActorRegistration[];
  /** Maps a capability to its real port (returns null → incomplete set). */
  readonly actorProvider: (capability: string) => unknown;
}

/** Closed composition verdict. */
export type TargetCompositionVerdict =
  | { readonly ok: true; readonly target: ResolvedRuntimeTarget; readonly targetClass: TargetClass; readonly actors: AuthActors }
  | {
      readonly ok: false;
      readonly code: 'TARGET_RESOLUTION_FAILED' | 'ACTOR_SET_INVALID' | 'REGISTRY_INVALID';
      readonly diagnostics: readonly unknown[];
      readonly target: ResolvedRuntimeTarget | null;
    };

/** Map a resolved runtime target to its composition target class. */
export function targetClassFor(target: ResolvedRuntimeTarget): TargetClass {
  return target.kind === 'browser' ? 'web' : target.platform;
}

/**
 * Build the one coherent real actor graph:
 * 1. resolve the trusted target (no handshake → Browser; native must validate
 *    exactly — a failed native handshake NEVER falls back to Browser);
 * 2. validate the complete registration set atomically for that target;
 * 3. assemble actors from real providers only.
 */
export function createTargetComposition(input: TargetCompositionInput): TargetCompositionVerdict {
  const targetResolution = resolveRuntimeTarget(input.handshake, input.manifest);
  if (!targetResolution.ok) {
    return { ok: false, code: 'TARGET_RESOLUTION_FAILED', diagnostics: targetResolution.diagnostics, target: null };
  }
  const target = targetResolution.target;
  const targetClass = targetClassFor(target);

  const setValidation = validateTargetAwareActorSet(
    input.registrations,
    targetClass,
    input.pinnedContractVersion,
    input.extension,
  );
  if (!setValidation.ok) {
    return { ok: false, code: 'ACTOR_SET_INVALID', diagnostics: setValidation.diagnostics, target };
  }

  // Translate the validated target-aware set into the FEAT-002 registration
  // vocabulary (all real, non-synthetic — already proven by set validation).
  const capabilityRegistrations: CapabilityRegistration[] = input.registrations
    .filter((registration) => registration.targetClasses.includes(targetClass))
    .map((registration) => ({
      capability: registration.capability,
      availability: (MANDATORY_TARGET_CAPABILITIES as readonly string[]).includes(registration.capability) ? 'mandatory' : 'optional',
      synthetic: false,
    }));

  const composition: CompositionResult = createProductionComposition(capabilityRegistrations, (capability) =>
    input.actorProvider(capability),
  );
  if (!composition.ok) {
    return { ok: false, code: 'REGISTRY_INVALID', diagnostics: composition.diagnostics, target };
  }

  // A null provider anywhere means the set is incomplete — fail closed even
  // if the registry passed (provider map and registrations must agree).
  const requiredCapabilities = new Set(input.registrations.filter((r) => r.targetClasses.includes(targetClass)).map((r) => r.capability));
  for (const capability of requiredCapabilities) {
    if (input.actorProvider(capability) === null) {
      return { ok: false, code: 'ACTOR_SET_INVALID', diagnostics: [{ code: 'NULL_PROVIDER', capability }], target };
    }
  }

  return { ok: true, target, targetClass, actors: composition.actors };
}
