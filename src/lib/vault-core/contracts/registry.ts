/**
 * FEAT-003 vault-core contracts — closed registries.
 *
 * Every registry here is a closed, versioned enumeration. Unknown values fail closed.
 * Future operation/extension support requires an explicit versioned registry update plus
 * conformance vectors.
 *
 * Normative source: FEAT-003 FeatureDescription "Session Core", "Extension mechanism".
 */
import { RECORD_PURPOSES, VAULT_LIFECYCLE_STATUSES } from './records';
import { ADAPTER_BINDINGS } from './versions';
import { REMOVAL_STAGES } from './sidecar';

/** Closed record-purpose registry. */
export const RECORD_PURPOSE_REGISTRY = Object.freeze([...RECORD_PURPOSES]) as readonly string[];

/** Closed lifecycle-status registry. */
export const LIFECYCLE_STATUS_REGISTRY = Object.freeze([...VAULT_LIFECYCLE_STATUSES]) as readonly string[];

/** Closed adapter/platform binding registry (AAD). */
export const ADAPTER_BINDING_REGISTRY = Object.freeze([...ADAPTER_BINDINGS]) as readonly string[];

/** Closed removal-stage registry. */
export const REMOVAL_STAGE_REGISTRY = Object.freeze([...REMOVAL_STAGES]) as readonly string[];

export function isRecordPurpose(value: unknown): value is 'ordinary' | 'mnemonic' {
  return typeof value === 'string' && RECORD_PURPOSE_REGISTRY.includes(value);
}

export function isLifecycleStatus(value: unknown): value is 'PendingRegistration' | 'Active' {
  return typeof value === 'string' && LIFECYCLE_STATUS_REGISTRY.includes(value);
}

export function isAdapterBinding(value: unknown): value is 'logical' | 'browser' | 'ubuntu' | 'android' {
  return typeof value === 'string' && ADAPTER_BINDING_REGISTRY.includes(value);
}

export function isRemovalStage(value: unknown): value is (typeof REMOVAL_STAGES)[number] {
  return typeof value === 'string' && REMOVAL_STAGE_REGISTRY.includes(value);
}
