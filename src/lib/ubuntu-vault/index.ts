/**
 * FEAT-005 Ubuntu vault bridge — public surface.
 *
 * The bridge registers Ubuntu native projections ONLY when the application
 * runs under the Tauri desktop runtime. Browser/Android compositions must
 * never observe a native actor or claim OS-backed protection. Mirrors the
 * runtime-target actor gating used by the browser-vault composition.
 *
 * Normative source: FEAT-005 FeatureDescription "Conceptual Architecture",
 * "Tauri IPC and Native Session"; `src/lib/runtime/runtime-target.ts`.
 */

import { getRuntimeTarget } from '../runtime/runtime-target';
import type { RuntimeTarget } from '../runtime/runtime-target';

export * from './composition';
export * from './contracts';
export * from './operations';
export * from './projections';

/** Whether this composition is the Ubuntu Tauri desktop runtime. */
export function isUbuntuTauriRuntime(target: RuntimeTarget = getRuntimeTarget()): boolean {
  return target === 'tauri';
}
