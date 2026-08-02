/**
 * FEAT-003 vault-core contracts — bounded namespaced extension mechanism.
 *
 * Root and record schemas are closed. Future data is allowed only inside a bounded
 * namespaced `extensions` object. `criticalExtensions` identifies extensions required to
 * interpret the vault safely:
 * - unknown critical extension → fail closed as unsupported and preserve bytes;
 * - unknown non-critical extension → preserve its canonical value through updates/migrations;
 * - extension data is included in size limits and AAD;
 * - extensions cannot replace or weaken required root fields, algorithms, limits, or
 *   lifecycle rules.
 *
 * Normative source: FEAT-003 FeatureDescription "Extension mechanism".
 */

/** Namespace key pattern: dot-separated lowercase tokens. */
export const EXTENSION_NAMESPACE_PATTERN = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;

export const EXTENSION_BOUNDS = {
  maxExtensionDepth: 4,
  maxNamespaceLength: 128,
  maxExtensions: 16,
  maxCriticalExtensions: 16,
} as const;

/** Bounded extension container (byte/depth bounds enforced at parse time). */
export interface ExtensionContainerV1 {
  readonly extensions: Readonly<Record<string, unknown>>;
  readonly criticalExtensions: readonly string[];
}

export type ExtensionValidation =
  | { readonly ok: true; readonly value: ExtensionContainerV1 }
  | { readonly ok: false; readonly code: 'INVALID_EXTENSIONS'; readonly message: string };

/** Structural validation; depth/byte bounds require the Phase 3 bounded parser. */
export function validateExtensionContainer(input: unknown): ExtensionValidation {
  if (typeof input !== 'object' || input === null) {
    return { ok: false, code: 'INVALID_EXTENSIONS', message: 'extension container must be an object' };
  }
  const e = input as Record<string, unknown>;
  const extensions = e.extensions;
  const critical = e.criticalExtensions;
  if (typeof extensions !== 'object' || extensions === null || Array.isArray(extensions)) {
    return { ok: false, code: 'INVALID_EXTENSIONS', message: 'extensions must be an object' };
  }
  const keys = Object.keys(extensions as Record<string, unknown>);
  if (keys.length > EXTENSION_BOUNDS.maxExtensions) {
    return { ok: false, code: 'INVALID_EXTENSIONS', message: 'too many extension namespaces' };
  }
  for (const key of keys) {
    if (key.length > EXTENSION_BOUNDS.maxNamespaceLength || !EXTENSION_NAMESPACE_PATTERN.test(key)) {
      return { ok: false, code: 'INVALID_EXTENSIONS', message: `invalid extension namespace: ${key}` };
    }
  }
  if (!Array.isArray(critical)) {
    return { ok: false, code: 'INVALID_EXTENSIONS', message: 'criticalExtensions must be an array' };
  }
  if (critical.length > EXTENSION_BOUNDS.maxCriticalExtensions) {
    return { ok: false, code: 'INVALID_EXTENSIONS', message: 'too many critical extensions' };
  }
  const unique = new Set(critical as string[]);
  if (unique.size !== critical.length) {
    return { ok: false, code: 'INVALID_EXTENSIONS', message: 'criticalExtensions must be unique' };
  }
  for (const name of critical) {
    if (typeof name !== 'string' || name.length === 0 || name.length > EXTENSION_BOUNDS.maxNamespaceLength || !EXTENSION_NAMESPACE_PATTERN.test(name)) {
      return { ok: false, code: 'INVALID_EXTENSIONS', message: 'invalid critical extension name' };
    }
    if (!Object.prototype.hasOwnProperty.call(extensions as Record<string, unknown>, name)) {
      return { ok: false, code: 'INVALID_EXTENSIONS', message: 'critical extension missing from extensions' };
    }
  }
  return { ok: true, value: input as unknown as ExtensionContainerV1 };
}
