/**
 * FEAT-009 credential-file restore integration — browser composition and
 * platform seam wiring (Tasks 6.1, 6.7).
 *
 * Wires the platform-neutral credential-file authority ports to real
 * browser capabilities: one user-selected `File` transferred as one bounded
 * snapshot into the isolated authority (never uploaded to the BFF), the
 * sealed `recoverFileProvision` browser-vault operation for encrypted
 * concrete-key staging, unchanged public `GetIdentity`-style lookup through
 * the same-origin BFF with `no-store`, one-owner coordination, and the
 * FEAT-008 protection-mode surface. Native Ubuntu/Android custody is
 * composed through the sealed native seams; physical qualification remains
 * an external release finding (EXT-009-002).
 *
 * SECRET BOUNDARY: file bytes, filenames, passwords, plaintext, mnemonic,
 * private keys, and wrapping keys never cross this composition — only the
 * bounded snapshot transfer, opaque refs, ciphertext, and typed outcomes.
 *
 * Normative source: FEAT-009 FeatureDescription "Browser custody",
 * "Bounded Read Lifecycle", "Persistent Staging and Activation",
 * "Security and Privacy Requirements"; FEAT-004 browser-vault handoff;
 * FEAT-007 transport contract.
 */
import type { RestoreEpoch } from '../contracts/lifecycle';
import type { PlatformSelectionOutcome } from '../contracts/custody';
import type { BoundedSourceReadPort } from '../authority/snapshot';
import type { LookupOutcome } from '../contracts/resolution';

/** Same-origin BFF identity endpoint (server-only; never NEXT_PUBLIC). */
export const BFF_IDENTITY_LOOKUP_PATH = '/api/identity' as const;

/** Browser file-transfer contract: exactly one bounded snapshot per epoch. */
export interface BrowserFileTransfer {
  /**
   * Reads the user-selected File as one bounded byte sequence. The File
   * object reference is released at the end of this call; the caller must
   * also clear the input element's value.
   */
  readFile(opts: { readonly file: File; readonly epoch: RestoreEpoch; readonly limitBytes: number }): Promise<{
    readonly outcome: PlatformSelectionOutcome;
    readonly bytes: Uint8Array | null;
    readonly elapsedMs: number;
  }>;
}

/**
 * Real browser source-read port over a user-selected File. Never uploads
 * bytes anywhere; the snapshot stays inside the isolated authority.
 */
export function createBrowserFileReadPort(transfer: BrowserFileTransfer, fileProvider: () => File | null): BoundedSourceReadPort {
  return {
    async read({ epoch, limitBytes }) {
      const file = fileProvider();
      if (file === null) {
        return { outcome: { kind: 'readUnavailable' }, bytes: null, elapsedMs: 0 };
      }
      const result = await transfer.readFile({ file, epoch, limitBytes });
      return result;
    },
    async cancel() {
      // File reads are single-shot; cancellation is handled by the caller
      // releasing the File reference and clearing the input value.
    },
  };
}

/** Real browser lookup port: bounded same-origin POST with no-store. */
export function createBffIdentityLookupPort(fetchImpl: typeof fetch = fetch): {
  lookup(opts: { readonly publicSigningAddress: string }): Promise<LookupOutcome>;
} {
  const timeoutMs = 10_000;
  return {
    async lookup({ publicSigningAddress }) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetchImpl(BFF_IDENTITY_LOOKUP_PATH, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ publicSigningAddress }),
          cache: 'no-store',
          signal: controller.signal,
        });
        if (!response.ok) {
          return { kind: 'transportFailure' };
        }
        const payload = (await response.json()) as {
          reply?: { identity?: { alias?: unknown; visibility?: unknown; signingAddress?: unknown; encryptionAddress?: unknown } | null } | null;
        };
        const identity = payload.reply?.identity;
        if (identity === null || identity === undefined) {
          return { kind: 'authoritativeNotFound' };
        }
        const alias = String(identity.alias ?? '');
        const visibility = identity.visibility === 'public' ? 'public' : 'private';
        const signingAddress = String(identity.signingAddress ?? '');
        const encryptionAddress = String(identity.encryptionAddress ?? '');
        // Exact both-key equality is enforced by the authority; the BFF
        // payload carries the authoritative chain profile.
        return {
          kind: 'existing',
          profile: { alias, isPublic: visibility === 'public', signingAddress, encryptionAddress, networkLabel: 'HushLocal' },
        };
      } catch {
        return { kind: 'transportFailure' };
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

/** Storage/cache exclusion policy for import surfaces. */
export function importCachePolicy(): {
  readonly serviceWorker: false;
  readonly cdn: false;
  readonly thirdPartyScripts: false;
  readonly analytics: false;
  readonly sessionReplay: false;
  readonly browserCache: false;
} {
  return { serviceWorker: false, cdn: false, thirdPartyScripts: false, analytics: false, sessionReplay: false, browserCache: false };
}

/** BFF boundary audit: request body may contain ONLY bounded public lookup data. */
export function assertBffBoundary(body: unknown): { readonly ok: true } | { readonly ok: false; readonly reason: string } {
  const serialized = JSON.stringify(body);
  if (!serialized) {
    return { ok: false, reason: 'empty body' };
  }
  const lower = serialized.toLowerCase();
  const forbidden = ['filename', 'filepath', 'fileuri', 'password', 'plaintext', 'mnemonic', 'privatekey', 'aeskey', 'publicencryptaddress'];
  for (const key of forbidden) {
    if (lower.includes(`"${key}"`)) {
      return { ok: false, reason: `forbidden field: ${key}` };
    }
  }
  return { ok: true };
}

/** Purpose-scoped browser operation payload (additive to recoverFileProvision). */
export interface RecoverFileProvisionPayload {
  readonly kind: 'recoverFileProvision';
  readonly version: 1;
  readonly purpose: 'FEAT-009 restore: decrypt/validate a HUSH .dat file inside the authority';
  readonly snapshotByteLength: number; // count only; bytes stay in the authority
  readonly protectionMode: string; // closed FEAT-008 mode id
  readonly networkLabel: string;
}
