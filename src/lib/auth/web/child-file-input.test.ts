import { afterEach, describe, expect, it, vi } from 'vitest';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { CredentialFileChildRuntime } from './child-bridge';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

afterEach(() => { resetChildViews(); vi.useRealTimers(); });

function browserFile(bytes: Uint8Array, size = bytes.byteLength, opened = () => undefined): File {
  return { size, slice: () => ({ stream: () => { opened(); return new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(bytes.slice()); controller.close(); } }); } }) } as unknown as File;
}

// These post-entry structural/lifecycle tests explicitly arrange empty custody.
// credential-entry.test.ts owns held, malformed, nonempty and failed inspections.
function runtimeWithEmptyCustody(context: ConstructorParameters<typeof CredentialFileChildRuntime>[0]) {
  const client = {
    ...context.client,
    dispatch(operation: Parameters<BrowserVaultClient['dispatch']>[0], ...args: Tail<Parameters<BrowserVaultClient['dispatch']>>) {
      if (operation === 'inspectStartup') return Promise.resolve({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
      return context.client.dispatch(operation, ...args);
    },
  } as BrowserVaultClient;
  return new CredentialFileChildRuntime({ ...context, client });
}
type Tail<T extends unknown[]> = T extends [unknown, ...infer Rest] ? Rest : never;

describe('HushVotingApp TwinTests — credential file structural gate', () => {
  // EPIC-001 -> FEAT-009 AC-009-054 -> Phase 3 Tasks 3.7/3.8,
  // Phase 6 Tasks 6.1/6.2. Projection evidence only; worker import is a collaborator.
  it('offers explicit session-only file restoration after exact profile lookup', async () => {
    const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
    const dispatch = vi.fn(async (operation: string) => operation === 'importFileCandidate'
      ? { outcome: 'OK', payload: { ref: 'candidate', signingAddress: 'public-signing', encryptionAddress: 'public-encryption' } }
      : { outcome: 'OK' });
    const runtime = runtimeWithEmptyCustody({ client: { dispatch, submitSecret: vi.fn(), cancel: vi.fn() } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'exact', profileName: 'Alice',
        signingAddress: 'public-signing', encryptionAddress: 'public-encryption', isPublic: false }), randomId: prefix => `${prefix}test` });
    try {
      await runtime.start();
      await runtime.onChooseFile(browserFile(bytes));
      await runtime.onSubmitPassword('backup');
      const child = resolveOnboardingChild('restoreCredentialFile');
      if (child?.kind !== 'credentialFile') throw new Error('Missing credential protection view');
      expect(child.props.view.screen).toBe('protection');
      expect(child.props.view.protectionChoices?.[0]).toBe('devicePassword');
      expect(child.props.view.protectionChoices).toContain('sessionOnly');
    } finally { await runtime.cleanup(); }
  });

  it.each(['verifyOnlineIdentity', 'promoteLifecycle'])('ignores a late successful %s reply after cleanup revokes file restoration', async blockedOperation => {
    const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
    const signing = 'a'.repeat(66), encryption = 'b'.repeat(66);
    let finish!: (value: unknown) => void;
    const dispatch = vi.fn((operation: string) => {
      if (operation === 'importFileCandidate') return Promise.resolve({ outcome: 'OK', payload: { ref: 'candidate', signingAddress: signing, encryptionAddress: encryption } });
      if (operation === blockedOperation) return new Promise(resolve => { finish = resolve; });
      return Promise.resolve({ outcome: 'OK' });
    });
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret: vi.fn(), dispatch, cancel: vi.fn(), issueCapability: async () => ({ capabilityId: 'cap' }) } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'exact', profileName: 'Chain profile', isPublic: false, signingAddress: signing, encryptionAddress: encryption }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onChooseFile(browserFile(bytes));
    await runtime.onSubmitPassword('backup');
    const completed = vi.fn();
    void runtime.awaitCompletion().then(completed);
    const protection = runtime.onProtect('separate-device-password');
    await vi.waitFor(() => expect(finish).toBeTypeOf('function'));
    await runtime.cleanup();
    finish({ outcome: 'OK' });
    await protection;
    await Promise.resolve();
    expect(completed).not.toHaveBeenCalled();
    expect(dispatch.mock.calls.filter(call => call[0] === 'lockAll')).toHaveLength(1);
    if (blockedOperation === 'verifyOnlineIdentity') expect(dispatch.mock.calls.some(call => call[0] === 'promoteLifecycle')).toBe(false);
    expect(resolveOnboardingChild('restoreCredentialFile')).toBeNull();
  });
  it('hands completion to the root without publishing a transient success announcement', async () => {
    const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
    const signing = 'a'.repeat(66), encryption = 'b'.repeat(66);
    const dispatch = vi.fn(async (operation: string) => operation === 'importFileCandidate'
      ? { outcome: 'OK', payload: { ref: 'candidate', signingAddress: signing, encryptionAddress: encryption } }
      : { outcome: 'OK' });
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret: vi.fn(), cancel: vi.fn(), dispatch, issueCapability: async () => ({ capabilityId: 'cap' }) } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'exact', profileName: 'Chain profile', isPublic: false, signingAddress: signing, encryptionAddress: encryption }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onChooseFile(browserFile(bytes));
    await runtime.onSubmitPassword('backup');
    await runtime.onProtect('separate-device-password');
    expect((await runtime.awaitCompletion()).binding).toEqual({ signingAddress: signing, encryptionAddress: encryption });
    const child = resolveOnboardingChild('restoreCredentialFile');
    if (child?.kind !== 'credentialFile') throw new Error('Missing waiting view');
    expect(child.props.view.screen).not.toBe('success');
    await runtime.cleanup();
  });
  it('reads a bounded stream and releases it before transferring the snapshot', async () => {
    const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
    const stream = vi.fn(() => new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(bytes.slice()); controller.close(); } }));
    const arrayBuffer = vi.fn(async () => bytes.buffer);
    const source = { size: bytes.length, slice: vi.fn(() => ({ stream })), arrayBuffer } as unknown as File;
    const submitSecret = vi.fn();
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret, cancel: vi.fn(), dispatch: vi.fn(async () => ({ outcome: 'OK' })) } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'authoritativeAbsent' }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onChooseFile(source);
    expect(arrayBuffer).not.toHaveBeenCalled();
    expect(stream).toHaveBeenCalledOnce();
    expect(submitSecret).toHaveBeenCalledOnce();
    const child = resolveOnboardingChild('restoreCredentialFile');
    if (child?.kind !== 'credentialFile') throw new Error('Missing password view');
    expect(child.props.view.screen).toBe('password');
    await runtime.cleanup();
  });
  it.each(['signing', 'encryption'])('rejects a blockchain %s address mismatch before device staging', async kind => {
    const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret: vi.fn(), cancel: vi.fn(), dispatch: vi.fn(async () => ({ outcome: 'OK', payload: { ref: 'c', signingAddress: 's', encryptionAddress: 'e' } })) } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'exact', profileName: 'Chain identity', isPublic: false, signingAddress: kind === 'signing' ? 'other' : 's', encryptionAddress: kind === 'encryption' ? 'other' : 'e' }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onChooseFile(browserFile(bytes));
    await runtime.onSubmitPassword('backup');
    const child = resolveOnboardingChild('restoreCredentialFile');
    if (child?.kind !== 'credentialFile') throw new Error('Missing safe failure');
    expect(child.props.view.screen).toBe('terminal');
    expect(child.props.view.profile).toBeNull();
    await runtime.cleanup();
  });

  it('requires current alias validation and fresh Public acknowledgement for a missing imported profile', async () => {
    const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret: vi.fn(), cancel: vi.fn(), dispatch: vi.fn(async () => ({ outcome: 'OK', payload: { ref: 'c', signingAddress: 's', encryptionAddress: 'e', profileName: 'Imported profile', visibility: 'public' } })) } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'authoritativeAbsent' }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onChooseFile(browserFile(bytes));
    await runtime.onSubmitPassword('backup');
    runtime.onCreateIdentity();
    const child = resolveOnboardingChild('restoreCredentialFile');
    if (child?.kind !== 'credentialFile') throw new Error('Missing profile review');
    expect(child.props.view.screen).toBe('profileReview');
    runtime.onUpdateProfile('   ', 'public');
    runtime.onAcknowledgePublic(true);
    runtime.onCreateIdentity();
    const invalid = resolveOnboardingChild('restoreCredentialFile');
    if (invalid?.kind !== 'credentialFile') throw new Error('Missing invalid review');
    expect(invalid.props.view.screen).toBe('profileReview');
    runtime.onUpdateProfile('  Cafe\u0301  ', 'public');
    runtime.onCreateIdentity();
    const accepted = resolveOnboardingChild('restoreCredentialFile');
    if (accepted?.kind !== 'credentialFile') throw new Error('Missing protection');
    expect(accepted.props.view.screen).toBe('protection');
    expect(accepted.props.view.profile?.alias).toBe('Café');
    await runtime.cleanup();
  });

  it('awaits in-flight staging before cleanup acknowledges and locks the committed vault once', async () => {
    const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
    let completeProvision!: (value: unknown) => void;
    const dispatch = vi.fn((operation: string) => {
      if (operation === 'importFileCandidate') return Promise.resolve({ outcome: 'OK', payload: { ref: 'candidate', signingAddress: 's', encryptionAddress: 'e' } });
      if (operation === 'provisionFromValidatedBundle') return new Promise(resolve => { completeProvision = resolve; });
      return Promise.resolve({ outcome: 'OK' });
    });
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret: vi.fn(), dispatch, cancel: vi.fn(), issueCapability: async () => ({ capabilityId: 'cap' }) } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'authoritativeAbsent' }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onChooseFile(browserFile(bytes));
    await runtime.onSubmitPassword('backup');
    runtime.onCreateIdentity();
    const staging = runtime.onProtect('new-device-password');
    await Promise.resolve();
    let cleaned = false;
    const cleanup = runtime.cleanup().then(() => { cleaned = true; });
    await Promise.resolve(); await Promise.resolve();
    expect(cleaned).toBe(false);
    completeProvision({ outcome: 'OK' });
    await Promise.all([staging, cleanup]);
    expect(dispatch.mock.calls.filter(call => call[0] === 'lockAll')).toHaveLength(1);
    expect(dispatch.mock.calls.some(call => call[0] === 'submitIdentityTransaction')).toBe(false);
  });

  it('retries a failed password against the worker-held ciphertext without re-reading or resending the file', async () => {
    const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
    const opened = vi.fn();
    const submitSecret = vi.fn();
    const dispatch = vi.fn().mockResolvedValueOnce({ outcome: 'WRONG_PASSWORD_OR_DAMAGED', retryDeadlineMs: 0 })
      .mockResolvedValueOnce({ outcome: 'OK', payload: { ref: 'valid-ref', signingAddress: 's', encryptionAddress: 'e' } })
      .mockResolvedValue({ outcome: 'OK' });
    const lookupIdentity = vi.fn(async () => ({ kind: 'authoritativeAbsent' as const }));
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret, dispatch, cancel: vi.fn() } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity, randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onChooseFile(browserFile(bytes, bytes.length, opened));
    await runtime.onSubmitPassword('incorrect');
    expect(lookupIdentity).not.toHaveBeenCalled();
    await runtime.onSubmitPassword('correct');
    expect(opened).toHaveBeenCalledTimes(1);
    expect(submitSecret.mock.calls.filter(call => call[1] === 'fileBytes')).toHaveLength(1);
    expect(dispatch.mock.calls.filter(call => call[0] === 'importFileCandidate').map(call => call[3])).toEqual(['file-op-test', 'file-op-test']);
    expect(lookupIdentity).toHaveBeenCalledTimes(1);
    await runtime.cleanup();
  });

  it('replaces a queued file by destroying its transfer without a global cancellation', async () => {
    const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
    const dispatch = vi.fn(async () => ({ outcome: 'OK' }));
    const cancel = vi.fn();
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret: vi.fn(), dispatch, cancel } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'transportFailure' }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onChooseFile(browserFile(bytes));
    await runtime.onChooseDifferentFile();
    expect(dispatch).toHaveBeenCalledWith('discardSecretTransfers', { transferOperationId: 'file-op-test' });
    expect(cancel).not.toHaveBeenCalled();
    const child = resolveOnboardingChild('restoreCredentialFile');
    if (child?.kind !== 'credentialFile') throw new Error('Missing picker');
    expect(child.props.view.screen).toBe('picker');
    await runtime.cleanup();
  });
  it('keeps cleanup idempotent and prevents a late import from publishing over a new child', async () => {
    const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
    let finishImport!: (value: unknown) => void;
    const dispatch = vi.fn((operation: string) => operation === 'importFileCandidate'
      ? new Promise(resolve => { finishImport = resolve; }) : Promise.resolve({ outcome: 'OK' }));
    const lookupIdentity = vi.fn(async () => ({ kind: 'authoritativeAbsent' as const }));
    const context = { client: { submitSecret: vi.fn(), dispatch, cancel: vi.fn() } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity, randomId: (prefix: string) => `${prefix}test` };
    const old = runtimeWithEmptyCustody(context);
    await old.start();
    await old.onChooseFile(browserFile(bytes));
    const pending = old.onSubmitPassword('backup-test');
    const cleanup = old.cleanup();
    expect(old.cleanup()).toBe(cleanup);
    await cleanup;
    const current = runtimeWithEmptyCustody(context);
    await current.start();
    finishImport({ outcome: 'OK', payload: { ref: 'late-candidate', signingAddress: 'test-signing', encryptionAddress: 'test-encryption' } });
    await pending;
    expect(lookupIdentity).not.toHaveBeenCalled();
    expect(dispatch).toHaveBeenCalledWith('destroyCandidate', { candidateRef: 'late-candidate' });
    const child = resolveOnboardingChild('restoreCredentialFile');
    if (child?.kind !== 'credentialFile') throw new Error('Missing new credential-file view');
    expect(child.props.view.screen).toBe('picker');
    await current.cleanup();
  });

  it('requires explicit empty-v1 consent and forwards it with the import operation', async () => {
    const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
    const submitSecret = vi.fn();
    const dispatch = vi.fn(async () => ({ outcome: 'INVALID_INPUT' }));
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret, dispatch, cancel: vi.fn() } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'transportFailure' }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onChooseFile(browserFile(bytes));
    submitSecret.mockClear();
    await runtime.onSubmitPassword('');
    expect(submitSecret).not.toHaveBeenCalled();
    expect(dispatch).not.toHaveBeenCalled();
    runtime.onToggleEmptyPassword(true);
    await runtime.onSubmitPassword('');
    expect(submitSecret).toHaveBeenCalledWith(expect.any(String), 'filePassword', '');
    expect(dispatch).toHaveBeenCalledWith('importFileCandidate', { emptyV1Confirmed: true }, undefined, expect.any(String));
    await runtime.cleanup();
  });
  it.each([
    [0, 'ENVELOPE_TOO_SHORT'], [35, 'ENVELOPE_TOO_SHORT'], [36, 'ENVELOPE_TOO_SHORT'], [51, 'ENVELOPE_TOO_SHORT'],
    [52, 'INVALID_MAGIC'], [53, 'UNSUPPORTED_VERSION'], [1_048_577, 'ENVELOPE_OVERSIZE'],
  ] as const)('rejects %i-byte invalid input before transferring a snapshot or showing a password', async (length, code) => {
    const bytes = new Uint8Array(length);
    if (code === 'UNSUPPORTED_VERSION') { bytes.set([72, 85, 83, 72]); bytes[4] = 2; }
    const file = browserFile(bytes, length);
    const submitSecret = vi.fn();
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret, cancel: vi.fn() } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'transportFailure' }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onChooseFile(file);
    const child = resolveOnboardingChild('restoreCredentialFile');
    if (child?.kind !== 'credentialFile') throw new Error('Missing credential-file view');
    expect(child.props.view.screen).toBe('picker');
    expect(child.props.view.failureCode).toBe(code);
    expect(submitSecret).not.toHaveBeenCalled();
    await runtime.cleanup();
  });
});
