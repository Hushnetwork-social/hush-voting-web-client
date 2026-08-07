import { describe, expect, it } from 'vitest';
import { classifyWorkerException, createSecretTransferBook, createWorkerBffIdentityLookup } from './worker-env';

describe('worker BFF identity lookup', () => {
  it('treats an explicit unsuccessful reply as authoritative absence', async () => {
    const lookup = createWorkerBffIdentityLookup(async () => new Response(JSON.stringify({
      reply: {
        successfull: false,
        profileName: '',
        publicSigningAddress: '',
        publicEncryptAddress: '',
        isPublic: false,
      },
    }), { status: 200, headers: { 'content-type': 'application/json' } }));

    await expect(lookup('public-test-signing-address')).resolves.toEqual({ kind: 'missing' });
  });
});

describe('worker exception diagnostics', () => {
  it('reports only a closed exception class without exposing the message', () => {
    expect(classifyWorkerException(new ReferenceError('sensitive runtime detail'))).toBe('WORKER_REFERENCE_ERROR');
    expect(classifyWorkerException(new TypeError('sensitive runtime detail'))).toBe('WORKER_TYPE_ERROR');
    expect(classifyWorkerException(new Error('sensitive runtime detail'))).toBe('WORKER_UNEXPECTED_EXCEPTION');
  });
});

describe('worker secret transfer book', () => {
  it('retains file bytes and password independently for one import operation', () => {
    const book = createSecretTransferBook();
    const fileBytes = 'SFVTSC1wdWJsaWMtdGVzdA';

    book.store({ operationId: 'import-1', kind: 'fileBytes', value: fileBytes, consumed: false });
    book.store({ operationId: 'import-1', kind: 'filePassword', value: 'public-test-password', consumed: false });

    expect(book.take('import-1', 'filePassword')).toBe('public-test-password');
    expect(book.take('import-1', 'fileBytes')).toBe(fileBytes);
  });

  it('consumes each purpose once without affecting other operations', () => {
    const book = createSecretTransferBook();
    book.store({ operationId: 'import-1', kind: 'fileBytes', value: 'bytes-1', consumed: false });
    book.store({ operationId: 'import-2', kind: 'fileBytes', value: 'bytes-2', consumed: false });

    expect(book.take('import-1', 'fileBytes')).toBe('bytes-1');
    expect(book.take('import-1', 'fileBytes')).toBeNull();
    expect(book.take('import-2', 'fileBytes')).toBe('bytes-2');
  });
});
