import { describe, expect, it } from 'vitest';
import { classifyWorkerException, createSecretTransferBook, createWorkerBffIdentityLookup } from './worker-env';

describe('worker BFF identity lookup', () => {
  it.each([{}, { reply: null }, { reply: {} }, { reply: { successfull: true } }])('never turns a malformed response into authoritative absence', async payload => {
    const lookup = createWorkerBffIdentityLookup(async () => new Response(JSON.stringify(payload), { status: 200 }));
    await expect(lookup('public-test-signing-address')).resolves.toEqual({ kind: 'unavailable' });
  });
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
  it('discards only the abandoned file snapshot without invalidating other operations', () => {
    const book = createSecretTransferBook();
    const bytes = new Uint8Array([1, 2]);
    book.store({ operationId: 'old', kind: 'fileBytes', value: bytes, consumed: false });
    book.store({ operationId: 'next', kind: 'fileBytes', value: 'new', consumed: false });
    book.discard('old');
    expect(bytes).toEqual(new Uint8Array(2));
    expect(book.take('old', 'fileBytes')).toBeNull();
    expect(book.take('next', 'fileBytes')).toBe('new');
  });
  it('destroys unconsumed transfers on authority invalidation', () => {
    const book = createSecretTransferBook();
    const bytes = new Uint8Array([1, 2, 3]);
    book.store({ operationId: 'abandoned', kind: 'fileBytes', value: bytes, consumed: false });
    book.store({ operationId: 'abandoned', kind: 'filePassword', value: 'test-password', consumed: false });
    book.clear();
    expect(bytes).toEqual(new Uint8Array(3));
    expect(book.take('abandoned', 'fileBytes')).toBeNull();
    expect(book.take('abandoned', 'filePassword')).toBeNull();
  });
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
