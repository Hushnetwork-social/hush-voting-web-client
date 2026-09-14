import { RESTORE_READ_HARD_BOUND_BYTES, RESTORE_MAX_SNAPSHOT_BYTES, RESTORE_READ_INACTIVITY_TIMEOUT_MS } from '../../credential-file-restore/contracts/lifecycle';

export class CredentialSourceError extends Error {
  constructor(readonly code: 'ENVELOPE_OVERSIZE' | 'READ_PARTIAL' | 'READ_INACTIVITY_TIMEOUT' | 'READ_UNAVAILABLE') {
    super(code);
  }
}

/** One read-only browser snapshot. The caller owns and must clear successful bytes. */
export async function readCredentialSnapshot(file: File, signal: AbortSignal): Promise<Uint8Array> {
  if (file.size > RESTORE_READ_HARD_BOUND_BYTES) throw new CredentialSourceError('ENVELOPE_OVERSIZE');
  if (signal.aborted) throw new CredentialSourceError('READ_UNAVAILABLE');
  // Slice before opening the stream: even an unexpected provider size cannot
  // cause the browser to read an unbounded source into our snapshot.
  const reader = file.slice(0, RESTORE_MAX_SNAPSHOT_BYTES).stream().getReader();
  const snapshot = new Uint8Array(file.size);
  let transferred = false;
  let count = 0;
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let rejectRead!: (error: CredentialSourceError) => void;
  const interrupted = new Promise<never>((_, reject) => { rejectRead = reject; });
  const cancel = () => {
    rejectRead(new CredentialSourceError('READ_UNAVAILABLE'));
    void reader.cancel().catch(() => undefined);
  };
  const resetDeadline = () => {
    clearTimeout(timeout);
    timeout = setTimeout(() => {
      rejectRead(new CredentialSourceError('READ_INACTIVITY_TIMEOUT'));
      void reader.cancel().catch(() => undefined);
    }, RESTORE_READ_INACTIVITY_TIMEOUT_MS);
  };
  signal.addEventListener('abort', cancel, { once: true });
  resetDeadline();
  try {
    while (true) {
      const chunk = await Promise.race([reader.read(), interrupted]);
      if (signal.aborted) throw new CredentialSourceError('READ_UNAVAILABLE');
      if (chunk.done) break;
      const length = chunk.value.byteLength;
      try {
        if (count + length > RESTORE_READ_HARD_BOUND_BYTES) throw new CredentialSourceError('ENVELOPE_OVERSIZE');
        if (count + length > file.size) throw new CredentialSourceError('READ_PARTIAL');
        snapshot.set(chunk.value, count);
        count += length;
        if (length > 0) resetDeadline();
      } finally { chunk.value.fill(0); }
    }
    if (count !== file.size) throw new CredentialSourceError('READ_PARTIAL');
    transferred = true;
    return snapshot;
  } finally {
    clearTimeout(timeout);
    signal.removeEventListener('abort', cancel);
    if (!transferred) snapshot.fill(0);
    void reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}
