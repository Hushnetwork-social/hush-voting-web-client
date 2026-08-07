'use client';

import { useEffect, useRef, useState } from 'react';
import type { AuthenticatedIdentityMetadata } from '../../lib/auth/types';

interface AuthenticatedUserMenuProps {
  readonly identity: AuthenticatedIdentityMetadata;
  readonly onLock: () => void;
}

type CopiedKey = 'signing' | 'encryption' | null;

export function abbreviatePublicKey(value: string): string {
  return value.length <= 17 ? value : `${value.slice(0, 8)}…${value.slice(-8)}`;
}

/** Authenticated-only public identity popup with keyboard/outside dismissal. */
export function AuthenticatedUserMenu({ identity, onLock }: AuthenticatedUserMenuProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const copiedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [copiedKey, setCopiedKey] = useState<CopiedKey>(null);

  useEffect(() => {
    if (!open) return;

    const onPointerDown = (event: PointerEvent) => {
      if (event.target instanceof Node && !rootRef.current?.contains(event.target)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        setOpen(false);
        triggerRef.current?.focus();
      }
    };

    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  useEffect(() => () => {
    if (copiedTimerRef.current !== null) clearTimeout(copiedTimerRef.current);
  }, []);

  async function copyKey(kind: Exclude<CopiedKey, null>, value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(kind);
      if (copiedTimerRef.current !== null) clearTimeout(copiedTimerRef.current);
      copiedTimerRef.current = setTimeout(() => setCopiedKey(null), 2_000);
    } catch {
      setCopiedKey(null);
    }
  }

  return (
    <div className="authenticated-user-menu" ref={rootRef}>
      <button
        ref={triggerRef}
        type="button"
        className="authenticated-user-trigger"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls="authenticated-user-popup"
        onClick={() => setOpen((current) => !current)}
      >
        <span>{identity.alias}</span>
        <svg aria-hidden="true" viewBox="0 0 20 20" width="16" height="16">
          <path d="m5 7.5 5 5 5-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>

      {open && (
        <section id="authenticated-user-popup" className="authenticated-user-popup" role="dialog" aria-label="User information">
          <header className="authenticated-user-popup-header">
            <h2>User information</h2>
            <button type="button" className="authenticated-user-close" aria-label="Close user information" onClick={() => setOpen(false)}>
              <span aria-hidden="true">×</span>
            </button>
          </header>

          <dl className="authenticated-user-details">
            <div>
              <dt>Alias</dt>
              <dd>{identity.alias}</dd>
            </div>
            <div>
              <dt>Public signing key</dt>
              <dd className="authenticated-key-row">
                <button type="button" className="authenticated-copy-key" aria-label="Copy public signing key" onClick={() => void copyKey('signing', identity.publicSigningKey)}>
                  <CopyIcon />
                </button>
                <span>{abbreviatePublicKey(identity.publicSigningKey)}</span>
                <span className="authenticated-copy-feedback" role="status" aria-live="polite">
                  {copiedKey === 'signing' ? 'Copied' : ''}
                </span>
              </dd>
            </div>
            <div>
              <dt>Public encryption key</dt>
              <dd className="authenticated-key-row">
                <button type="button" className="authenticated-copy-key" aria-label="Copy public encryption key" onClick={() => void copyKey('encryption', identity.publicEncryptionKey)}>
                  <CopyIcon />
                </button>
                <span>{abbreviatePublicKey(identity.publicEncryptionKey)}</span>
                <span className="authenticated-copy-feedback" role="status" aria-live="polite">
                  {copiedKey === 'encryption' ? 'Copied' : ''}
                </span>
              </dd>
            </div>
          </dl>

          <button
            type="button"
            className="authenticated-lock-button"
            onClick={() => {
              setOpen(false);
              onLock();
            }}
          >
            <svg aria-hidden="true" viewBox="0 0 24 24" width="18" height="18">
              <path d="M7 10V7a5 5 0 0 1 10 0v3M6 10h12a1 1 0 0 1 1 1v9H5v-9a1 1 0 0 1 1-1Z" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span>Lock</span>
          </button>
        </section>
      )}
    </div>
  );
}

function CopyIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" width="17" height="17">
      <rect x="8" y="8" width="11" height="11" rx="1.5" fill="none" stroke="currentColor" strokeWidth="1.7" />
      <path d="M16 8V5H5v11h3" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
