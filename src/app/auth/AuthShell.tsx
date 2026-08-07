/**
 * FEAT-002 Sovereign Shield shell — the minimal branded authentication shell.
 *
 * Renders the branded non-sensitive shell immediately for every pre-auth
 * state. Never mounts authenticated navigation, election summaries, dashboard
 * components, or remote avatars behind the shell. After authentication, the
 * application switches to the full-width operational shell.
 *
 * Visual rules (HushVoting frontend): complementary surfaces, spacing, and
 * radius rather than pervasive white outlines or heavy nested cards; borders
 * reserved for focus/selected/warning/error states.
 */

import Image from 'next/image';
import { useEffect } from 'react';
import type { ReactNode } from 'react';
import { documentTitleForState } from '../../lib/auth/ui/copy';
import type { AuthRenderProjection } from '../../lib/auth/react/adapter';

interface AuthShellProps {
  readonly projection: AuthRenderProjection;
  readonly children: ReactNode;
  readonly onBack?: () => void;
}

export function AuthShell({ projection, children, onBack }: AuthShellProps) {
  const { authState, safeIdentity, supportCode } = projection;

  // Document title is a non-sensitive accessibility surface; never a secret.
  useEffect(() => {
    document.title = documentTitleForState(authState);
  }, [authState]);

  return (
    <main className="auth-shell" aria-labelledby="auth-shell-heading">
      <div className="auth-shell-inner">
        <header className="auth-brand" aria-label="HushVoting!">
          <span className="auth-brand-mark" aria-hidden="true">
            <Image
              src="/assets/hushvoting-logo.png"
              alt=""
              width={48}
              height={48}
              priority
              data-testid="hushvoting-logo"
            />
          </span>
          <span className="auth-brand-name">HushVoting!</span>
          <span className="auth-env" data-connectivity={projection.connectivity} aria-label={`Network ${connectivityLabel(projection.connectivity)}`}>
            {connectivityLabel(projection.connectivity)}
          </span>
        </header>

        <section className={`auth-surface${onBack !== undefined ? ' auth-surface-with-back' : ''}`} aria-labelledby="auth-shell-heading">
          {onBack !== undefined && (
            <button type="button" className="auth-back-link" onClick={onBack}>
              <span aria-hidden="true">←</span> Back
            </button>
          )}
          <h1 id="auth-shell-heading" className="auth-heading">
            {projection.authState === 'initializing' ? 'HushVoting!' : headingForProjection(projection)}
          </h1>

          {authState !== 'initializing' && safeIdentity !== null && (
            <p className="auth-identity" aria-label="Local identity">
              <span>{safeIdentity.alias}</span>
              <span className="auth-address" aria-label="Abbreviated address">
                {safeIdentity.abbreviatedSigningAddress}
              </span>
            </p>
          )}

          {children}
        </section>

        {supportCode !== null && (
          <p className="auth-support-code" role="status">
            Support code: {supportCode}
          </p>
        )}

        {authState === 'locked' && (
          <footer className="auth-footer">
            <span>Your device password protects credentials on this device only.</span>
            <span aria-hidden="true">It is never sent to HushServerNode.</span>
          </footer>
        )}
      </div>
      <span className="sr-only" role="status" aria-live="polite">
        {progressAnnouncement(projection)}
      </span>
    </main>
  );
}

function connectivityLabel(connectivity: AuthRenderProjection['connectivity']): string {
  switch (connectivity) {
    case 'online':
      return 'online';
    case 'paused':
      return 'paused';
    case 'offline':
      return 'offline';
    case 'reconnecting':
      return 'reconnecting';
    case 'unknown':
      return 'checking';
  }
}

function headingForProjection(projection: AuthRenderProjection): string {
  switch (projection.authState) {
    case 'noLocalUser':
      return 'Welcome to HushVoting!';
    case 'locked':
      return 'Unlock HushVoting!';
    case 'unlocking':
      return 'Unlocking…';
    case 'verifyingIdentityOnline':
      return 'Verifying your identity…';
    case 'missingProfileConfirmation':
      return 'Confirm your identity';
    case 'recoverableError':
      return 'Something went wrong';
    case 'blockedError':
      return 'HushVoting! is locked';
    case 'removingLocalUser':
      return 'Remove local user';
    case 'onboarding':
      return 'Set up this device';
    default:
      return 'HushVoting!';
  }
}

function progressAnnouncement(projection: AuthRenderProjection): string {
  switch (projection.authState) {
    case 'unlocking':
      return 'Unlocking this device';
    case 'verifyingIdentityOnline':
      return 'Checking your identity with the network';
    case 'removingLocalUser':
      return 'Removing local data';
    default:
      return '';
  }
}
