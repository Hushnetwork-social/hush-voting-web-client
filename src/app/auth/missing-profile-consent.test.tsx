// EPIC-001 -> FEAT-010 AC-010-025/040 and FEAT-002 explicit-consent/state contract;
// FEAT-002 Phase 3 Tasks 3.1/3.2, FEAT-010 Phase 7 Task 7.3;
// FEAT-019 Phase 0 Task 0.1. Real machine/adapter/Gate with scripted ports: FEAT-only evidence.
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { AuthGate } from './AuthGate';
import { buildEmptyActors } from '../../lib/auth/composition';
import { createAuthAdapter } from '../../lib/auth/react/adapter';
import type { AuthIntent } from '../../lib/auth/types';
import {
  completeAllPendingOperations,
  createIdentityVerificationTestActor,
  createLocalUserAuthorityTestActor,
  createOnboardingTestActor,
  createSecretAuthorityTestActor,
} from '../../lib/auth/testing/actors';

function existingMissingProfile() {
  const actors = buildEmptyActors();
  const safeIdentity = { alias: 'Existing local identity', abbreviatedSigningAddress: '02abcd…1234' };
  actors.localUserAuthority = createLocalUserAuthorityTestActor([
    { code: 'INIT_LOCKED_USER', safeIdentity },
    { code: 'INIT_LOCKED_USER', safeIdentity },
  ]);
  actors.secretAuthority = createSecretAuthorityTestActor([{ code: 'UNLOCK_SUCCESS' }]);
  actors.identityVerification = createIdentityVerificationTestActor([
    { code: 'VERIFY_PROFILE_MISSING', safeCandidate: safeIdentity },
  ]);
  const port = createOnboardingTestActor([], [
    { code: 'VERIFY_PROFILE_MISSING', safeCandidate: safeIdentity },
    { code: 'VERIFY_PROFILE_MISSING', safeCandidate: safeIdentity },
  ]);
  const confirm = vi.spyOn(port, 'confirmMissingProfile');
  actors.onboarding.createUser = port;
  const adapter = createAuthAdapter({ actors, registeredCapabilities: new Set(), safeCoordination: true });
  const settleAt = async (state: string) => vi.waitFor(() => {
    completeAllPendingOperations();
    expect(adapter.snapshot().authState).toBe(state);
  });
  const handlers = { dispatch: (intent: AuthIntent) => adapter.send(intent), submitSecret: vi.fn() };
  return { adapter, confirm, settleAt, handlers };
}

describe('HushVotingApp Twins — returning missing-profile consent', () => {
  it('waits for explicit creation consent and coalesces repeated clicks while confirmation is pending', async () => {
    const user = userEvent.setup();
    const { adapter, confirm, settleAt, handlers } = existingMissingProfile();
    try {
      await settleAt('locked');
      adapter.send({ type: 'INTENT.UNLOCK' });
      await settleAt('missingProfileConfirmation');
      render(<AuthGate projection={adapter.snapshot()} handlers={handlers} />);
      expect(adapter.snapshot().protectedAccess).toBe(false);
      expect(confirm).not.toHaveBeenCalled();
      const create = screen.getByRole('button', { name: 'Create the identity' });
      await user.click(create);
      expect(confirm).toHaveBeenCalledOnce();
      await user.dblClick(create);
      expect(confirm).toHaveBeenCalledOnce();
      await settleAt('missingProfileConfirmation');
      expect(confirm).toHaveBeenCalledOnce();
      expect(adapter.snapshot().protectedAccess).toBe(false);
      await user.click(create);
      expect(confirm).toHaveBeenCalledTimes(2);
    } finally {
      adapter.stop();
      completeAllPendingOperations();
    }
  });

  it('does not expose first-run creation or recovery after Back while the local authority still reports a vault', async () => {
    const user = userEvent.setup();
    const { adapter, settleAt, handlers } = existingMissingProfile();
    try {
      await settleAt('locked');
      adapter.send({ type: 'INTENT.UNLOCK' });
      await settleAt('missingProfileConfirmation');
      const view = render(<AuthGate projection={adapter.snapshot()} handlers={handlers} />);
      await user.click(screen.getByRole('button', { name: 'Back' }));
      await settleAt('locked');
      view.rerender(<AuthGate projection={adapter.snapshot()} handlers={handlers} />);
      expect(adapter.snapshot().protectedAccess).toBe(false);
      expect(adapter.snapshot().authState).not.toBe('noLocalUser');
      expect(screen.queryByRole('button', { name: /create user/i })).toBeNull();
      expect(screen.queryByRole('button', { name: /restore credential file/i })).toBeNull();
      expect(screen.queryByRole('button', { name: /restore recovery words/i })).toBeNull();
    } finally {
      adapter.stop();
      completeAllPendingOperations();
    }
  });
});
