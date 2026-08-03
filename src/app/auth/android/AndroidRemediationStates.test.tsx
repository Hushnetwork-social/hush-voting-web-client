/**
 * FEAT-006 Phase 5 Task 5.4 — component tests for the Android remediation
 * states (accessible rendering, approved actions, fail-closed unknown input).
 */
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AndroidRemediationStates } from './AndroidRemediationStates';

describe('AndroidRemediationStates', () => {
  it('renders a typed remediation state with its approved actions', async () => {
    const onAction = vi.fn();
    render(<AndroidRemediationStates code="secureLockRequired" onAction={onAction} />);
    expect(screen.getByRole('alert')).toBeTruthy();
    expect(screen.getByText('Secure screen lock required')).toBeTruthy();
    const openSettings = screen.getByRole('button', { name: 'Open security settings' });
    await userEvent.click(openSettings);
    expect(onAction).toHaveBeenCalledWith('openSecuritySettings');
  });

  it('never renders a continue-anyway path for unsupported hardware', () => {
    render(<AndroidRemediationStates code="hardwareBackedKeystoreUnavailable" />);
    expect(screen.getByRole('alert')).toBeTruthy();
    expect(screen.queryByText(/continue anyway/i)).toBeNull();
    expect(screen.queryByText(/alias|uri|path|exception|model/i)).toBeNull();
  });

  it('fails closed to generic guidance for unknown values', () => {
    render(<AndroidRemediationStates code="decryptVault" />);
    expect(screen.getByText('Something went wrong')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeTruthy();
  });

  it('announces state changes via live regions', () => {
    render(<AndroidRemediationStates code="buildProtocolMismatch" />);
    const alert = screen.getByRole('alert');
    expect(alert.getAttribute('aria-live')).toBeTruthy();
  });
});
