// EPIC-001 -> FEAT-008 AC-008-045 -> Phase 5 Tasks 5.5/5.6.
// Original migration ID: HV-RW-PASSKEY-004.
// Frontend-only acceptance of disclosure in the real protection component.
// The supplied qualified projection is a test input, not WebAuthn qualification
// or proof that the application currently offers PRF protection end to end.
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ProtectionProjection } from '../../../lib/recovery-words/contracts/projection';
import { ProtectionScreen } from './lifecycle';

const disclosure = 'Your platform provider may synchronize the passkey under its own policy; the encrypted HushVoting vault stays on this device.';

function renderProtection(qualified: boolean) {
  const onChooseMode = vi.fn();
  const protection: ProtectionProjection = {
    defaultPasswordChecked: true,
    allowedModes: qualified ? ['devicePasswordWeb', 'passwordlessWeb'] : ['devicePasswordWeb'],
    sessionOnlyAcknowledgementRequired: false,
    passwordlessQualified: qualified,
    platformHints: ['webauthn-platform-required'],
    busy: false,
  };
  const rendered = render(<ProtectionScreen protection={protection} onChooseMode={onChooseMode}
    onAcknowledge={vi.fn()} onProtect={vi.fn()} onBack={vi.fn()} />);
  return { ...rendered, onChooseMode };
}

describe('HushVotingApp TwinTests — HV-RW-PASSKEY-004 / AC-008-045', () => {
  it('discloses provider-controlled sync before and after selecting qualified Web passwordless protection', async () => {
    // Given the real UI receives a qualified Web protection projection.
    const user = userEvent.setup();
    const { container, onChooseMode } = renderProtection(true);
    expect(screen.getByTestId('mode-password')).toBeChecked();
    expect(screen.getByText(disclosure)).toBeVisible();

    // When the user explicitly chooses Web passwordless protection.
    await user.click(screen.getByTestId('mode-passwordless-web'));

    // Then disclosure remains visible and the UI makes no hardware promises.
    expect(screen.getByTestId('mode-passwordless-web')).toBeChecked();
    expect(onChooseMode).toHaveBeenCalledExactlyOnceWith('passwordlessWeb');
    expect(screen.getByText(disclosure)).toBeVisible();
    expect(container).not.toHaveTextContent(/device.bound|hardware.backed|hardware.isolat|passkey never leaves/i);
    expect(screen.queryByTestId('mode-passwordless-native')).not.toBeInTheDocument();
  });

  it('keeps unavailable Web passwordless protection absent instead of offering an unsupported alternative', () => {
    const { container, onChooseMode } = renderProtection(false);
    expect(screen.getByTestId('mode-password')).toBeChecked();
    expect(screen.queryByTestId('mode-passwordless-web')).not.toBeInTheDocument();
    expect(screen.queryByTestId('mode-passwordless-native')).not.toBeInTheDocument();
    expect(screen.queryByText(disclosure)).not.toBeInTheDocument();
    expect(container).not.toHaveTextContent(/device.bound|hardware.backed|hardware.isolat/i);
    expect(onChooseMode).not.toHaveBeenCalled();
  });
});
