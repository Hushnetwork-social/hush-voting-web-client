// EPIC-001 -> FEAT-008 AC-008-035, Phase 5 Tasks 5.3/5.4;
// FEAT-009 AC-009-041, Phase 5 Tasks 5.5/5.6. Frontend Twin evidence only.
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { SafeAlias } from './recovery-words/candidate-review';
import { SuccessScreen } from './credential-file/profile-protection';
import { AuthenticatedUserMenu } from './AuthenticatedUserMenu';
import { toRestoreViewState } from '../../lib/credential-file-restore/presentation/view';

const historical = '<img src=x>\u202eOld\u0007 name';
const displayed = '<img src=x>\ufffdOld\ufffd name';

describe('HushVotingApp Twins — historical profile display', () => {
  it.each(['recovery review', 'credential success', 'authenticated menu'] as const)(
    '%s visibly replaces unsafe controls without interpreting markup or changing metadata', surface => {
      const profile = Object.freeze({ alias: historical, isPublic: false, signingAddressAbbreviated: '02aa…bb',
        encryptionAddressAbbreviated: '03cc…dd', networkLabel: 'Test network', source: 'blockchain' as const,
        aliasEditable: false, publicAcknowledgementRequired: false });
      const { container } = render(surface === 'recovery review' ? <SafeAlias alias={profile.alias} />
        : surface === 'authenticated menu' ? <AuthenticatedUserMenu identity={{ alias: profile.alias, publicSigningKey: '02aa', publicEncryptionKey: '03cc' }} onLock={vi.fn()} />
          : <SuccessScreen view={toRestoreViewState({ stage: 'success', progress: null, failureCode: null,
            backoffRemainingSeconds: 0, passwordField: null, protectionChoices: null, profile, reveal: null })} />);
      expect(container.querySelector('img, script, a')).toBeNull();
      const alias = screen.getByTestId('safe-alias');
      expect(alias.textContent).toBe(displayed);
      expect(alias.tagName).toBe('BDI');
      expect(screen.getByText('This historical profile name may need updating.')).toBeVisible();
      expect(profile.alias).toBe(historical);
    },
  );

  it('preserves ordinary RTL, joiners and emoji without a legacy warning', () => {
    const alias = 'نام\u200cمن 👩\u200d💻';
    render(<SafeAlias alias={alias} />);
    expect(screen.getByTestId('safe-alias').textContent).toBe(alias);
    expect(screen.queryByText('This historical profile name may need updating.')).toBeNull();
  });
});
