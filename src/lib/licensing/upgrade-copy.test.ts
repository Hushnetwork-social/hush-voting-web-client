/**
 * FEAT-017 Task 4.4 — shared copy module tests.
 *
 * Proves: the canonical FEAT-017 copy table is exact and centralized; every
 * key resolves to non-empty English text; template interpolation uses only
 * bounded validated facts; governance labels map ONLY the frozen FEAT-012 ids
 * (unknown ids → null, never inferred); the confirmation consequence list is
 * frozen; and the copy surface rejects scattered provider/server text and
 * forbidden payment/contact/Enterprise-action paths.
 */

import { describe, expect, it } from 'vitest';
import {
  activationNotificationMessage,
  currentRemainsActiveMessage,
  delayedCurrentMessage,
  delayedTargetMessage,
  governanceLabels,
  governanceOptionLabel,
  LICENCE_CONFIRMATION_CONSEQUENCES,
  LICENCE_UPGRADE_COPY,
  LICENCE_UPGRADE_COPY_KEYS,
  licenceUpgradeCopy,
  multiYearTermText,
  pendingIndicatorAccessibleLabel,
  pendingIndicatorVisibleLabel,
  pendingWaitingMessage,
  resultActiveMessage,
  upToEligibleVotersText,
} from './upgrade-copy';

describe('canonical copy table is exact and centralized', () => {
  it('pins the design-summary canonical copy table verbatim', () => {
    expect(licenceUpgradeCopy('actionUpgrade')).toBe('Upgrade');
    expect(licenceUpgradeCopy('actionViewLicence')).toBe('View licence');
    expect(licenceUpgradeCopy('actionViewProgress')).toBe('View progress');
    expect(licenceUpgradeCopy('actionReviewPlan')).toBe('Review plan');
    expect(licenceUpgradeCopy('actionActivateLicence')).toBe('Activate licence');
    expect(licenceUpgradeCopy('actionBackToPlans')).toBe('Back to plans');
    expect(licenceUpgradeCopy('actionContinueWorking')).toBe('Continue working');
    expect(licenceUpgradeCopy('actionRetry')).toBe('Retry');
    expect(licenceUpgradeCopy('statusUpgradePending')).toBe('Upgrade pending');
    expect(licenceUpgradeCopy('noHigherMessage')).toBe(
      'No higher self-service plan is available.',
    );
    expect(licenceUpgradeCopy('staleNotice')).toBe(
      'Your licence or available plans have changed. Please review the updated options.',
    );
    expect(licenceUpgradeCopy('enterpriseTag')).toBe('Contact provider — not yet available');
    expect(licenceUpgradeCopy('copyFailureFeedback')).toBe(
      'Couldn’t copy. Select the licence reference to copy it manually.',
    );
  });

  it('resolves every static key to non-empty English text', () => {
    expect(LICENCE_UPGRADE_COPY_KEYS.length).toBeGreaterThan(0);
    for (const key of LICENCE_UPGRADE_COPY_KEYS) {
      const text = licenceUpgradeCopy(key);
      expect(text.length).toBeGreaterThan(0);
      // No raw provider/server/JSON material may ever be a copy string.
      expect(text).not.toMatch(/grpc|json|sql|http|code|status:\s/i);
    }
  });

  it('exposes the frozen copy through the single typed accessor', () => {
    // Every copy member must be reachable through the typed accessor, so UI
    // cannot legitimately import LICENCE_UPGRADE_COPY constants and scatter
    // parallel strings.
    expect(licenceUpgradeCopy('titleLicence')).toBe(LICENCE_UPGRADE_COPY.titleLicence);
  });
});

describe('interpolated copy uses bounded presentation facts only', () => {
  it('composes the N0 visible + accessible labels exactly', () => {
    expect(pendingIndicatorVisibleLabel('HushVoting! Veritas 2k')).toBe(
      'Upgrade pending · HushVoting! Veritas 2k',
    );
    expect(pendingIndicatorAccessibleLabel('HushVoting! Veritas 2k')).toBe(
      'Upgrade pending for HushVoting! Veritas 2k. View progress.',
    );
  });

  it('composes N1, R0, P0 and D0 messages from validated plan names', () => {
    expect(activationNotificationMessage('HushVoting! Veritas 2k')).toBe(
      'Your HushVoting! Veritas 2k licence is now active',
    );
    expect(resultActiveMessage('HushVoting! Veritas 2k')).toBe(
      'HushVoting! Veritas 2k is now active.',
    );
    expect(pendingWaitingMessage('HushVoting! Veritas 2k')).toBe(
      'Waiting for the network to activate HushVoting! Veritas 2k…',
    );
    expect(currentRemainsActiveMessage('HushVoting! Direct Free')).toBe(
      'HushVoting! Direct Free remains active.',
    );
    expect(delayedTargetMessage('HushVoting! Veritas 2k')).toBe(
      'HushVoting! Veritas 2k may still be waiting for indexed confirmation.',
    );
    expect(delayedCurrentMessage('HushVoting! Direct Free')).toBe(
      'Your current HushVoting! Direct Free licence remains active.',
    );
  });

  it('formats caps with deterministic English grouping and term text', () => {
    expect(upToEligibleVotersText(100)).toBe('Up to 100 eligible voters');
    expect(upToEligibleVotersText(2000)).toBe('Up to 2,000 eligible voters');
    expect(multiYearTermText(3)).toBe('3-year term');
  });
});

describe('governance labels map only frozen FEAT-012 ids', () => {
  it('maps the four canonical ids and nothing else', () => {
    expect(governanceOptionLabel('no-customer-trustees')).toBe('No customer trustees');
    expect(governanceOptionLabel('trustees-3of5')).toBe('3-of-5 trustees');
    expect(governanceOptionLabel('trustees-7of10')).toBe('7-of-10 trustees');
    expect(governanceOptionLabel('trustees-8of13')).toBe('8-of-13 trustees');
    // Unknown/fabricated ids are NEVER labelled (no client catalogue).
    expect(governanceOptionLabel('gov-trustees-7-of-10')).toBeNull();
    expect(governanceOptionLabel('veritas-admin')).toBeNull();
    expect(governanceOptionLabel('')).toBeNull();
  });

  it('joins only resolvable labels and drops unknowns deterministically', () => {
    expect(
      governanceLabels(['no-customer-trustees', 'trustees-3of5', 'unknown-x', 'trustees-3of5']),
    ).toEqual(['No customer trustees', '3-of-5 trustees']);
    expect(governanceLabels([])).toEqual([]);
  });
});

describe('confirmation consequences and forbidden paths', () => {
  it('freezes the C0 consequence list with no price/payment or provider action', () => {
    expect(LICENCE_CONFIRMATION_CONSEQUENCES).toEqual([
      'The target becomes active only after indexed network confirmation.',
      'Once indexed, it immediately supersedes the current licence.',
      'The new term lasts one year from the committed activation instant.',
      'Downgrade, cancellation, and renewal before expiry are unavailable.',
      'No price or payment is part of this v1 activation.',
    ]);
  });

  it('action labels never include payment, renewal, downgrade, or provider contact verbs', () => {
    const actionText = [
      licenceUpgradeCopy('actionUpgrade'),
      licenceUpgradeCopy('actionViewLicence'),
      licenceUpgradeCopy('actionViewProgress'),
      licenceUpgradeCopy('actionReviewPlan'),
      licenceUpgradeCopy('actionActivateLicence'),
      licenceUpgradeCopy('actionBackToPlans'),
      licenceUpgradeCopy('actionContinueWorking'),
      licenceUpgradeCopy('actionRetry'),
      licenceUpgradeCopy('actionDismiss'),
      licenceUpgradeCopy('actionReturnToWorkspace'),
      licenceUpgradeCopy('actionViewCurrentLicence'),
      licenceUpgradeCopy('actionCopy'),
    ].join(' ');
    expect(actionText).not.toMatch(/pay|price|renew|downgrade|cancel|contact provider|request/i);
  });
});
