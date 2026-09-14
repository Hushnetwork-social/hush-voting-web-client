/**
 * FEAT-016 Task 4.4 — entitlement presentation model + adapter copy tests.
 *
 * Proves: exact approved copy per stage/connectivity; control availability
 * (Retry only for recoverable delayed/unavailable/unsupported; Lock always);
 * busy/aria-busy and no-poll-spam live-region policy; focus heading placement;
 * redacted support codes (never free-form text); offline wins over business
 * stages; ready mounts the workspace (null gate presentation).
 */

import { describe, expect, it } from 'vitest';
import {
  entitlementGatePresentation,
  gateLiveRegionPolicy,
  safeRedactedSupportCode,
} from './entitlement-presentation';

const ONLINE = 'online' as const;
const PAUSED = 'paused' as const;
const OFFLINE = 'offline' as const;

describe('exact approved copy', () => {
  it('pins the Deep-Dive copy table per stage', () => {
    expect(entitlementGatePresentation('entitlementResolving', ONLINE)?.bodyCopy).toBe(
      'Checking your HushVoting! licence…',
    );
    expect(entitlementGatePresentation('baselineSigning', ONLINE)?.bodyCopy).toBe(
      'Setting up HushVoting! Direct Free…',
    );
    expect(entitlementGatePresentation('baselineSubmitting', ONLINE)?.bodyCopy).toBe(
      'Setting up HushVoting! Direct Free…',
    );
    expect(entitlementGatePresentation('awaitingIndex', ONLINE)?.bodyCopy).toBe(
      'Waiting for the network to activate your licence…',
    );
    expect(entitlementGatePresentation('confirmationDelayed', ONLINE)?.bodyCopy).toBe(
      'Licence activation is taking longer than expected.',
    );
    expect(entitlementGatePresentation('entitlementUnavailable', ONLINE)?.bodyCopy).toBe(
      'We couldn’t verify your licence. HushVoting! cannot open until verification succeeds.',
    );
  });

  it('offline/reconnecting wins over business stages', () => {
    for (const stage of ['awaitingIndex', 'entitlementUnavailable', 'baselineSigning'] as const) {
      expect(entitlementGatePresentation(stage, OFFLINE)?.bodyCopy).toBe(
        'Connection lost. Reconnect to continue.',
      );
      expect(entitlementGatePresentation(stage, 'reconnecting')?.bodyCopy).toBe(
        'Connection lost. Reconnect to continue.',
      );
    }
  });

  it('paused shows delayed confirmation while awaiting index', () => {
    expect(entitlementGatePresentation('awaitingIndex', PAUSED)?.key).toBe('confirmationDelayed');
  });

  it('ready/null renders nothing (workspace mounts without a gate screen)', () => {
    expect(entitlementGatePresentation('entitlementReady', ONLINE)).toBeNull();
    expect(entitlementGatePresentation(null, ONLINE)).toBeNull();
  });
});

describe('control availability', () => {
  it('Retry is available only for recoverable delayed/unavailable/unsupported', () => {
    expect(entitlementGatePresentation('confirmationDelayed', ONLINE)?.controls.retry).toBe(true);
    expect(entitlementGatePresentation('entitlementUnavailable', ONLINE)?.controls.retry).toBe(true);
    expect(entitlementGatePresentation('entitlementUnsupported', ONLINE)?.controls.retry).toBe(true);
    expect(entitlementGatePresentation('awaitingIndex', ONLINE)?.controls.retry).toBe(false);
    expect(entitlementGatePresentation('entitlementResolving', ONLINE)?.controls.retry).toBe(false);
    expect(entitlementGatePresentation('entitlementRepair', ONLINE)?.controls.retry).toBe(false);
  });

  it('Lock is always available while the gate is visible', () => {
    for (const stage of [
      'entitlementResolving',
      'baselineSigning',
      'baselineSubmitting',
      'awaitingIndex',
      'confirmationDelayed',
      'entitlementUnavailable',
      'entitlementUnsupported',
      'entitlementRepair',
    ] as const) {
      expect(entitlementGatePresentation(stage, ONLINE)?.controls.lock).toBe(true);
    }
  });
});

describe('busy, focus, and live-region policy', () => {
  it('marks resolving/setup/submitting as busy and delayed/unsupported as not', () => {
    expect(entitlementGatePresentation('entitlementResolving', ONLINE)?.ariaBusy).toBe(true);
    expect(entitlementGatePresentation('baselineSigning', ONLINE)?.ariaBusy).toBe(true);
    expect(entitlementGatePresentation('confirmationDelayed', ONLINE)?.ariaBusy).toBe(false);
    expect(entitlementGatePresentation('entitlementUnsupported', ONLINE)?.ariaBusy).toBe(false);
  });

  it('focuses the heading on meaningful transitions but not on each poll', () => {
    expect(entitlementGatePresentation('confirmationDelayed', ONLINE)?.focusHeading).toBe(true);
    expect(entitlementGatePresentation('entitlementUnavailable', ONLINE)?.focusHeading).toBe(true);
    expect(entitlementGatePresentation('awaitingIndex', ONLINE)?.focusHeading).toBe(false);
  });

  it('does not announce every three-second poll (no announcement spam)', () => {
    const policy = gateLiveRegionPolicy(entitlementGatePresentation('awaitingIndex', ONLINE));
    expect(policy.announce).toBe(false);
    const resolving = gateLiveRegionPolicy(entitlementGatePresentation('entitlementResolving', ONLINE));
    expect(resolving.announce).toBe(true);
    expect(resolving.polite).toBe(true);
  });
});

describe('redaction boundary', () => {
  it('redacts anything that is not the bounded support-code format', () => {
    expect(safeRedactedSupportCode('AB12-CD34')).toBe('AB12-CD34');
    expect(safeRedactedSupportCode('abc')).toBeNull();
    expect(safeRedactedSupportCode('SELECT * FROM licences')).toBeNull();
    expect(safeRedactedSupportCode('{"error":"raw server text"}')).toBeNull();
    expect(safeRedactedSupportCode(null)).toBeNull();
  });
});
