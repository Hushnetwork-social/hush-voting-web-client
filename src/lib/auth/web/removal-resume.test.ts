import type { CapabilityId } from '../types';
import { describe, expect, it, vi } from 'vitest';
import { createActor } from 'xstate';
import { authMachine } from '../state/machine';
import { buildEmptyActors } from '../composition';
import { createWebLocalUserAuthority } from './web-actors';
import type { BrowserVaultClient } from '../../browser-vault/production/client';

// EPIC-001 -> FEAT-003 operational-sidecar trust boundary; FEAT-010
// AC-010-074/075 -> Phase 6 Tasks 6.5/6.6. Migration audit AUD-024.
// These guards do not prove resumable cleanup. FEAT-022 tracks the unresolved
// persisted-intent contract; an untrusted marker alone cannot authorize deletion.
describe('HushVotingApp TwinTests — interrupted removal startup', () => {
  it.each(['removalTombstone', 'quarantine'])('does not infer destructive consent or absence from %s on startup or Retry', async surface => {
    const issueCapability = vi.fn();
    const dispatch = vi.fn(async () => ({ outcome: 'OK', payload: { surface } }));
    const client = { isConnected: () => true, dispatch, issueCapability, cancel: vi.fn() } as unknown as BrowserVaultClient;
    const actors = buildEmptyActors();
    actors.localUserAuthority = createWebLocalUserAuthority(client);
    const root = createActor(authMachine, { input: { actors, registeredCapabilities: new Set<CapabilityId>(), safeCoordination: true } });
    root.start();
    try {
      await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'blockedError' })).toBe(true));
      root.send({ type: 'INTENT.RETRY' });
      await vi.waitFor(() => expect(dispatch).toHaveBeenCalledTimes(2));
      await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'blockedError' })).toBe(true));
      expect(issueCapability).not.toHaveBeenCalled();
      expect(dispatch.mock.calls).toEqual([['inspectStartup'], ['inspectStartup']]);
    } finally { root.stop(); }
  });

  it('requires a fresh verified-absence result before returning to first-run', async () => {
    const dispatch = vi.fn()
      .mockResolvedValueOnce({ outcome: 'OK', payload: { surface: 'removalTombstone' } })
      .mockResolvedValueOnce({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
    const issueCapability = vi.fn();
    const client = { isConnected: () => true, dispatch, issueCapability, cancel: vi.fn() } as unknown as BrowserVaultClient;
    const actors = buildEmptyActors();
    actors.localUserAuthority = createWebLocalUserAuthority(client);
    const root = createActor(authMachine, { input: { actors, registeredCapabilities: new Set<CapabilityId>(), safeCoordination: true } });
    root.start();
    try {
      await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'blockedError' })).toBe(true));
      root.send({ type: 'INTENT.RETRY' });
      await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'noLocalUser' })).toBe(true));
      expect(issueCapability).not.toHaveBeenCalled();
      expect(dispatch.mock.calls).toEqual([['inspectStartup'], ['inspectStartup']]);
    } finally { root.stop(); }
  });
});
