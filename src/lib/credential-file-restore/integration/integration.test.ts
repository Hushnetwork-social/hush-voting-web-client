/**
 * FEAT-009 Tasks 6.2/6.4/6.6/6.8/6.10 — integration tests for the browser,
 * native, server, and tooling seams.
 *
 * Proves: browser file transfer stays local (BFF boundary audit), native
 * contracts (regular-file-only, no URI/path in WebView, no persistable
 * grant, no fallback), server scenario catalog integrity, external finding
 * admission (PASS requires a pin), controlled-corpus preflight refusal,
 * aggregate-only evidence, and immutable handoff validation.
 */
import { describe, expect, it } from 'vitest';
import {
  BFF_IDENTITY_LOOKUP_PATH,
  assertBffBoundary,
  createBffIdentityLookupPort,
  createBrowserFileReadPort,
  importCachePolicy,
} from './browser';
import {
  androidCredentialFileContract,
  mapNativeSourceKind,
  startupOrphanScanPolicy,
  ubuntuCredentialFileContract,
} from './native';
import {
  RELEASE_FINDINGS,
  SERVER_SCENARIOS,
  admitReleaseFinding,
  aggregateCorpusEvidence,
  controlledCorpusPreflight,
} from './server';
import { createFileRestoreHandoff } from './handoff';
import { validateFileRestoreHandoff } from '../contracts/evidence';
import type { RestoreEpoch } from '../contracts/lifecycle';

const EPOCH = 'epoch-1' as RestoreEpoch;

describe('FEAT-009 browser composition (Task 6.1)', () => {
  it('the BFF boundary accepts only bounded public lookup data', () => {
    expect(assertBffBoundary({ publicSigningAddress: 'abc' }).ok).toBe(true);
    const poisoned = assertBffBoundary({ publicSigningAddress: 'abc', password: 'x' });
    expect(poisoned.ok).toBe(false);
    if (!poisoned.ok) expect(poisoned.reason).toContain('password');
    expect(assertBffBoundary({ publicSigningAddress: 'abc', fileName: 'backup.dat' }).ok).toBe(false);
    expect(assertBffBoundary({ publicSigningAddress: 'abc', mnemonic: 'words' }).ok).toBe(false);
  });

  it('file bytes never leave the authority via the read port', async () => {
    let transferred = false;
    const port = createBrowserFileReadPort(
      {
        async readFile({ file, limitBytes }) {
          transferred = true;
          // The transfer contract receives the File reference only; bytes are
          // read inside the transfer (jsdom File lacks text()/arrayBuffer()).
          const bytes = new TextEncoder().encode((file as { readonly name?: string }).name ?? 'fixture-bytes');
          if (bytes.byteLength > limitBytes) {
            return { outcome: { kind: 'tooLarge' }, bytes: null, elapsedMs: 1 };
          }
          return { outcome: { kind: 'selected' }, bytes, elapsedMs: 1 };
        },
      },
      () => new File(['fixture-bytes'], 'fixture.dat'),
    );
    const result = await port.read({ epoch: EPOCH, limitBytes: 1024, inactivityTimeoutMs: 30_000 });
    expect(transferred).toBe(true);
    expect(result.outcome.kind).toBe('selected');
    expect(result.bytes?.byteLength).toBe('fixture.dat'.length); // name-only local read; never uploaded
    // The port contract has no upload surface; serialization cannot contain
    // a filename or URL.
    expect(JSON.stringify(result)).not.toMatch(/fixture|upload|post/i);
  });

  it('browser read port returns readUnavailable when no file is selected', async () => {
    const port = createBrowserFileReadPort(
      { readFile: async () => ({ outcome: { kind: 'readUnavailable' }, bytes: null, elapsedMs: 0 }) },
      () => null,
    );
    const result = await port.read({ epoch: EPOCH, limitBytes: 1024, inactivityTimeoutMs: 30_000 });
    expect(result.outcome.kind).toBe('readUnavailable');
  });

  it('BFF lookup maps transport to transportFailure and not-found to authoritativeNotFound', async () => {
    const fetchMock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      expect(String(input)).toBe(BFF_IDENTITY_LOOKUP_PATH);
      expect((init?.headers as Record<string, string>)?.['content-type']).toBe('application/json');
      const body = JSON.parse(String(init?.body));
      expect(body.publicSigningAddress).toBeDefined();
      expect(Object.keys(body)).toEqual(['publicSigningAddress']); // bounded public data only
      return new Response(JSON.stringify({ reply: { identity: null } }), { status: 200 });
    };
    const port = createBffIdentityLookupPort(fetchMock as typeof fetch);
    const outcome = await port.lookup({ publicSigningAddress: 'abc' });
    expect(outcome.kind).toBe('authoritativeNotFound');
  });

  it('import cache policy excludes every web cache/analytics surface', () => {
    const policy = importCachePolicy();
    expect(policy).toEqual({ serviceWorker: false, cdn: false, thirdPartyScripts: false, analytics: false, sessionReplay: false, browserCache: false });
  });
});

describe('FEAT-009 native custody contracts (Tasks 6.3/6.5)', () => {
  it('Ubuntu contract: regular files only, read-only, path never in WebView', () => {
    const report = ubuntuCredentialFileContract();
    expect(report.sourceKindRules.allowed).toEqual(['regularFile']);
    expect(report.sourceKindRules.rejectBeforeDecryption).toBe(true);
    expect(report.ubuntu).toMatchObject({ readOnlyOpen: true, noWriteRenameDeleteChmod: true, noPathInWebView: true, noSourceReopen: true });
    expect(report.webViewFallbackProhibited).toBe(true);
    expect(report.android).toBeNull();
  });

  it('Android contract: one-shot SAF, no persistable grant, no URI in WebView', () => {
    const report = androidCredentialFileContract();
    expect(report.android).toMatchObject({ oneShotSaf: true, noPersistablePermission: true, noUriInWebView: true, noBrowserStorageFallback: true, releaseGrantOnAllPaths: true });
    expect(report.webViewFallbackProhibited).toBe(true);
    expect(report.ubuntu).toBeNull();
  });

  it('native source-kind mapping rejects unsafe kinds before decryption', () => {
    expect(mapNativeSourceKind('regularFile').ok).toBe(true);
    for (const kind of ['directory', 'device', 'fifo', 'socket', 'symlinkRace', 'unknown'] as const) {
      const result = mapNativeSourceKind(kind);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe('UNSAFE_FILE_KIND');
    }
  });

  it('startup orphan scan never targets the external source', () => {
    expect(startupOrphanScanPolicy()).toEqual({ scanOnStartup: true, quarantineOnFailure: true, externalSourceNeverTargeted: true });
  });
});

describe('FEAT-009 server scenario contract (Task 6.7)', () => {
  it('the scenario catalog is stable, complete, and NOT_SUPPLIED', () => {
    expect(SERVER_SCENARIOS).toHaveLength(11);
    expect(SERVER_SCENARIOS[0].scenarioId).toBe('HV-DAT-SRV-001');
    expect(SERVER_SCENARIOS[10].scenarioId).toBe('HV-DAT-SRV-011');
    const ids = new Set(SERVER_SCENARIOS.map((s) => s.scenarioId));
    expect(ids.size).toBe(11); // unique
    for (const scenario of SERVER_SCENARIOS) {
      expect(scenario.evidenceState).toBe('NOT_SUPPLIED'); // never fabricated
      expect(scenario.expectedOutcome).not.toMatch(/unknown|error/i);
    }
  });
});

describe('FEAT-009 external admission (Task 6.7)', () => {
  it('release findings start NOT_SUPPLIED and PASS requires an immutable pin', () => {
    expect(RELEASE_FINDINGS).toHaveLength(5);
    expect(RELEASE_FINDINGS.map((f) => f.id)).toEqual(['EXT-009-001', 'EXT-009-002', 'EXT-009-003', 'EXT-009-004', 'EXT-009-005']);
    for (const finding of RELEASE_FINDINGS) {
      expect(finding.state).toBe('NOT_SUPPLIED');
    }
    const passWithoutPin = admitReleaseFinding(RELEASE_FINDINGS, 'EXT-009-003', 'PASS', null);
    expect(passWithoutPin.ok).toBe(false);
    const passWithPin = admitReleaseFinding(RELEASE_FINDINGS, 'EXT-009-003', 'PASS', 'a'.repeat(64));
    expect(passWithPin.ok).toBe(true);
    const unknown = admitReleaseFinding(RELEASE_FINDINGS, 'EXT-009-099', 'PASS', 'a'.repeat(64));
    expect(unknown.ok).toBe(false);
  });
});

describe('FEAT-009 controlled-corpus harness (Task 6.9)', () => {
  it('preflight refuses CI/cloud/shared/production/recording/echo/output violations', () => {
    const safe = controlledCorpusPreflight({ ciMarker: false, cloudMarker: false, sharedNetworkMarker: false, productionNetworkMarker: false, recordingEnabled: false, echoCapablePasswordSource: false, outputPathAllowed: true });
    expect(safe.ok).toBe(true);
    expect(controlledCorpusPreflight({ ...safeOk(), ciMarker: true }).ok).toBe(false);
    expect(controlledCorpusPreflight({ ...safeOk(), productionNetworkMarker: true }).ok).toBe(false);
    expect(controlledCorpusPreflight({ ...safeOk(), recordingEnabled: true }).ok).toBe(false);
    expect(controlledCorpusPreflight({ ...safeOk(), echoCapablePasswordSource: true }).ok).toBe(false);
    expect(controlledCorpusPreflight({ ...safeOk(), outputPathAllowed: false }).ok).toBe(false);
  });

  it('aggregate evidence is consistent and capture-disabled', () => {
    const result = aggregateCorpusEvidence({ totalFiles: 10, passed: 8, failed: 2, sourceUnchangedAggregate: true, producerShapeClasses: 3, isolatedNetworkDigest: 'a'.repeat(64) });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.evidence.captureDisabled).toBe(true);
      expect(result.evidence.totalFiles).toBe(10);
    }
    const inconsistent = aggregateCorpusEvidence({ totalFiles: 10, passed: 9, failed: 2, sourceUnchangedAggregate: true, producerShapeClasses: 3, isolatedNetworkDigest: 'a'.repeat(64) });
    expect(inconsistent.ok).toBe(false);
  });
});

describe('FEAT-009 downstream handoff (Task 6.9)', () => {
  it('the immutable handoff validates with pinned contract references', () => {
    const handoff = createFileRestoreHandoff({ 'credential-file-restore/contracts': 'a'.repeat(64) }, '2026-08-05T27:00:00Z');
    expect(validateFileRestoreHandoff(handoff).ok).toBe(true);
    expect(handoff.prohibitedSurfaces).toContain('mnemonic');
    expect(handoff.prohibitedSurfaces).toContain('genericCapability');
    expect(handoff.exportedContracts.length).toBeGreaterThanOrEqual(8);
  });
});

function safeOk() {
  return { ciMarker: false, cloudMarker: false, sharedNetworkMarker: false, productionNetworkMarker: false, recordingEnabled: false, echoCapablePasswordSource: false, outputPathAllowed: true };
}
