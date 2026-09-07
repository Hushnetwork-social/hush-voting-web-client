/**
 * FEAT-016 Task 6.3 — worker-hosted entitlement bootstrap session.
 *
 * The SharedWorker-side host that owns ONE licence reconciliation session
 * across same-origin tabs. It binds the Phase 3 `LicenceEntitlementCoordinator`
 * to the sealed engine's closed licence operations (fresh signed query,
 * deterministic baseline sealing, encrypted two-slot pending licence journal)
 * and to the same-origin BFF transports. Page ports receive only safe
 * snapshots/progress (`LicenceBootstrapSnapshot`); the coordinator's journal
 * mirror is flushed to the encrypted durable journal after every step, always
 * in the exact signed form (the Phase 3 review "exact-bytes seam").
 *
 * Eligibility (foreground/reachable/paused) is pushed by the page bridge;
 * the worker env runs the serialized pump loop (the authority-owned loop).
 * Lock/logout/removal/epoch invalidation tears the session down through
 * `stop()`; a submitted encrypted pending transaction survives in the durable
 * journal for query-first reconciliation after the next authentication.
 *
 * SECRET BOUNDARY: this module runs ONLY inside the SharedWorker (never page
 * code). Exact signed bytes never appear in progress payloads or outcomes.
 *
 * Normative source: FEAT-016 FeatureDescription "Web" (SharedWorker is the
 * one signing/journal/reconciliation authority; safe broadcasts only),
 * "Licence Transaction and Pending Journal"; planning-analysis-report §6.
 */

import { LicenceEntitlementCoordinator, type LicenceCoordinatorPorts, type CoordinatorSnapshot } from '../../licensing/coordinator';
import type { LicenceAdmissionOutcome } from '../../licensing/direct-free';
import type { LicencePendingTransactionRecord } from '../../licensing/pending-transaction';
import { parsePendingLicenceRecordJson, serializePendingLicenceRecord } from '../../licensing/pending-transaction';
import type { LicenceQuerySignature } from '../../licensing/sealing';
import { isLicenceSignedTransactionJson } from '../../licensing/sealing';
import { sha256Hex, utf8Bytes } from '../../identity-compatibility/crypto';
import type { LicenceQueryTransportResult } from '../../licensing/contracts';
import type { SealedVaultEngine } from './sealed-vault';
import type {
  LicenceBootstrapSnapshot,
  LicenceBootstrapStepResult,
  LicenceConnectivityInput,
  LicenceProgressPayload,
  LicenceRevalidationTrigger,
} from '../../licensing/session-contract';
import {
  isLicenceConnectivityInput,
  isLicenceRevalidationTrigger,
} from '../../licensing/session-contract';
import { isBoundedPlanId } from '../../licensing/upgrade';
import { createUuidV4 } from '../../identity-creation/profile';

/** Safe snapshot of one coordinator (no journal/transport internals). */
function snapshotFromCoordinator(snapshot: CoordinatorSnapshot): LicenceBootstrapSnapshot {
  return {
    phase: snapshot.phase,
    projection: snapshot.projection,
    lastOutcomeCode: snapshot.lastOutcomeCode,
    pendingTransactionId: snapshot.pendingTransactionId,
    upgradeOperation: snapshot.upgradeOperation,
    upgradeNotificationEligible: snapshot.upgradeNotificationEligible,
  };
}

/** Host dependencies (production wiring in the worker env; deterministic in tests). */
export interface LicenceBootstrapSessionDeps {
  readonly engine: SealedVaultEngine;
  readonly nowMs: () => number;
  /** Canonical network binding the authority is approved for (manifest id). */
  readonly expectedNetworkBinding: string;
  /** Same-origin BFF query submit (fresh three metadata headers forwarded). */
  readonly querySubmit: (headers: LicenceQuerySignature) => Promise<LicenceQueryTransportResult>;
  /** Canonical transaction ingress submission (maps to admission vocabulary). */
  readonly transactionSubmit: (signedJson: string) => Promise<LicenceAdmissionOutcome>;
  /** Publish one safe progress payload to connected clients. */
  readonly onProgress: (payload: LicenceProgressPayload) => void;
}

/**
 * One authority-owned entitlement bootstrap session. Created lazily on the
 * first `licenceBootstrapStart` after authentication; torn down on Lock,
 * removal, network change, epoch invalidation, or worker death.
 */
export class LicenceBootstrapSession {
  private coordinator: LicenceEntitlementCoordinator | null = null;
  private eligibility: { readonly foregrounded: boolean; readonly reachable: boolean; readonly paused: boolean } = {
    foregrounded: true,
    reachable: true,
    paused: false,
  };
  private readonly mirror = new Map<string, LicencePendingTransactionRecord>();
  private durableHealthy = true;
  private actorSigningAddress: string | null = null;
  private networkBinding: string | null = null;
  private lastProgressKey: string | null = null;
  private lastConnectivity: LicenceConnectivityInput | null = null;

  constructor(private readonly deps: LicenceBootstrapSessionDeps) {}

  /** True while an authenticated session is bound (loop keep-alive). */
  isActive(): boolean {
    return this.coordinator !== null && this.deps.engine.licenceActor() !== null;
  }

  /** Current safe snapshot (null before the session is bound). */
  snapshot(): LicenceBootstrapSnapshot | null {
    return this.coordinator === null ? null : snapshotFromCoordinator(this.coordinator.snapshot());
  }

  /**
   * Start/resume query-first bootstrap after authentication or restart.
   * `networkBinding` is re-verified against the authority-owned manifest.
   */
  async start(networkBinding: string): Promise<LicenceBootstrapStepResult> {
    const actor = this.deps.engine.licenceActor();
    if (actor === null) {
      return { ok: false, reason: 'not-authenticated' };
    }
    if (typeof networkBinding !== 'string' || networkBinding.length === 0 || networkBinding.length > 256) {
      return { ok: false, reason: 'invalid-input' };
    }
    if (networkBinding !== this.deps.expectedNetworkBinding) {
      // Closed network semantics: never bind a record/coordinator to a
      // network the authority is not approved for.
      return { ok: false, reason: 'invalid-input' };
    }
    // Network/actor change (or a stale session after an invalidation) tears
    // the old session down before a fresh one may bind.
    if (
      this.coordinator !== null &&
      (this.actorSigningAddress !== actor.signingAddress || this.networkBinding !== networkBinding)
    ) {
      this.teardown();
    }
    if (this.coordinator !== null) {
      const result = await this.pumpOnce();
      return result.ok ? { ok: true, snapshot: result.snapshot } : { ok: false, reason: 'authority-unavailable' };
    }
    this.actorSigningAddress = actor.signingAddress;
    this.networkBinding = networkBinding;
    // Hydrate the encrypted durable journal (query-first restart discipline).
    const hydrated = await this.hydrateDurable();
    if (!hydrated.ok) {
      this.durableHealthy = false;
    }
    this.coordinator = new LicenceEntitlementCoordinator(
      actor.signingAddress as never,
      networkBinding as never,
      this.buildPorts(),
    );
    const started = await this.coordinator.start();
    const snapshot = snapshotFromCoordinator(started);
    await this.flushDurable();
    this.emitProgress(snapshot);
    return { ok: true, snapshot };
  }

  /** Page-pushed eligibility/lifecycle/connectivity inputs. */
  async updateEligibility(input: { readonly foregrounded?: boolean; readonly connectivity?: LicenceConnectivityInput }): Promise<LicenceBootstrapStepResult> {
    if (this.coordinator === null) {
      return { ok: false, reason: 'not-authenticated' };
    }
    const foregrounded = input.foregrounded ?? this.eligibility.foregrounded;
    if (typeof foregrounded !== 'boolean') {
      return { ok: false, reason: 'invalid-input' };
    }
    this.eligibility = { ...this.eligibility, foregrounded };
    if (input.connectivity !== undefined) {
      if (!isLicenceConnectivityInput(input.connectivity)) {
        return { ok: false, reason: 'invalid-input' };
      }
      if (input.connectivity !== this.lastConnectivity) {
        this.lastConnectivity = input.connectivity;
        await this.coordinator.onConnectivity(input.connectivity);
        this.applyConnectivityEligibility(input.connectivity);
      }
    }
    return this.pumpOnce();
  }

  /** User/UI control intents (Retry, recovery, revalidation triggers). */
  async control(kind: string, trigger: unknown): Promise<LicenceBootstrapStepResult> {
    if (this.coordinator === null || this.deps.engine.licenceActor() === null) {
      return { ok: false, reason: 'not-authenticated' };
    }
    switch (kind) {
      case 'retry': {
        await this.coordinator.retryExact();
        break;
      }
      case 'recover': {
        await this.coordinator.recoverFromError();
        break;
      }
      case 'revalidate': {
        if (!isLicenceRevalidationTrigger(trigger)) {
          return { ok: false, reason: 'invalid-input' };
        }
        await this.coordinator.revalidate(trigger as LicenceRevalidationTrigger);
        break;
      }
      default:
        return { ok: false, reason: 'invalid-input' };
    }
    await this.flushDurable();
    const snapshot = snapshotFromCoordinator(this.coordinator.snapshot());
    this.emitProgress(snapshot);
    return { ok: true, snapshot };
  }

  /**
   * FEAT-017 Task 6.1 — one closed confirmed-upgrade activation routed
   * through the SAME serialized authority session. The page hands a bounded
   * server plan handle; the coordinator re-queries fresh truth, seals exactly
   * one confirmed_upgrade record, and the existing journal/loop/retry own
   * everything after that. A second request while an operation is live
   * coalesces (never a second transaction).
   */
  async confirmUpgrade(targetPlanId: unknown): Promise<LicenceBootstrapStepResult> {
    if (this.coordinator === null || this.deps.engine.licenceActor() === null) {
      return { ok: false, reason: 'not-authenticated' };
    }
    if (typeof targetPlanId !== 'string' || !isBoundedPlanId(targetPlanId)) {
      return { ok: false, reason: 'invalid-input' };
    }
    await this.coordinator.confirmUpgrade(targetPlanId);
    await this.flushDurable();
    const snapshot = snapshotFromCoordinator(this.coordinator.snapshot());
    this.emitProgress(snapshot);
    return { ok: true, snapshot };
  }

  /** FEAT-017 Task 6.1 — acknowledge a surfaced terminal upgrade outcome. */
  async acknowledgeUpgradeOutcome(): Promise<LicenceBootstrapStepResult> {
    if (this.coordinator === null || this.deps.engine.licenceActor() === null) {
      return { ok: false, reason: 'not-authenticated' };
    }
    this.coordinator.acknowledgeUpgradeOutcome();
    await this.flushDurable();
    const snapshot = snapshotFromCoordinator(this.coordinator.snapshot());
    this.emitProgress(snapshot);
    return { ok: true, snapshot };
  }

  /** One serialized pump cycle (authority-owned loop; ~1 s cadence). */
  async pump(): Promise<LicenceBootstrapSnapshot | null> {
    const result = await this.pumpOnce();
    return result.ok ? result.snapshot : null;
  }

  /** Teardown: drop coordinator + mirror + binding (never the durable journal). */
  teardown(): void {
    this.coordinator = null;
    this.mirror.clear();
    this.actorSigningAddress = null;
    this.networkBinding = null;
    this.lastConnectivity = null;
    this.lastProgressKey = null;
    this.durableHealthy = true;
    this.eligibility = { foregrounded: true, reachable: true, paused: false };
  }

  private async pumpOnce(): Promise<LicenceBootstrapStepResult> {
    if (this.coordinator === null) {
      return { ok: false, reason: 'not-authenticated' };
    }
    if (this.deps.engine.licenceActor() === null) {
      // Lock/invalidation while pumping: tear down; the machine gates.
      this.teardown();
      return { ok: false, reason: 'not-authenticated' };
    }
    const snapshot = await this.coordinator.tick({
      authenticated: true,
      foregrounded: this.eligibility.foregrounded,
      reachable: this.eligibility.reachable,
      paused: this.eligibility.paused,
    });
    const safe = snapshotFromCoordinator(snapshot);
    await this.flushDurable();
    this.emitProgress(safe);
    return { ok: true, snapshot: safe };
  }

  private applyConnectivityEligibility(connectivity: LicenceConnectivityInput): void {
    switch (connectivity) {
      case 'online':
        this.eligibility = { ...this.eligibility, reachable: true, paused: false };
        break;
      case 'paused':
        this.eligibility = { ...this.eligibility, reachable: true, paused: true };
        break;
      case 'offline':
      case 'reconnecting':
        this.eligibility = { ...this.eligibility, reachable: false, paused: false };
        break;
    }
  }

  private buildPorts(): LicenceCoordinatorPorts {
    return {
      nowMs: () => this.deps.nowMs(),
      queryTransport: async () => {
        const actor = this.deps.engine.licenceActor();
        if (actor === null) {
          return { ok: false, status: 'UNAVAILABLE' };
        }
        return this.deps.engine.licenceQuery((headers) => this.deps.querySubmit(headers));
      },
      submitBaseline: async (record) => this.submitBaseline(record),
      nextBaselineIdentity: () => ({ transactionId: createUuidV4(), timestampUtc: new Date(this.deps.nowMs()).toISOString() }),
      savePending: (record) => this.mirrorSave(record),
      loadPending: (transactionId) => this.mirrorLoad(transactionId),
      loadPendingForIdentity: (identityBinding, networkBinding) => this.mirrorLoadForIdentity(identityBinding, networkBinding),
      deletePending: (transactionId) => this.mirrorDelete(transactionId),
    };
  }

  /**
   * Exact-bytes seam (Phase 3 review note 1): if the coordinator hands an
   * unsigned envelope, the authority seals it deterministically, persists the
   * exact signed form to the encrypted durable journal, and ONLY then submits
   * the exact signed transaction through the canonical ingress.
   */
  private async submitBaseline(record: LicencePendingTransactionRecord): Promise<LicenceAdmissionOutcome> {
    let exactJson = record.transaction.exactJson;
    let digest = record.transaction.digest;
    if (!isLicenceSignedTransactionJson(exactJson)) {
      const actor = this.deps.engine.licenceActor();
      if (actor === null) {
        return 'terminalRejected';
      }
      const sealed = this.deps.engine.licenceSignBaseline(exactJson);
      if (!sealed.ok) {
        // Fail closed: never submit unverified bytes; no replacement loop.
        return 'terminalRejected';
      }
      exactJson = sealed.signedJson;
      digest = sealed.signedDigest;
    }
    const signedRecord: LicencePendingTransactionRecord = {
      ...record,
      transaction: { exactJson, digest },
      submittedUtc: new Date(this.deps.nowMs()).toISOString(),
    };
    const persisted = await this.writeDurable(signedRecord);
    if (!persisted.ok) {
      this.durableHealthy = false;
      return 'uncertain'; // never submit before a verified durable seal
    }
    return this.deps.transactionSubmit(exactJson);
  }

  private async writeDurable(record: LicencePendingTransactionRecord): Promise<{ readonly ok: boolean }> {
    const validated = parsePendingLicenceRecordJson(serializePendingLicenceRecord(record));
    if (validated === null) {
      return { ok: false };
    }
    const result = await this.deps.engine.licenceJournalWrite(serializePendingLicenceRecord(validated));
    if (result.ok) {
      this.mirror.set(record.transactionId, validated);
      this.durableHealthy = true;
    }
    return { ok: result.ok };
  }

  /**
   * Flush the in-memory mirror to the encrypted durable journal after every
   * step. The durable record always carries the exact signed form (sealed
   * deterministically here when the coordinator mirrored an unsigned staging
   * envelope). An empty mirror clears the durable journal.
   */
  private async flushDurable(): Promise<void> {
    if (this.mirror.size === 0) {
      const cleared = await this.deps.engine.licenceJournalClear();
      if (!cleared.ok) {
        this.durableHealthy = false;
      }
      return;
    }
    const record = this.mirror.values().next().value as LicencePendingTransactionRecord | undefined;
    if (record === undefined) {
      return;
    }
    let durableRecord = record;
    if (!isLicenceSignedTransactionJson(record.transaction.exactJson)) {
      const sealed = this.deps.engine.licenceSignBaseline(record.transaction.exactJson);
      if (sealed.ok) {
        durableRecord = { ...record, transaction: { exactJson: sealed.signedJson, digest: sealed.signedDigest } };
      }
    }
    const result = await this.deps.engine.licenceJournalWrite(serializePendingLicenceRecord(durableRecord));
    if (result.ok) {
      this.durableHealthy = true;
      this.mirror.set(durableRecord.transactionId, durableRecord);
    } else {
      this.durableHealthy = false;
    }
  }

  private async hydrateDurable(): Promise<{ readonly ok: boolean }> {
    const read = await this.deps.engine.licenceJournalRead();
    if (!read.ok) {
      return { ok: false };
    }
    if (read.recordJson === null) {
      return { ok: true };
    }
    const record = parsePendingLicenceRecordJson(read.recordJson);
    if (record === null) {
      return { ok: false };
    }
    // Binding-scoped hydration: a durable record from another identity or
    // network is never loaded into this session (query-first restart; a
    // returned original network reconciles after its own re-authentication).
    if (
      record.identityBinding !== this.actorSigningAddress ||
      record.networkBinding !== this.networkBinding
    ) {
      return { ok: true };
    }
    this.mirror.set(record.transactionId, record);
    this.durableHealthy = true;
    return { ok: true };
  }

  private mirrorSave(record: LicencePendingTransactionRecord): { ok: boolean; reason?: string } {
    if (this.actorSigningAddress !== null && record.identityBinding !== this.actorSigningAddress) {
      return { ok: false, reason: 'binding-mismatch' };
    }
    if (!this.durableHealthy) {
      return { ok: false, reason: 'storage-unavailable' };
    }
    const validated = parsePendingLicenceRecordJson(serializePendingLicenceRecord(record));
    if (validated === null) {
      return { ok: false, reason: 'corrupt' };
    }
    this.mirror.set(record.transactionId, validated);
    return { ok: true };
  }

  private mirrorLoad(transactionId: string): { ok: boolean; record?: LicencePendingTransactionRecord; reason?: string } {
    const record = this.mirror.get(transactionId);
    if (record === undefined) {
      return { ok: false, reason: 'not-found' };
    }
    return { ok: true, record };
  }

  private mirrorLoadForIdentity(identityBinding: string, networkBinding: string): { ok: boolean; record?: LicencePendingTransactionRecord } {
    for (const record of this.mirror.values()) {
      if (record.identityBinding === identityBinding && record.networkBinding === networkBinding) {
        return { ok: true, record };
      }
    }
    return { ok: false };
  }

  private mirrorDelete(transactionId: string): void {
    this.mirror.delete(transactionId);
  }

  /** Emit safe progress only when the observable surface changed. */
  private emitProgress(snapshot: LicenceBootstrapSnapshot): void {
    const upgradeKey =
      snapshot.upgradeOperation === null
        ? 'none'
        : `${snapshot.upgradeOperation.status}:${snapshot.upgradeOperation.operation?.pendingTransactionId ?? '-'}`;
    const key = `${snapshot.phase}|${snapshot.lastOutcomeCode ?? ''}|${snapshot.projection === null ? '-' : snapshot.projection.licenceReference}|${upgradeKey}|${snapshot.upgradeNotificationEligible ? 'n1' : 'no-n1'}`;
    if (key === this.lastProgressKey) {
      return;
    }
    this.lastProgressKey = key;
    this.deps.onProgress({ ...snapshot, emittedAtMs: this.deps.nowMs() });
  }
}

/** Deterministic digest helper for sealed records (kept local). */
export function signedDigestOf(json: string): string {
  return sha256Hex(utf8Bytes(json));
}

/** Random id helper kept out of the class for tree-shaking clarity. */
export const licenceSessionExports = { snapshotFromCoordinator, signedDigestOf };
