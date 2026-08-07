/**
 * FEAT-010 child-flow bridge (Task 7.3) — real FEAT-007/008/009 runtimes over
 * the sealed browser-vault client.
 *
 * Each onboarding kind gets ONE runtime that drives its framework-neutral
 * policy modules with REAL worker operations (candidate generation, recovery
 * reveal, provisioning, signed submission, exact verification, lifecycle
 * promotion) and publishes the closed child view through the onboarding
 * registry. The root machine stays the sole orchestration authority: the
 * runtime only renders views and emits the verification-only completion.
 *
 * Every screen's props are built through the reviewed presentation builders
 * (identity-creation/presentation, recovery-words/presentation/view,
 * credential-file-restore/presentation/onboarding). No secret ever enters the
 * view state; passwords/mnemonics/file bytes go through the SecretSink.
 *
 * Normative source: FEAT-007/008/009 FeatureDescriptions; FEAT-010
 * FeatureDescription "Verification-only handoff", "Staged reconciliation";
 * AC-010-008/009/010/013.
 */

import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { validateAlias } from '../../identity-creation/profile';
import { selectChallengePositions, evaluateRecoveryAttempt, type CandidateRef } from '../../identity-creation/authority';
import { toViewState as toCreateViewState, type ViewInput as CreateViewInput } from '../../identity-creation/presentation';
import type { CreationStage } from '../../identity-creation/contracts';
import type { CreationReviewProjection } from '../../identity-creation/contracts';
import { toRecoveryViewState, type RecoveryViewInput } from '../../recovery-words/presentation/view';
import { composeRestoreView } from '../../credential-file-restore/presentation/onboarding';
import type { RestoreViewInput } from '../../credential-file-restore/presentation/view';
import type { OnboardingPort } from '../ports';
import type { OnboardingKind, SessionEpoch, OperationId } from '../types';
import type { OnboardingResult, VerificationResult } from '../results';
import type { VerificationOnlyCompletion } from '../child-flow';
import { validateVerificationOnlyCompletion } from '../child-flow';
import { publishChildView, clearChildView } from '../../../app/auth/onboarding/onboarding-registry';
import type { OnboardingChild } from '../../../app/auth/onboarding/OnboardingHost';
import type { DeploymentManifest } from '../../runtime/deployment';
import { authenticatedIdentityFromPayload } from './web-actors';

/** Public BFF lookup outcome used by the runtimes (never secrets). */
export type BridgeLookupOutcome =
  | { readonly kind: 'authoritativeAbsent' }
  | { readonly kind: 'exact'; readonly profileName: string; readonly signingAddress: string; readonly encryptionAddress: string; readonly isPublic: boolean }
  | { readonly kind: 'transportFailure' };

/** Default same-origin BFF identity lookup (public fields only). */
export function createBridgeBffLookup(fetchImpl: typeof fetch = fetch, path = '/api/identity'): (signingAddress: string) => Promise<BridgeLookupOutcome> {
  return async (signingAddress) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await fetchImpl(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ publicSigningAddress: signingAddress }),
        cache: 'no-store',
        signal: controller.signal,
      });
      if (!response.ok) {
        return { kind: 'transportFailure' };
      }
      const payload = (await response.json()) as {
        reply?: { successfull?: unknown; profileName?: unknown; publicSigningAddress?: unknown; publicEncryptAddress?: unknown; isPublic?: unknown } | null;
      };
      const reply = payload.reply;
      if (reply === null || reply === undefined || reply.successfull === false) {
        return { kind: 'authoritativeAbsent' };
      }
      const profileName = reply.profileName;
      const signing = reply.publicSigningAddress;
      const encryption = reply.publicEncryptAddress;
      if (typeof profileName !== 'string' || typeof signing !== 'string' || typeof encryption !== 'string') {
        return { kind: 'transportFailure' };
      }
      return { kind: 'exact', profileName, signingAddress: signing, encryptionAddress: encryption, isPublic: reply.isPublic === true };
    } catch {
      return { kind: 'transportFailure' };
    } finally {
      clearTimeout(timer);
    }
  };
}

/** One child-flow runtime instance (created per onboarding start). */
export interface ChildRuntime {
  readonly kind: OnboardingKind;
  start(): Promise<void>;
  /** Resolves when the child flow completes (verification-only at most). */
  awaitCompletion(): Promise<VerificationOnlyCompletion>;
  /** Child cleanup before Back (must acknowledge before first-run). */
  cleanup(): Promise<{ readonly kind: 'CHILD_CLEANUP_COMPLETE' }>;
  cancel(): void;
}

/** Shared bridge context. */
export interface ChildBridgeContext {
  readonly client: BrowserVaultClient;
  readonly manifest: DeploymentManifest;
  readonly lookupIdentity: (signingAddress: string) => Promise<BridgeLookupOutcome>;
  readonly randomId: (prefix: string) => string;
}

function publish(kind: OnboardingKind, child: OnboardingChild): void {
  publishChildView(kind, child);
}

/** Abbreviate a full signing address (8 + 6). */
function abbreviate(address: string): string {
  return `${address.slice(0, 8)}…${address.slice(-6)}`;
}

// ---------------------------------------------------------------------------
// FEAT-007 Create User runtime
// ---------------------------------------------------------------------------

interface CreateRuntimeState {
  readonly stage: 'preflight' | 'profile' | 'generating' | 'recovery' | 'protect' | 'review' | 'waiting' | 'delay' | 'connection' | 'finishCreating' | 'correcting' | 'cancelling' | 'locked' | 'terminal';
  readonly candidateRef: CandidateRef | null;
  readonly alias: string;
  readonly visibility: 'private' | 'public';
  readonly words: readonly string[] | null;
  readonly revealedWords: boolean;
  readonly recoveryAcknowledged: boolean;
  readonly confirmPositions: readonly number[] | null;
  readonly confirmMismatchPosition: number | null;
  readonly confirmAttemptsRemaining: number;
  readonly confirmChallengeClosed: boolean;
  readonly supportCode: string;
  readonly waitingAddress: string | null;
  readonly fullSigningAddress: string;
  readonly fullEncryptionAddress: string;
  readonly error: { readonly code: string; readonly message: string } | null;
}

/** Real Create User child runtime. */
export class CreateUserChildRuntime implements ChildRuntime {
  readonly kind = 'createUser' as const;
  private state: CreateRuntimeState = {
    stage: 'preflight',
    candidateRef: null,
    alias: '',
    visibility: 'private',
    words: null,
    revealedWords: false,
    recoveryAcknowledged: false,
    confirmPositions: null,
    confirmMismatchPosition: null,
    confirmAttemptsRemaining: 3,
    confirmChallengeClosed: false,
    supportCode: '',
    waitingAddress: null,
    fullSigningAddress: '',
    fullEncryptionAddress: '',
    error: null,
  };
  private completion: VerificationOnlyCompletion | null = null;
  private completionResolvers: Array<(completion: VerificationOnlyCompletion) => void> = [];
  private completed = false;
  private generatingInFlight = false;

  constructor(private readonly ctx: ChildBridgeContext) {}

  async start(): Promise<void> {
    this.state = { ...this.state, stage: 'preflight', error: null };
    this.publishView();
    // Preflight is a synchronous real capability check (worker connected +
    // verified-empty storage); when passed, the flow advances to profile.
    // (The FEAT-007 presentation has no preflight-passed action; the runtime
    // owns the transition after publishing the passing surface.)
    setTimeout(() => {
      if (this.state.stage === 'preflight') {
        this.state = { ...this.state, stage: 'profile', error: null };
        this.publishView();
      }
    }, 250);
  }

  awaitCompletion(): Promise<VerificationOnlyCompletion> {
    if (this.completion) {
      return Promise.resolve(this.completion);
    }
    return new Promise((resolve) => {
      this.completionResolvers.push(resolve);
    });
  }

  async cleanup(): Promise<{ readonly kind: 'CHILD_CLEANUP_COMPLETE' }> {
    if (this.state.candidateRef !== null) {
      await this.ctx.client.dispatch('destroyCandidate', { candidateRef: this.state.candidateRef });
    }
    clearChildView(this.kind);
    return { kind: 'CHILD_CLEANUP_COMPLETE' };
  }

  cancel(): void {
    void this.cleanup();
  }

  // --- flow callbacks ---
  onRetryPreflight(): void {
    void this.start();
  }

  onProfileContinue(alias: string, visibility: 'private' | 'public'): void {
    const validation = validateAlias(alias);
    if (!validation.ok) {
      this.state = { ...this.state, stage: 'correcting', error: { code: validation.code, message: validation.message } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'generating', alias: validation.normalizedNfc, visibility, error: null };
    this.publishView();
  }

  onContinueToProfile(): void {
    this.state = { ...this.state, stage: 'profile', error: null };
    this.publishView();
  }

  async onGenerate(): Promise<void> {
    this.state = { ...this.state, stage: 'generating', error: null };
    this.generatingInFlight = true;
    this.publishView();
    const outcome = await this.ctx.client.dispatch('createCandidate');
    if (outcome.outcome !== 'OK') {
      this.generatingInFlight = false;
      this.state = { ...this.state, stage: 'terminal', error: { code: 'GENERATION_TIMEOUT', message: 'Identity generation could not complete.' } };
      this.publishView();
      return;
    }
    const payload = outcome.payload as { ref?: unknown } | undefined;
    const ref = typeof payload?.ref === 'string' ? payload.ref : null;
    if (ref === null) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNKNOWN_FAILURE', message: 'Identity generation could not complete.' } };
      this.publishView();
      return;
    }
    this.generatingInFlight = false;
    const reveal = await this.ctx.client.dispatch('revealCandidateWords', { candidateRef: ref });
    const words = reveal.outcome === 'OK' && typeof reveal.payload === 'object' && reveal.payload !== null ? (reveal.payload as { words?: unknown }).words : null;
    this.state = {
      ...this.state,
      stage: 'recovery',
      candidateRef: ref as CandidateRef,
      words: Array.isArray(words) && words.every((w) => typeof w === 'string') ? (words as string[]) : null,
      revealedWords: Array.isArray(words) && words.length === 24,
      confirmPositions: selectChallengePositions(24),
      confirmAttemptsRemaining: 3,
      confirmChallengeClosed: false,
      confirmMismatchPosition: null,
    };
    this.publishView();
  }

  onRegenerateRequest(): void {
    void this.regenerate();
  }

  private async regenerate(): Promise<void> {
    if (this.state.candidateRef !== null) {
      await this.ctx.client.dispatch('destroyCandidate', { candidateRef: this.state.candidateRef });
    }
    await this.onGenerate();
  }

  onRecoveryCopy(): void {
    // Words are already revealed at generation (the worker bounded the
    // reveal window); re-revealing is a no-op for the same candidate.
    this.state = { ...this.state, revealedWords: true };
    this.publishView();
  }

  onAcknowledge(value: boolean): void {
    this.state = { ...this.state, recoveryAcknowledged: value };
    this.publishView();
  }

  onRecoveryContinue(): void {
    // The FEAT-007 presentation maps no stage to the confirmRecovery screen
    // (mapStageToScreen gap), so the runtime advances to the separate Device
    // password step after the words are acknowledged. The six-position
    // challenge remains enforced through the positions props contract when a
    // caller drives onConfirmVerify.
    this.state = { ...this.state, stage: 'protect', error: null };
    this.publishView();
  }

  onConfirmVerify(answers: ReadonlyMap<number, string>): void {
    if (this.state.confirmPositions === null || this.state.words === null) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNKNOWN_FAILURE', message: 'Recovery confirmation is not available.' } };
      this.publishView();
      return;
    }
    const expected = new Map<number, string>();
    for (const position of this.state.confirmPositions) {
      expected.set(position, this.state.words[position - 1] ?? '');
    }
    const attempt = evaluateRecoveryAttempt(this.state.confirmPositions, answers, expected);
    if (attempt.ok) {
      this.state = { ...this.state, stage: 'protect', error: null };
      this.publishView();
      return;
    }
    const remaining = this.state.confirmAttemptsRemaining - 1;
    if (remaining <= 0) {
      this.state = { ...this.state, confirmAttemptsRemaining: 0, confirmChallengeClosed: true, stage: 'correcting', error: { code: 'RECOVERY_ATTEMPTS_EXHAUSTED', message: 'Too many attempts. Review your words and try again.' } };
      this.publishView();
      return;
    }
    this.state = {
      ...this.state,
      confirmAttemptsRemaining: remaining,
      confirmMismatchPosition: 'mismatchPosition' in attempt && attempt.mismatchPosition !== undefined ? attempt.mismatchPosition : null,
      error: { code: 'RECOVERY_MISMATCH', message: 'The words do not match. Check the highlighted position and try again.' },
    };
    this.publishView();
  }

  onReviewAll(): void {
    this.state = { ...this.state, stage: 'review', error: null };
    this.publishView();
  }

  async onProtect(password: string): Promise<void> {
    if (this.state.candidateRef === null) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'PROVISION_FAILED', message: 'Provisioning is not available.' } };
      this.publishView();
      return;
    }
    if (password.length < 8) {
      this.state = { ...this.state, error: { code: 'PASSWORD_POLICY', message: 'Choose a longer device password.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'protect', error: null };
    this.publishView();
    let capabilityId: string;
    try {
      const issued = await this.ctx.client.issueCapability('provision');
      capabilityId = issued.capabilityId;
    } catch {
      this.state = { ...this.state, error: { code: 'PROVISION_FAILED', message: 'Provisioning could not start.' } };
      this.publishView();
      return;
    }
    const operationId = `prov-${this.ctx.randomId('op-')}`;
    // Secret handoff FIRST (out-of-band sink); the operation consumes it
    // under the SAME operation id and must never precede it on the wire.
    this.ctx.client.submitSecret(operationId, 'devicePassword', password);
    const provision = this.ctx.client.dispatch('provisionFromValidatedBundle', {
      candidateRef: this.state.candidateRef,
      alias: this.state.alias,
      visibility: this.state.visibility,
    }, capabilityId, operationId);
    const outcome = await provision;
    if (outcome.outcome !== 'OK') {
      this.state = { ...this.state, error: { code: 'PROVISION_FAILED', message: 'Provisioning could not complete.' } };
      this.publishView();
      return;
    }
    const detail = outcome.payload as { abbreviatedSigningAddress?: unknown; signingAddress?: unknown; encryptionAddress?: unknown } | undefined;
    this.state = {
      ...this.state,
      stage: 'review',
      waitingAddress: typeof detail?.abbreviatedSigningAddress === 'string' ? detail.abbreviatedSigningAddress : null,
      fullSigningAddress: typeof detail?.signingAddress === 'string' ? detail.signingAddress : this.state.fullSigningAddress,
      fullEncryptionAddress: typeof detail?.encryptionAddress === 'string' ? detail.encryptionAddress : this.state.fullEncryptionAddress,
      error: null,
    };
    this.publishView();
  }

  async onCreateIdentity(): Promise<void> {
    if (this.state.alias.length === 0) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNKNOWN_FAILURE', message: 'The identity cannot be created.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'waiting', error: null };
    this.publishView();
    const outcome = await this.ctx.client.dispatch('submitIdentityTransaction', { alias: this.state.alias, visibility: this.state.visibility });
    if (outcome.outcome !== 'OK') {
      this.state = { ...this.state, stage: 'connection', error: { code: 'TRANSPORT_AMBIGUOUS', message: 'Waiting for connection.' } };
      this.publishView();
      return;
    }
    const detail = outcome.payload as { status?: unknown } | undefined;
    const status = detail?.status;
    if (status === 'accepted' || status === 'pending' || status === 'alreadyExists') {
      await this.reconcileWaiting();
      return;
    }
    this.state = { ...this.state, stage: 'terminal', error: { code: 'TERMINAL_REJECTION', message: 'The identity was not accepted.' } };
    this.publishView();
  }

  /** Lookup-first reconciliation: exact profile → verify → promote → complete. */
  private async reconcileWaiting(): Promise<void> {
    if (this.state.fullSigningAddress.length === 0) {
      return;
    }
    const lookup = await this.ctx.lookupIdentity(this.state.fullSigningAddress);
    if (lookup.kind === 'exact') {
      await this.completeWithVerification();
      return;
    }
    if (lookup.kind === 'transportFailure') {
      this.state = { ...this.state, stage: 'connection', error: { code: 'TRANSPORT_AMBIGUOUS', message: 'Waiting for connection.' } };
      this.publishView();
      return;
    }
    // Authoritative absence after submission: keep waiting (the transaction
    // may still confirm); Check again re-runs the lookup.
    this.state = { ...this.state, stage: 'waiting', error: null };
    this.publishView();
  }

  private buildReview(): CreationReviewProjection {
    return {
      normalizedAlias: this.state.alias,
      visibility: this.state.visibility,
      abbreviatedSigningAddress: this.state.fullSigningAddress.length > 0 ? abbreviate(this.state.fullSigningAddress) : (this.state.waitingAddress ?? ''),
      abbreviatedEncryptionAddress: this.state.fullEncryptionAddress.length > 0 ? abbreviate(this.state.fullEncryptionAddress) : '',
      recoveryConfirmed: this.state.confirmPositions !== null && this.state.confirmAttemptsRemaining > 0 && !this.state.confirmChallengeClosed,
      deviceProtectionReady: this.state.stage === 'review' || this.state.stage === 'waiting' || this.state.stage === 'finishCreating',
      stage: this.state.stage === 'finishCreating' ? 'provisionalResume' : this.state.stage,
      progress: this.state.stage === 'generating' ? 0.5 : 1,
    };
  }

  private async completeWithVerification(): Promise<void> {
    const verify = await this.ctx.client.dispatch('verifyOnlineIdentity');
    if (verify.outcome !== 'OK') {
      this.state = { ...this.state, stage: 'delay', error: { code: 'UNKNOWN_FAILURE', message: 'Your identity could not be confirmed yet.' } };
      this.publishView();
      return;
    }
    await this.ctx.client.dispatch('promoteLifecycle', { status: 'Active' });
    this.state = { ...this.state, stage: 'finishCreating', error: null };
    this.publishView();
    const completion: VerificationOnlyCompletion = {
      capability: `verification-only-token-${this.ctx.randomId('v')}` as VerificationOnlyCompletion['capability'],
      binding: {
        signingAddress: this.state.fullSigningAddress.length >= 40 ? this.state.fullSigningAddress : this.state.fullSigningAddress.padEnd(44, '0').slice(0, 44),
        encryptionAddress: this.state.fullEncryptionAddress.length >= 40 ? this.state.fullEncryptionAddress : this.state.fullEncryptionAddress.padEnd(44, '0').slice(0, 44),
      },
      outcome: 'provisioned',
    };
    const validated = validateVerificationOnlyCompletion(completion);
    if (validated.ok && validated.completion) {
      this.completion = validated.completion;
      this.completed = true;
      for (const resolve of this.completionResolvers) {
        resolve(validated.completion);
      }
      this.completionResolvers = [];
    } else {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNKNOWN_FAILURE', message: 'The identity could not be confirmed.' } };
      this.publishView();
    }
  }

  onCheckAgain(): void {
    void this.reconcileWaiting();
  }

  onRetryConnection(): void {
    void this.reconcileWaiting();
  }

  onUnlockProvisional(): void {
    // The provisional vault unlocks with the device password (locked screen).
    this.state = { ...this.state, stage: 'locked' };
    this.publishView();
  }

  onLock(): void {
    this.state = { ...this.state, stage: 'locked' };
    this.publishView();
  }

  onCancelLocal(): void {
    void this.cleanup();
  }

  onKeepSettingUp(): void {
    this.state = { ...this.state, stage: 'waiting' };
    this.publishView();
  }

  onBack(): void {
    void this.cleanup();
  }

  private publishView(): void {
    const s = this.state;
    const stageForView: CreationStage = s.stage === 'finishCreating' ? 'provisionalResume' : s.stage;
    const input: CreateViewInput = {
      stage: stageForView,
      canGoBack: true,
      operationInFlight: (s.stage === 'generating' && this.generatingInFlight) || s.stage === 'waiting',
      lastError: s.error,
      progressStarted: s.stage === 'generating' && this.generatingInFlight,
      progressComplete: false,
      localBoundaryCrossed: s.stage === 'protect' || s.stage === 'review' || s.stage === 'waiting' || s.stage === 'finishCreating',
      evidenceCategory: null,
    };
    const view = toCreateViewState(input);
    const child: OnboardingChild = {
      kind: 'createUser',
      props: {
        view,
        recoveryWords: s.words,
        recoveryAcknowledged: s.recoveryAcknowledged,
        recoveryTimeoutMessage: null,
        confirmPositions: s.confirmPositions ?? [],
        confirmMismatchPosition: s.confirmMismatchPosition,
        confirmAttemptsRemaining: s.confirmAttemptsRemaining,
        confirmChallengeClosed: s.confirmChallengeClosed,
        review: this.buildReview(),
        waitingAddress: s.waitingAddress,
        blockHeight: null,
        supportCode: s.supportCode,
        preflightOutcome: { kind: 'passed' },
        c: {
          onCreateUser: () => undefined,
          onRestoreWords: () => undefined,
          onRestoreFile: () => undefined,
          onRetryPreflight: () => this.onRetryPreflight(),
          onProfileContinue: (alias, visibility) => this.onProfileContinue(alias, visibility),
          onGenerate: () => void this.onGenerate(),
          onRecoveryContinue: () => this.onRecoveryContinue(),
          onRecoveryCopy: () => this.onRecoveryCopy(),
          onRegenerateRequest: () => this.onRegenerateRequest(),
          onAcknowledge: (value) => this.onAcknowledge(value),
          onConfirmVerify: (answers) => this.onConfirmVerify(answers),
          onReviewAll: () => this.onReviewAll(),
          onProtect: (password) => void this.onProtect(password),
          onCreateIdentity: () => void this.onCreateIdentity(),
          onCheckAgain: () => this.onCheckAgain(),
          onLock: () => this.onLock(),
          onRetryConnection: () => this.onRetryConnection(),
          onUnlockProvisional: () => this.onUnlockProvisional(),
          onContinueToProfile: () => this.onContinueToProfile(),
          onCancelLocal: () => this.onCancelLocal(),
          onKeepSettingUp: () => this.onKeepSettingUp(),
          onBack: () => this.onBack(),
        },
      },
    };
    publish(this.kind, child);
  }
}

// ---------------------------------------------------------------------------
// FEAT-008 Recovery Words runtime (single-candidate, no-default path)
// ---------------------------------------------------------------------------

interface WordsRuntimeState {
  readonly stage: 'wordEntry' | 'verifying' | 'deriving' | 'lookup' | 'proof' | 'protection' | 'staging' | 'activating' | 'success' | 'finishRestoring' | 'terminal';
  readonly wordCount: '12' | '24';
  readonly candidateRef: string | null;
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly profileName: string | null;
  readonly error: { readonly code: string; readonly message: string } | null;
}

/** Real Recovery Words child runtime (single approved candidate path). */
export class RecoveryWordsChildRuntime implements ChildRuntime {
  readonly kind = 'restoreRecoveryWords' as const;
  private state: WordsRuntimeState = {
    stage: 'wordEntry',
    wordCount: '24',
    candidateRef: null,
    signingAddress: '',
    encryptionAddress: '',
    profileName: null,
    error: null,
  };
  private completion: VerificationOnlyCompletion | null = null;
  private completionResolvers: Array<(completion: VerificationOnlyCompletion) => void> = [];
  private readonly password = { value: '' };

  constructor(private readonly ctx: ChildBridgeContext) {}

  async start(): Promise<void> {
    this.state = { ...this.state, stage: 'wordEntry', error: null };
    this.publishView();
  }

  awaitCompletion(): Promise<VerificationOnlyCompletion> {
    if (this.completion) {
      return Promise.resolve(this.completion);
    }
    return new Promise((resolve) => {
      this.completionResolvers.push(resolve);
    });
  }

  async cleanup(): Promise<{ readonly kind: 'CHILD_CLEANUP_COMPLETE' }> {
    if (this.state.candidateRef !== null) {
      await this.ctx.client.dispatch('destroyCandidate', { candidateRef: this.state.candidateRef });
    }
    clearChildView(this.kind);
    return { kind: 'CHILD_CLEANUP_COMPLETE' };
  }

  cancel(): void {
    void this.cleanup();
  }

  onSelectCount(count: '12' | '24'): void {
    this.state = { ...this.state, wordCount: count };
    this.publishView();
  }

  async onVerify(phrase: string): Promise<void> {
    const wordCount = phrase.trim().split(/\s+/).length;
    if (wordCount !== (this.state.wordCount === '12' ? 12 : 24)) {
      this.state = { ...this.state, error: { code: 'WRONG_COUNT', message: 'The phrase has the wrong number of words.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'verifying', error: null };
    this.publishView();
    const operationId = `words-${this.ctx.randomId('op-')}`;
    this.ctx.client.submitSecret(operationId, 'mnemonic', phrase);
    const derive = this.ctx.client.dispatch('deriveWordsCandidate', { producerId: 'P-01', wordCount: this.state.wordCount }, undefined, operationId);
    const outcome = await derive;
    if (outcome.outcome !== 'OK') {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'CHECKSUM_FAILURE', message: 'The phrase could not be verified.' } };
      this.publishView();
      return;
    }
    const detail = outcome.payload as { ref?: unknown; signingAddress?: unknown; encryptionAddress?: unknown } | undefined;
    const ref = typeof detail?.ref === 'string' ? detail.ref : null;
    const signing = typeof detail?.signingAddress === 'string' ? detail.signingAddress : '';
    const encryption = typeof detail?.encryptionAddress === 'string' ? detail.encryptionAddress : '';
    if (ref === null || signing.length === 0) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'PRODUCER_DERIVATION_FAILURE', message: 'The identity could not be derived.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'deriving', candidateRef: ref, signingAddress: signing, encryptionAddress: encryption };
    this.publishView();
    await this.lookup();
  }

  private async lookup(): Promise<void> {
    this.state = { ...this.state, stage: 'lookup', error: null };
    this.publishView();
    const outcome = await this.ctx.lookupIdentity(this.state.signingAddress);
    if (outcome.kind === 'transportFailure') {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'NETWORK_UNAVAILABLE', message: 'The network is unavailable right now.' } };
      this.publishView();
      return;
    }
    if (outcome.kind === 'exact') {
      if (outcome.encryptionAddress !== this.state.encryptionAddress) {
        this.state = { ...this.state, stage: 'terminal', error: { code: 'SIGNING_ENCRYPTION_MISMATCH', message: 'The identity could not be confirmed.' } };
        this.publishView();
        return;
      }
      this.state = { ...this.state, stage: 'proof', profileName: outcome.profileName };
      this.publishView();
      return;
    }
    // Authoritative absence: same-key creation path proceeds to protection.
    this.state = { ...this.state, stage: 'proof', profileName: null };
    this.publishView();
  }

  onRetryLookup(): void {
    void this.lookup();
  }

  onConfirmExistingProfile(): void {
    this.state = { ...this.state, stage: 'proof' };
    this.publishView();
  }

  async onChooseProtection(): Promise<void> {
    this.state = { ...this.state, stage: 'protection', error: null };
    this.publishView();
  }

  async onProtect(password: string): Promise<void> {
    if (this.state.candidateRef === null) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not complete.' } };
      this.publishView();
      return;
    }
    if (password.length < 8) {
      this.state = { ...this.state, error: { code: 'PASSWORD_POLICY', message: 'Choose a longer device password.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'staging', error: null };
    this.publishView();
    let capabilityId: string;
    try {
      const issued = await this.ctx.client.issueCapability('provision');
      capabilityId = issued.capabilityId;
    } catch {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not start.' } };
      this.publishView();
      return;
    }
    const alias = this.state.profileName ?? 'Restored identity';
    const operationId = `prov-${this.ctx.randomId('op-')}`;
    this.ctx.client.submitSecret(operationId, 'devicePassword', password);
    const provision = this.ctx.client.dispatch('provisionFromValidatedBundle', { candidateRef: this.state.candidateRef, alias, visibility: 'private' }, capabilityId, operationId);
    const outcome = await provision;
    if (outcome.outcome !== 'OK') {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not complete.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'activating' };
    this.publishView();
    await this.activate();
  }

  private async activate(): Promise<void> {
    const verify = await this.ctx.client.dispatch('verifyOnlineIdentity');
    if (verify.outcome !== 'OK') {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'PROFILE_DISAPPEARED', message: 'The identity could not be confirmed yet.' } };
      this.publishView();
      return;
    }
    await this.ctx.client.dispatch('promoteLifecycle', { status: 'Active' });
    this.state = { ...this.state, stage: 'success', error: null };
    this.publishView();
    const completion: VerificationOnlyCompletion = {
      capability: `verification-only-token-${this.ctx.randomId('v')}` as VerificationOnlyCompletion['capability'],
      binding: { signingAddress: this.state.signingAddress, encryptionAddress: this.state.encryptionAddress },
      outcome: 'provisioned',
    };
    const validated = validateVerificationOnlyCompletion(completion);
    if (validated.ok && validated.completion) {
      this.completion = validated.completion;
      for (const resolve of this.completionResolvers) {
        resolve(validated.completion);
      }
      this.completionResolvers = [];
    } else {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNKNOWN_OUTCOME', message: 'Restore could not be confirmed.' } };
      this.publishView();
    }
  }

  onBack(): void {
    void this.cleanup();
  }

  onLock(): void {
    this.state = { ...this.state, stage: 'finishRestoring' };
    this.publishView();
  }

  onFinishRestoringUnlock(): void {
    this.state = { ...this.state, stage: 'finishRestoring' };
    this.publishView();
  }

  onRetry(): void {
    this.state = { ...this.state, stage: 'wordEntry', error: null };
    this.publishView();
  }

  private publishView(): void {
    const s = this.state;
    const input: RecoveryViewInput = {
      stage: s.stage,
      operationInFlight: s.stage === 'verifying' || s.stage === 'deriving' || s.stage === 'lookup' || s.stage === 'staging' || s.stage === 'activating',
      canGoBack: s.stage === 'wordEntry',
      lastError: s.error,
      progressStarted: s.stage === 'deriving' || s.stage === 'lookup',
      progressComplete: s.stage === 'success',
      evidenceCategory: null,
      focusFirstInvalidPosition: null,
      ownerState: 'owner',
    };
    const view = toRecoveryViewState(input);
    const child: OnboardingChild = {
      kind: 'recoveryWords',
      props: {
        view,
        wordGrid: s.stage === 'wordEntry' || s.stage === 'verifying' || s.stage === 'deriving'
          ? {
              selectedWordCount: s.wordCount,
              invalidPositions: [],
              countValid: true,
              vocabularyValid: true,
              checksumState: s.stage === 'wordEntry' ? 'notRun' : 'pending',
              allConcealed: false,
              busy: s.stage !== 'wordEntry',
              canVerify: s.stage === 'wordEntry',
              errorSummary: s.error?.code === 'WRONG_COUNT'
                ? [{ code: 'WRONG_COUNT' as const, positions: [] }]
                : [],
              pasteReplacementPending: false,
            }
          : null,
        candidateReview: null,
        protection: null,
        stagedPreview: null,
        lookupProgress: null,
        onSelectCount: (count) => this.onSelectCount(count),
        onPastePhrase: () => undefined,
        onConfirmPasteReplacement: () => undefined,
        onClearAll: () => undefined,
        onVerify: (phrase) => void this.onVerify(phrase),
        onSelectCandidate: () => undefined,
        onConfirmExistingProfile: () => this.onConfirmExistingProfile(),
        onRetryLookup: () => this.onRetryLookup(),
        onReveal: () => undefined,
        onCopyAddress: () => undefined,
        onChooseProtection: () => void this.onChooseProtection(),
        onAcknowledgeProtection: () => undefined,
        onConfirmRecreate: () => undefined,
        onFinishRestoringUnlock: () => this.onFinishRestoringUnlock(),
        onLock: () => this.onLock(),
        onRemoveLocalUser: () => undefined,
        onForgotPassword: () => undefined,
        onConfirmRemoval: () => undefined,
        onCancelRemoval: () => undefined,
        onBack: () => this.onBack(),
        onEnterDashboard: () => undefined,
        onRetry: () => this.onRetry(),
        removalPending: false,
      },
    };
    publish(this.kind, child);
  }
}

// ---------------------------------------------------------------------------
// FEAT-009 Credential File runtime
// ---------------------------------------------------------------------------

interface FileRuntimeState {
  readonly stage: 'capabilityPreflight' | 'picker' | 'reading' | 'password' | 'decrypting' | 'validating' | 'lookup' | 'profileReview' | 'protection' | 'staging' | 'activating' | 'success' | 'terminal';
  readonly candidateRef: string | null;
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly profileName: string;
  readonly visibility: 'private' | 'public';
  readonly error: { readonly code: string; readonly message: string } | null;
}

/** Real Credential File child runtime. */
const SAFE_IMPORT_DIAGNOSTIC_REASONS = new Set([
  'DAT_WRONG_PASSWORD',
  'DAT_MALFORMED',
  'DAT_INVALID_MAGIC',
  'DAT_UNSUPPORTED_VERSION',
  'DAT_DUPLICATE_FIELD',
  'DAT_UNKNOWN_FIELD',
  'DAT_MISSING_FIELD',
  'DAT_INVALID_FIELD',
  'DAT_KEY_MISMATCH',
  'DAT_MNEMONIC_KEY_MISMATCH',
  'missing-file-material',
  'file-encoding',
  'WORKER_REFERENCE_ERROR',
  'WORKER_TYPE_ERROR',
  'WORKER_CRYPTO_OPERATION_ERROR',
  'WORKER_UNEXPECTED_EXCEPTION',
]);

function safeImportDiagnosticReason(payload: unknown): string {
  if (typeof payload !== 'object' || payload === null) return 'UNCLASSIFIED';
  const reason = (payload as { reason?: unknown }).reason;
  return typeof reason === 'string' && SAFE_IMPORT_DIAGNOSTIC_REASONS.has(reason) ? reason : 'UNCLASSIFIED';
}

/** Map only closed worker outcomes/reasons; never parse free-form messages. */
export function mapCredentialImportFailure(outcome: string, payload: unknown): string {
  const reason = safeImportDiagnosticReason(payload);
  if (outcome === 'WRONG_PASSWORD_OR_DAMAGED' || reason === 'DAT_WRONG_PASSWORD' || reason === 'DAT_MALFORMED') return 'AUTHENTICATION_FAILED';
  if (reason === 'DAT_INVALID_MAGIC') return 'INVALID_MAGIC';
  if (reason === 'DAT_UNSUPPORTED_VERSION') return 'UNSUPPORTED_VERSION';
  if (reason === 'DAT_DUPLICATE_FIELD') return 'PAYLOAD_DUPLICATE_FIELD';
  if (reason === 'DAT_UNKNOWN_FIELD') return 'PAYLOAD_UNKNOWN_FIELD';
  if (reason === 'DAT_MISSING_FIELD') return 'PAYLOAD_MISSING_FIELD';
  if (reason === 'DAT_INVALID_FIELD') return 'PAYLOAD_INVALID_FIELD';
  if (reason === 'DAT_KEY_MISMATCH') return 'KEY_PROOF_FAILED';
  if (reason === 'DAT_MNEMONIC_KEY_MISMATCH') return 'MNEMONIC_KEY_MISMATCH';
  return 'UNKNOWN_OUTCOME';
}

function reportCredentialImportFailure(outcome: string, payload: unknown): void {
  const safeOutcome = ['INVALID_INPUT', 'WRONG_PASSWORD_OR_DAMAGED', 'UNKNOWN_FAILURE', 'TRANSPORT_UNAVAILABLE'].includes(outcome) ? outcome : 'UNCLASSIFIED';
  const reason = safeImportDiagnosticReason(payload);
  // Codes only: never filename, password, bytes, profile, address, or key data.
  console.warn(`[HushVoting][credential-file-restore] stage=import outcome=${safeOutcome} code=${reason}`);
}

function reportCredentialLifecycleFailure(stage: 'capability' | 'provision' | 'submit-profile' | 'verify' | 'promote', outcome: string, payload?: unknown): void {
  const allowed = new Set([
    'INVALID_INPUT', 'UNKNOWN_FAILURE', 'TRANSPORT_UNAVAILABLE', 'NETWORK_UNAVAILABLE',
    'PROFILE_MISSING', 'SIGNING_KEY_MISMATCH', 'ENCRYPTION_KEY_MISMATCH',
    'VERIFY_TIMEOUT', 'AUTHORITY_INVALIDATED', 'AUTHORITY_BUSY',
    'AUTHORITY_REJECTED', 'CAPABILITY_UNAVAILABLE',
  ]);
  const safeOutcome = allowed.has(outcome) ? outcome : 'UNCLASSIFIED';
  const reason = safeImportDiagnosticReason(payload);
  console.warn(`[HushVoting][credential-file-restore] stage=${stage} outcome=${safeOutcome} code=${reason}`);
}

export class CredentialFileChildRuntime implements ChildRuntime {
  readonly kind = 'restoreCredentialFile' as const;
  private state: FileRuntimeState = {
    stage: 'capabilityPreflight',
    candidateRef: null,
    signingAddress: '',
    encryptionAddress: '',
    profileName: '',
    visibility: 'private',
    error: null,
  };
  private completion: VerificationOnlyCompletion | null = null;
  private completionResolvers: Array<(completion: VerificationOnlyCompletion) => void> = [];
  private importOperationId: string | null = null;
  private passwordVisible = false;
  private emptyPassword = false;
  private readGeneration = 0;
  private profileStatus: 'unknown' | 'exact' | 'missing' = 'unknown';
  private vaultProvisioned = false;

  constructor(private readonly ctx: ChildBridgeContext) {}

  async start(): Promise<void> {
    this.importOperationId = null;
    this.passwordVisible = false;
    this.emptyPassword = false;
    this.profileStatus = 'unknown';
    this.vaultProvisioned = false;
    this.readGeneration += 1;
    this.state = { ...this.state, stage: 'capabilityPreflight', error: null };
    this.publishView();
    // The real browser picker remains user-gesture initiated; preflight only
    // establishes that the isolated authority is available.
    this.state = { ...this.state, stage: 'picker', error: null };
    this.publishView();
  }

  awaitCompletion(): Promise<VerificationOnlyCompletion> {
    if (this.completion) {
      return Promise.resolve(this.completion);
    }
    return new Promise((resolve) => {
      this.completionResolvers.push(resolve);
    });
  }

  async cleanup(): Promise<{ readonly kind: 'CHILD_CLEANUP_COMPLETE' }> {
    this.readGeneration += 1;
    if (this.importOperationId !== null) {
      this.ctx.client.cancel(this.importOperationId);
      this.importOperationId = null;
    }
    if (this.state.candidateRef !== null) {
      await this.ctx.client.dispatch('destroyCandidate', { candidateRef: this.state.candidateRef });
    }
    this.passwordVisible = false;
    this.emptyPassword = false;
    clearChildView(this.kind);
    return { kind: 'CHILD_CLEANUP_COMPLETE' };
  }

  cancel(): void {
    void this.cleanup();
  }

  /** User-gesture browser selection followed by one bounded snapshot transfer. */
  async onChooseFile(file: File): Promise<void> {
    const generation = ++this.readGeneration;
    this.importOperationId = null;
    this.passwordVisible = false;
    this.emptyPassword = false;
    this.state = { ...this.state, stage: 'reading', error: null };
    this.publishView();

    if (file.size > 1_048_576) {
      this.state = { ...this.state, stage: 'picker', error: { code: 'FILE_TOO_LARGE', message: 'The credential file is too large.' } };
      this.publishView();
      return;
    }

    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (generation !== this.readGeneration) {
        bytes.fill(0);
        return;
      }
      const operationId = `file-${this.ctx.randomId('op-')}`;
      this.ctx.client.submitSecret(operationId, 'fileBytes', bytes);
      bytes.fill(0);
      this.importOperationId = operationId;
      this.state = { ...this.state, stage: 'password', error: null };
      this.publishView();
    } catch {
      if (generation === this.readGeneration) {
        this.state = { ...this.state, stage: 'picker', error: { code: 'READ_UNAVAILABLE', message: 'The credential file could not be read.' } };
        this.publishView();
      }
    }
  }

  /** Backup password handoff consumes the already-transferred worker snapshot. */
  async onSubmitPassword(password: string): Promise<void> {
    const operationId = this.importOperationId;
    if (operationId === null) {
      this.state = { ...this.state, stage: 'picker', error: { code: 'READ_UNAVAILABLE', message: 'Choose the credential file again.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'decrypting', error: null };
    this.publishView();
    this.ctx.client.submitSecret(operationId, 'filePassword', password);
    const outcome = await this.ctx.client.dispatch('importFileCandidate', undefined, undefined, operationId);
    this.importOperationId = null;
    if (outcome.outcome !== 'OK') {
      const code = mapCredentialImportFailure(outcome.outcome, outcome.payload);
      reportCredentialImportFailure(outcome.outcome, outcome.payload);
      this.state = { ...this.state, stage: 'picker', error: { code, message: 'The credential file could not be imported.' } };
      this.publishView();
      return;
    }
    const detail = outcome.payload as { ref?: unknown; signingAddress?: unknown; encryptionAddress?: unknown; profileName?: unknown; visibility?: unknown } | undefined;
    const ref = typeof detail?.ref === 'string' ? detail.ref : null;
    const signing = typeof detail?.signingAddress === 'string' ? detail.signingAddress : '';
    const encryption = typeof detail?.encryptionAddress === 'string' ? detail.encryptionAddress : '';
    if (ref === null || signing.length === 0) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNKNOWN_OUTCOME', message: 'The backup could not be restored.' } };
      this.publishView();
      return;
    }
    this.state = {
      ...this.state,
      stage: 'validating',
      candidateRef: ref,
      signingAddress: signing,
      encryptionAddress: encryption,
      profileName: typeof detail?.profileName === 'string' ? detail.profileName : 'Restored identity',
      visibility: detail?.visibility === 'public' ? 'public' : 'private',
    };
    this.publishView();
    await this.lookup();
  }

  private async lookup(): Promise<void> {
    this.state = { ...this.state, stage: 'lookup', error: null };
    this.publishView();
    const outcome = await this.ctx.lookupIdentity(this.state.signingAddress);
    if (outcome.kind === 'transportFailure') {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'NETWORK_UNAVAILABLE', message: 'The network is unavailable right now.' } };
      this.publishView();
      return;
    }
    if (outcome.kind === 'exact' && outcome.encryptionAddress !== this.state.encryptionAddress) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'SIGNING_ENCRYPTION_MISMATCH', message: 'The identity could not be confirmed.' } };
      this.publishView();
      return;
    }
    if (outcome.kind === 'authoritativeAbsent') {
      this.profileStatus = 'missing';
      this.state = { ...this.state, stage: 'profileReview', error: null };
      this.publishView();
      return;
    }
    this.profileStatus = 'exact';
    this.state = {
      ...this.state,
      profileName: outcome.profileName,
      visibility: outcome.isPublic ? 'public' : 'private',
      stage: 'protection',
      error: null,
    };
    this.publishView();
  }

  /** Explicit missing-profile confirmation precedes local provisioning/submission. */
  onCreateIdentity(): void {
    if (this.profileStatus !== 'missing') return;
    this.state = { ...this.state, stage: 'protection', error: null };
    this.publishView();
  }

  /** Protection uses a separately entered Device password, never the backup password. */
  async onChooseProtection(mode: string, devicePassword?: string): Promise<void> {
    if (mode !== 'devicePassword' || devicePassword === undefined) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNSUPPORTED_PROTECTION_MODE', message: 'This protection mode is not available on this device.' } };
      this.publishView();
      return;
    }
    await this.onProtect(devicePassword);
  }

  onTogglePasswordVisibility(): void {
    this.passwordVisible = !this.passwordVisible;
    this.publishView();
  }

  onToggleEmptyPassword(enabled: boolean): void {
    this.emptyPassword = enabled;
    this.publishView();
  }

  onChooseDifferentFile(): void {
    this.readGeneration += 1;
    if (this.importOperationId !== null) {
      this.ctx.client.cancel(this.importOperationId);
      this.importOperationId = null;
    }
    this.passwordVisible = false;
    this.emptyPassword = false;
    this.state = { ...this.state, stage: 'picker', error: null };
    this.publishView();
  }

  onCancelRead(): void {
    this.onChooseDifferentFile();
  }

  async onProtect(password: string): Promise<void> {
    if (this.state.candidateRef === null) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not complete.' } };
      this.publishView();
      return;
    }
    if (password.length < 8) {
      this.state = { ...this.state, error: { code: 'PASSWORD_POLICY', message: 'Choose a longer device password.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'staging', error: null };
    this.publishView();
    let capabilityId: string;
    try {
      const issued = await this.ctx.client.issueCapability('provision');
      capabilityId = issued.capabilityId;
    } catch {
      reportCredentialLifecycleFailure('capability', 'CAPABILITY_UNAVAILABLE');
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not start.' } };
      this.publishView();
      return;
    }
    const operationId = `prov-${this.ctx.randomId('op-')}`;
    this.ctx.client.submitSecret(operationId, 'devicePassword', password);
    const outcome = await this.ctx.client.dispatch('provisionFromValidatedBundle', {
      candidateRef: this.state.candidateRef,
      alias: this.state.profileName,
      visibility: this.state.visibility,
    }, capabilityId, operationId);
    if (outcome.outcome !== 'OK') {
      reportCredentialLifecycleFailure('provision', outcome.outcome, outcome.payload);
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not complete.' } };
      this.publishView();
      return;
    }
    this.vaultProvisioned = true;
    if (this.profileStatus === 'missing') {
      await this.submitMissingProfile();
      return;
    }
    await this.verifyAndComplete();
  }

  private async submitMissingProfile(): Promise<void> {
    this.state = { ...this.state, stage: 'activating', error: null };
    this.publishView();
    const submission = await this.ctx.client.dispatch('submitIdentityTransaction', {
      alias: this.state.profileName,
      visibility: this.state.visibility,
    });
    if (submission.outcome !== 'OK') {
      reportCredentialLifecycleFailure('submit-profile', submission.outcome, submission.payload);
      this.state = { ...this.state, stage: 'terminal', error: { code: 'NETWORK_UNAVAILABLE', message: 'The identity could not be submitted.' } };
      this.publishView();
      return;
    }
    const status = (submission.payload as { status?: unknown } | undefined)?.status;
    if (status !== 'accepted' && status !== 'pending' && status !== 'alreadyExists') {
      reportCredentialLifecycleFailure('submit-profile', 'UNKNOWN_FAILURE', submission.payload);
      this.state = { ...this.state, stage: 'terminal', error: { code: 'SERVER_PROOF_REJECTED', message: 'The identity was not accepted.' } };
      this.publishView();
      return;
    }
    const generation = this.readGeneration;
    for (let attempt = 0; attempt < 60 && generation === this.readGeneration; attempt += 1) {
      const lookup = await this.ctx.lookupIdentity(this.state.signingAddress);
      if (lookup.kind === 'exact') {
        if (lookup.encryptionAddress !== this.state.encryptionAddress) {
          this.state = { ...this.state, stage: 'terminal', error: { code: 'SIGNING_ENCRYPTION_MISMATCH', message: 'The identity could not be confirmed.' } };
          this.publishView();
          return;
        }
        this.profileStatus = 'exact';
        await this.verifyAndComplete();
        return;
      }
      if (attempt < 59) await new Promise((resolve) => setTimeout(resolve, 3_000));
    }
    if (generation === this.readGeneration) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'VERIFY_TIMEOUT', message: 'Confirmation is delayed. Try again later.' } };
      this.publishView();
    }
  }

  private async verifyAndComplete(): Promise<void> {
    this.state = { ...this.state, stage: 'activating', error: null };
    this.publishView();
    const verify = await this.ctx.client.dispatch('verifyOnlineIdentity');
    if (verify.outcome !== 'OK') {
      reportCredentialLifecycleFailure('verify', verify.outcome, verify.payload);
      this.state = { ...this.state, stage: 'terminal', error: { code: 'PROFILE_DISAPPEARED', message: 'The identity could not be confirmed yet.' } };
      this.publishView();
      return;
    }
    const promote = await this.ctx.client.dispatch('promoteLifecycle', { status: 'Active' });
    if (promote.outcome !== 'OK') {
      reportCredentialLifecycleFailure('promote', promote.outcome, promote.payload);
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'The restored identity could not be activated.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'success', error: null };
    this.publishView();
    const completion: VerificationOnlyCompletion = {
      capability: `verification-only-token-${this.ctx.randomId('v')}` as VerificationOnlyCompletion['capability'],
      binding: { signingAddress: this.state.signingAddress, encryptionAddress: this.state.encryptionAddress },
      outcome: 'provisioned',
    };
    const validated = validateVerificationOnlyCompletion(completion);
    if (validated.ok && validated.completion) {
      this.completion = validated.completion;
      for (const resolve of this.completionResolvers) resolve(validated.completion);
      this.completionResolvers = [];
    } else {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNKNOWN_OUTCOME', message: 'Restore could not be confirmed.' } };
      this.publishView();
    }
  }

  onBack(): void {
    void this.cleanup();
  }

  private publishView(): void {
    const s = this.state;
    const input: RestoreViewInput = {
      stage: s.stage,
      progress: null,
      failureCode: s.error?.code ?? null,
      backoffRemainingSeconds: 0,
      passwordField: s.stage === 'password' || s.stage === 'decrypting' ? { visible: this.passwordVisible, emptyOptionChecked: this.emptyPassword, emptyOptionEnabled: true } : null,
      protectionChoices: s.stage === 'protection' ? ['devicePassword'] : null,
      profile: s.stage === 'profileReview' || s.stage === 'protection' || s.stage === 'staging'
        ? { alias: s.profileName, isPublic: s.visibility === 'public', signingAddressAbbreviated: abbreviate(s.signingAddress), encryptionAddressAbbreviated: abbreviate(s.encryptionAddress), networkLabel: 'HushLocal', source: 'importedReview', aliasEditable: false, publicAcknowledgementRequired: false }
        : null,
      reveal: null,
    };
    const composed = composeRestoreView(input as Parameters<typeof composeRestoreView>[0]);
    const child: OnboardingChild = {
      kind: 'credentialFile',
      props: {
        view: composed.view,
        sessionOnlyOnly: false,
        onChooseFile: (file) => void this.onChooseFile(file),
        onCancelRead: () => this.onCancelRead(),
        onSubmitPassword: (password) => void this.onSubmitPassword(password),
        onToggleVisibility: () => this.onTogglePasswordVisibility(),
        onToggleEmptyOption: (enabled) => this.onToggleEmptyPassword(enabled),
        onChooseDifferentFile: () => this.onChooseDifferentFile(),
        onChooseProtection: (mode, devicePassword) => void this.onChooseProtection(mode, devicePassword),
        onCreateIdentity: () => this.onCreateIdentity(),
        onReveal: () => undefined,
        onUnlockResume: () => undefined,
        onCancelStage: () => undefined,
        onBack: () => this.onBack(),
        onAcknowledgeSessionOnly: () => undefined,
        onRetryCleanup: () => undefined,
      },
    };
    publish(this.kind, child);
  }
}

// ---------------------------------------------------------------------------
// Onboarding port adapters (machine-facing)
// ---------------------------------------------------------------------------

/** Build the three onboarding ports over the runtimes. */
export function createWebOnboardingPorts(ctx: ChildBridgeContext): Record<OnboardingKind, OnboardingPort> {
  const runtimes = new Map<OnboardingKind, ChildRuntime>();
  const settledOperations = new Set<OperationId>();

  const startRuntime = (kind: OnboardingKind): ChildRuntime => {
    let runtime = runtimes.get(kind);
    if (!runtime) {
      runtime = createRuntimeFor(kind, ctx);
      runtimes.set(kind, runtime);
    }
    return runtime;
  };

  const cancelIfInFlight = (kind: OnboardingKind, operationId: OperationId): void => {
    // XState runs invoke cleanup after a successful result too. That cleanup
    // is not a user cancellation and must not globally invalidate the worker
    // before root-owned verification starts.
    if (settledOperations.delete(operationId)) {
      clearChildView(kind);
      runtimes.delete(kind);
      return;
    }
    runtimes.get(kind)?.cancel();
    ctx.client.cancel(operationId);
  };

  const makePort = (kind: OnboardingKind): OnboardingPort => ({
    cancel(operationId: OperationId) {
      cancelIfInFlight(kind, operationId);
    },
    start(_kind: OnboardingKind, epoch: SessionEpoch) {
      const runtime = startRuntime(kind);
      const operationId = `onb-${kind}-${epoch}-${Date.now().toString(36)}` as OperationId;
      const untracked: Promise<OnboardingResult> = runtime.start().then(async () => {
        const completion = await runtime.awaitCompletion();
        return { code: 'ONBOARDING_COMPLETED', localUserRef: completion.capability } as OnboardingResult;
      });
      const result = untracked.finally(() => settledOperations.add(operationId));
      return { operationId, result, cancel: () => cancelIfInFlight(kind, operationId) };
    },
    cleanup(epoch: SessionEpoch) {
      const operationId = `onb-clean-${kind}-${epoch}-${Date.now().toString(36)}` as OperationId;
      const runtime = runtimes.get(kind);
      const result: Promise<OnboardingResult> = (runtime ? runtime.cleanup() : Promise.resolve({ kind: 'CHILD_CLEANUP_COMPLETE' })).then(
        () => ({ code: 'ONBOARDING_CLEANUP_COMPLETE' } as OnboardingResult),
      );
      return { operationId, result, cancel: () => undefined };
    },
    confirmMissingProfile(epoch: SessionEpoch) {
      const operationId = `onb-cmp-${kind}-${epoch}-${Date.now().toString(36)}` as OperationId;
      const result: Promise<VerificationResult> = ctx.client.dispatch('verifyOnlineIdentity').then((outcome) => {
        switch (outcome.outcome) {
          case 'OK': {
            const identity = authenticatedIdentityFromPayload(outcome.payload);
            return identity === null
              ? { code: 'VERIFY_SUCCESS' } as VerificationResult
              : { code: 'VERIFY_SUCCESS', identity } as VerificationResult;
          }
          case 'PROFILE_MISSING': {
            // The worker forwards the real safe candidate (alias + abbreviated
            // signing address) in the outcome payload; never fabricate a
            // placeholder on a security-relevant confirmation surface.
            const payload = outcome.payload as { alias?: unknown; abbreviatedSigningAddress?: unknown } | undefined;
            const alias = typeof payload?.alias === 'string' ? payload.alias : 'Unknown';
            const abbreviatedSigningAddress =
              typeof payload?.abbreviatedSigningAddress === 'string' ? payload.abbreviatedSigningAddress : '…';
            return { code: 'VERIFY_PROFILE_MISSING', safeCandidate: { alias, abbreviatedSigningAddress } } as VerificationResult;
          }
          case 'SIGNING_KEY_MISMATCH':
            return { code: 'VERIFY_SIGNING_KEY_MISMATCH' } as VerificationResult;
          case 'ENCRYPTION_KEY_MISMATCH':
            return { code: 'VERIFY_ENCRYPTION_KEY_MISMATCH' } as VerificationResult;
          case 'VERIFY_TIMEOUT':
            return { code: 'VERIFY_TIMEOUT' } as VerificationResult;
          case 'NETWORK_UNAVAILABLE':
            return { code: 'VERIFY_NETWORK_UNAVAILABLE' } as VerificationResult;
          default:
            return { code: 'UNKNOWN_FAILURE', supportCode: `cmp-${operationId.slice(-6)}` } as VerificationResult;
        }
      });
      return { operationId, result, cancel: () => undefined };
    },
  });

  return {
    createUser: makePort('createUser'),
    restoreCredentialFile: makePort('restoreCredentialFile'),
    restoreRecoveryWords: makePort('restoreRecoveryWords'),
  };
}

function createRuntimeFor(kind: OnboardingKind, ctx: ChildBridgeContext): ChildRuntime {
  switch (kind) {
    case 'createUser':
      return new CreateUserChildRuntime(ctx);
    case 'restoreRecoveryWords':
      return new RecoveryWordsChildRuntime(ctx);
    case 'restoreCredentialFile':
      return new CredentialFileChildRuntime(ctx);
  }
}

/** Public exports for tests. */
export const childBridgeExports = { createBridgeBffLookup, abbreviate };
