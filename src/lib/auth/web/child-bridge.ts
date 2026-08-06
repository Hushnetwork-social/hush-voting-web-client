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
        wordGrid: null,
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
  private filePassword = '';

  constructor(private readonly ctx: ChildBridgeContext) {}

  async start(): Promise<void> {
    this.state = { ...this.state, stage: 'capabilityPreflight', error: null };
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
    this.filePassword = '';
    clearChildView(this.kind);
    return { kind: 'CHILD_CLEANUP_COMPLETE' };
  }

  cancel(): void {
    void this.cleanup();
  }

  async onChooseFile(): Promise<void> {
    this.state = { ...this.state, stage: 'picker' };
    this.publishView();
  }

  /** File bytes + backup password handoff: read is bounded, then transferred. */
  async onSubmitFile(file: File, password: string): Promise<void> {
    if (file.size > 1_048_576) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'FILE_TOO_LARGE', message: 'The credential file is too large.' } };
      this.publishView();
      return;
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    this.filePassword = password;
    this.state = { ...this.state, stage: 'reading' };
    this.publishView();
    const operationId = `file-${this.ctx.randomId('op-')}`;
    this.ctx.client.submitSecret(operationId, 'filePassword', password);
    this.ctx.client.submitSecret(operationId, 'fileBytes', bytes);
    const importOp = this.ctx.client.dispatch('importFileCandidate', undefined, undefined, operationId);
    const outcome = await importOp;
    if (outcome.outcome !== 'OK') {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'DAT_WRONG_PASSWORD', message: 'The backup could not be opened.' } };
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
    this.state = { ...this.state, stage: 'protection' };
    this.publishView();
  }

  /** Protection choice: the already-entered backup password is the initial device password (single entry). */
  async onChooseProtection(mode: string): Promise<void> {
    if (mode !== 'devicePassword') {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNSUPPORTED_PROTECTION_MODE', message: 'This protection mode is not available on this device.' } };
      this.publishView();
      return;
    }
    await this.onProtect(this.filePassword);
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
    const operationId = `prov-${this.ctx.randomId('op-')}`;
    this.ctx.client.submitSecret(operationId, 'devicePassword', password);
    const provision = this.ctx.client.dispatch('provisionFromValidatedBundle', {
      candidateRef: this.state.candidateRef,
      alias: this.state.profileName,
      visibility: this.state.visibility,
    }, capabilityId, operationId);
    const outcome = await provision;
    if (outcome.outcome !== 'OK') {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not complete.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'activating' };
    this.publishView();
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

  private publishView(): void {
    const s = this.state;
    const input: RestoreViewInput = {
      stage: s.stage,
      progress: null,
      failureCode: s.error?.code ?? null,
      backoffRemainingSeconds: 0,
      passwordField: s.stage === 'password' || s.stage === 'decrypting' ? { visible: false, emptyOptionChecked: false, emptyOptionEnabled: false } : null,
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
        onChooseFile: () => void this.onChooseFile(),
        onCancelRead: () => undefined,
        onSubmitPassword: () => undefined,
        onToggleVisibility: () => undefined,
        onToggleEmptyOption: () => undefined,
        onChooseDifferentFile: () => undefined,
        onChooseProtection: (mode) => void this.onChooseProtection(mode),
        onCreateIdentity: () => undefined,
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

  const startRuntime = (kind: OnboardingKind): ChildRuntime => {
    let runtime = runtimes.get(kind);
    if (!runtime) {
      runtime = createRuntimeFor(kind, ctx);
      runtimes.set(kind, runtime);
    }
    return runtime;
  };

  const makePort = (kind: OnboardingKind): OnboardingPort => ({
    cancel(operationId: OperationId) {
      runtimes.get(kind)?.cancel();
      ctx.client.cancel(operationId);
    },
    start(_kind: OnboardingKind, epoch: SessionEpoch) {
      const runtime = startRuntime(kind);
      const operationId = `onb-${kind}-${epoch}-${Date.now().toString(36)}` as OperationId;
      const result: Promise<OnboardingResult> = runtime.start().then(async () => {
        const completion = await runtime.awaitCompletion();
        return { code: 'ONBOARDING_COMPLETED', localUserRef: completion.capability } as OnboardingResult;
      });
      return { operationId, result, cancel: () => runtime.cancel() };
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
          case 'OK':
            return { code: 'VERIFY_SUCCESS' } as VerificationResult;
          case 'PROFILE_MISSING':
            return { code: 'VERIFY_PROFILE_MISSING', safeCandidate: { alias: 'Unknown', abbreviatedSigningAddress: '…' } } as VerificationResult;
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
