import { hasBoundedHistoricalName, readIdentityResponse } from '../../identity-compatibility/historical-profile';
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

import type { BrowserVaultClient, ClientOperationResult } from '../../browser-vault/production/client';
import { validateAlias } from '../../identity-creation/profile';
import { ABNORMAL_DELAY_MS, evaluateDelay } from '../../identity-creation/reconciliation';
import { selectChallengePositions, evaluateRecoveryAttempt, type CandidateRef, type PreflightOutcome } from '../../identity-creation/authority';
import { toViewState as toCreateViewState, type ViewInput as CreateViewInput } from '../../identity-creation/presentation';
import type { CreationStage } from '../../identity-creation/contracts';
import type { CreationReviewProjection } from '../../identity-creation/contracts';
import { abbreviateAddress, type CandidateReviewProjection } from '../../recovery-words/contracts/projection';
import type { RecoveryCandidateDetail } from '../../browser-vault/production/sealed-vault';
import { toRecoveryViewState, type RecoveryViewInput } from '../../recovery-words/presentation/view';
import { composeRestoreView } from '../../credential-file-restore/presentation/onboarding';
import { evaluateEnvelopeGate } from '../../credential-file-restore/authority/snapshot';
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
import { createRecoveryWordDisplay } from './recovery-word-display';
import { CredentialSourceError, readCredentialSnapshot } from './credential-source';

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
      const payload = (await readIdentityResponse(response, controller.signal)) as {
        reply?: { successfull?: unknown; profileName?: unknown; publicSigningAddress?: unknown; publicEncryptAddress?: unknown; isPublic?: unknown } | null;
      };
      const reply = payload.reply;
      if (reply?.successfull === false) return { kind: 'authoritativeAbsent' };
      if (reply?.successfull !== true) return { kind: 'transportFailure' };
      const profileName = reply.profileName;
      const signing = reply.publicSigningAddress;
      const encryption = reply.publicEncryptAddress;
      if (!hasBoundedHistoricalName(profileName) || typeof signing !== 'string' || signing.length === 0 || typeof encryption !== 'string' || encryption.length === 0 || typeof reply.isPublic !== 'boolean') {
        return { kind: 'transportFailure' };
      }
      return { kind: 'exact', profileName, signingAddress: signing, encryptionAddress: encryption, isPublic: reply.isPublic };
    } catch {
      return { kind: 'transportFailure' };
    } finally {
      clearTimeout(timer);
    }
  };
}

/** One child-flow runtime instance (created per onboarding start). */
export type ChildCleanupResult =
  | { readonly kind: 'CHILD_CLEANUP_COMPLETE'; readonly next?: 'credentialFilePicker' }
  | { readonly kind: 'CHILD_CLEANUP_FAILED' };

export interface ChildRuntime {
  readonly kind: OnboardingKind;
  start(): Promise<void>;
  /** Resolves when the child flow completes (verification-only at most). */
  awaitCompletion(): Promise<VerificationOnlyCompletion>;
  /** Child cleanup before Back (must acknowledge before first-run). */
  cleanup(): Promise<ChildCleanupResult>;
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
  readonly stage: 'preflight' | 'profile' | 'generating' | 'recovery' | 'confirmRecovery' | 'protect' | 'review' | 'waiting' | 'delay' | 'connection' | 'finishCreating' | 'correcting' | 'cancelling' | 'locked' | 'terminal';
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
  private readonly recoveryDisplay = createRecoveryWordDisplay();
  readonly kind = 'createUser' as const;
  private preflightOutcome: PreflightOutcome = { kind: 'checking' };
  private preflightCheck: Promise<void> | null = null;
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
  private reconciliationInFlight = false;
  private promotionReady = false;
  private promotionInFlight = false;
  private initialSubmissionInFlight = false;
  private registrationRequested = false;
  private submissionAttempted = false;
  private confirmationPoll: ReturnType<typeof setInterval> | null = null;
  private confirmationDeadlineTimer: ReturnType<typeof setTimeout> | null = null;
  private acceptedSinceMs: number | null = null;
  private recoveryConfirmed = false;
  private revealTimer: ReturnType<typeof setTimeout> | null = null;
  private disposed = false;
  private vaultProvisioned = false;
  private globalLock: Promise<ClientOperationResult> | null = null;
  private provisioning: Promise<ClientOperationResult> | null = null;
  private cleanupPromise: Promise<ChildCleanupResult> | null = null;
  private readonly concealOnVisibility = () => {
    if (document.visibilityState !== 'visible') this.concealRecovery();
  };
  private readonly concealOnPageHide = () => this.concealRecovery();

  constructor(private readonly ctx: ChildBridgeContext) {}

  async start(): Promise<void> {
    if (this.disposed) return;
    if (this.preflightCheck) return this.preflightCheck;
    this.state = { ...this.state, stage: 'preflight', error: null };
    this.preflightOutcome = { kind: 'checking' };
    this.publishView();
    // Recheck current custody through the real authority. The root's earlier
    // empty result cannot authorize creation after storage/ownership changes.
    // This check does not replace the adapter's full primitive preflight.
    this.preflightCheck = (async () => {
      try {
        const outcome = await this.ctx.client.dispatch('inspectStartup');
        if (this.disposed) return;
        const surface = (outcome.payload as { surface?: unknown } | undefined)?.surface;
        if (outcome.outcome === 'OK' && surface === 'verifiedAbsent') {
          this.preflightOutcome = { kind: 'passed' };
          this.state = { ...this.state, stage: 'profile', error: null };
        } else if (outcome.outcome === 'TRANSPORT_UNAVAILABLE' || outcome.outcome === 'AUTHORITY_INVALIDATED'
          || outcome.outcome === 'AUTHORITY_BUSY' || outcome.outcome === 'UNKNOWN_FAILURE') {
          this.preflightOutcome = { kind: 'temporaryUnavailable' };
        } else {
          this.preflightOutcome = { kind: 'failClosed' };
        }
      } catch {
        if (this.disposed) return;
        this.preflightOutcome = { kind: 'temporaryUnavailable' };
      }
      if (!this.disposed) {
        this.publishView();
      }
    })().finally(() => { this.preflightCheck = null; });
    return this.preflightCheck;
  }

  awaitCompletion(): Promise<VerificationOnlyCompletion> {
    if (this.completion) {
      return Promise.resolve(this.completion);
    }
    return new Promise((resolve) => {
      this.completionResolvers.push(resolve);
    });
  }

  cleanup(): Promise<ChildCleanupResult> {
    if (this.cleanupPromise) return this.cleanupPromise;
    this.disposed = true;
    this.recoveryDisplay.dispose();
    this.stopConfirmationPolling();
    this.clearRevealWindow();
    this.state = { ...this.state, words: null, revealedWords: false };
    clearChildView(this.kind);
    return this.cleanupPromise = (async () => {
      if (this.provisioning !== null) {
        const staged = await this.provisioning;
        if (staged.outcome === 'OK') this.vaultProvisioned = true;
      }
      const discarded = this.vaultProvisioned ? await this.requestGlobalLock()
        : this.state.candidateRef !== null ? await this.ctx.client.dispatch('destroyCandidate', { candidateRef: this.state.candidateRef }) : null;
      if (discarded !== null && discarded.outcome !== 'OK') {
        this.globalLock = null;
        this.cleanupPromise = null;
        return { kind: 'CHILD_CLEANUP_FAILED' as const };
      }
      this.state = { ...this.state, candidateRef: null };
      return { kind: 'CHILD_CLEANUP_COMPLETE' as const };
    })().catch(() => {
      this.globalLock = null;
      this.cleanupPromise = null;
      return { kind: 'CHILD_CLEANUP_FAILED' as const };
    });
  }

  private clearRevealWindow(): void {
    if (this.revealTimer !== null) clearTimeout(this.revealTimer);
    this.revealTimer = null;
    if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', this.concealOnVisibility);
    if (typeof window !== 'undefined') window.removeEventListener('pagehide', this.concealOnPageHide);
  }

  private beginRevealWindow(expiresAtMs?: unknown): void {
    this.clearRevealWindow();
    const remaining = typeof expiresAtMs === 'number' && Number.isFinite(expiresAtMs)
      ? Math.max(0, Math.min(60_000, expiresAtMs - Date.now())) : 60_000;
    if (remaining === 0) { this.concealRecovery(); return; }
    this.revealTimer = setTimeout(() => this.concealRecovery(), remaining);
    if (typeof document !== 'undefined') document.addEventListener('visibilitychange', this.concealOnVisibility);
    if (typeof window !== 'undefined') window.addEventListener('pagehide', this.concealOnPageHide);
  }

  private concealRecovery(): void {
    this.clearRevealWindow();
    if (this.disposed || !this.state.revealedWords) return;
    this.state = { ...this.state, revealedWords: false };
    this.publishView();
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
    if (this.disposed || this.generatingInFlight) return;
    this.clearRevealWindow();
    this.recoveryConfirmed = false;
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
    if (this.disposed) {
      if (ref !== null) await this.ctx.client.dispatch('destroyCandidate', { candidateRef: ref });
      return;
    }
    if (ref === null) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNKNOWN_FAILURE', message: 'Identity generation could not complete.' } };
      this.publishView();
      return;
    }
    this.generatingInFlight = false;
    this.state = { ...this.state, candidateRef: ref as CandidateRef };
    const reveal = await this.ctx.client.dispatch('revealCandidateWords', { candidateRef: ref });
    if (this.disposed) return;
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
      recoveryAcknowledged: false,
    };
    this.beginRevealWindow((reveal.payload as { expiresAtMs?: unknown } | undefined)?.expiresAtMs);
    this.publishView();
  }

  onRegenerateRequest(confirmed?: true): void {
    if (confirmed !== true || this.disposed || this.state.stage !== 'recovery') return;
    void this.regenerate();
  }

  private async regenerate(): Promise<void> {
    this.clearRevealWindow();
    this.recoveryConfirmed = false;
    this.state = { ...this.state, revealedWords: false, words: null, recoveryAcknowledged: false };
    this.publishView();
    if (this.state.candidateRef !== null) {
      const destroyed = await this.ctx.client.dispatch('destroyCandidate', { candidateRef: this.state.candidateRef });
      if (destroyed.outcome !== 'OK') {
        this.state = { ...this.state, stage: 'terminal', error: { code: 'UNKNOWN_FAILURE', message: 'The previous candidate could not be discarded safely.' } };
        this.publishView();
        return;
      }
    }
    await this.onGenerate();
  }

  onRecoveryCopy(): void {
    // Copy does not extend the reveal deadline or reopen a concealed phrase.
  }

  onAcknowledge(value: boolean): void {
    this.state = { ...this.state, recoveryAcknowledged: value };
    this.publishView();
  }

  onRecoveryContinue(): void {
    if (this.state.stage !== 'recovery' || !this.state.revealedWords || !this.state.recoveryAcknowledged || this.state.words?.length !== 24) return;
    this.clearRevealWindow();
    this.state = { ...this.state, stage: 'confirmRecovery', revealedWords: false, error: null };
    this.publishView();
  }

  onConfirmVerify(answers: ReadonlyMap<number, string>): void {
    if (this.state.stage !== 'confirmRecovery' || this.state.confirmChallengeClosed) return;
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
      this.recoveryConfirmed = true;
      this.state = { ...this.state, stage: 'protect', error: null };
      this.publishView();
      return;
    }
    const remaining = this.state.confirmAttemptsRemaining - 1;
    if (remaining <= 0) {
      this.state = { ...this.state, confirmAttemptsRemaining: 0, confirmChallengeClosed: true, stage: 'confirmRecovery', error: { code: 'RECOVERY_ATTEMPTS_EXHAUSTED', message: 'Too many attempts. Review your words and try again.' } };
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
    void this.reviewRecoveryWords();
  }

  private async reviewRecoveryWords(): Promise<void> {
    const stage = this.state.stage;
    if ((stage !== 'confirmRecovery' && !(stage === 'recovery' && !this.state.revealedWords)) || this.state.candidateRef === null) return;
    const ref = this.state.candidateRef;
    const reveal = await this.ctx.client.dispatch('revealCandidateWords', { candidateRef: ref });
    if (this.disposed || this.state.stage !== stage || this.state.candidateRef !== ref) return;
    const words = reveal.outcome === 'OK' && typeof reveal.payload === 'object' && reveal.payload !== null
      ? (reveal.payload as { words?: unknown }).words : null;
    if (!Array.isArray(words) || words.length !== 24 || !words.every(w => typeof w === 'string')) return;
    this.recoveryConfirmed = false;
    this.state = { ...this.state, stage: 'recovery', words, revealedWords: true, recoveryAcknowledged: false,
      confirmPositions: selectChallengePositions(24), confirmAttemptsRemaining: 3, confirmChallengeClosed: false,
      confirmMismatchPosition: null, error: null };
    this.beginRevealWindow((reveal.payload as { expiresAtMs?: unknown } | undefined)?.expiresAtMs);
    this.publishView();
  }

  async onProtect(password: string): Promise<void> {
    if (this.state.stage !== 'protect' || !this.recoveryConfirmed) return;
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
      if (this.disposed) return;
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
    this.provisioning = provision;
    const outcome = await provision;
    this.provisioning = null;
    if (outcome.outcome !== 'OK') {
      this.state = { ...this.state, error: { code: 'PROVISION_FAILED', message: 'Provisioning could not complete.' } };
      this.publishView();
      return;
    }
    this.vaultProvisioned = true;
    if (this.disposed) return;
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
    if (this.creationAuthorityEnded() || this.completed || this.state.stage !== 'review' || !this.vaultProvisioned || !this.recoveryConfirmed) return;
    this.registrationRequested = true;
    await this.submitAfterInitialLookup();
  }

  private async submitAfterInitialLookup(): Promise<void> {
    if (this.creationAuthorityEnded() || this.completed || !this.registrationRequested || this.submissionAttempted || this.initialSubmissionInFlight) return;
    if (this.state.alias.length === 0 || this.state.fullSigningAddress.length === 0 || this.state.fullEncryptionAddress.length === 0) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNKNOWN_FAILURE', message: 'The identity cannot be created.' } };
      this.publishView();
      return;
    }
    this.initialSubmissionInFlight = true;
    this.publishView();
    try {
      if (!navigator.onLine || document.visibilityState !== 'visible') {
        this.state = { ...this.state, stage: 'connection', error: { code: 'NETWORK_UNAVAILABLE', message: 'Waiting for connection.' } };
        return;
      }
      const lookup = await this.ctx.lookupIdentity(this.state.fullSigningAddress);
      if (this.creationAuthorityEnded()) return;
      if (!navigator.onLine || document.visibilityState !== 'visible') {
        this.state = { ...this.state, stage: 'connection', error: { code: 'NETWORK_UNAVAILABLE', message: 'Waiting for connection.' } };
        return;
      }
      if (lookup.kind === 'transportFailure') {
        this.state = { ...this.state, stage: 'connection', error: { code: 'NETWORK_UNAVAILABLE', message: 'Waiting for connection.' } };
        return;
      }
      if (lookup.kind === 'exact') {
        if (lookup.signingAddress !== this.state.fullSigningAddress || lookup.encryptionAddress !== this.state.fullEncryptionAddress) {
          this.state = { ...this.state, stage: 'terminal', error: { code: 'KEY_MISMATCH', message: 'The identity could not be confirmed.' } };
          return;
        }
        await this.completeWithVerification();
        return;
      }
      // Only authoritative absence can admit the first submission. Once it
      // starts, connection recovery and Check again remain lookup-only.
      if (lookup.kind !== 'authoritativeAbsent') {
        this.state = { ...this.state, stage: 'terminal', error: { code: 'UNKNOWN_FAILURE', message: 'The identity could not be confirmed.' } };
        return;
      }
      this.submissionAttempted = true;
      const outcome = await this.ctx.client.dispatch('submitIdentityTransaction', { alias: this.state.alias, visibility: this.state.visibility });
      if (this.creationAuthorityEnded()) return;
      if (outcome.outcome !== 'OK') {
        this.state = { ...this.state, stage: 'connection', error: { code: 'TRANSPORT_AMBIGUOUS', message: 'Waiting for connection.' } };
        return;
      }
      const status = (outcome.payload as { status?: unknown } | undefined)?.status;
      if (status === 'transportFailure') {
        this.state = { ...this.state, stage: 'connection', error: { code: 'TRANSPORT_AMBIGUOUS', message: 'Waiting for connection.' } };
        return;
      }
      if (status === 'accepted' || status === 'pending' || status === 'alreadyExists') {
        this.state = { ...this.state, stage: 'waiting', error: null };
        if (status === 'accepted' || status === 'pending') this.startConfirmationDeadline();
        this.initialSubmissionInFlight = false;
        this.publishView();
        this.ensureConfirmationPolling();
        await this.reconcileWaiting();
        return;
      }
      this.state = { ...this.state, stage: 'terminal', supportCode: 'TERMINAL_REJECTION', error: { code: 'TERMINAL_REJECTION', message: 'The identity was not accepted.' } };
    } catch {
      if (!this.creationAuthorityEnded()) this.state = { ...this.state, stage: 'connection', error: { code: 'NETWORK_UNAVAILABLE', message: 'Waiting for connection.' } };
    } finally {
      this.initialSubmissionInFlight = false;
      this.publishView();
    }
  }

  /** Lookup-first reconciliation: exact profile → verify → promote → complete. */
  private async reconcileWaiting(): Promise<void> {
    if (this.disposed || this.completed || this.promotionReady || this.initialSubmissionInFlight || this.reconciliationInFlight || this.state.fullSigningAddress.length === 0
      || !['waiting', 'connection', 'delay'].includes(this.state.stage)
      || document.visibilityState !== 'visible' || !navigator.onLine) return;
    this.reconciliationInFlight = true;
    try {
      const lookup = await this.ctx.lookupIdentity(this.state.fullSigningAddress);
      if (this.disposed || this.state.stage === 'locked') return;
      if (lookup.kind === 'exact') {
        if (lookup.signingAddress !== this.state.fullSigningAddress || lookup.encryptionAddress !== this.state.fullEncryptionAddress) {
          this.stopConfirmationPolling();
          this.state = { ...this.state, stage: 'terminal', error: { code: 'KEY_MISMATCH', message: 'The identity could not be confirmed.' } };
          this.publishView();
          return;
        }
        await this.completeWithVerification();
        return;
      }
      if (lookup.kind === 'transportFailure') {
        this.state = this.confirmationDelayed()
          ? { ...this.state, stage: 'delay', error: null }
          : { ...this.state, stage: 'connection', error: { code: 'TRANSPORT_AMBIGUOUS', message: 'Waiting for connection.' } };
        this.publishView();
        return;
      }
      // Absence after admission permits lookup-only waiting, never resubmission.
      this.state = { ...this.state, stage: 'waiting', error: null };
      this.ensureConfirmationPolling();
      this.publishView();
    } finally {
      this.reconciliationInFlight = false;
    }
  }

  private ensureConfirmationPolling(): void {
    if (this.confirmationDelayed()) { this.enterConfirmationDelay(); return; }
    if (this.confirmationPoll === null) {
      this.confirmationPoll = setInterval(() => { void this.reconcileWaiting(); }, 3000);
    }
  }

  private stopConfirmationPolling(): void {
    if (this.confirmationPoll !== null) clearInterval(this.confirmationPoll);
    this.confirmationPoll = null;
    if (this.confirmationDeadlineTimer !== null) clearTimeout(this.confirmationDeadlineTimer);
    this.confirmationDeadlineTimer = null;
  }

  private startConfirmationDeadline(): void {
    if (this.acceptedSinceMs !== null) return;
    this.acceptedSinceMs = Date.now();
    this.confirmationDeadlineTimer = setTimeout(() => this.enterConfirmationDelay(), ABNORMAL_DELAY_MS);
  }

  private confirmationDelayed(): boolean {
    return this.acceptedSinceMs !== null && evaluateDelay(this.acceptedSinceMs, Date.now()).delayed;
  }

  private enterConfirmationDelay(): void {
    this.stopConfirmationPolling();
    if (this.creationAuthorityEnded() || this.completed || !['waiting', 'connection', 'delay'].includes(this.state.stage)) return;
    this.state = { ...this.state, stage: 'delay', error: null };
    this.publishView();
  }

  private creationAuthorityEnded(): boolean {
    return this.disposed || this.state.stage === 'locked';
  }

  private buildReview(): CreationReviewProjection {
    return {
      normalizedAlias: this.state.alias,
      visibility: this.state.visibility,
      abbreviatedSigningAddress: this.state.fullSigningAddress.length > 0 ? abbreviate(this.state.fullSigningAddress) : (this.state.waitingAddress ?? ''),
      abbreviatedEncryptionAddress: this.state.fullEncryptionAddress.length > 0 ? abbreviate(this.state.fullEncryptionAddress) : '',
      recoveryConfirmed: this.recoveryConfirmed,
      deviceProtectionReady: this.state.stage === 'review' || this.state.stage === 'waiting' || this.state.stage === 'finishCreating',
      stage: this.state.stage === 'finishCreating' ? 'provisionalResume' : this.state.stage,
      progress: this.state.stage === 'generating' ? 0.5 : 1,
    };
  }

  private async completeWithVerification(): Promise<void> {
    const verify = await this.ctx.client.dispatch('verifyOnlineIdentity');
    if (this.creationAuthorityEnded()) return;
    if (verify.outcome !== 'OK') {
      this.state = { ...this.state, stage: 'delay', error: { code: 'UNKNOWN_FAILURE', message: 'Your identity could not be confirmed yet.' } };
      this.publishView();
      return;
    }
    // Exact verification has finished. A failed local save must not restart
    // network polling or repeat verification on the explicit save retry.
    this.stopConfirmationPolling();
    this.promotionReady = true;
    await this.promoteConfirmedIdentity();
  }

  private async promoteConfirmedIdentity(): Promise<void> {
    if (this.creationAuthorityEnded() || this.completed || !this.promotionReady || this.promotionInFlight) return;
    this.promotionInFlight = true;
    this.publishView();
    try {
      const promoted = await this.ctx.client.dispatch('promoteLifecycle', { status: 'Active' });
      if (this.creationAuthorityEnded()) return;
      if (promoted.outcome !== 'OK') {
        this.state = { ...this.state, stage: 'delay', error: { code: 'PROVISION_FAILED', message: 'The confirmed identity could not be saved yet.' } };
        this.publishView();
        return;
      }
      this.promotionReady = false;
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
    } finally {
      this.promotionInFlight = false;
      this.publishView();
    }
  }

  onCheckAgain(): void {
    if (this.promotionReady) void this.promoteConfirmedIdentity();
    else void this.reconcileWaiting();
  }

  onRetryConnection(): void {
    if (this.state.stage !== 'connection') return;
    if (this.registrationRequested && !this.submissionAttempted) void this.submitAfterInitialLookup();
    else void this.reconcileWaiting();
  }

  onUnlockProvisional(): void {
    // The provisional vault unlocks with the device password (locked screen).
    this.state = { ...this.state, stage: 'locked' };
    this.publishView();
  }

  onLock(): void {
    this.stopConfirmationPolling();
    this.clearRevealWindow();
    this.state = { ...this.state, stage: 'locked', words: null, revealedWords: false };
    this.publishView();
    // The ordinary root observes the worker's global invalidation, cancels
    // this child and rereads durable local state for the unlock surface.
    void this.requestGlobalLock();
  }

  private requestGlobalLock(): Promise<ClientOperationResult> {
    // Revocation cancels this child. Its cleanup must await the same lock:
    // a second revocation would invalidate the root's new initialization.
    return this.globalLock ??= Promise.resolve().then(() => this.ctx.client.dispatch('lockAll'));
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
    if (this.disposed) return;
    const s = this.state;
    this.recoveryDisplay.update(s.stage === 'recovery' && s.revealedWords ? s.words : null);
    const stageForView: CreationStage = s.stage === 'finishCreating' ? 'provisionalResume' : s.stage;
    const input: CreateViewInput = {
      stage: stageForView,
      canGoBack: true,
      operationInFlight: this.initialSubmissionInFlight || this.promotionInFlight || (s.stage === 'generating' && this.generatingInFlight) || s.stage === 'waiting',
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
        recoveryDisplay: this.recoveryDisplay.display,
        recoveryVisible: s.stage === 'recovery' && s.revealedWords && s.words !== null,
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
        preflightOutcome: this.preflightOutcome,
        c: {
          onCreateUser: () => undefined,
          onRestoreWords: () => undefined,
          onRestoreFile: () => undefined,
          onRetryPreflight: () => this.onRetryPreflight(),
          onProfileContinue: (alias, visibility) => this.onProfileContinue(alias, visibility),
          onGenerate: () => void this.onGenerate(),
          onRecoveryContinue: () => this.onRecoveryContinue(),
          onRecoveryCopy: () => this.onRecoveryCopy(),
          onRegenerateRequest: (confirmed) => this.onRegenerateRequest(confirmed),
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
  readonly stage: 'vaultGuard' | 'wordEntry' | 'verifying' | 'deriving' | 'lookup' | 'candidateSelection' | 'profileSelection' | 'existingProfileVerify' | 'recreateReview' | 'registration' | 'proof' | 'protection' | 'staging' | 'activating' | 'success' | 'finishRestoring' | 'terminal';
  readonly wordCount: '12' | '24';
  readonly candidateRef: string | null;
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly profileName: string | null;
  readonly error: { readonly code: string; readonly message: string } | null;
}

/** Real Recovery Words child runtime (single approved candidate path). */
export class RecoveryWordsChildRuntime implements ChildRuntime {
  private sessionOnly = false;
  readonly kind = 'restoreRecoveryWords' as const;
  private state: WordsRuntimeState = {
    stage: 'vaultGuard',
    wordCount: '24',
    candidateRef: null,
    signingAddress: '',
    encryptionAddress: '',
    profileName: null,
    error: null,
  };
  private completion: VerificationOnlyCompletion | null = null;
  private completionResolvers: Array<(completion: VerificationOnlyCompletion) => void> = [];
  private invalidPositions: readonly number[] = [];
  private disposed = false;
  private vaultProvisioned = false;
  private provisioning: Promise<ClientOperationResult> | null = null;
  private cleanupPromise: Promise<ChildCleanupResult> | null = null;
  private noRetentionAcknowledged = false;
  private profileWasMissing = false;
  private profileVisibility: 'private' | 'public' = 'private';
  private candidates: Array<RecoveryCandidateDetail & { profile: Exclude<BridgeLookupOutcome, { kind: 'transportFailure' }> | null }> = [];
  private selectedIndex: number | null = null;
  private revealedIndex: number | null = null;
  private registrationPoll: ReturnType<typeof setInterval> | null = null;
  private activationInFlight = false;
  private entryInspection: Promise<void> | null = null;
  private failedStageNeedsLock = false;
  private failedStageCleanup: Promise<boolean> | null = null;

  constructor(private readonly ctx: ChildBridgeContext) {}

  async start(): Promise<void> {
    if (this.disposed) return;
    if (this.failedStageNeedsLock && !await this.clearFailedStage()) return;
    if (this.disposed) return;
    if (this.entryInspection) return this.entryInspection;
    this.state = { ...this.state, stage: 'vaultGuard', error: null };
    this.publishView();
    this.entryInspection = (async () => {
      let empty = false;
      try {
        const result = await this.ctx.client.dispatch('inspectStartup');
        empty = result.outcome === 'OK'
          && (result.payload as { surface?: unknown } | undefined)?.surface === 'verifiedAbsent';
      } catch { /* Failed inspection cannot authorize phrase entry. */ }
      if (this.disposed) return;
      this.state = empty ? { ...this.state, stage: 'wordEntry', error: null }
        : { ...this.state, stage: 'vaultGuard', error: { code: 'VAULT_NOT_VERIFIED_EMPTY', message: 'Local credential absence could not be verified.' } };
      this.publishView();
    })().finally(() => { this.entryInspection = null; });
    return this.entryInspection;
  }

  awaitCompletion(): Promise<VerificationOnlyCompletion> {
    if (this.completion) {
      return Promise.resolve(this.completion);
    }
    return new Promise((resolve) => {
      this.completionResolvers.push(resolve);
    });
  }

  cleanup(): Promise<ChildCleanupResult> {
    if (this.cleanupPromise) return this.cleanupPromise;
    this.disposed = true;
    this.stopRegistrationPolling();
    clearChildView(this.kind);
    return this.cleanupPromise = (async () => {
      if (this.provisioning !== null) {
        const staged = await this.provisioning;
        if (staged.outcome === 'OK') this.vaultProvisioned = true;
      }
      // FEAT-008 Tasks 3.9/3.10: retain only unacknowledged cleanup for root-owned Retry.
      if (this.failedStageNeedsLock && !await this.clearFailedStage()) {
        this.cleanupPromise = null;
        return { kind: 'CHILD_CLEANUP_FAILED' as const };
      }
      if (this.vaultProvisioned) {
        const locked = await this.ctx.client.dispatch('lockAll');
        if (locked.outcome !== 'OK') {
          this.cleanupPromise = null;
          return { kind: 'CHILD_CLEANUP_FAILED' as const };
        }
        this.candidates = [];
      } else {
        while (this.candidates.length > 0) {
          const discarded = await this.ctx.client.dispatch('destroyCandidate', { candidateRef: this.candidates[0].ref });
          if (discarded.outcome !== 'OK') {
            this.cleanupPromise = null;
            return { kind: 'CHILD_CLEANUP_FAILED' as const };
          }
          this.candidates.shift();
        }
      }
      return { kind: 'CHILD_CLEANUP_COMPLETE' as const };
    })().catch(() => {
      this.cleanupPromise = null;
      return { kind: 'CHILD_CLEANUP_FAILED' as const };
    });
  }

  cancel(): void {
    void this.cleanup();
  }

  onSelectCount(count: '12' | '24'): void {
    if (this.disposed || this.state.stage !== 'wordEntry') return;
    this.invalidPositions = [];
    this.state = { ...this.state, wordCount: count, error: null };
    this.publishView();
  }

  async onVerify(phrase: string): Promise<void> {
    if (this.disposed || this.state.stage !== 'wordEntry') return;
    this.invalidPositions = [];
    const wordCount = phrase.trim().split(/[ \t\r\n]+/).length;
    if (wordCount !== (this.state.wordCount === '12' ? 12 : 24)) {
      this.state = { ...this.state, error: { code: 'WRONG_COUNT', message: 'The phrase has the wrong number of words.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'verifying', error: null };
    this.publishView();
    const operationId = `words-${this.ctx.randomId('op-')}`;
    this.ctx.client.submitSecret(operationId, 'mnemonic', phrase);
    const derive = this.ctx.client.dispatch('deriveRecoveryCandidates', { wordCount: Number(this.state.wordCount) }, undefined, operationId);
    const outcome = await derive;
    if (this.disposed) {
      const candidates = (outcome.payload as { candidates?: RecoveryCandidateDetail[] } | undefined)?.candidates;
      if (Array.isArray(candidates)) for (const candidate of candidates) if (typeof candidate.ref === 'string') await this.ctx.client.dispatch('destroyCandidate', { candidateRef: candidate.ref });
      return;
    }
    if (outcome.outcome !== 'OK') {
      const payload = outcome.payload as { reason?: unknown; invalidPositions?: unknown } | undefined;
      const reason = payload?.reason;
      const code = reason === 'UNKNOWN_WORD' ? 'UNKNOWN_WORD'
        : reason === 'INVALID_CHECKSUM' ? 'CHECKSUM_FAILURE'
        : reason === 'wrong-word-count' || reason === 'INVALID_WORD_COUNT' ? 'WRONG_COUNT'
        : 'UNSUPPORTED_INPUT';
      if (code === 'UNKNOWN_WORD' && Array.isArray(payload?.invalidPositions)) {
        this.invalidPositions = payload.invalidPositions.filter((p): p is number => Number.isInteger(p) && p >= 1 && p <= Number(this.state.wordCount));
      }
      this.state = { ...this.state, stage: 'wordEntry', error: { code, message: 'Review your recovery words against your secure copy.' } };
      this.publishView();
      return;
    }
    const detail = outcome.payload as { candidates?: RecoveryCandidateDetail[] } | undefined;
    if (!Array.isArray(detail?.candidates) || detail.candidates.length === 0 || detail.candidates.some(candidate =>
      typeof candidate.ref !== 'string' || typeof candidate.signingAddress !== 'string' || typeof candidate.encryptionAddress !== 'string'
      || !Array.isArray(candidate.producerIds) || candidate.producerIds.length === 0)) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'PRODUCER_DERIVATION_FAILURE', message: 'The identity formats could not be derived.' } };
      this.publishView();
      return;
    }
    this.candidates = detail.candidates.map(candidate => ({ ...candidate, profile: null }));
    await this.lookup();
  }

  private async lookup(): Promise<void> {
    if (this.disposed || this.candidates.length === 0) return;
    this.state = { ...this.state, stage: 'lookup', error: null };
    this.publishView();
    for (const candidate of this.candidates) {
      if (candidate.profile !== null) continue;
      const outcome = await this.ctx.lookupIdentity(candidate.signingAddress);
      if (this.disposed) return;
      if (outcome.kind === 'transportFailure') {
        this.state = { ...this.state, error: { code: 'NETWORK_UNAVAILABLE', message: 'The network is unavailable. Retry the unresolved identity checks.' } };
        this.publishView();
        return;
      }
      if (outcome.kind === 'exact' && (outcome.signingAddress !== candidate.signingAddress || outcome.encryptionAddress !== candidate.encryptionAddress)) {
        this.state = { ...this.state, stage: 'terminal', error: { code: 'SIGNING_ENCRYPTION_MISMATCH', message: 'The identity could not be confirmed.' } };
        this.publishView();
        return;
      }
      candidate.profile = outcome;
      this.publishView();
    }
    const existing = this.candidates.filter(candidate => candidate.profile?.kind === 'exact');
    this.state = { ...this.state, stage: existing.length === 1 ? 'existingProfileVerify' : existing.length > 1 ? 'profileSelection' : 'candidateSelection' };
    this.publishView();
  }

  onRetryLookup(): void {
    if (this.state.stage === 'lookup' && this.state.error !== null) void this.lookup();
  }

  onSelectCandidate(index: number): void {
    if (this.disposed || !['candidateSelection', 'profileSelection'].includes(this.state.stage)) return;
    if (!this.reviewEntries().some(entry => entry.index === index)) return;
    this.selectedIndex = index;
    this.publishView();
  }

  private reviewEntries() {
    const entries = this.candidates.map((candidate, index) => ({ candidate, index }));
    const existing = entries.filter(entry => entry.candidate.profile?.kind === 'exact');
    return existing.length ? existing : entries;
  }

  async onConfirmExistingProfile(): Promise<void> {
    if (this.disposed || !['candidateSelection', 'profileSelection', 'existingProfileVerify'].includes(this.state.stage)) return;
    const entries = this.reviewEntries();
    const selected = entries.length === 1 ? entries[0] : entries.find(entry => entry.index === this.selectedIndex);
    if (!selected || selected.candidate.profile === null) return;
    this.state = { ...this.state, stage: 'proof' };
    this.revealedIndex = null;
    this.publishView();
    for (const candidate of this.candidates) {
      if (candidate.ref === selected.candidate.ref) continue;
      const destroyed = await this.ctx.client.dispatch('destroyCandidate', { candidateRef: candidate.ref });
      if (this.disposed) return;
      if (destroyed.outcome !== 'OK') {
        this.state = { ...this.state, stage: 'terminal', error: { code: 'CLEANUP_FAILED', message: 'Unselected identity material could not be cleared.' } };
        this.publishView();
        return;
      }
    }
    this.candidates = [selected.candidate];
    const profile = selected.candidate.profile;
    this.profileWasMissing = profile.kind !== 'exact';
    this.profileVisibility = profile.kind === 'exact' && profile.isPublic ? 'public' : 'private';
    this.state = { ...this.state, candidateRef: selected.candidate.ref, signingAddress: selected.candidate.signingAddress,
      encryptionAddress: selected.candidate.encryptionAddress, profileName: profile.kind === 'exact' ? profile.profileName : null, stage: this.profileWasMissing ? 'recreateReview' : 'protection' };
    this.publishView();
  }

  onReveal(index: number | null): void {
    if (!['candidateSelection', 'profileSelection', 'existingProfileVerify'].includes(this.state.stage)) return;
    this.revealedIndex = index !== null && this.reviewEntries().some(entry => entry.index === index) ? index : null;
    this.publishView();
  }

  onCopyAddress(address: string): void {
    if (this.disposed || !['candidateSelection', 'profileSelection', 'existingProfileVerify'].includes(this.state.stage)) return;
    const candidate = this.reviewEntries().find(entry => entry.index === this.revealedIndex)?.candidate;
    if (!candidate || (address !== candidate.signingAddress && address !== candidate.encryptionAddress)) return;
    // Only the explicitly revealed public pair can cross this clipboard seam.
    try { void navigator.clipboard.writeText(address).catch(() => undefined); } catch { /* Clipboard permission unavailable; the address remains selectable. */ }
  }

  private buildCandidateReview(): CandidateReviewProjection | null {
    if (!['candidateSelection', 'profileSelection', 'existingProfileVerify', 'recreateReview'].includes(this.state.stage)) return null;
    const entries = this.reviewEntries();
    const hasExisting = entries.some(entry => entry.candidate.profile?.kind === 'exact');
    const revealed = entries.find(entry => entry.index === this.revealedIndex)?.candidate;
    return {
      outcome: hasExisting ? entries.length === 1 ? 'exactlyOneExisting' : 'multipleExisting'
        : entries.length === 1 ? 'zeroExistingOneCandidate' : 'zeroExistingMultipleCandidates',
      entries: entries.map(({ candidate, index }) => ({ candidateIndex: index,
        sourceLabel: candidate.producerIds.includes('P-01') ? 'Hush Web Client' : 'Historical Hush desktop and .NET identities',
        abbreviatedSigningAddress: abbreviateAddress(candidate.signingAddress), abbreviatedEncryptionAddress: abbreviateAddress(candidate.encryptionAddress),
        producerIds: candidate.producerIds, profileAlias: candidate.profile?.kind === 'exact' ? candidate.profile.profileName : null,
        visibility: candidate.profile?.kind === 'exact' ? candidate.profile.isPublic ? 'public' : 'private' : null,
        selected: this.selectedIndex === index })),
      networkLabel: this.ctx.manifest.canonicalNetworkId, selectionRequired: entries.length > 1,
      uncertainGuidance: hasExisting ? null : 'Use a trusted public address to identify your historical identity.',
      revealState: { revealedCandidateIndex: this.revealedIndex, fullSigningAddress: revealed?.signingAddress ?? null, fullEncryptionAddress: revealed?.encryptionAddress ?? null },
      busy: false,
    };
  }

  async onConfirmRecreate(alias: string, visibility: 'private' | 'public'): Promise<void> {
    if (this.disposed || this.state.stage !== 'recreateReview' || !this.profileWasMissing) return;
    const validated = validateAlias(alias);
    if (!validated.ok) {
      this.state = { ...this.state, error: { code: 'INVALID_ALIAS', message: 'Review the profile name.' } };
      this.publishView();
      return;
    }
    this.profileVisibility = visibility;
    if (this.vaultProvisioned) {
      // Final verification found authoritative absence after staging. Keep the
      // protected recovered keys and submit only after this new explicit review.
      this.state = { ...this.state, profileName: validated.normalizedNfc };
      await this.submitReviewedProfile(validated.normalizedNfc);
      return;
    }
    this.state = { ...this.state, profileName: validated.normalizedNfc, stage: 'protection', error: null };
    this.publishView();
  }

  async onChooseProtection(mode: string): Promise<void> {
    if (this.disposed || this.state.stage !== 'protection') return;
    if (mode !== 'devicePasswordWeb' && mode !== 'sessionOnly') return;
    this.sessionOnly = mode === 'sessionOnly';
  }

  // FEAT-008 AC-008-037: failed staging revokes transient material even when
  // the response is lost. Lock preserves any committed encrypted vault for inspection.
  private clearFailedStage(): Promise<boolean> {
    this.failedStageNeedsLock = true;
    return this.failedStageCleanup ??= (async () => {
      try {
        const cleared = await this.ctx.client.dispatch('lockAll');
        if (cleared.outcome !== 'OK') return false;
        this.candidates = [];
        this.selectedIndex = null;
        this.revealedIndex = null;
        this.noRetentionAcknowledged = false;
        this.state = { ...this.state, candidateRef: null, signingAddress: '', encryptionAddress: '', profileName: null };
        this.failedStageNeedsLock = false;
        return true;
      } catch { return false; }
    })().finally(() => { this.failedStageCleanup = null; });
  }

  private async failStaging(): Promise<void> {
    const cleared = await this.clearFailedStage();
    this.state = { ...this.state, stage: 'terminal', error: cleared
      ? { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not complete. Enter your recovery words again to retry.' }
      : { code: 'CLEANUP_FAILED', message: 'Recovery material could not be cleared.' } };
    this.publishView();
  }

  async onProtect(password: string): Promise<void> {
    if (this.disposed || this.state.stage !== 'protection' || !this.noRetentionAcknowledged) return;
    if (this.state.candidateRef === null) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not complete.' } };
      this.publishView();
      return;
    }
    if (!this.sessionOnly && password.length < 8) {
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
      if (this.disposed) return;
    } catch {
      await this.failStaging();
      return;
    }
    const alias = this.state.profileName ?? 'Restored identity';
    const operationId = `prov-${this.ctx.randomId('op-')}`;
    if (!this.sessionOnly) this.ctx.client.submitSecret(operationId, 'devicePassword', password);
    const provision = this.ctx.client.dispatch('provisionFromValidatedBundle', { candidateRef: this.state.candidateRef, alias, visibility: this.profileVisibility, ...(this.sessionOnly ? { protectionMode: 'sessionOnly' } : {}) }, capabilityId, operationId);
    this.provisioning = provision;
    let outcome: ClientOperationResult | undefined;
    try { outcome = await provision; }
    catch { /* A lost response still requires transient-authority revocation. */ }
    finally { this.provisioning = null; }
    if (outcome?.outcome !== 'OK') {
      await this.failStaging();
      return;
    }
    this.vaultProvisioned = true;
    if (this.disposed) return;
    if (this.profileWasMissing) {
      await this.submitReviewedProfile(alias);
      return;
    }
    this.state = { ...this.state, stage: 'activating' };
    this.publishView();
    await this.activate();
  }

  private async submitReviewedProfile(alias: string): Promise<void> {
    this.state = { ...this.state, stage: 'registration', error: null };
    this.publishView();
    const submitted = await this.ctx.client.dispatch('submitIdentityTransaction', { alias, visibility: this.profileVisibility });
    if (this.disposed) return;
    const status = (submitted.payload as { status?: unknown } | undefined)?.status;
    if (submitted.outcome !== 'OK' || !['accepted', 'pending', 'alreadyExists'].includes(String(status))) {
      this.state = { ...this.state, error: { code: 'REGISTRATION_UNCONFIRMED', message: 'The profile is not confirmed. Check the network before continuing.' } };
      this.publishView();
    } else {
      this.stopRegistrationPolling();
      this.registrationPoll = setInterval(() => { void this.onCheckAgain(); }, 3000);
    }
  }

  private stopRegistrationPolling(): void {
    if (this.registrationPoll !== null) clearInterval(this.registrationPoll);
    this.registrationPoll = null;
  }

  async onCheckAgain(): Promise<void> {
    if (this.disposed || this.activationInFlight || this.state.stage !== 'registration') return;
    if (document.visibilityState !== 'visible' || !navigator.onLine) return;
    this.activationInFlight = true;
    try { await this.activate(); } finally { this.activationInFlight = false; }
  }

  private async activate(): Promise<void> {
    const verify = await this.ctx.client.dispatch('verifyOnlineIdentity');
    if (this.disposed) return;
    if (verify.outcome === 'PROFILE_MISSING' && !this.profileWasMissing) {
      this.stopRegistrationPolling();
      this.profileWasMissing = true;
      this.profileVisibility = 'private';
      this.revealedIndex = null;
      this.candidates = this.candidates.map(candidate => ({ ...candidate, profile: { kind: 'authoritativeAbsent' } }));
      this.state = { ...this.state, profileName: null, stage: 'recreateReview', error: null };
      this.publishView();
      return;
    }
    if (verify.outcome !== 'OK') {
      this.state = { ...this.state, stage: this.profileWasMissing && ['PROFILE_MISSING', 'VERIFY_TIMEOUT', 'NETWORK_UNAVAILABLE'].includes(verify.outcome) ? 'registration' : 'terminal', error: { code: 'PROFILE_DISAPPEARED', message: 'The identity could not be confirmed yet.' } };
      if (this.state.stage === 'terminal') this.stopRegistrationPolling();
      this.publishView();
      return;
    }
    const promoted = await this.ctx.client.dispatch('promoteLifecycle', { status: 'Active' });
    if (this.disposed) return;
    if (promoted.outcome !== 'OK') {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ACTIVATION_FAILED', message: 'The restored identity could not be activated.' } };
      this.publishView();
      return;
    }
    this.stopRegistrationPolling();
    this.state = { ...this.state, stage: 'success', error: null };
    // The root owns the success announcement after its own verification gate.
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
    this.stopRegistrationPolling();
    void this.ctx.client.dispatch('lockAll');
  }

  onFinishRestoringUnlock(): void {
    this.state = { ...this.state, stage: 'finishRestoring' };
    this.publishView();
  }

  onRetry(): void {
    void this.start();
  }

  private publishView(): void {
    if (this.disposed) return;
    const s = this.state;
    const input: RecoveryViewInput = {
      stage: s.stage,
      operationInFlight: s.stage === 'verifying' || s.stage === 'deriving' || (s.stage === 'lookup' && s.error === null) || s.stage === 'staging' || s.stage === 'activating',
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
        network: { canonicalNetworkId: this.ctx.manifest.canonicalNetworkId, classification: this.ctx.manifest.classification },
        wordGrid: s.stage === 'wordEntry' || s.stage === 'verifying' || s.stage === 'deriving'
          ? {
              selectedWordCount: s.wordCount,
              invalidPositions: this.invalidPositions,
              countValid: s.error?.code !== 'WRONG_COUNT',
              vocabularyValid: s.error?.code !== 'UNKNOWN_WORD',
              checksumState: s.error?.code === 'CHECKSUM_FAILURE' ? 'failed' : s.stage === 'wordEntry' ? 'notRun' : 'pending',
              allConcealed: false,
              busy: s.stage !== 'wordEntry',
              canVerify: s.stage === 'wordEntry',
              errorSummary: s.error?.code === 'WRONG_COUNT' || s.error?.code === 'UNKNOWN_WORD' || s.error?.code === 'UNSUPPORTED_INPUT'
                ? [{ code: s.error.code, positions: this.invalidPositions }]
                : [],
              pasteReplacementPending: false,
            }
          : null,
        candidateReview: this.buildCandidateReview(),
        protection: s.stage === 'protection' ? { defaultPasswordChecked: !this.sessionOnly, allowedModes: ['devicePasswordWeb', 'sessionOnly'], sessionOnlyAcknowledgementRequired: true, passwordlessQualified: false, platformHints: [], busy: false } : null,
        stagedPreview: null,
        lookupProgress: s.stage === 'lookup' ? { done: this.candidates.filter(candidate => candidate.profile !== null).length, total: this.candidates.length } : null,
        onSelectCount: (count) => this.onSelectCount(count),
        onPastePhrase: () => undefined,
        onConfirmPasteReplacement: () => undefined,
        onClearAll: () => undefined,
        onVerify: (phrase) => void this.onVerify(phrase),
        onSelectCandidate: index => this.onSelectCandidate(index),
        onConfirmExistingProfile: () => void this.onConfirmExistingProfile(),
        onRetryLookup: () => this.onRetryLookup(),
        onReveal: index => this.onReveal(index),
        onCopyAddress: address => this.onCopyAddress(address),
        onChooseProtection: mode => void this.onChooseProtection(mode),
        onAcknowledgeProtection: () => { if (this.state.stage === 'protection') this.noRetentionAcknowledged = true; },
        onProtect: password => void this.onProtect(password),
        onConfirmRecreate: (alias, visibility) => this.onConfirmRecreate(alias, visibility),
        onCheckAgain: () => void this.onCheckAgain(),
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
  private sessionOnly = false;
  private sessionAcknowledged = false;
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
  private entryInspection: Promise<void> | null = null;
  private importOperationId: string | null = null;
  private backoffDeadlineMs = 0;
  private backoffTimer: ReturnType<typeof setInterval> | null = null;
  private publicAcknowledged = false;
  private publicAddressesRevealed = false;
  private passwordVisible = false;
  private emptyPassword = false;
  private readGeneration = 0;
  private sourceRead: AbortController | null = null;
  private disposed = false;
  private cleanupPromise: Promise<ChildCleanupResult> | null = null;
  private profileStatus: 'unknown' | 'exact' | 'missing' = 'unknown';
  private vaultProvisioned = false;
  private provisioning: Promise<ClientOperationResult> | null = null;

  constructor(private readonly ctx: ChildBridgeContext) {}

  async start(): Promise<void> {
    if (this.disposed) return;
    if (this.entryInspection) return this.entryInspection;
    this.importOperationId = null;
    this.passwordVisible = false;
    this.emptyPassword = false;
    this.profileStatus = 'unknown';
    this.vaultProvisioned = false;
    this.readGeneration += 1;
    this.state = { ...this.state, stage: 'capabilityPreflight', error: null };
    this.publishView();
    // The root's previous empty result is not authority for a later import.
    // Recheck the actual worker before mounting or accepting a file source.
    this.entryInspection = (async () => {
      let empty = false;
      try {
        const result = await this.ctx.client.dispatch('inspectStartup');
        empty = result.outcome === 'OK'
          && (result.payload as { surface?: unknown } | undefined)?.surface === 'verifiedAbsent';
      } catch { /* Unavailable custody never means absent. */ }
      if (this.disposed) return;
      this.state = empty ? { ...this.state, stage: 'picker', error: null }
        : { ...this.state, stage: 'terminal', error: { code: 'VAULT_NOT_VERIFIED_EMPTY', message: 'Local credential absence could not be verified.' } };
      this.publishView();
    })().finally(() => { this.entryInspection = null; });
    return this.entryInspection;
  }

  awaitCompletion(): Promise<VerificationOnlyCompletion> {
    if (this.completion) {
      return Promise.resolve(this.completion);
    }
    return new Promise((resolve) => {
      this.completionResolvers.push(resolve);
    });
  }

  cleanup(): Promise<ChildCleanupResult> {
    if (this.cleanupPromise) return this.cleanupPromise;
    this.disposed = true;
    if (this.backoffTimer !== null) clearInterval(this.backoffTimer);
    this.backoffTimer = null;
    this.readGeneration += 1;
    const importOperationId = this.importOperationId;
    this.sourceRead?.abort();
    this.sourceRead = null;
    const wasDecrypting = this.state.stage === 'decrypting';
    const candidateRef = this.state.candidateRef;
    this.passwordVisible = false;
    this.emptyPassword = false;
    clearChildView(this.kind);
    return this.cleanupPromise = (async () => {
      if (this.provisioning !== null) {
        const staged = await this.provisioning;
        if (staged.outcome === 'OK') this.vaultProvisioned = true;
      }
      if (importOperationId !== null) {
        if (wasDecrypting) this.ctx.client.cancel(importOperationId);
        else {
          const discarded = await this.ctx.client.dispatch('discardSecretTransfers', { transferOperationId: importOperationId });
          if (discarded.outcome !== 'OK') {
            this.cleanupPromise = null;
            return { kind: 'CHILD_CLEANUP_FAILED' as const };
          }
        }
        this.importOperationId = null;
      }
      const discarded = this.vaultProvisioned ? await this.ctx.client.dispatch('lockAll')
        : candidateRef !== null ? await this.ctx.client.dispatch('destroyCandidate', { candidateRef }) : null;
      if (discarded !== null && discarded.outcome !== 'OK') {
        this.cleanupPromise = null;
        return { kind: 'CHILD_CLEANUP_FAILED' as const };
      }
      this.state = { ...this.state, candidateRef: null };
      return { kind: 'CHILD_CLEANUP_COMPLETE' as const,
        ...(candidateRef !== null && !this.vaultProvisioned ? { next: 'credentialFilePicker' as const } : {}) };
    })().catch(() => {
      this.cleanupPromise = null;
      return { kind: 'CHILD_CLEANUP_FAILED' as const };
    });
  }

  cancel(): void {
    void this.cleanup();
  }

  /** User-gesture browser selection followed by one bounded snapshot transfer. */
  async onChooseFile(file: File): Promise<void> {
    if (this.disposed || this.state.stage !== 'picker') return;
    this.sourceRead?.abort();
    this.sourceRead = null;
    if (this.importOperationId !== null) await this.ctx.client.dispatch('discardSecretTransfers', { transferOperationId: this.importOperationId });
    if (this.disposed) return;
    const generation = ++this.readGeneration;
    this.importOperationId = null;
    this.passwordVisible = false;
    this.emptyPassword = false;
    this.state = { ...this.state, stage: 'reading', error: null };
    this.publishView();

    if (file.size > 1_048_576) {
      this.state = { ...this.state, stage: 'picker', error: { code: 'ENVELOPE_OVERSIZE', message: 'The credential file is too large.' } };
      this.publishView();
      return;
    }

    const sourceRead = new AbortController();
    this.sourceRead = sourceRead;
    try {
      const bytes = await readCredentialSnapshot(file, sourceRead.signal);
      if (generation !== this.readGeneration) {
        bytes.fill(0);
        return;
      }
      const envelope = evaluateEnvelopeGate(bytes);
      if (envelope.kind !== 'valid') {
        bytes.fill(0);
        const code = envelope.kind === 'tooShort' ? 'ENVELOPE_TOO_SHORT' : envelope.kind === 'tooLarge' ? 'ENVELOPE_OVERSIZE'
          : envelope.kind === 'invalidMagic' ? 'INVALID_MAGIC' : 'UNSUPPORTED_VERSION';
        this.state = { ...this.state, stage: 'picker', error: { code, message: 'The credential file does not have a supported complete envelope.' } };
        this.publishView();
        return;
      }
      const operationId = `file-${this.ctx.randomId('op-')}`;
      try { this.ctx.client.submitSecret(operationId, 'fileBytes', bytes); }
      finally { bytes.fill(0); }
      this.importOperationId = operationId;
      this.state = { ...this.state, stage: 'password', error: null };
      this.publishView();
    } catch (error) {
      if (generation === this.readGeneration) {
        const code = error instanceof CredentialSourceError ? error.code : 'READ_UNAVAILABLE';
        this.state = { ...this.state, stage: 'picker', error: { code, message: 'The credential file could not be read.' } };
        this.publishView();
      }
    } finally {
      if (this.sourceRead === sourceRead) this.sourceRead = null;
    }
  }

  /** Backup password handoff consumes the already-transferred worker snapshot. */
  async onSubmitPassword(password: string): Promise<void> {
    if (this.disposed || this.state.stage !== 'password' || Date.now() < this.backoffDeadlineMs) return;
    if (password.length === 0 && !this.emptyPassword) return;
    if (new TextEncoder().encode(password).byteLength > 4096) {
      this.state = { ...this.state, error: { code: 'BACKUP_PASSWORD_TOO_LONG', message: 'The backup-file password exceeds 4096 UTF-8 bytes.' } };
      this.publishView();
      return;
    }
    const operationId = this.importOperationId;
    if (operationId === null) {
      this.state = { ...this.state, stage: 'picker', error: { code: 'READ_UNAVAILABLE', message: 'Choose the credential file again.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'decrypting', error: null };
    this.publishView();
    const generation = this.readGeneration;
    this.ctx.client.submitSecret(operationId, 'filePassword', password);
    const outcome = await this.ctx.client.dispatch('importFileCandidate', this.emptyPassword ? { emptyV1Confirmed: true } : undefined, undefined, operationId);
    if (this.disposed || generation !== this.readGeneration) {
      const ref = (outcome.payload as { ref?: unknown } | undefined)?.ref;
      if (outcome.outcome === 'OK' && typeof ref === 'string') await this.ctx.client.dispatch('destroyCandidate', { candidateRef: ref });
      return;
    }
    if (outcome.outcome === 'WRONG_PASSWORD_OR_DAMAGED' || outcome.outcome === 'THROTTLED') {
      this.passwordVisible = false;
      this.emptyPassword = false;
      this.backoffDeadlineMs = outcome.retryDeadlineMs ?? 0;
      this.state = { ...this.state, stage: 'password', error: { code: outcome.outcome === 'THROTTLED' ? 'BACKOFF_ACTIVE' : 'AUTHENTICATION_FAILED', message: 'The backup password is incorrect or the credential file is damaged.' } };
      if (this.backoffTimer !== null) clearInterval(this.backoffTimer);
      if (this.backoffDeadlineMs > Date.now()) this.backoffTimer = setInterval(() => {
        if (Date.now() >= this.backoffDeadlineMs && this.backoffTimer !== null) {
          clearInterval(this.backoffTimer);
          this.backoffTimer = null;
        }
        this.publishView();
      }, 200);
      this.publishView();
      return;
    }
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
    const generation = this.readGeneration;
    const outcome = await this.ctx.lookupIdentity(this.state.signingAddress);
    if (this.disposed || generation !== this.readGeneration) return;
    if (outcome.kind === 'transportFailure') {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'NETWORK_UNAVAILABLE', message: 'The network is unavailable right now.' } };
      this.publishView();
      return;
    }
    if (outcome.kind === 'exact' && (outcome.signingAddress !== this.state.signingAddress || outcome.encryptionAddress !== this.state.encryptionAddress)) {
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
  onUpdateProfile(alias: string, visibility: 'private' | 'public'): void {
    if (this.disposed || this.state.stage !== 'profileReview' || this.profileStatus !== 'missing') return;
    if (visibility !== this.state.visibility) this.publicAcknowledged = false;
    const validation = validateAlias(alias);
    this.state = { ...this.state, profileName: alias, visibility,
      error: validation.ok ? null : { code: validation.code, message: validation.message } };
    this.publishView();
  }

  onAcknowledgePublic(acknowledged: boolean): void {
    if (this.disposed || this.state.stage !== 'profileReview') return;
    this.publicAcknowledged = acknowledged;
    this.publishView();
  }

  onRevealAddresses(): void {
    if (this.disposed || this.state.stage !== 'profileReview') return;
    this.publicAddressesRevealed = !this.publicAddressesRevealed;
    this.publishView();
  }

  onCreateIdentity(): void {
    if (this.disposed || this.profileStatus !== 'missing' || this.state.stage !== 'profileReview') return;
    const validation = validateAlias(this.state.profileName);
    if (!validation.ok || (this.state.visibility === 'public' && !this.publicAcknowledged)) return;
    this.publicAddressesRevealed = false;
    this.state = { ...this.state, profileName: validation.normalizedNfc, stage: 'protection', error: null };
    this.publishView();
  }

  /** Protection uses a separately entered Device password, never the backup password. */
  async onChooseProtection(mode: string, devicePassword?: string): Promise<void> {
    if (this.disposed || this.state.stage !== 'protection') return;
    if (mode === 'sessionOnly' && this.sessionAcknowledged) {
      this.sessionOnly = true;
      await this.onProtect('');
      return;
    }
    if (mode !== 'devicePassword' || devicePassword === undefined) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'UNSUPPORTED_PROTECTION_MODE', message: 'This protection mode is not available on this device.' } };
      this.publishView();
      return;
    }
    this.sessionOnly = false;
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

  async onChooseDifferentFile(): Promise<void> {
    if (this.disposed) return;
    const generation = ++this.readGeneration;
    this.sourceRead?.abort();
    this.sourceRead = null;
    const operationId = this.importOperationId;
    this.importOperationId = null;
    this.passwordVisible = false;
    this.emptyPassword = false;
    this.state = { ...this.state, stage: 'reading', error: null };
    this.publishView();
    if (operationId !== null) {
      const result = await this.ctx.client.dispatch('discardSecretTransfers', { transferOperationId: operationId });
      if (this.disposed || generation !== this.readGeneration) return;
      if (result.outcome !== 'OK') {
        this.state = { ...this.state, stage: 'terminal', error: { code: 'CLEANUP_FAILURE', message: 'Cleanup could not be confirmed.' } };
        this.publishView();
        return;
      }
    }
    this.state = { ...this.state, stage: 'picker', error: null };
    this.publishView();
  }

  onCancelRead(): void {
    void this.onChooseDifferentFile();
  }

  async onProtect(password: string): Promise<void> {
    if (this.state.candidateRef === null) {
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not complete.' } };
      this.publishView();
      return;
    }
    if (!this.sessionOnly && password.length < 8) {
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
      if (this.disposed) return;
    } catch {
      reportCredentialLifecycleFailure('capability', 'CAPABILITY_UNAVAILABLE');
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not start.' } };
      this.publishView();
      return;
    }
    const operationId = `prov-${this.ctx.randomId('op-')}`;
    if (!this.sessionOnly) this.ctx.client.submitSecret(operationId, 'devicePassword', password);
    this.provisioning = this.ctx.client.dispatch('provisionFromValidatedBundle', {
      candidateRef: this.state.candidateRef,
      ...(this.sessionOnly ? { protectionMode: 'sessionOnly' } : {}),
      alias: this.state.profileName,
      visibility: this.state.visibility,
    }, capabilityId, operationId);
    const outcome = await this.provisioning;
    this.provisioning = null;
    if (outcome.outcome !== 'OK') {
      reportCredentialLifecycleFailure('provision', outcome.outcome, outcome.payload);
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'Restore could not complete.' } };
      this.publishView();
      return;
    }
    this.vaultProvisioned = true;
    if (this.disposed) return;
    if (this.profileStatus === 'missing') {
      await this.submitMissingProfile();
      return;
    }
    await this.verifyAndComplete();
  }

  private async submitMissingProfile(): Promise<void> {
    if (this.disposed) return;
    const generation = this.readGeneration;
    this.state = { ...this.state, stage: 'activating', error: null };
    this.publishView();
    const submission = await this.ctx.client.dispatch('submitIdentityTransaction', {
      alias: this.state.profileName,
      visibility: this.state.visibility,
    });
    if (this.disposed || generation !== this.readGeneration) return;
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
    for (let attempt = 0; attempt < 60 && generation === this.readGeneration; attempt += 1) {
      const lookup = await this.ctx.lookupIdentity(this.state.signingAddress);
      if (this.disposed || generation !== this.readGeneration) return;
      if (lookup.kind === 'exact') {
        if (lookup.signingAddress !== this.state.signingAddress || lookup.encryptionAddress !== this.state.encryptionAddress) {
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
    if (this.disposed) return;
    const generation = this.readGeneration;
    this.state = { ...this.state, stage: 'activating', error: null };
    this.publishView();
    const verify = await this.ctx.client.dispatch('verifyOnlineIdentity');
    if (this.disposed || generation !== this.readGeneration) return;
    if (verify.outcome !== 'OK') {
      reportCredentialLifecycleFailure('verify', verify.outcome, verify.payload);
      this.state = { ...this.state, stage: 'terminal', error: { code: 'PROFILE_DISAPPEARED', message: 'The identity could not be confirmed yet.' } };
      this.publishView();
      return;
    }
    const promote = await this.ctx.client.dispatch('promoteLifecycle', { status: 'Active' });
    if (this.disposed || generation !== this.readGeneration) return;
    if (promote.outcome !== 'OK') {
      reportCredentialLifecycleFailure('promote', promote.outcome, promote.payload);
      this.state = { ...this.state, stage: 'terminal', error: { code: 'ENCRYPTED_STAGE_FAILURE', message: 'The restored identity could not be activated.' } };
      this.publishView();
      return;
    }
    this.state = { ...this.state, stage: 'success', error: null };
    // Keep the waiting surface until the root verifies and announces completion.
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
    if (this.disposed) return;
    const s = this.state;
    const input: RestoreViewInput = {
      stage: s.stage,
      progress: null,
      failureCode: s.error?.code ?? null,
      backoffRemainingSeconds: Math.max(0, Math.ceil((this.backoffDeadlineMs - Date.now()) / 1000)),
      passwordField: s.stage === 'password' || s.stage === 'decrypting' ? { visible: this.passwordVisible, emptyOptionChecked: this.emptyPassword, emptyOptionEnabled: true } : null,
      protectionChoices: s.stage === 'protection' ? ['devicePassword', 'sessionOnly'] : null,
      profile: s.stage === 'profileReview' || s.stage === 'protection' || s.stage === 'staging'
        ? { alias: s.profileName, isPublic: s.visibility === 'public', signingAddressAbbreviated: abbreviate(s.signingAddress), encryptionAddressAbbreviated: abbreviate(s.encryptionAddress), networkLabel: this.ctx.manifest.canonicalNetworkId, source: this.profileStatus === 'exact' ? 'blockchain' : 'importedReview', aliasEditable: s.stage === 'profileReview', publicAcknowledgementRequired: s.visibility === 'public' }
        : null,
      reveal: this.publicAddressesRevealed && s.stage === 'profileReview' ? { token: 'explicit-file-public-addresses', fullSigningAddress: s.signingAddress, fullEncryptionAddress: s.encryptionAddress } : null,
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
        onChooseDifferentFile: () => void this.onChooseDifferentFile(),
        onChooseProtection: (mode, devicePassword) => void this.onChooseProtection(mode, devicePassword),
        onCreateIdentity: () => this.onCreateIdentity(),
        onReveal: () => this.onRevealAddresses(),
        onUpdateProfile: (alias, visibility) => this.onUpdateProfile(alias, visibility),
        onAcknowledgePublic: acknowledged => this.onAcknowledgePublic(acknowledged),
        publicAcknowledged: this.publicAcknowledged,
        canCreateProfile: validateAlias(s.profileName).ok && (s.visibility !== 'public' || this.publicAcknowledged),
        onUnlockResume: () => undefined,
        onCancelStage: () => undefined,
        onBack: () => this.onBack(),
        onAcknowledgeSessionOnly: (acknowledged = true) => { this.sessionAcknowledged = acknowledged; },
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
  const failedCleanups = new Set<ChildRuntime>();
  const operationRuntimes = new Map<OperationId, ChildRuntime | undefined>();

  const startRuntime = (kind: OnboardingKind): ChildRuntime => {
    // One fresh runtime per onboarding operation; a cancelled runtime's
    // lifecycle/secret state must never be reused after Back or Lock.
    const runtime = createRuntimeFor(kind, ctx);
    runtimes.set(kind, runtime);
    return runtime;
  };

  const cancelIfInFlight = (kind: OnboardingKind, operationId: OperationId): void => {
    // XState runs invoke cleanup after a successful result too. That cleanup
    // is not a user cancellation and must not globally invalidate the worker
    // before root-owned verification starts.
    const runtime = operationRuntimes.get(operationId);
    operationRuntimes.delete(operationId);
    if (settledOperations.delete(operationId)) {
      if (runtime !== undefined && failedCleanups.has(runtime)) return;
      if (runtime !== undefined && runtimes.get(kind) === runtime) {
        clearChildView(kind);
        runtimes.delete(kind);
      }
      return;
    }
    // These IDs identify root actors, not worker operations. The runtime owns
    // its actual import/candidate cleanup; cancelling a synthetic ID globally
    // revokes unrelated startup work and can strand the Back transition.
    runtime?.cancel();
  };

  const makePort = (kind: OnboardingKind): OnboardingPort => ({
    cancel(operationId: OperationId) {
      cancelIfInFlight(kind, operationId);
    },
    start(_kind: OnboardingKind, epoch: SessionEpoch) {
      const runtime = startRuntime(kind);
      const operationId = `onb-${kind}-${epoch}-${Date.now().toString(36)}` as OperationId;
      operationRuntimes.set(operationId, runtime);
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
      operationRuntimes.set(operationId, runtime);
      const cleanup: Promise<ChildCleanupResult> = runtime ? runtime.cleanup() : Promise.resolve({ kind: 'CHILD_CLEANUP_COMPLETE' });
      const result: Promise<OnboardingResult> = cleanup.then(outcome => {
        if (outcome.kind === 'CHILD_CLEANUP_FAILED') {
          if (runtime) failedCleanups.add(runtime);
          return { code: 'UNKNOWN_FAILURE', supportCode: 'ONBOARDING_CLEANUP_FAILED' } as const;
        }
        if (runtime) failedCleanups.delete(runtime);
        return { code: 'ONBOARDING_CLEANUP_COMPLETE', ...(outcome.next ? { next: outcome.next } : {}) } as const;
      }).finally(() => settledOperations.add(operationId));
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
