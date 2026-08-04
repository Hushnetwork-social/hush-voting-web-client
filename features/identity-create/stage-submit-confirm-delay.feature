@FEAT-007
Feature: Identity create — staging, submission, confirmation, delay, correction, reset
  Covers HV-ID-CREATE-STAGE, HV-ID-CREATE-SUBMIT, HV-ID-CREATE-CONFIRM,
  HV-ID-CREATE-DELAY, HV-ID-CREATE-CORRECT, HV-ID-CREATE-RESET.

  @FEAT-007 @AC-007-022 @HV-ID-CREATE-STAGE-001
  Scenario: A sealed provisional record precedes any network call
    Given recovery confirmation and a valid device-password capability
    When Create Identity is invoked
    Then the credential bundle, separate mnemonic record, reviewed profile, exact signed transaction, and digest commit atomically
    And no network call occurs before read-back verification

  @FEAT-007 @AC-007-023 @HV-ID-CREATE-STAGE-002
  Scenario: A provisional identity is never authenticated and blocks first-run
    Given a sealed provisional record
    When the lifecycle is evaluated
    Then it is not authenticated and cannot enter HushVoting
    And it blocks another first-run/Create User flow

  @FEAT-007 @AC-007-027 @HV-ID-CREATE-STAGE-003
  Scenario: The exact signed transaction survives process death
    Given an exact transaction is encrypted in the provisional record
    When the process dies and restarts
    Then the exact transaction is recoverable without exposing its private signing authority

  @FEAT-007 @AC-007-052 @HV-ID-CREATE-STAGE-004
  Scenario: Restart with a provisional record resumes safely without mnemonic reveal
    Given a provisional record exists after restart
    When the user unlocks the device
    Then Finish creating your identity shows only safe abbreviated context
    And lookup-first resume runs without revealing the mnemonic automatically

  @FEAT-007 @AC-007-054 @HV-ID-CREATE-STAGE-005
  Scenario: Promotion failure retries only the local transition
    Given the server may have accepted the exact transaction
    When provisional-to-saved promotion fails
    Then credentials and the exact transaction remain preserved
    And only the local transition is retried without rollback or resubmission

  @FEAT-007 @AC-007-025 @HV-ID-CREATE-SUBMIT-001
  Scenario: The transaction is canonical
    Given reviewed profile fields and exact candidate addresses
    When the signed transaction is constructed
    Then it uses CSPRNG UUIDv4, a corpus-exact UTC timestamp, approved property order, exact UTF-8 PayloadSize, the exact payload GUID, and the established signed JSON representation

  @FEAT-007 @AC-007-026 @HV-ID-CREATE-SUBMIT-002
  Scenario: Signatory, payload signing address, and signing key bind exactly
    Given the authority owns the signing key
    When the transaction is signed
    Then UserSignature.Signatory equals the payload signing address
    And both equal the authority-owned signing key

  @FEAT-007 @AC-007-028 @HV-ID-CREATE-SUBMIT-003
  Scenario: Every cycle performs GetIdentity before submission
    Given startup, unlock, foreground, or reconnection occurs
    When reconciliation runs
    Then GetIdentity runs first using the exact local public signing address

  @FEAT-007 @AC-007-029 @HV-ID-CREATE-SUBMIT-004
  Scenario: Only authoritative absence permits submission
    Given transport succeeded and GetIdentity reports authoritative absence
    When submission eligibility is evaluated
    Then submission may proceed
    And connectivity or malformed responses never authorize submission

  @FEAT-007 @AC-007-030 @HV-ID-CREATE-SUBMIT-005
  Scenario: Exact keys confirm the same identity; encryption mismatch fails closed
    Given GetIdentity returns a profile
    When the profile is compared
    Then exact signing and encryption addresses confirm the same identity
    And a signing match with encryption mismatch fails closed

  @FEAT-007 @AC-007-031 @HV-ID-CREATE-SUBMIT-006
  Scenario: One reconciliation cycle submits at most once
    Given startup, focus, connectivity, and user retry occur together
    When reconciliation coalesces
    Then one authority-owned lookup runs
    And at most one submission follows authoritative absence

  @FEAT-007 @AC-007-032 @HV-ID-CREATE-SUBMIT-007
  Scenario: ACCEPTED promotes to saved-waiting without claiming confirmation
    Given submission returns ACCEPTED
    When the lifecycle is promoted
    Then the provisional lifecycle becomes saved-user waiting
    And no block confirmation is claimed

  @FEAT-007 @AC-007-033 @HV-ID-CREATE-SUBMIT-008
  Scenario: PENDING waits without another submission
    Given submission returns PENDING
    When the same signing key is already in the mempool
    Then HushVoting promotes/waits like ACCEPTED
    And never resubmits or generates replacement bytes while pending knowledge is current

  @FEAT-007 @AC-007-034 @HV-ID-CREATE-SUBMIT-009
  Scenario: ALREADY_EXISTS resolves by exact lookup only
    Given submission returns ALREADY_EXISTS
    When reconciliation proceeds
    Then an exact GetIdentity lookup runs
    And ALREADY_EXISTS alone never authenticates the user

  @FEAT-007 @AC-007-035 @HV-ID-CREATE-SUBMIT-010
  Scenario: Status/code combinations use a closed allowlist
    Given any submission reply
    When it is normalized
    Then only allowlisted status/code combinations drive behavior
    And message parsing, unknown codes, unspecified statuses, and contradictions fail closed

  @FEAT-007 @AC-007-036 @HV-ID-CREATE-SUBMIT-011
  Scenario: Transport ambiguity preserves the exact transaction
    Given a transport or server failure
    When the outcome is evaluated
    Then the exact transaction and provisional identity are preserved
    And no replacement bytes are generated

  @FEAT-007 @AC-007-045 @HV-ID-CREATE-SUBMIT-012
  Scenario: Ambiguous retries reuse exact signed bytes
    Given an ambiguous retry while the transaction may be pending
    When retry occurs
    Then the exact signed bytes are reused
    And no new transaction is created

  @FEAT-007 @AC-007-048 @HV-ID-CREATE-SUBMIT-013
  Scenario: A missing transaction can be rebuilt only after verified eligibility
    Given the retained transaction record is missing
    When rebuild eligibility is evaluated
    Then authenticated credential/profile verification AND authoritative absence are both required
    And corruption never counts as missing

  @FEAT-007 @AC-007-050 @HV-ID-CREATE-SUBMIT-014
  Scenario: The client never polls as retry or periodically replaces transactions
    Given the waiting gate is active
    When time passes
    Then no submission occurs every three seconds
    And no periodic replacement or liveness submission is implemented

  @FEAT-007 @AC-007-037 @HV-ID-CREATE-CONFIRM-001
  Scenario: The waiting gate is accessible and explicit
    Given the transaction is accepted or pending
    When the confirmation gate renders
    Then it states that mempool admission is not block confirmation
    And it offers safe Lock/close guidance without an endless unexplained spinner

  @FEAT-007 @AC-007-038 @HV-ID-CREATE-CONFIRM-002
  Scenario: GetIdentity polls every three seconds while eligible
    Given the waiting gate is foregrounded, online, visible, and authority-valid
    When polling runs
    Then GetIdentity is called every three seconds through one coalesced loop
    And submission never happens on a poll

  @FEAT-007 @AC-007-039 @HV-ID-CREATE-CONFIRM-003
  Scenario: Polling pauses on background, offline, Lock, or revocation
    Given the app backgrounds, goes offline, locks, or revokes the authority
    When polling eligibility is evaluated
    Then polling pauses immediately
    And polling never counts as user activity

  @FEAT-007 @AC-007-040 @HV-ID-CREATE-CONFIRM-004
  Scenario: Check again performs lookup only
    Given the waiting gate with a Check again control
    When the user selects Check again
    Then one immediate coalesced lookup runs
    And no new poll loop or submission is created

  @FEAT-007 @AC-007-042 @HV-ID-CREATE-CONFIRM-005
  Scenario: Exact confirmation synchronizes and clears
    Given GetIdentity returns the exact key pair
    When confirmation is established
    Then blockchain-authoritative alias/visibility are synchronized atomically
    And the retained transaction is cleared and a valid authority epoch authenticates

  @FEAT-007 @AC-007-043 @HV-ID-CREATE-CONFIRM-006
  Scenario: A revoked, expired, or restarted authority requires ordinary unlock
    Given confirmation occurred but the authority is revoked, expired, backgrounded, or restarted
    When authentication is evaluated
    Then ordinary unlock is required before entering HushVoting

  @FEAT-007 @AC-007-044 @HV-ID-CREATE-CONFIRM-007
  Scenario: Mempool acceptance alone never enters the authenticated shell
    Given only ACCEPTED or PENDING knowledge exists
    When the shell entry is evaluated
    Then HushVoting does not enter the authenticated shell
    And exact GetIdentity confirmation is required

  @FEAT-007 @AC-007-053 @HV-ID-CREATE-CONFIRM-008
  Scenario: A lost acceptance response converges without another identity
    Given a lost acceptance response
    When lookup-first reconciliation resumes
    Then exact lookup or exact-transaction PENDING/ACCEPTED handling resolves the state
    And no second identity is created

  @FEAT-007 @AC-007-041 @HV-ID-CREATE-DELAY-001
  Scenario: Three minutes without confirmation enters the delay state
    Given three minutes elapsed without exact confirmation
    When the delay policy evaluates
    Then automatic polling stops and Blockchain confirmation delayed is shown
    And only lookup-only Check again and Lock are offered
    And the exact transaction and vault remain unchanged

  @FEAT-007 @AC-007-046 @HV-ID-CREATE-CORRECT-001
  Scenario: Editable alias rejection reopens Profile only
    Given an allowlisted editable pre-admission code
    When correction runs
    Then only Profile/Review reopens with the same identity
    And a fresh Device-password authorization is required before one new replacement transaction

  @FEAT-007 @AC-007-047 @HV-ID-CREATE-CORRECT-002
  Scenario: Cryptographic and unknown rejections fail closed without retry
    Given signature, signatory, key-binding, malformed, encoding, payload, or unknown rejection
    When the outcome is evaluated
    Then it fails closed with a sanitized support code
    And no automatic retry occurs

  @FEAT-007 @AC-007-049 @HV-ID-CREATE-RESET-001
  Scenario: Blockchain reset re-registers the same identity
    Given a previously confirmed local identity is authoritatively absent
    When reconciliation completes credential/profile verification
    Then one fresh transaction is created from the same vault identity and latest verified encrypted profile
    And no new recovery words are generated because the chain was reset
