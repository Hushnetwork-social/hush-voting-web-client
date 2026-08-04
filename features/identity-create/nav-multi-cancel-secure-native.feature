@FEAT-007
Feature: Identity create — navigation, multi-owner, cancellation, security, native
  Covers HV-ID-CREATE-NAV, HV-ID-CREATE-MULTI, HV-ID-CREATE-CANCEL,
  HV-ID-CREATE-SECURITY, HV-ID-CREATE-NATIVE.

  @FEAT-007 @AC-007-058 @HV-ID-CREATE-NAV-001
  Scenario: Browser, Android, and in-app Back share one typed authority
    Given any navigation-relevant pre-commit screen
    When browser, Android, or in-app Back is invoked
    Then one typed transition returns to the prior safe step
    And no secret input or concealed words are restored from history

  @FEAT-007 @AC-007-059 @HV-ID-CREATE-NAV-002
  Scenario: After provisional persistence, stale history cannot reopen creation
    Given the local boundary has been crossed
    When Back or a stale onboarding token is used
    Then creation history cannot render
    And the local identity is locked behind returning-user/provisional resume

  @FEAT-007 @AC-007-060 @HV-ID-CREATE-NAV-003
  Scenario: Forged, stale, or restored onboarding tokens are rejected
    Given a forged, stale, restored, or manually navigated onboarding token
    When the vault-inspection guard evaluates it
    Then the token is rejected
    And a local/provisional user always blocks the three first-run actions

  @FEAT-007 @AC-007-061 @HV-ID-CREATE-MULTI-002
  Scenario: A non-secret cross-tab event invalidates stale onboarding authorities
    Given another tab commits a local user
    When the non-secret local-user event is observed or vault inspection runs
    Then the stale onboarding authority is invalidated
    And no alias, address, transaction, password, mnemonic, or key is broadcast

  @FEAT-007 @AC-007-062 @HV-ID-CREATE-MULTI-003
  Scenario: Single-owner authority prevents competing candidates
    Given two tabs/windows/processes attempt provisioning
    When ownership is evaluated
    Then only the single owner may provision or submit
    And a second owner cannot create a competing FEAT-007 candidate

  @FEAT-007 @AC-007-031 @HV-ID-CREATE-MULTI-001
  Scenario: Concurrent triggers coalesce into one reconciliation cycle
    Given startup, focus, connectivity, and user retry occur together
    When reconciliation starts
    Then one authority-owned lookup runs
    And at most one submission follows authoritative absence

  @FEAT-007 @AC-007-055 @HV-ID-CREATE-CANCEL-001
  Scenario: Pre-submit cancellation verifies rollback before restoring first-run
    Given no submission has been attempted
    When cancellation is confirmed
    Then rollback is invoked with destructive confirmation and fresh Device-password authorization
    And first-run is restored only after storage absence is verified

  @FEAT-007 @AC-007-056 @HV-ID-CREATE-CANCEL-002
  Scenario: Post-submit cancellation warns that blockchain creation cannot be cancelled
    Given a submission may have occurred
    When local cancellation is confirmed
    Then the warning states the transaction may still confirm and saved recovery words are required to restore
    And fresh authorization and acknowledgement are required

  @FEAT-007 @AC-007-057 @HV-ID-CREATE-CANCEL-003
  Scenario: Rollback failure quarantines the authority
    Given rollback cannot verify storage absence
    When cleanup is evaluated
    Then the authority is quarantined, capabilities revoked, and first-run/authentication blocked
    And tombstone-backed cleanup retries until every slot is verified absent

  @FEAT-007 @AC-007-016 @HV-ID-CREATE-SECURITY-001
  Scenario: Secrets never enter React, XState, history, logs, or plaintext storage
    Given the creation flow runs
    When secrets are handled
    Then private keys and the full phrase never enter React, XState, route/history state, logs, analytics, or persistent plaintext storage

  @FEAT-007 @AC-007-024 @HV-ID-CREATE-SECURITY-002
  Scenario: Each platform uses only its sealed operation seams
    Given Browser, Ubuntu, and Android runtimes
    When creation executes
    Then each uses only its sealed operation seams
    And no generic signer, decryptor, or private-key export exists

  @FEAT-007 @AC-007-067 @HV-ID-CREATE-SECURITY-003
  Scenario: No social or feed state is initialized during onboarding
    Given the creation flow completes
    When side effects are evaluated
    Then no HushFeeds personal feed, HushSocial state, or non-identity transaction is created

  @FEAT-007 @AC-007-069 @HV-ID-CREATE-SECURITY-004
  Scenario: Secret-bearing scenarios disable capture and artifact scanning finds nothing
    Given a scenario that displays recovery words or accepts a password
    When evidence is collected
    Then trace, screenshot, and video capture are disabled before exposure
    And artifact scanning finds no mnemonic-like sequences, private keys, passwords, or full transactions

  @FEAT-007 @AC-007-071 @HV-ID-CREATE-SECURITY-005
  Scenario: Server TwinTests prove rejection and confirmation semantics
    Given a pinned qualified HushServerNode
    When focused FEAT-007 TwinTests run
    Then valid, duplicate, forged, altered, mismatch, confirmation, retry, and reset scenarios all pass

  @FEAT-007 @AC-007-072 @HV-ID-CREATE-SECURITY-006
  Scenario: Concurrent admission produces exactly one ACCEPTED
    Given concurrent valid same-key submissions
    When HushServerNode admits them
    Then exactly one returns ACCEPTED
    And all other same-key valid submissions return PENDING

  @FEAT-007 @AC-007-073 @HV-ID-CREATE-SECURITY-007
  Scenario: The fault matrix converges safely
    Given fault injection at journal, network, promotion, polling, synchronization, deletion, and ownership boundaries
    When each interruption occurs
    Then every interruption converges to one safe state
    And no duplicate candidate/submission, secret exposure, or false authentication occurs

  @FEAT-007 @AC-007-076 @HV-ID-CREATE-SECURITY-008
  Scenario: The external hardening blocker is green before completion
    Given the signature/authenticity, atomic identity reservation, stable code mapping, and full TwinTest blocker
    When completion is evaluated
    Then the blocker is green before release
    And no client mock substitutes for the server gate

  @FEAT-007 @AC-007-064 @HV-ID-CREATE-NATIVE-001
  Scenario: Ubuntu uses native custody and never exposes credentials to the WebView
    Given a qualified Secret Service or its approved explicit fallback
    When identity creation runs
    Then credentials, signing, and transport remain native
    And the WebView receives only safe projections

  @FEAT-007 @AC-007-065 @HV-ID-CREATE-NATIVE-002
  Scenario: Android requires hardware-backed protection with no fallback
    Given secure lock or qualified hardware-backed Keystore is absent
    When Create User preflight runs
    Then generation is blocked
    And no browser, software, or password-only fallback is selected

  @FEAT-007 @AC-007-066 @HV-ID-CREATE-NATIVE-003
  Scenario: Adapters observe the same server reply equivalently
    Given equivalent browser, Ubuntu, and Android responses
    When each adapter normalizes them
    Then they produce the same closed result and reconciliation action

  @FEAT-007 @AC-007-070 @HV-ID-CREATE-NATIVE-004
  Scenario: Every acceptance criterion maps to executable Gherkin
    Given the FEAT-007 acceptance catalog
    When the coverage manifest validator runs
    Then all 76 criteria have executable scenarios
    And every scenario references known criteria and a declared target

  @FEAT-007 @AC-007-075 @HV-ID-CREATE-NATIVE-005
  Scenario: Release evidence pins immutable digests
    Given exact HushVoting build, server revision, protocol/corpus versions, dependency locks, and adapter handoff digests
    When the release evidence is produced
    Then every pin is recorded immutably
    And mutable latest tags are prohibited
