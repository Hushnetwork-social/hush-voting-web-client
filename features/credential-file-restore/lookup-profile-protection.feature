@FEAT-009
Feature: Credential file restore — Lookup, profile, protection, and staging
  Covers HV-DAT-LOOKUP, HV-DAT-RESET, HV-DAT-SIGNATURE, HV-DAT-SEPARATION, HV-DAT-PROTECT, HV-DAT-STAGE, HV-DAT-SESSION, HV-DAT-RESUME.

  @FEAT-009 @AC-009-038 @HV-DAT-LOOKUP-AC038
  Scenario: AC-009-038 — HV-DAT-LOOKUP
    Given local key proof completed and source state released
    When the unchanged unsigned public lookup runs
    Then existing profiles require exact signing and encryption equality and transport is never not-found

  @FEAT-009 @AC-009-039 @HV-DAT-LOOKUP-AC039
  Scenario: AC-009-039 — HV-DAT-LOOKUP
    Given local key proof completed and source state released
    When the unchanged unsigned public lookup runs
    Then existing profiles require exact signing and encryption equality and transport is never not-found

  @FEAT-009 @AC-009-040 @HV-DAT-LOOKUP-AC040
  Scenario: AC-009-040 — HV-DAT-LOOKUP
    Given local key proof completed and source state released
    When the unchanged unsigned public lookup runs
    Then existing profiles require exact signing and encryption equality and transport is never not-found

  @FEAT-009 @AC-009-041 @HV-DAT-LOOKUP-AC041
  Scenario: AC-009-041 — HV-DAT-LOOKUP
    Given local key proof completed and source state released
    When the unchanged unsigned public lookup runs
    Then existing profiles require exact signing and encryption equality and transport is never not-found

  @FEAT-009 @AC-009-042 @HV-DAT-LOOKUP-AC042
  Scenario: AC-009-042 — HV-DAT-LOOKUP
    Given local key proof completed and source state released
    When the unchanged unsigned public lookup runs
    Then existing profiles require exact signing and encryption equality and transport is never not-found

  @FEAT-009 @AC-009-043 @HV-DAT-RESET-AC043
  Scenario: AC-009-043 — HV-DAT-RESET
    Given an authoritative not-found result exists
    When missing-profile review is created
    Then authenticated metadata may prefill review and creation requires exact file keys with explicit Create

  @FEAT-009 @AC-009-044 @HV-DAT-RESET-AC044
  Scenario: AC-009-044 — HV-DAT-RESET
    Given an authoritative not-found result exists
    When missing-profile review is created
    Then authenticated metadata may prefill review and creation requires exact file keys with explicit Create

  @FEAT-009 @AC-009-045 @HV-DAT-RESET-AC045
  Scenario: AC-009-045 — HV-DAT-RESET
    Given an authoritative not-found result exists
    When missing-profile review is created
    Then authenticated metadata may prefill review and creation requires exact file keys with explicit Create

  @FEAT-009 @AC-009-046 @HV-DAT-SIGNATURE-AC046
  Scenario: AC-009-046 — HV-DAT-SIGNATURE
    Given missing-profile creation is submitted
    When the FEAT-007 lifecycle runs
    Then the canonical transaction uses exact imported keys and server invalid-proof rejection is distinct from unsigned lookup

  @FEAT-009 @AC-009-047 @HV-DAT-SIGNATURE-AC047
  Scenario: AC-009-047 — HV-DAT-SIGNATURE
    Given missing-profile creation is submitted
    When the FEAT-007 lifecycle runs
    Then the canonical transaction uses exact imported keys and server invalid-proof rejection is distinct from unsigned lookup

  @FEAT-009 @AC-009-048 @HV-DAT-SIGNATURE-AC048
  Scenario: AC-009-048 — HV-DAT-SIGNATURE
    Given missing-profile creation is submitted
    When the FEAT-007 lifecycle runs
    Then the canonical transaction uses exact imported keys and server invalid-proof rejection is distinct from unsigned lookup

  @FEAT-009 @AC-009-049 @HV-DAT-SEPARATION-AC049
  Scenario: AC-009-049 — HV-DAT-SEPARATION
    Given validated credentials advance to protection
    When the backup-password component unmounts
    Then backup-password state is destroyed before the separate protection component mounts with no copy or prefill

  @FEAT-009 @AC-009-050 @HV-DAT-SEPARATION-AC050
  Scenario: AC-009-050 — HV-DAT-SEPARATION
    Given validated credentials advance to protection
    When the backup-password component unmounts
    Then backup-password state is destroyed before the separate protection component mounts with no copy or prefill

  @FEAT-009 @AC-009-051 @HV-DAT-PROTECT-AC051
  Scenario: AC-009-051 — HV-DAT-PROTECT
    Given protection choices are available
    When a mode is selected
    Then Device-password is default and only qualified passwordless or explicit session-only alternatives are representable

  @FEAT-009 @AC-009-052 @HV-DAT-PROTECT-AC052
  Scenario: AC-009-052 — HV-DAT-PROTECT
    Given protection choices are available
    When a mode is selected
    Then Device-password is default and only qualified passwordless or explicit session-only alternatives are representable

  @FEAT-009 @AC-009-053 @HV-DAT-PROTECT-AC053
  Scenario: AC-009-053 — HV-DAT-PROTECT
    Given protection choices are available
    When a mode is selected
    Then Device-password is default and only qualified passwordless or explicit session-only alternatives are representable

  @FEAT-009 @AC-009-054 @HV-DAT-SESSION-AC054
  Scenario: AC-009-054 — HV-DAT-SESSION
    Given session-only is selected
    When the session authority ends
    Then no local user, stage, or transaction persists and exact online verification is required again

  @FEAT-009 @AC-009-055 @HV-DAT-PROTECT-AC055
  Scenario: AC-009-055 — HV-DAT-PROTECT
    Given protection choices are available
    When a mode is selected
    Then Device-password is default and only qualified passwordless or explicit session-only alternatives are representable

  @FEAT-009 @AC-009-056 @HV-DAT-STAGE-AC056
  Scenario: AC-009-056 — HV-DAT-STAGE
    Given verified concrete keys exist
    When encrypted staging runs
    Then keys are encrypted, journaled, read back, and CAS-committed with exact bindings and the stage is never authentication

  @FEAT-009 @AC-009-057 @HV-DAT-STAGE-AC057
  Scenario: AC-009-057 — HV-DAT-STAGE
    Given verified concrete keys exist
    When encrypted staging runs
    Then keys are encrypted, journaled, read back, and CAS-committed with exact bindings and the stage is never authentication

  @FEAT-009 @AC-009-058 @HV-DAT-STAGE-AC058
  Scenario: AC-009-058 — HV-DAT-STAGE
    Given verified concrete keys exist
    When encrypted staging runs
    Then keys are encrypted, journaled, read back, and CAS-committed with exact bindings and the stage is never authentication

  @FEAT-009 @AC-009-059 @HV-DAT-STAGE-AC059
  Scenario: AC-009-059 — HV-DAT-STAGE
    Given verified concrete keys exist
    When encrypted staging runs
    Then keys are encrypted, journaled, read back, and CAS-committed with exact bindings and the stage is never authentication

  @FEAT-009 @AC-009-060 @HV-DAT-SESSION-AC060
  Scenario: AC-009-060 — HV-DAT-SESSION
    Given session-only is selected
    When the session authority ends
    Then no local user, stage, or transaction persists and exact online verification is required again

  @FEAT-009 @AC-009-061 @HV-DAT-STAGE-AC061
  Scenario: AC-009-061 — HV-DAT-STAGE
    Given verified concrete keys exist
    When encrypted staging runs
    Then keys are encrypted, journaled, read back, and CAS-committed with exact bindings and the stage is never authentication

  @FEAT-009 @AC-009-062 @HV-DAT-RESUME-AC062
  Scenario: AC-009-062 — HV-DAT-RESUME
    Given a persistent stage exists at startup
    When the selected protection unlocks the stage
    Then Finish restoring your identity performs lookup-first reconciliation and never restores source state

  @FEAT-009 @AC-009-063 @HV-DAT-RESUME-AC063
  Scenario: AC-009-063 — HV-DAT-RESUME
    Given a persistent stage exists at startup
    When the selected protection unlocks the stage
    Then Finish restoring your identity performs lookup-first reconciliation and never restores source state

