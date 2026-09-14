@FEAT-009
Feature: Credential file restore — Lookup, profile, protection, and staging
  Covers HV-DAT-LOOKUP, HV-DAT-RESET, HV-DAT-SIGNATURE, HV-DAT-SEPARATION, HV-DAT-PROTECT, HV-DAT-STAGE, HV-DAT-SESSION, HV-DAT-RESUME.

  @FEAT-009 @AC-009-041 @HV-DAT-LOOKUP-AC041
  Scenario: AC-009-041 — HV-DAT-LOOKUP
    Given local key proof completed and source state released
    When the unchanged unsigned public lookup runs
    Then existing profiles require exact signing and encryption equality and transport is never not-found

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

