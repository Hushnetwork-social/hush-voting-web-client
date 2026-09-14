@FEAT-008
Feature: Recovery words — entry-input-validation
  Covers HV-RW-ENTRY-GUARD, HV-RW-INPUT, HV-RW-PASTE, HV-RW-VALIDATE.

  @FEAT-008 @AC-008-004 @HV-RW-ENTRY-GUARD-004
  Scenario: AC-008-004 — HV-RW-ENTRY-GUARD
    Given verified empty local state
    When the entry guard inspects the local authority
    Then recovery starts only with no active, staged, rollback, quarantine, or competing authority

