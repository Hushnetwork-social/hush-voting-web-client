@FEAT-008
Feature: Recovery words — entry-input-validation
  Covers HV-RW-ENTRY-GUARD, HV-RW-INPUT, HV-RW-PASTE, HV-RW-VALIDATE.

  @FEAT-008 @AC-008-001 @HV-RW-ENTRY-GUARD-001
  Scenario: AC-008-001 — HV-RW-ENTRY-GUARD
    Given verified empty local state
    When the entry guard inspects the local authority
    Then recovery starts only with no active, staged, rollback, quarantine, or competing authority

  @FEAT-008 @AC-008-002 @HV-RW-ENTRY-GUARD-002
  Scenario: AC-008-002 — HV-RW-ENTRY-GUARD
    Given verified empty local state
    When the entry guard inspects the local authority
    Then recovery starts only with no active, staged, rollback, quarantine, or competing authority

  @FEAT-008 @AC-008-003 @HV-RW-ENTRY-GUARD-003
  Scenario: AC-008-003 — HV-RW-ENTRY-GUARD
    Given verified empty local state
    When the entry guard inspects the local authority
    Then recovery starts only with no active, staged, rollback, quarantine, or competing authority

  @FEAT-008 @AC-008-004 @HV-RW-ENTRY-GUARD-004
  Scenario: AC-008-004 — HV-RW-ENTRY-GUARD
    Given verified empty local state
    When the entry guard inspects the local authority
    Then recovery starts only with no active, staged, rollback, quarantine, or competing authority

  @FEAT-008 @AC-008-005 @HV-RW-INPUT-001
  Scenario: AC-008-005 — HV-RW-INPUT
    Given a twelve-or-twenty-four word selector with indexed fields
    When the user selects a word count
    Then exactly that many indexed responsive fields render with accessible labels

  @FEAT-008 @AC-008-006 @HV-RW-VALIDATE-001
  Scenario: AC-008-006 — HV-RW-VALIDATE
    Given entered recovery words
    When validation runs inside the authority
    Then NFKD/vocabulary/count/checksum rules apply without autocorrection or lockout

  @FEAT-008 @AC-008-007 @HV-RW-VALIDATE-002
  Scenario: AC-008-007 — HV-RW-VALIDATE
    Given entered recovery words
    When validation runs inside the authority
    Then NFKD/vocabulary/count/checksum rules apply without autocorrection or lockout

  @FEAT-008 @AC-008-008 @HV-RW-PASTE-001
  Scenario: AC-008-008 — HV-RW-PASTE
    Given a focused word box and a clipboard phrase
    When the user pastes a complete phrase
    Then count-correct phrases fill the grid atomically and mismatches reject the entire paste

  @FEAT-008 @AC-008-009 @HV-RW-PASTE-002
  Scenario: AC-008-009 — HV-RW-PASTE
    Given a focused word box and a clipboard phrase
    When the user pastes a complete phrase
    Then count-correct phrases fill the grid atomically and mismatches reject the entire paste

  @FEAT-008 @AC-008-010 @HV-RW-PASTE-003
  Scenario: AC-008-010 — HV-RW-PASTE
    Given a focused word box and a clipboard phrase
    When the user pastes a complete phrase
    Then count-correct phrases fill the grid atomically and mismatches reject the entire paste

  @FEAT-008 @AC-008-011 @HV-RW-PASTE-004
  Scenario: AC-008-011 — HV-RW-PASTE
    Given a focused word box and a clipboard phrase
    When the user pastes a complete phrase
    Then count-correct phrases fill the grid atomically and mismatches reject the entire paste

  @FEAT-008 @AC-008-012 @HV-RW-PASTE-005
  Scenario: AC-008-012 — HV-RW-PASTE
    Given a focused word box and a clipboard phrase
    When the user pastes a complete phrase
    Then count-correct phrases fill the grid atomically and mismatches reject the entire paste

  @FEAT-008 @AC-008-013 @HV-RW-INPUT-002
  Scenario: AC-008-013 — HV-RW-INPUT
    Given a twelve-or-twenty-four word selector with indexed fields
    When the user selects a word count
    Then exactly that many indexed responsive fields render with accessible labels

  @FEAT-008 @AC-008-014 @HV-RW-INPUT-003
  Scenario: AC-008-014 — HV-RW-INPUT
    Given a twelve-or-twenty-four word selector with indexed fields
    When the user selects a word count
    Then exactly that many indexed responsive fields render with accessible labels

  @FEAT-008 @AC-008-015 @HV-RW-VALIDATE-003
  Scenario: AC-008-015 — HV-RW-VALIDATE
    Given entered recovery words
    When validation runs inside the authority
    Then NFKD/vocabulary/count/checksum rules apply without autocorrection or lockout
