@FEAT-008
Feature: Recovery words — lookup-select-profile-recreate
  Covers HV-RW-LOOKUP, HV-RW-SELECT, HV-RW-PROFILE, HV-RW-RECREATE.

  @FEAT-008 @AC-008-024 @HV-RW-LOOKUP-001
  Scenario: AC-008-024 — HV-RW-LOOKUP
    Given a complete candidate set and a bound network
    When sequential public lookups run
    Then every candidate resolves to exact profile or authoritative not-found with a 10-second bound

  @FEAT-008 @AC-008-025 @HV-RW-LOOKUP-002
  Scenario: AC-008-025 — HV-RW-LOOKUP
    Given a complete candidate set and a bound network
    When sequential public lookups run
    Then every candidate resolves to exact profile or authoritative not-found with a 10-second bound

  @FEAT-008 @AC-008-026 @HV-RW-LOOKUP-003
  Scenario: AC-008-026 — HV-RW-LOOKUP
    Given a complete candidate set and a bound network
    When sequential public lookups run
    Then every candidate resolves to exact profile or authoritative not-found with a 10-second bound

  @FEAT-008 @AC-008-027 @HV-RW-LOOKUP-004
  Scenario: AC-008-027 — HV-RW-LOOKUP
    Given a complete candidate set and a bound network
    When sequential public lookups run
    Then every candidate resolves to exact profile or authoritative not-found with a 10-second bound

  @FEAT-008 @AC-008-028 @HV-RW-LOOKUP-005
  Scenario: AC-008-028 — HV-RW-LOOKUP
    Given a complete candidate set and a bound network
    When sequential public lookups run
    Then every candidate resolves to exact profile or authoritative not-found with a 10-second bound

  @FEAT-008 @AC-008-029 @HV-RW-SELECT-001
  Scenario: AC-008-029 — HV-RW-SELECT
    Given complete lookup outcomes
    When the resolution review renders
    Then zero/one/multiple outcomes require explicit no-default selection

  @FEAT-008 @AC-008-030 @HV-RW-SELECT-002
  Scenario: AC-008-030 — HV-RW-SELECT
    Given complete lookup outcomes
    When the resolution review renders
    Then zero/one/multiple outcomes require explicit no-default selection

  @FEAT-008 @AC-008-031 @HV-RW-SELECT-003
  Scenario: AC-008-031 — HV-RW-SELECT
    Given complete lookup outcomes
    When the resolution review renders
    Then zero/one/multiple outcomes require explicit no-default selection

  @FEAT-008 @AC-008-032 @HV-RW-SELECT-004
  Scenario: AC-008-032 — HV-RW-SELECT
    Given complete lookup outcomes
    When the resolution review renders
    Then zero/one/multiple outcomes require explicit no-default selection

  @FEAT-008 @AC-008-033 @HV-RW-SELECT-005
  Scenario: AC-008-033 — HV-RW-SELECT
    Given complete lookup outcomes
    When the resolution review renders
    Then zero/one/multiple outcomes require explicit no-default selection

  @FEAT-008 @AC-008-034 @HV-RW-PROFILE-001
  Scenario: AC-008-034 — HV-RW-PROFILE
    Given an existing blockchain profile
    When profile review renders
    Then blockchain alias and visibility are authoritative and historical aliases render safely

  @FEAT-008 @AC-008-035 @HV-RW-PROFILE-002
  Scenario: AC-008-035 — HV-RW-PROFILE
    Given an existing blockchain profile
    When profile review renders
    Then blockchain alias and visibility are authoritative and historical aliases render safely

  @FEAT-008 @AC-008-057 @HV-RW-RECREATE-001
  Scenario: AC-008-057 — HV-RW-RECREATE
    Given no profile for the recovered keys
    When missing-profile recreation review renders
    Then alias starts empty, visibility defaults Private, and exact recovered keys are reused

  @FEAT-008 @AC-008-058 @HV-RW-RECREATE-002
  Scenario: AC-008-058 — HV-RW-RECREATE
    Given no profile for the recovered keys
    When missing-profile recreation review renders
    Then alias starts empty, visibility defaults Private, and exact recovered keys are reused

  @FEAT-008 @AC-008-059 @HV-RW-RECREATE-003
  Scenario: AC-008-059 — HV-RW-RECREATE
    Given no profile for the recovered keys
    When missing-profile recreation review renders
    Then alias starts empty, visibility defaults Private, and exact recovered keys are reused

  @FEAT-008 @AC-008-061 @HV-RW-RECREATE-004
  Scenario: AC-008-061 — HV-RW-RECREATE
    Given no profile for the recovered keys
    When missing-profile recreation review renders
    Then alias starts empty, visibility defaults Private, and exact recovered keys are reused
