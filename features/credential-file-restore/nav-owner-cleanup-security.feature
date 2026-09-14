@FEAT-009
Feature: Credential file restore — Navigation, ownership, cleanup, and security
  Covers HV-DAT-NAV, HV-DAT-OWNER, HV-DAT-CLEANUP, HV-DAT-EXTERNAL, HV-DAT-SECURITY.

  @FEAT-009 @AC-009-069 @HV-DAT-NAV-AC069
  Scenario: AC-009-069 — HV-DAT-NAV
    Given a navigation event occurs
    When the shared Back authority evaluates the stage
    Then pre-decryption clears, post-validation destroys, and post-stage locks with visible URL remaining root

  @FEAT-009 @AC-009-070 @HV-DAT-OWNER-AC070
  Scenario: AC-009-070 — HV-DAT-OWNER
    Given two authorities attempt restore
    When ownership is acquired atomically
    Then exactly one owner may select, decrypt, stage, or submit and non-owners receive only safe blocked state

  @FEAT-009 @AC-009-078 @HV-DAT-SECURITY-AC078
  Scenario: AC-009-078 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

  @FEAT-009 @AC-009-079 @HV-DAT-SECURITY-AC079
  Scenario: AC-009-079 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

  @FEAT-009 @AC-009-080 @HV-DAT-SECURITY-AC080
  Scenario: AC-009-080 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

  @FEAT-009 @AC-009-083 @HV-DAT-SECURITY-AC083
  Scenario: AC-009-083 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

  @FEAT-009 @AC-009-084 @HV-DAT-SECURITY-AC084
  Scenario: AC-009-084 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

  @FEAT-009 @AC-009-085 @HV-DAT-SECURITY-AC085
  Scenario: AC-009-085 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

  @FEAT-009 @AC-009-086 @HV-DAT-SECURITY-AC086
  Scenario: AC-009-086 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

  @FEAT-009 @AC-009-089 @HV-DAT-SECURITY-AC089
  Scenario: AC-009-089 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

