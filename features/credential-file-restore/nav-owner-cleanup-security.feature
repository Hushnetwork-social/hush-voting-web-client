@FEAT-009
Feature: Credential file restore — Navigation, ownership, cleanup, and security
  Covers HV-DAT-NAV, HV-DAT-OWNER, HV-DAT-CLEANUP, HV-DAT-EXTERNAL, HV-DAT-SECURITY.

  @FEAT-009 @AC-009-064 @HV-DAT-NAV-AC064
  Scenario: AC-009-064 — HV-DAT-NAV
    Given a navigation event occurs
    When the shared Back authority evaluates the stage
    Then pre-decryption clears, post-validation destroys, and post-stage locks with visible URL remaining root

  @FEAT-009 @AC-009-065 @HV-DAT-NAV-AC065
  Scenario: AC-009-065 — HV-DAT-NAV
    Given a navigation event occurs
    When the shared Back authority evaluates the stage
    Then pre-decryption clears, post-validation destroys, and post-stage locks with visible URL remaining root

  @FEAT-009 @AC-009-066 @HV-DAT-NAV-AC066
  Scenario: AC-009-066 — HV-DAT-NAV
    Given a navigation event occurs
    When the shared Back authority evaluates the stage
    Then pre-decryption clears, post-validation destroys, and post-stage locks with visible URL remaining root

  @FEAT-009 @AC-009-067 @HV-DAT-NAV-AC067
  Scenario: AC-009-067 — HV-DAT-NAV
    Given a navigation event occurs
    When the shared Back authority evaluates the stage
    Then pre-decryption clears, post-validation destroys, and post-stage locks with visible URL remaining root

  @FEAT-009 @AC-009-068 @HV-DAT-NAV-AC068
  Scenario: AC-009-068 — HV-DAT-NAV
    Given a navigation event occurs
    When the shared Back authority evaluates the stage
    Then pre-decryption clears, post-validation destroys, and post-stage locks with visible URL remaining root

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

  @FEAT-009 @AC-009-071 @HV-DAT-CLEANUP-AC071
  Scenario: AC-009-071 — HV-DAT-CLEANUP
    Given logout or removal is requested
    When managed cleanup verification runs
    Then all HushVoting-managed data is removed, the external source is never targeted, and failure quarantines

  @FEAT-009 @AC-009-072 @HV-DAT-CLEANUP-AC072
  Scenario: AC-009-072 — HV-DAT-CLEANUP
    Given logout or removal is requested
    When managed cleanup verification runs
    Then all HushVoting-managed data is removed, the external source is never targeted, and failure quarantines

  @FEAT-009 @AC-009-073 @HV-DAT-EXTERNAL-AC073
  Scenario: AC-009-073 — HV-DAT-EXTERNAL
    Given controlled external qualification is invoked locally
    When the isolated harness guard runs
    Then execution is refused on unsafe networks or recordings and aggregate-only evidence is emitted

  @FEAT-009 @AC-009-074 @HV-DAT-EXTERNAL-AC074
  Scenario: AC-009-074 — HV-DAT-EXTERNAL
    Given controlled external qualification is invoked locally
    When the isolated harness guard runs
    Then execution is refused on unsafe networks or recordings and aggregate-only evidence is emitted

  @FEAT-009 @AC-009-075 @HV-DAT-EXTERNAL-AC075
  Scenario: AC-009-075 — HV-DAT-EXTERNAL
    Given controlled external qualification is invoked locally
    When the isolated harness guard runs
    Then execution is refused on unsafe networks or recordings and aggregate-only evidence is emitted

  @FEAT-009 @AC-009-076 @HV-DAT-EXTERNAL-AC076
  Scenario: AC-009-076 — HV-DAT-EXTERNAL
    Given controlled external qualification is invoked locally
    When the isolated harness guard runs
    Then execution is refused on unsafe networks or recordings and aggregate-only evidence is emitted

  @FEAT-009 @AC-009-077 @HV-DAT-EXTERNAL-AC077
  Scenario: AC-009-077 — HV-DAT-EXTERNAL
    Given controlled external qualification is invoked locally
    When the isolated harness guard runs
    Then execution is refused on unsafe networks or recordings and aggregate-only evidence is emitted

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

  @FEAT-009 @AC-009-081 @HV-DAT-SECURITY-AC081
  Scenario: AC-009-081 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

  @FEAT-009 @AC-009-082 @HV-DAT-SECURITY-AC082
  Scenario: AC-009-082 — HV-DAT-SECURITY
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

  @FEAT-009 @AC-009-087 @HV-DAT-SECURITY-AC087
  Scenario: AC-009-087 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

  @FEAT-009 @AC-009-088 @HV-DAT-SECURITY-AC088
  Scenario: AC-009-088 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

  @FEAT-009 @AC-009-089 @HV-DAT-SECURITY-AC089
  Scenario: AC-009-089 — HV-DAT-SECURITY
    Given secret-bearing scenarios are configured
    When capture policy and scanners run
    Then trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material

