@FEAT-010
Feature: HushVoting real-root Web acceptance matrix — FEAT-010
  Covers HV-AUTH-ROOT, HV-AUTH-COMPOSE, HV-AUTH-START, HV-AUTH-LOCK,
  HV-AUTH-REMOVE, HV-AUTH-NAV, HV-AUTH-OFFLINE, HV-AUTH-PASSWORD,
  HV-AUTH-HOME, HV-AUTH-SECURITY for the Web target. Secret-bearing
  scenarios MUST disable screenshots/traces/video/DOM snapshots before any
  password, word, or file material appears (capture is OFF by default in the
  config; steps never enable it for these scenarios).

  @FEAT-010 @AC-010-001 @AC-010-002 @AC-010-003 @AC-010-007 @HV-AUTH-ROOT-001
  Scenario: The real root mounts the real composition and shows exactly three first-run choices
    Given the ordinary development server serves the real root
    When a fresh browser context opens the root
    Then the real target-aware composition is selected and never a synthetic actor
    And Create User, Restore Credential File, and Restore Recovery Words are shown with equal primary weight
    And no password field exists anywhere on the entry
    And the visible URL stays root-only

  @FEAT-010 @AC-010-012 @AC-010-013 @HV-AUTH-ROOT-002
  Scenario: A child flow cannot grant protected access without fresh exact verification
    Given the first-run entry renders
    When Create User is selected
    Then the real child flow mounts without a placeholder
    And the URL stays root-only

  @FEAT-010 @AC-010-029 @AC-010-036 @HV-AUTH-PASSWORD-001
  Scenario: Returning unlock shows the locked preview and a combined credential error
    Given a provisioned vault exists on this device
    When the returning user submits a wrong device password
    Then the combined credential error is shown
    And the user stays locked with the safe identity preview only

  @FEAT-010 @AC-010-027 @AC-010-028 @HV-AUTH-START-001
  Scenario: A persistent user always starts locked after a restart
    Given a provisioned vault exists on this device
    When the application restarts
    Then the locked surface shows only safe identity preview fields
    And no protected content mounts

  @FEAT-010 @AC-010-062 @HV-AUTH-LOCK-001 @server-fixture
  Scenario: Global Lock revokes capability and unmounts protected content
    Given an authenticated session is active
    When the user locks the device
    Then protected content unmounts and the locked surface returns
    And no secret-bearing evidence is captured

  @FEAT-010 @AC-010-073 @AC-010-074 @AC-010-075 @HV-AUTH-REMOVE-001
  Scenario: Removal verifies absence before first-run returns
    Given a provisioned vault exists on this device
    When the user confirms local removal
    Then every vault artifact is deleted and verified absent
    And the three first-run choices return

  @FEAT-010 @AC-010-083 @AC-010-084 @AC-010-085 @HV-AUTH-NAV-001
  Scenario: Back from a selected flow returns to first-run without leaving root
    Given the first-run entry renders
    When the user selects Create User and then goes Back
    Then the first-run entry returns
    And the visible URL stays root-only

  @FEAT-010 @AC-010-047 @AC-010-048 @HV-AUTH-OFFLINE-001
  Scenario: A server outage is typed and retryable, never fabricated success
    Given a provisioned vault exists on this device
    And the identity lookup endpoint is unreachable
    When verification is attempted
    Then the offline retry surface is shown with a bounded retry
    And no success is ever claimed

  @FEAT-010 @AC-010-089 @AC-010-097 @HV-AUTH-SECURITY-001
  Scenario: Evidence capture stays disabled for secret-bearing flows
    Given a secret-bearing journey is about to run
    When the scenario executes
    Then no screenshot, trace, video, DOM snapshot, or raw log is captured
    And artifact scans find no credential, identity, endpoint, or file material
