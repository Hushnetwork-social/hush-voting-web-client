@FEAT-008
Feature: Recovery words — protection-staging-session
  Covers HV-RW-PASSWORD, HV-RW-PASSKEY, HV-RW-NATIVE-PASSWORDLESS, HV-RW-SESSION, HV-RW-STAGE.

  @FEAT-008 @AC-008-036 @HV-RW-PASSWORD-001
  Scenario: AC-008-036 — HV-RW-PASSWORD
    Given the protection screen
    When the user chooses protection
    Then Device-password is checked by default and secrets enter the authority directly

  @FEAT-008 @AC-008-037 @HV-RW-STAGE-001
  Scenario: AC-008-037 — HV-RW-STAGE
    Given selected keys and a protection mode
    When encrypted staging runs
    Then selected keys stage atomically with read-back verification before mnemonic destruction

  @FEAT-008 @AC-008-038 @HV-RW-SESSION-001
  Scenario: AC-008-038 — HV-RW-SESSION
    Given explicit session-only selection
    When the session authority is issued
    Then nothing persists and recovery is required after authority loss

  @FEAT-008 @AC-008-040 @HV-RW-PASSWORD-002
  Scenario: AC-008-040 — HV-RW-PASSWORD
    Given the protection screen
    When the user chooses protection
    Then Device-password is checked by default and secrets enter the authority directly

  @FEAT-008 @AC-008-041 @HV-RW-PASSWORD-003
  Scenario: AC-008-041 — HV-RW-PASSWORD
    Given the protection screen
    When the user chooses protection
    Then Device-password is checked by default and secrets enter the authority directly

  @FEAT-008 @AC-008-042 @HV-RW-PASSKEY-001
  Scenario: AC-008-042 — HV-RW-PASSKEY
    Given passwordless Web selection
    When WebAuthn PRF qualification is evaluated
    Then qualified platform/PRF/RP checks gate persistence and failures offer no silent fallback

  @FEAT-008 @AC-008-043 @HV-RW-PASSKEY-002
  Scenario: AC-008-043 — HV-RW-PASSKEY
    Given passwordless Web selection
    When WebAuthn PRF qualification is evaluated
    Then qualified platform/PRF/RP checks gate persistence and failures offer no silent fallback

  @FEAT-008 @AC-008-044 @HV-RW-PASSKEY-003
  Scenario: AC-008-044 — HV-RW-PASSKEY
    Given passwordless Web selection
    When WebAuthn PRF qualification is evaluated
    Then qualified platform/PRF/RP checks gate persistence and failures offer no silent fallback

  @FEAT-008 @AC-008-045 @HV-RW-PASSKEY-004
  Scenario: AC-008-045 — HV-RW-PASSKEY
    Given passwordless Web selection
    When WebAuthn PRF qualification is evaluated
    Then qualified platform/PRF/RP checks gate persistence and failures offer no silent fallback

  @FEAT-008 @AC-008-046 @HV-RW-PASSKEY-005
  Scenario: AC-008-046 — HV-RW-PASSKEY
    Given passwordless Web selection
    When WebAuthn PRF qualification is evaluated
    Then qualified platform/PRF/RP checks gate persistence and failures offer no silent fallback

  @FEAT-008 @AC-008-047 @HV-RW-PASSKEY-006
  Scenario: AC-008-047 — HV-RW-PASSKEY
    Given passwordless Web selection
    When WebAuthn PRF qualification is evaluated
    Then qualified platform/PRF/RP checks gate persistence and failures offer no silent fallback

  @FEAT-008 @AC-008-048 @HV-RW-NATIVE-PASSWORDLESS-001
  Scenario: AC-008-048 — HV-RW-NATIVE-PASSWORDLESS
    Given a native platform
    When passwordless native protection is selected
    Then qualified Secret Service or hardware-backed Keystore gates persistence and warns honestly

  @FEAT-008 @AC-008-049 @HV-RW-NATIVE-PASSWORDLESS-002
  Scenario: AC-008-049 — HV-RW-NATIVE-PASSWORDLESS
    Given a native platform
    When passwordless native protection is selected
    Then qualified Secret Service or hardware-backed Keystore gates persistence and warns honestly

  @FEAT-008 @AC-008-050 @HV-RW-NATIVE-PASSWORDLESS-003
  Scenario: AC-008-050 — HV-RW-NATIVE-PASSWORDLESS
    Given a native platform
    When passwordless native protection is selected
    Then qualified Secret Service or hardware-backed Keystore gates persistence and warns honestly

  @FEAT-008 @AC-008-051 @HV-RW-SESSION-002
  Scenario: AC-008-051 — HV-RW-SESSION
    Given explicit session-only selection
    When the session authority is issued
    Then nothing persists and recovery is required after authority loss

  @FEAT-008 @AC-008-053 @HV-RW-STAGE-002
  Scenario: AC-008-053 — HV-RW-STAGE
    Given selected keys and a protection mode
    When encrypted staging runs
    Then selected keys stage atomically with read-back verification before mnemonic destruction

  @FEAT-008 @AC-008-054 @HV-RW-STAGE-003
  Scenario: AC-008-054 — HV-RW-STAGE
    Given selected keys and a protection mode
    When encrypted staging runs
    Then selected keys stage atomically with read-back verification before mnemonic destruction

  @FEAT-008 @AC-008-055 @HV-RW-STAGE-004
  Scenario: AC-008-055 — HV-RW-STAGE
    Given selected keys and a protection mode
    When encrypted staging runs
    Then selected keys stage atomically with read-back verification before mnemonic destruction

  @FEAT-008 @AC-008-060 @HV-RW-SESSION-003
  Scenario: AC-008-060 — HV-RW-SESSION
    Given explicit session-only selection
    When the session authority is issued
    Then nothing persists and recovery is required after authority loss

  @FEAT-008 @AC-008-081 @HV-RW-PASSKEY-007
  Scenario: AC-008-081 — HV-RW-PASSKEY
    Given passwordless Web selection
    When WebAuthn PRF qualification is evaluated
    Then qualified platform/PRF/RP checks gate persistence and failures offer no silent fallback
