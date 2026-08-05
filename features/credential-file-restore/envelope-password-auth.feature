@FEAT-009
Feature: Credential file restore — Envelope, password, and backoff
  Covers HV-DAT-ENVELOPE, HV-DAT-PASSWORD, HV-DAT-BACKOFF, HV-DAT-AUTH.

  @FEAT-009 @AC-009-013 @HV-DAT-ENVELOPE-AC013
  Scenario: AC-009-013 — HV-DAT-ENVELOPE
    Given a HUSH v1 envelope is inspected
    When the structural gate runs before password use
    Then magic, little-endian version one, salt, nonce, and ciphertext bounds are validated with safe pre-password errors

  @FEAT-009 @AC-009-014 @HV-DAT-ENVELOPE-AC014
  Scenario: AC-009-014 — HV-DAT-ENVELOPE
    Given a HUSH v1 envelope is inspected
    When the structural gate runs before password use
    Then magic, little-endian version one, salt, nonce, and ciphertext bounds are validated with safe pre-password errors

  @FEAT-009 @AC-009-015 @HV-DAT-ENVELOPE-AC015
  Scenario: AC-009-015 — HV-DAT-ENVELOPE
    Given a HUSH v1 envelope is inspected
    When the structural gate runs before password use
    Then magic, little-endian version one, salt, nonce, and ciphertext bounds are validated with safe pre-password errors

  @FEAT-009 @AC-009-016 @HV-DAT-PASSWORD-AC016
  Scenario: AC-009-016 — HV-DAT-PASSWORD
    Given the Backup-file password field is ready
    When exact legacy password bytes are submitted
    Then exact untrimmed UTF-8 up to 4096 bytes is used with explicit-only empty option and no Device-password policy

  @FEAT-009 @AC-009-017 @HV-DAT-PASSWORD-AC017
  Scenario: AC-009-017 — HV-DAT-PASSWORD
    Given the Backup-file password field is ready
    When exact legacy password bytes are submitted
    Then exact untrimmed UTF-8 up to 4096 bytes is used with explicit-only empty option and no Device-password policy

  @FEAT-009 @AC-009-018 @HV-DAT-PASSWORD-AC018
  Scenario: AC-009-018 — HV-DAT-PASSWORD
    Given the Backup-file password field is ready
    When exact legacy password bytes are submitted
    Then exact untrimmed UTF-8 up to 4096 bytes is used with explicit-only empty option and no Device-password policy

  @FEAT-009 @AC-009-019 @HV-DAT-AUTH-AC019
  Scenario: AC-009-019 — HV-DAT-AUTH
    Given an AES-GCM authentication attempt fails
    When the combined outcome is projected
    Then the wrong-password-or-damaged message is shown without cause inference and all secret state is destroyed

  @FEAT-009 @AC-009-020 @HV-DAT-BACKOFF-AC020
  Scenario: AC-009-020 — HV-DAT-BACKOFF
    Given repeated authenticated-decryption failures occur
    When the authority-wide counter is evaluated
    Then the exact 2/4/8/16/30-second delay sequence applies across files and resets only on complete validation

  @FEAT-009 @AC-009-021 @HV-DAT-BACKOFF-AC021
  Scenario: AC-009-021 — HV-DAT-BACKOFF
    Given repeated authenticated-decryption failures occur
    When the authority-wide counter is evaluated
    Then the exact 2/4/8/16/30-second delay sequence applies across files and resets only on complete validation

  @FEAT-009 @AC-009-022 @HV-DAT-AUTH-AC022
  Scenario: AC-009-022 — HV-DAT-AUTH
    Given an AES-GCM authentication attempt fails
    When the combined outcome is projected
    Then the wrong-password-or-damaged message is shown without cause inference and all secret state is destroyed

