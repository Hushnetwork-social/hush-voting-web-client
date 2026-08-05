@FEAT-009
Feature: Credential file restore — Strict schema, key proof, and mnemonic
  Covers HV-DAT-SCHEMA, HV-DAT-KEYS, HV-DAT-MNEMONIC.

  @FEAT-009 @AC-009-023 @HV-DAT-SCHEMA-AC023
  Scenario: AC-009-023 — HV-DAT-SCHEMA
    Given authenticated portable credential JSON is present
    When strict duplicate-safe parsing runs
    Then duplicate, unknown, missing, wrong-type, and oversized fields are rejected before object construction

  @FEAT-009 @AC-009-024 @HV-DAT-KEYS-AC024
  Scenario: AC-009-024 — HV-DAT-KEYS
    Given concrete signing and encryption pairs are present
    When local key-control proof runs
    Then both private keys independently derive exact stored public addresses and pass domain-separated consistency checks before lookup

  @FEAT-009 @AC-009-025 @HV-DAT-KEYS-AC025
  Scenario: AC-009-025 — HV-DAT-KEYS
    Given concrete signing and encryption pairs are present
    When local key-control proof runs
    Then both private keys independently derive exact stored public addresses and pass domain-separated consistency checks before lookup

  @FEAT-009 @AC-009-026 @HV-DAT-KEYS-AC026
  Scenario: AC-009-026 — HV-DAT-KEYS
    Given concrete signing and encryption pairs are present
    When local key-control proof runs
    Then both private keys independently derive exact stored public addresses and pass domain-separated consistency checks before lookup

  @FEAT-009 @AC-009-027 @HV-DAT-MNEMONIC-AC027
  Scenario: AC-009-027 — HV-DAT-MNEMONIC
    Given an optional mnemonic is present
    When mnemonic consistency validation runs
    Then a present mnemonic must derive both pairs exactly and is destroyed without persistence or reveal

  @FEAT-009 @AC-009-028 @HV-DAT-MNEMONIC-AC028
  Scenario: AC-009-028 — HV-DAT-MNEMONIC
    Given an optional mnemonic is present
    When mnemonic consistency validation runs
    Then a present mnemonic must derive both pairs exactly and is destroyed without persistence or reveal

  @FEAT-009 @AC-009-029 @HV-DAT-KEYS-AC029
  Scenario: AC-009-029 — HV-DAT-KEYS
    Given concrete signing and encryption pairs are present
    When local key-control proof runs
    Then both private keys independently derive exact stored public addresses and pass domain-separated consistency checks before lookup

  @FEAT-009 @AC-009-030 @HV-DAT-KEYS-AC030
  Scenario: AC-009-030 — HV-DAT-KEYS
    Given concrete signing and encryption pairs are present
    When local key-control proof runs
    Then both private keys independently derive exact stored public addresses and pass domain-separated consistency checks before lookup

  @FEAT-009 @AC-009-031 @HV-DAT-SCHEMA-AC031
  Scenario: AC-009-031 — HV-DAT-SCHEMA
    Given authenticated portable credential JSON is present
    When strict duplicate-safe parsing runs
    Then duplicate, unknown, missing, wrong-type, and oversized fields are rejected before object construction

  @FEAT-009 @AC-009-032 @HV-DAT-KEYS-AC032
  Scenario: AC-009-032 — HV-DAT-KEYS
    Given concrete signing and encryption pairs are present
    When local key-control proof runs
    Then both private keys independently derive exact stored public addresses and pass domain-separated consistency checks before lookup

  @FEAT-009 @AC-009-033 @HV-DAT-MNEMONIC-AC033
  Scenario: AC-009-033 — HV-DAT-MNEMONIC
    Given an optional mnemonic is present
    When mnemonic consistency validation runs
    Then a present mnemonic must derive both pairs exactly and is destroyed without persistence or reveal

  @FEAT-009 @AC-009-034 @HV-DAT-MNEMONIC-AC034
  Scenario: AC-009-034 — HV-DAT-MNEMONIC
    Given an optional mnemonic is present
    When mnemonic consistency validation runs
    Then a present mnemonic must derive both pairs exactly and is destroyed without persistence or reveal

