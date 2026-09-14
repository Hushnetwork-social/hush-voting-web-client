@FEAT-009
Feature: Credential file restore — Strict schema, key proof, and mnemonic
  Covers HV-DAT-SCHEMA, HV-DAT-KEYS, HV-DAT-MNEMONIC.

  @FEAT-009 @AC-009-026 @HV-DAT-KEYS-AC026
  Scenario: AC-009-026 — HV-DAT-KEYS
    Given concrete signing and encryption pairs are present
    When local key-control proof runs
    Then both private keys independently derive exact stored public addresses and pass domain-separated consistency checks before lookup

