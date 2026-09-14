@FEAT-009
Feature: Credential file restore — Entry, picker, and read custody
  Covers HV-DAT-ENTRY, HV-DAT-PICKER, HV-DAT-READ, HV-DAT-TEMP, HV-DAT-SOURCE.

  @FEAT-009 @AC-009-008 @HV-DAT-PICKER-AC008
  Scenario: AC-009-008 — HV-DAT-PICKER
    Given one source is selected through the platform picker
    When the picker outcome is projected
    Then exactly one file is accepted per attempt and cancel is neutral with no identifier shown

  @FEAT-009 @AC-009-009 @HV-DAT-PICKER-AC009
  Scenario: AC-009-009 — HV-DAT-PICKER
    Given one source is selected through the platform picker
    When the picker outcome is projected
    Then exactly one file is accepted per attempt and cancel is neutral with no identifier shown

  @FEAT-009 @AC-009-012 @HV-DAT-TEMP-AC012
  Scenario: AC-009-012 — HV-DAT-TEMP
    Given an unavoidable temporary ciphertext copy exists
    When cleanup runs on the current path
    Then app-private no-backup storage is used and verified cleanup covers every path and startup

