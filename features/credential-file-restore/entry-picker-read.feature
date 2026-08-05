@FEAT-009
Feature: Credential file restore — Entry, picker, and read custody
  Covers HV-DAT-ENTRY, HV-DAT-PICKER, HV-DAT-READ, HV-DAT-TEMP, HV-DAT-SOURCE.

  @FEAT-009 @AC-009-001 @HV-DAT-ENTRY-AC001
  Scenario: AC-009-001 — HV-DAT-ENTRY
    Given verified empty local state
    When the entry guard inspects the local authority
    Then restore starts only with verified absence of active, staged, rollback, removal, quarantined, or competing authority

  @FEAT-009 @AC-009-002 @HV-DAT-ENTRY-AC002
  Scenario: AC-009-002 — HV-DAT-ENTRY
    Given verified empty local state
    When the entry guard inspects the local authority
    Then restore starts only with verified absence of active, staged, rollback, removal, quarantined, or competing authority

  @FEAT-009 @AC-009-003 @HV-DAT-ENTRY-AC003
  Scenario: AC-009-003 — HV-DAT-ENTRY
    Given verified empty local state
    When the entry guard inspects the local authority
    Then restore starts only with verified absence of active, staged, rollback, removal, quarantined, or competing authority

  @FEAT-009 @AC-009-004 @HV-DAT-PICKER-AC004
  Scenario: AC-009-004 — HV-DAT-PICKER
    Given one source is selected through the platform picker
    When the picker outcome is projected
    Then exactly one file is accepted per attempt and cancel is neutral with no identifier shown

  @FEAT-009 @AC-009-005 @HV-DAT-PICKER-AC005
  Scenario: AC-009-005 — HV-DAT-PICKER
    Given one source is selected through the platform picker
    When the picker outcome is projected
    Then exactly one file is accepted per attempt and cancel is neutral with no identifier shown

  @FEAT-009 @AC-009-006 @HV-DAT-PICKER-AC006
  Scenario: AC-009-006 — HV-DAT-PICKER
    Given one source is selected through the platform picker
    When the picker outcome is projected
    Then exactly one file is accepted per attempt and cancel is neutral with no identifier shown

  @FEAT-009 @AC-009-007 @HV-DAT-READ-AC007
  Scenario: AC-009-007 — HV-DAT-READ
    Given a bounded source stream is open
    When the read enforces the hard bound and inactivity budget
    Then at most 1 MiB plus one overflow byte is accepted and partial or timed-out reads are cleared

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

  @FEAT-009 @AC-009-010 @HV-DAT-READ-AC010
  Scenario: AC-009-010 — HV-DAT-READ
    Given a bounded source stream is open
    When the read enforces the hard bound and inactivity budget
    Then at most 1 MiB plus one overflow byte is accepted and partial or timed-out reads are cleared

  @FEAT-009 @AC-009-011 @HV-DAT-READ-AC011
  Scenario: AC-009-011 — HV-DAT-READ
    Given a bounded source stream is open
    When the read enforces the hard bound and inactivity budget
    Then at most 1 MiB plus one overflow byte is accepted and partial or timed-out reads are cleared

  @FEAT-009 @AC-009-012 @HV-DAT-TEMP-AC012
  Scenario: AC-009-012 — HV-DAT-TEMP
    Given an unavoidable temporary ciphertext copy exists
    When cleanup runs on the current path
    Then app-private no-backup storage is used and verified cleanup covers every path and startup

  @FEAT-009 @AC-009-035 @HV-DAT-SOURCE-AC035
  Scenario: AC-009-035 — HV-DAT-SOURCE
    Given the source file is selected
    When the import epoch completes or fails
    Then the source remains byte-for-byte unchanged with no durable copy, grant, path, or metadata retained

  @FEAT-009 @AC-009-036 @HV-DAT-SOURCE-AC036
  Scenario: AC-009-036 — HV-DAT-SOURCE
    Given the source file is selected
    When the import epoch completes or fails
    Then the source remains byte-for-byte unchanged with no durable copy, grant, path, or metadata retained

  @FEAT-009 @AC-009-037 @HV-DAT-SOURCE-AC037
  Scenario: AC-009-037 — HV-DAT-SOURCE
    Given the source file is selected
    When the import epoch completes or fails
    Then the source remains byte-for-byte unchanged with no durable copy, grant, path, or metadata retained

