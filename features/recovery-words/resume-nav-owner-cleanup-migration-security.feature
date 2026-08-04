@FEAT-008
Feature: Recovery words — resume-nav-owner-cleanup-migration-security
  Covers HV-RW-RESUME, HV-RW-NAV, HV-RW-OWNER, HV-RW-CLEANUP, HV-RW-MIGRATION, HV-RW-SECURITY.

  @FEAT-008 @AC-008-039 @HV-RW-SECURITY-001
  Scenario: AC-008-039 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-052 @HV-RW-SECURITY-002
  Scenario: AC-008-052 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-056 @HV-RW-RESUME-001
  Scenario: AC-008-056 — HV-RW-RESUME
    Given staged selected keys after restart
    When startup inspection runs
    Then Finish restoring your identity is shown and words are never reconstructed

  @FEAT-008 @AC-008-062 @HV-RW-RESUME-002
  Scenario: AC-008-062 — HV-RW-RESUME
    Given staged selected keys after restart
    When startup inspection runs
    Then Finish restoring your identity is shown and words are never reconstructed

  @FEAT-008 @AC-008-063 @HV-RW-RESUME-003
  Scenario: AC-008-063 — HV-RW-RESUME
    Given staged selected keys after restart
    When startup inspection runs
    Then Finish restoring your identity is shown and words are never reconstructed

  @FEAT-008 @AC-008-064 @HV-RW-NAV-001
  Scenario: AC-008-064 — HV-RW-NAV
    Given a recovery workflow step
    When Back is invoked at any stage
    Then root-only navigation clears, destroys, or locks per stage without history restoration

  @FEAT-008 @AC-008-065 @HV-RW-NAV-002
  Scenario: AC-008-065 — HV-RW-NAV
    Given a recovery workflow step
    When Back is invoked at any stage
    Then root-only navigation clears, destroys, or locks per stage without history restoration

  @FEAT-008 @AC-008-066 @HV-RW-OWNER-001
  Scenario: AC-008-066 — HV-RW-OWNER
    Given one live recovery owner
    When another tab attempts recovery
    Then the non-owner is blocked with a safe notification and no secret data is broadcast

  @FEAT-008 @AC-008-067 @HV-RW-OWNER-002
  Scenario: AC-008-067 — HV-RW-OWNER
    Given one live recovery owner
    When another tab attempts recovery
    Then the non-owner is blocked with a safe notification and no secret data is broadcast

  @FEAT-008 @AC-008-068 @HV-RW-CLEANUP-001
  Scenario: AC-008-068 — HV-RW-CLEANUP
    Given a completed local removal
    When cleanup verification runs
    Then every managed artifact is removed and failure quarantines recovery

  @FEAT-008 @AC-008-069 @HV-RW-CLEANUP-002
  Scenario: AC-008-069 — HV-RW-CLEANUP
    Given a completed local removal
    When cleanup verification runs
    Then every managed artifact is removed and failure quarantines recovery

  @FEAT-008 @AC-008-070 @HV-RW-CLEANUP-003
  Scenario: AC-008-070 — HV-RW-CLEANUP
    Given a completed local removal
    When cleanup verification runs
    Then every managed artifact is removed and failure quarantines recovery

  @FEAT-008 @AC-008-071 @HV-RW-SECURITY-003
  Scenario: AC-008-071 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-072 @HV-RW-MIGRATION-001
  Scenario: AC-008-072 — HV-RW-MIGRATION
    Given an older vault with an encrypted mnemonic record
    When migration runs
    Then mnemonic ciphertext is omitted and deleted atomically without loading or displaying it

  @FEAT-008 @AC-008-073 @HV-RW-SECURITY-004
  Scenario: AC-008-073 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-074 @HV-RW-SECURITY-005
  Scenario: AC-008-074 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-075 @HV-RW-SECURITY-006
  Scenario: AC-008-075 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-076 @HV-RW-SECURITY-007
  Scenario: AC-008-076 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-077 @HV-RW-SECURITY-008
  Scenario: AC-008-077 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-078 @HV-RW-SECURITY-009
  Scenario: AC-008-078 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-079 @HV-RW-SECURITY-010
  Scenario: AC-008-079 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-080 @HV-RW-SECURITY-011
  Scenario: AC-008-080 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-082 @HV-RW-MIGRATION-002
  Scenario: AC-008-082 — HV-RW-MIGRATION
    Given an older vault with an encrypted mnemonic record
    When migration runs
    Then mnemonic ciphertext is omitted and deleted atomically without loading or displaying it

  @FEAT-008 @AC-008-083 @HV-RW-SECURITY-012
  Scenario: AC-008-083 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-084 @HV-RW-SECURITY-013
  Scenario: AC-008-084 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found

  @FEAT-008 @AC-008-085 @HV-RW-SECURITY-014
  Scenario: AC-008-085 — HV-RW-SECURITY
    Given secret-bearing recovery material
    When evidence and artifact scanning runs
    Then trace/screenshot/video are disabled and no prohibited credential material is found
