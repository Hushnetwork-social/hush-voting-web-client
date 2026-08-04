@FEAT-008
Feature: Recovery words — custody-candidates
  Covers HV-RW-CUSTODY, HV-RW-CANDIDATES, HV-RW-CONTROL.

  @FEAT-008 @AC-008-016 @HV-RW-CUSTODY-001
  Scenario: AC-008-016 — HV-RW-CUSTODY
    Given a valid phrase in the input component
    When Verify transfers the phrase to the secret authority
    Then page buffers clear and the phrase never enters state, storage, logs, or history

  @FEAT-008 @AC-008-017 @HV-RW-CUSTODY-002
  Scenario: AC-008-017 — HV-RW-CUSTODY
    Given a valid phrase in the input component
    When Verify transfers the phrase to the secret authority
    Then page buffers clear and the phrase never enters state, storage, logs, or history

  @FEAT-008 @AC-008-018 @HV-RW-CANDIDATES-001
  Scenario: AC-008-018 — HV-RW-CANDIDATES
    Given a checksum-valid phrase
    When every applicable Approved producer derives public candidates
    Then the complete deduplicated candidate set is assembled and partial sets fail closed

  @FEAT-008 @AC-008-019 @HV-RW-CANDIDATES-002
  Scenario: AC-008-019 — HV-RW-CANDIDATES
    Given a checksum-valid phrase
    When every applicable Approved producer derives public candidates
    Then the complete deduplicated candidate set is assembled and partial sets fail closed

  @FEAT-008 @AC-008-020 @HV-RW-CANDIDATES-003
  Scenario: AC-008-020 — HV-RW-CANDIDATES
    Given a checksum-valid phrase
    When every applicable Approved producer derives public candidates
    Then the complete deduplicated candidate set is assembled and partial sets fail closed

  @FEAT-008 @AC-008-021 @HV-RW-CANDIDATES-004
  Scenario: AC-008-021 — HV-RW-CANDIDATES
    Given a checksum-valid phrase
    When every applicable Approved producer derives public candidates
    Then the complete deduplicated candidate set is assembled and partial sets fail closed

  @FEAT-008 @AC-008-022 @HV-RW-CONTROL-001
  Scenario: AC-008-022 — HV-RW-CONTROL
    Given a selected candidate
    When the selected-key control proof runs locally
    Then exact signing and encryption consistency is proven before staging

  @FEAT-008 @AC-008-023 @HV-RW-CUSTODY-003
  Scenario: AC-008-023 — HV-RW-CUSTODY
    Given a valid phrase in the input component
    When Verify transfers the phrase to the secret authority
    Then page buffers clear and the phrase never enters state, storage, logs, or history
