@FEAT-007
Feature: Identity create — staging, submission, confirmation, delay, correction, reset
  Covers HV-ID-CREATE-STAGE, HV-ID-CREATE-SUBMIT, HV-ID-CREATE-CONFIRM,
  HV-ID-CREATE-DELAY, HV-ID-CREATE-CORRECT, HV-ID-CREATE-RESET.

  @FEAT-007 @AC-007-022 @HV-ID-CREATE-STAGE-001
  Scenario: A sealed provisional record precedes any network call
    Given recovery confirmation and a valid device-password capability
    When Create Identity is invoked
    Then the credential bundle, separate mnemonic record, reviewed profile, exact signed transaction, and digest commit atomically
    And no network call occurs before read-back verification

  @FEAT-007 @AC-007-052 @HV-ID-CREATE-STAGE-004
  Scenario: Restart with a provisional record resumes safely without mnemonic reveal
    Given a provisional record exists after restart
    When the user unlocks the device
    Then Finish creating your identity shows only safe abbreviated context
    And lookup-first resume runs without revealing the mnemonic automatically

  @FEAT-007 @AC-007-048 @HV-ID-CREATE-SUBMIT-012
  Scenario: A missing transaction can be rebuilt only after verified eligibility
    Given the retained transaction record is missing
    When rebuild eligibility is evaluated
    Then authenticated credential/profile verification AND authoritative absence are both required
    And corruption never counts as missing

  @FEAT-007 @AC-007-043 @HV-ID-CREATE-CONFIRM-006
  Scenario: A revoked, expired, or restarted authority requires ordinary unlock
    Given confirmation occurred but the authority is revoked, expired, backgrounded, or restarted
    When authentication is evaluated
    Then ordinary unlock is required before entering HushVoting

  @FEAT-007 @AC-007-046 @HV-ID-CREATE-CORRECT-001
  Scenario: Editable alias rejection reopens Profile only
    Given an allowlisted editable pre-admission code
    When correction runs
    Then only Profile/Review reopens with the same identity
    And a fresh Device-password authorization is required before one new replacement transaction

  @FEAT-007 @AC-007-049 @HV-ID-CREATE-RESET-001
  Scenario: Blockchain reset re-registers the same identity
    Given a previously confirmed local identity is authoritatively absent
    When reconciliation completes credential/profile verification
    Then one fresh transaction is created from the same vault identity and latest verified encrypted profile
    And no new recovery words are generated because the chain was reset
