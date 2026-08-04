@FEAT-007
Feature: Identity create — entry, preflight, profile, generation
  Covers HV-ID-CREATE-ENTRY, HV-ID-CREATE-PROFILE, HV-ID-CREATE-GENERATE.

  @FEAT-007 @AC-007-001 @HV-ID-CREATE-ENTRY-001
  Scenario: The no-local-user entry offers exactly three equal primary choices
    Given there is no local user
    When the first-run entry renders
    Then Create User, Restore Credential File, and Restore Recovery Words are shown with equal primary weight
    And no password field exists anywhere on the entry

  @FEAT-007 @AC-007-002 @HV-ID-CREATE-ENTRY-002
  Scenario: Create User runs the platform security preflight before collecting anything
    Given the user selects Create User
    When the active platform's security and durable-persistence preflight runs
    Then alias collection and secret generation are blocked until the preflight passes
    And an unsupported or unsafe capability fails closed without collecting an alias

  @FEAT-007 @AC-007-063 @HV-ID-CREATE-ENTRY-003
  Scenario: The browser adapter is the only web storage authority
    Given a Web runtime
    When composition resolves the creation authority
    Then the Web-only worker/IndexedDB adapter is selected
    And native static builds can never select that adapter

  @FEAT-007 @AC-007-068 @HV-ID-CREATE-ENTRY-004
  Scenario: Entry and profile surfaces meet WCAG 2.2 AA and responsive rules
    Given desktop, mobile, and zoomed viewports
    When the entry, preflight, profile, and generation screens render
    Then no horizontal scrolling occurs at 320 CSS px
    And every interactive target is at least 44x44 CSS px
    And focus, labels, and error summaries are accessible

  @FEAT-007 @AC-007-003 @HV-ID-CREATE-PROFILE-001
  Scenario: Alias normalization follows the exact profile contract
    Given a new alias with outer Unicode whitespace
    When profile validation runs
    Then the alias is trimmed, normalized to NFC, and accepted within 1-64 graphemes and 256 UTF-8 bytes
    And disallowed controls, bidi, and unsafe invisible characters are rejected

  @FEAT-007 @AC-007-004 @HV-ID-CREATE-PROFILE-002
  Scenario: Private is the default and Public requires acknowledgement
    Given the Profile screen renders
    When the user reviews visibility
    Then Private is selected by default
    And choosing Public shows a plain-language exposure/permanence warning requiring explicit acknowledgement

  @FEAT-007 @AC-007-051 @HV-ID-CREATE-PROFILE-003
  Scenario: Initial visibility is immutable through the current interface
    Given a confirmed identity
    When the user attempts to change visibility via a duplicate FullIdentity submission
    Then FEAT-007 never misuses duplicate submission as an update
    And the initial visibility remains blockchain-authoritative

  @FEAT-007 @AC-007-005 @HV-ID-CREATE-GENERATE-001
  Scenario: No password participates in identity derivation
    Given a profile with alias and visibility
    When the identity is generated
    Then no password, alias, visibility, endpoint, or device property contributes to mnemonic/key/address derivation

  @FEAT-007 @AC-007-006 @HV-ID-CREATE-GENERATE-002
  Scenario: The authority creates exactly one valid P-01 candidate
    Given the platform preflight passed
    When the user explicitly generates recovery words
    Then exactly one valid 24-word English BIP-39 identity is produced with CSPRNG entropy and approved HKDF labels
    And compressed public addresses match the FEAT-001 corpus

  @FEAT-007 @AC-007-007 @HV-ID-CREATE-GENERATE-003
  Scenario: Hidden invalid candidates are destroyed before display
    Given a candidate whose hidden scalar or derivation validation fails
    When generation retries
    Then the complete invalid candidate is destroyed and fresh entropy regenerates within a bounded attempt count
    And no invalid phrase is ever revealed

  @FEAT-007 @AC-007-008 @HV-ID-CREATE-GENERATE-004
  Scenario: Regeneration requires destructive confirmation and never substitutes silently
    Given words have been displayed for a candidate
    When the user requests Regenerate
    Then a destructive confirmation is required
    And the complete old candidate is destroyed, confirmation state resets, and a wholly new candidate is created

  @FEAT-007 @AC-007-009 @HV-ID-CREATE-GENERATE-005
  Scenario: Generation timing meets the documented budgets
    Given explicit generation starts
    When progress becomes visible
    Then progress appears after 150 ms
    And generation completes within 1 second on the minimum supported class, never exceeding the 10 second hard bound

  @FEAT-007 @AC-007-074 @HV-ID-CREATE-GENERATE-006
  Scenario: Performance budgets never weaken cryptography or skip validation
    Given the generation and KDF gates run
    When resource limits are applied
    Then timing budgets pass without skipping lookup, weakening cryptography, or increasing secret exposure
