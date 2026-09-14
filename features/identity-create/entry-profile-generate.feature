@FEAT-007
Feature: Identity create — entry, preflight, profile, generation
  Covers HV-ID-CREATE-ENTRY, HV-ID-CREATE-PROFILE, HV-ID-CREATE-GENERATE.

  @FEAT-007 @AC-007-068 @HV-ID-CREATE-ENTRY-004
  Scenario: Entry and profile surfaces meet WCAG 2.2 AA and responsive rules
    Given desktop, mobile, and zoomed viewports
    When the entry, preflight, profile, and generation screens render
    Then no horizontal scrolling occurs at 320 CSS px
    And every interactive target is at least 44x44 CSS px
    And focus, labels, and error summaries are accessible

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
