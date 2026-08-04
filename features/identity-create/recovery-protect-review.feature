@FEAT-007
Feature: Identity create — recovery words, protection, review
  Covers HV-ID-CREATE-RECOVERY, HV-ID-CREATE-PROTECT, HV-ID-CREATE-REVIEW.

  @FEAT-007 @AC-007-010 @HV-ID-CREATE-RECOVERY-001
  Scenario: Recovery words are displayed only through the bounded exception
    Given an active reveal authority
    When Save Recovery Words renders
    Then 24 numbered words are shown in a responsive semantic ordered layout
    And the reveal lasts at most 60 seconds per reveal

  @FEAT-007 @AC-007-011 @HV-ID-CREATE-RECOVERY-002
  Scenario: Concealment removes visual and accessibility content
    Given recovery words are visible
    When timeout, Back, route change, lifecycle loss, Lock, regeneration, or revocation occurs
    Then the words are concealed from both visual rendering and the accessibility tree

  @FEAT-007 @AC-007-012 @HV-ID-CREATE-RECOVERY-003
  Scenario: Copy is secondary, explicit, warned, and bounded
    Given the recovery screen is visible
    When the user copies the words
    Then the action is explicit and warned
    And the active adapter's bounded clipboard cleanup policy applies
    And browser screenshot/clipboard limitations are stated honestly

  @FEAT-007 @AC-007-013 @HV-ID-CREATE-RECOVERY-004
  Scenario: Six unpredictable distinct positions are requested in randomized order
    Given a valid candidate
    When the confirmation challenge renders
    Then six unpredictable distinct positions are requested in randomized display order
    And release builds provide no bypass

  @FEAT-007 @AC-007-014 @HV-ID-CREATE-RECOVERY-005
  Scenario: A mismatch identifies only the requested position
    Given a six-position challenge
    When one answer mismatches
    Then the error identifies only that position
    And never echoes the expected or any other word

  @FEAT-007 @AC-007-015 @HV-ID-CREATE-RECOVERY-006
  Scenario: Three failed attempts invalidate the challenge without regenerating
    Given the same candidate and challenge
    When three attempts mismatch
    Then the challenge is invalidated and protected review resumes
    And the candidate is not regenerated or exposed

  @FEAT-007 @AC-007-017 @HV-ID-CREATE-PROTECT-001
  Scenario: The Device password is collected only after recovery confirmation
    Given recovery confirmation succeeded
    When Protect this device renders
    Then a Device password and confirmation are requested through a direct authority boundary
    And the password never reaches React, XState, logs, or analytics

  @FEAT-007 @AC-007-018 @HV-ID-CREATE-PROTECT-002
  Scenario: Device and backup-file passwords are never confused or reused
    Given the Protect this device screen
    When the user enters the Device password
    Then it is never copied, prefilled, suggested, compared with, or reused as a backup-file password
    And FEAT-007 never collects a backup-file password

  @FEAT-007 @AC-007-019 @HV-ID-CREATE-PROTECT-003
  Scenario: Successful validation issues one one-use authorization
    Given a valid Device password
    When the authority validates it
    Then one purpose/channel/epoch-bound one-use provisioning authorization is issued
    And it expires after at most 60 seconds

  @FEAT-007 @AC-007-020 @HV-ID-CREATE-REVIEW-001
  Scenario: Final review contains safe fields only
    Given provisioning authorization is valid
    When Review renders
    Then normalized alias, visibility, protection/recovery state, and both abbreviated public addresses are shown
    And no private material, full address, or transaction JSON is present

  @FEAT-007 @AC-007-021 @HV-ID-CREATE-REVIEW-002
  Scenario: Create binds the reviewed fields and prevents double dispatch
    Given the review screen with a valid authorization
    When Create Identity is invoked
    Then the full reviewed fields are bound to the operation-scoped authorization
    And the action is disabled during the in-flight command with a single provisioning owner
