@FEAT-017
Feature: Upgrade activation progress, stale recovery, and pending indicator journeys
  FEAT-017 phase 7 canonical production-composition journeys for strict
  higher-plan activation after indexing, old-current-plus-pending across
  query/restart, the persistent pending indicator, exact local success, the
  one-time notification, competing indexed changes, stale refresh/reconfirm,
  and delayed/paused exact Retry. Real composition and controlled real
  HushServerNode fixture only; no interception, state injection, or synthetic
  provider.

  @EPIC-002 @AT-LIC-006 @TwinTest @Playwright @server-fixture
  Scenario: A strictly higher Veritas plan activates only after indexed confirmation
    Given Alice has completed exact EPIC-001 identity authentication
    And HushServerNode has indexed an active Direct Free licence for Alice
    When Alice confirms and activates a strictly higher Veritas plan
    Then pending shows the old indexed limits remain in effect and the pending target
    And no higher capability is granted before indexed confirmation
    When the exact sealed transaction is indexed for Alice
    Then the current licence becomes the higher Veritas plan with a one-year term
    And Account refreshes to the higher plan exactly once without a repeated notification

  @EPIC-002 @AT-LIC-009 @TwinTest @Playwright @server-fixture
  Scenario: A stale current-plan or catalogue precondition refreshes and requires reselection
    Given Alice has completed exact EPIC-001 identity authentication
    And Alice selected a higher Veritas plan while Direct Free was effective
    When indexed truth changes to a different compatible current licence before activation
    Then the selection is cleared and the exact changed-options message is shown
    And fresh options are presented from the authoritative query
    And activation requires a new selection and explicit confirmation

  @EPIC-002 @AT-LIC-015 @Playwright @server-fixture
  Scenario: Back and in-app navigation preserve coherent licence state
    Given Alice has completed exact EPIC-001 identity authentication
    And HushServerNode has indexed an active Direct Free licence for Alice
    When Alice selects a higher Veritas plan and uses in-app Back
    Then the options surface returns with no draft and no submitted transaction
    When Alice opens a plan and uses browser Back
    Then the safe shell state returns without duplicate activation or stale plan display

  @EPIC-002 @AT-LIC-016 @Playwright @server-fixture
  Scenario: Licence surfaces are accessible and responsive across supported Web viewports
    Given Alice has completed exact EPIC-001 identity authentication
    And HushServerNode has indexed an active Direct Free licence for Alice
    When Alice uses only the keyboard at each supported Web viewport
    Then she can open and close the account popup and reach the Upgrade action
    And focus is trapped and restored correctly for the popup and confirmation
    And current, activating, unavailable, conflict, and error states have programmatic names
    And plan meaning is not communicated by colour alone
    And no control or status is clipped or hidden by overflow
