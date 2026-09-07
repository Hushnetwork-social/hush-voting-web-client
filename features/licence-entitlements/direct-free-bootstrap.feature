@FEAT-016
Feature: Post-login Direct Free entitlement bootstrap journeys
  FEAT-016 phase 7 canonical production-composition journeys. Scenarios
  execute against the ORDINARY production composition (real target-aware
  root, real SharedWorker authority, real sealed licence journal, real
  no-store licence BFF and real blockchain submit/query path) with a
  CONTROLLED REAL HushServerNode fixture and test-owned identities/network.
  Request interception, injected entitlement state, window state patching,
  synthetic production providers, and production-only bypasses are never
  acceptance evidence. Secret-bearing scenarios keep capture disabled.

  @EPIC-002 @AT-LIC-002 @TwinTest @Playwright @server-fixture
  Scenario: A no-active user enters only after signed Direct Free is indexed
    Given Alice has completed exact EPIC-001 identity authentication
    And Alice has no active indexed HushVoting entitlement
    When the entitlement authority requests Alice's current entitlement
    Then the workspace remains unmounted
    And the authority signs and submits one server-templated Direct Free transaction as Alice
    And ACCEPTED or PENDING does not open the workspace
    When a fresh signed query returns the indexed Direct Free entitlement
    Then HushVoting opens immediately with that safe entitlement in session memory
    And exactly one effective Direct Free assignment exists

  @EPIC-002 @AT-LIC-016-001 @Playwright @server-fixture
  Scenario: Existing active entitlement opens without extra confirmation
    Given Alice has completed exact EPIC-001 identity authentication
    When a fresh signed query returns compatible active indexed entitlement
    Then HushVoting opens workspace immediately
    And no licence success or Continue screen appears

  @EPIC-002 @AT-LIC-016-002 @Playwright @server-fixture
  Scenario: One browser authority coordinates all tabs
    Given two tabs share Alice's authenticated SharedWorker
    When both require entitlement bootstrap
    Then exactly one signed query and reconciliation loop owns the operation
    And tabs receive only the same safe progress and active projection

  @EPIC-002 @AT-LIC-016-003 @Playwright @server-fixture
  Scenario: Restart queries before resubmitting pending Direct Free
    Given Alice has an exact sealed pending Direct Free transaction
    When HushVoting restarts and Alice authenticates
    Then authority queries indexed truth before resubmission
    And clears pending when it or another valid entitlement is active
    And resubmits only exact stored transaction when truth remains no-active
