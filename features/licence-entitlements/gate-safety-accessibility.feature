@FEAT-016
Feature: Entitlement gate safety and accessibility journeys
  FEAT-016 phase 7 canonical production-composition journeys for Lock/stale
  result rejection, incompatible projections, Back behavior, and assistive
  technology. Real composition and controlled real HushServerNode fixture
  only; no interception, state injection, or synthetic provider.

  @EPIC-002 @AT-LIC-011 @TwinTest @Playwright @server-fixture
  Scenario: Lock prevents a late entitlement result from restoring access
    Given Alice is authenticated and entitlement resolution is in progress
    When Alice Locks HushVoting
    And the old operation completes later
    Then its stale epoch result is ignored
    And the workspace remains unmounted
    And no Alice entitlement is available to a later identity

  @EPIC-002 @AT-LIC-012 @TwinTest @Playwright @server-fixture
  Scenario: Incompatible active projection cannot become Direct Free
    Given HushServerNode returns active entitlement with incompatible critical semantics
    When HushVoting validates the response
    Then workspace remains gated with compatible-client guidance
    And it is not mapped to Direct Free or known Veritas
    And no baseline transaction is created

  @EPIC-002 @AT-LIC-016-006 @Playwright @server-fixture
  Scenario: Back cannot bypass or cancel the authenticated gate
    Given Alice is authenticated and waiting for indexed entitlement
    When Alice uses browser or platform Back
    Then HushVoting remains on the authenticated entitlement gate
    And it neither exposes workspace nor returns to pre-authentication UI

  @EPIC-002 @AT-LIC-016-007 @Playwright @server-fixture
  Scenario: Entitlement recovery is accessible
    Given Alice uses keyboard screen-reader reduced-motion and enlarged text
    When states change from resolving through delayed or unavailable
    Then the gate announces meaningful changes without polling spam
    And Retry and Lock have visible focus names and deterministic focus placement
