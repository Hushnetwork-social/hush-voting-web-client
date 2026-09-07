@FEAT-016
Feature: Entitlement failure, recovery, and expiry journeys
  FEAT-016 phase 7 canonical production-composition journeys for authority
  failure, delayed confirmation, exact retry, expiry-triggered bootstrap,
  paused chains, and temporary disconnection. Every scenario drives the real
  composition and the controlled real HushServerNode fixture; capture stays
  disabled and no synthetic provider or state injection is used.

  @EPIC-002 @AT-LIC-003 @TwinTest @Playwright @server-fixture
  Scenario: Entitlement authority failure never fabricates a plan
    Given Alice's identity is authenticated
    And no valid Redis projection can be returned
    And indexed PostgreSQL entitlement authority is unavailable
    When HushVoting requests Alice's entitlement
    Then the workspace remains unmounted
    And HushVoting says it cannot verify the licence
    And it does not show Direct Free or a previous entitlement
    When authority recovers and Alice retries
    Then a fresh signed query controls the next state

  @EPIC-002 @AT-LIC-007 @TwinTest @Playwright @server-fixture
  Scenario: Delayed confirmation retries the exact licence transaction
    Given Alice's signed Direct Free transaction is sealed and pending
    And blocks continue but indexed entitlement is absent for 30 seconds
    When Alice chooses Retry from delayed confirmation
    Then the authority resubmits the original UUID timestamp payload and signature
    And PENDING or ALREADY_EXISTS is reconciliation rather than failure
    And only a later active indexed query opens the workspace

  @EPIC-002 @AT-LIC-010 @TwinTest @Playwright @server-fixture
  Scenario: Expiry triggers authoritative Direct Free bootstrap
    Given Alice is using an active annual Veritas entitlement
    When its upper-exclusive expiry trigger is reached
    Then HushVoting gates workspace and makes a fresh signed query
    And it does not declare expiry from client clock alone
    When HushServerNode returns no active entitlement
    Then Alice signs one Direct Free transaction automatically
    And workspace reopens only after Direct Free is indexed

  @EPIC-002 @AT-LIC-016-004 @Playwright @server-fixture
  Scenario: Paused chain exposes delayed recovery before 30 seconds
    Given Alice's Direct Free transaction awaits indexed confirmation
    When connectivity authority reports the chain paused
    Then HushVoting immediately shows delayed confirmation with Retry and Lock
    And Retry never creates a replacement transaction

  @EPIC-002 @AT-LIC-016-005 @Playwright @server-fixture
  Scenario: Temporary disconnection cannot use stale entitlement
    Given Alice is inside workspace with active same-session entitlement
    When connection is lost
    Then workspace is gated and previous entitlement cannot authorize or render as current
    When connectivity returns in the same authenticated session
    Then a fresh signed query runs automatically
    And only compatible active result restores workspace
