@FEAT-017
Feature: Account licence summary and upgrade entry journeys
  FEAT-017 phase 7 canonical production-composition journeys for the account
  licence summary (A0), the contextual Upgrade action, the fresh-query entry
  and the authority-failure non-fabrication contract. Real composition and
  controlled real HushServerNode fixture only; no interception, state
  injection, or synthetic provider.

  @EPIC-002 @AT-LIC-001 @TwinTest @Playwright @server-fixture
  Scenario: Account popup shows the exact indexed plan, limits, and shortened public reference
    Given Alice has completed exact EPIC-001 identity authentication
    And HushServerNode has indexed an active Direct Free licence for Alice
    When the Account popup opens and its licence entry is refreshed
    Then the popup licence block shows HushVoting! Direct Free as current
    And the popup shows Active and the exact 100 eligible-voter limit
    And the popup shows a shortened licence reference and the Upgrade action
    And no licence value from another identity is present

  @EPIC-002 @AT-LIC-004 @TwinTest @Playwright @server-fixture
  Scenario: The full-width licence page reflects the exact server catalogue in server order
    Given Alice has completed exact EPIC-001 identity authentication
    And HushServerNode has indexed an active Direct Free licence for Alice
    When Alice opens Upgrade from the account licence block
    Then the full-width licence page shows the current Direct Free detail first
    And it lists only strictly higher Veritas plans in server order
    And each option shows its exact cap and one-year term from the catalogue
    And Enterprise is informational with no activation, link, form, or request
    And no price, payment, or provider submission surface is shown

  @EPIC-002 @AT-LIC-005 @TwinTest @Playwright @server-fixture
  Scenario: Activation requires explicit informed confirmation and cancel commits nothing
    Given Alice has completed exact EPIC-001 identity authentication
    And HushServerNode has indexed an active Direct Free licence for Alice
    When Alice reviews a higher Veritas plan
    Then no assignment change happens before confirmation
    And confirmation shows current and target plans with the exact one-year term and supersession
    When Alice cancels confirmation
    Then Direct Free remains effective and no activation operation exists
    And reopening requires a fresh selection and confirmation again

  @EPIC-002 @AT-LIC-008 @TwinTest @Playwright @server-fixture
  Scenario: Current lower and Enterprise actions cannot mutate the assignment
    Given Alice has completed exact EPIC-001 identity authentication
    And HushServerNode has indexed an active HushVoting! Veritas 2k licence for Alice
    When Alice opens the licence page
    Then no activation control exists for the current Veritas 2k plan
    And lower or Enterprise plans are not actionable in the delivered UI
    And HushServerNode returns a stable typed rejection for any such attempt
    And Alice's plan, expiry, and assignment remain unchanged
