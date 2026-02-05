Feature: Schedule Change History Edge Cases
  As an employee
  I want the system to handle edge cases in my schedule change history
  So that I can reliably access my request history regardless of data volume or complexity

  Background:
    Given user is logged in as an authenticated employee
    And user is on the schedule change history page

  @edge @regression @priority-medium
  Scenario: System handles employee with extremely large number of schedule change requests
    Given employee has 1000 schedule change requests in the database
    And pagination mechanism is implemented
    And performance requirements specify response time under 2 seconds
    When user navigates to schedule change history page
    Then page should load within 2 seconds
    And first page of results should be displayed
    And loading indicator should be shown during fetch
    And pagination controls should be visible
    And pagination should show "Page 1 of 100" format
    And summary should show "Showing 1-10 of 1000 results" format
    When user clicks "Next" button
    Then page 2 should load within 2 seconds
    And records 11 to 20 should be displayed
    And page should not reload entirely
    And URL should update to reflect pagination
    When user jumps to page 50 using page number input
    Then page 50 should load within 2 seconds
    And records 491 to 500 should be displayed
    And system should maintain performance without degradation
    When user applies filter with status "Approved"
    Then filtered results should load within 2 seconds
    And pagination should adjust to show filtered result count
    And summary should show "Showing 1-10 of 300 Approved results" format
    And performance should remain acceptable
    And memory usage should remain stable
    And browser should not crash

  @edge @regression @priority-medium
  Scenario: System handles date range filter spanning multiple years of history
    Given employee has schedule change requests spanning 5 years from 2019 to 2024
    When user sets "From Date" to "01/01/2019"
    And user sets "To Date" to "12/31/2024"
    Then both date fields should accept the dates
    And dates should be displayed in "MM/DD/YYYY" format
    When user clicks "Apply Filter" button
    Then system should process the wide date range
    And results should be returned within 2 seconds
    And all requests from the specified period should be displayed
    And pagination should be shown if result set is large
    And results should include requests from 2019
    And results should include requests from 2020
    And results should include requests from 2021
    And results should include requests from 2022
    And results should include requests from 2023
    And results should include requests from 2024
    And results should be sorted in chronological order with most recent first
    And summary should show "Displaying 250 results from 01/01/2019 to 12/31/2024" format
    And page should remain responsive
    And no timeout errors should occur
    And database query should be optimized for wide date range

  @edge @regression @priority-low
  Scenario: System handles schedule change requests with extremely long comments
    Given at least one schedule change request has manager comments exceeding 5000 characters
    When user clicks on schedule change request with extremely long manager comments
    Then request details should open in expanded view or modal
    And layout should not break
    And comments should be displayed with truncation and "Read More" link or scrollable text area or expandable section
    And page layout should remain intact
    When user clicks "Read More" or expand button
    Then full comment text should become visible
    And scrollable container or expanded section should be shown
    And all 5000 characters should be accessible
    And text should remain readable without horizontal scrolling
    And page layout should remain intact
    And no text overflow outside containers should occur
    And other request details should remain visible and accessible
    And overall page usability should be maintained

  @edge @regression @priority-medium
  Scenario: System handles concurrent filter applications and rapid filter changes
    Given schedule change history page has multiple requests
    And filter controls are responsive
    And system has debouncing or request cancellation mechanisms
    When user rapidly selects "Approved" from status filter
    And user immediately selects "Pending" from status filter
    And user immediately selects "Rejected" from status filter within 2 seconds
    Then system should handle rapid changes gracefully
    And system should debounce requests or cancel previous requests
    And only final filter "Rejected" should be applied
    When user quickly changes date range filters while previous filter request is processing
    Then system should cancel in-flight request
    And system should process only most recent filter criteria
    And no errors should occur
    When user applies multiple filters simultaneously for date range and status
    And user immediately clears all filters
    Then system should process clear action
    And system should cancel any pending filter requests
    And unfiltered full history list should be displayed
    And no stale or incorrect data should be shown
    And browser network tab should show appropriate request cancellation or debouncing
    And only one final API call should be made for last filter state
    And displayed data should match final filter criteria
    And no race conditions should occur
    And no data inconsistencies should occur
    And no memory leaks should occur
    And no performance degradation from cancelled requests should occur

  @edge @regression @priority-low
  Scenario: System handles special characters and Unicode in comments and schedule descriptions
    Given at least one schedule change request contains special characters and emojis and Unicode in comments
    And system supports UTF-8 encoding
    When user locates schedule change request with special characters
    Then request should be visible in history list
    And no rendering issues should occur
    When user clicks to view full details of request with special characters
    Then request details should open
    And all special characters should be displayed correctly
    And all emojis should be displayed correctly
    And all Unicode text should be displayed correctly
    And no garbled characters should appear
    And no encoding errors should occur
    And text "Approved ✓ 你好 café" should appear exactly as entered
    And special characters in schedule descriptions should be rendered properly
    And arrow symbols should be displayed correctly
    And time formats should be displayed correctly
    And special punctuation should be displayed correctly
    And text should remain readable
    When user applies filters
    Then filters should work correctly regardless of special characters in data
    And filtered results should display special characters properly
    And no encoding errors should occur
    And system should maintain data integrity for international characters