Feature: Schedule Review Cycles with Edge Case Handling
  As a Performance Manager
  I want to schedule review cycles with proper handling of edge cases
  So that I can ensure reliable performance evaluations across all scenarios

  Background:
    Given user is logged in as "Performance Manager" with scheduling permissions
    And review cycle management page is loaded

  @edge @regression @priority-high @timezone
  Scenario: Schedule review cycle at exact midnight boundary across time zones
    Given system is configured with multiple time zones "PST, EST, GMT"
    And no existing review cycles are scheduled for target date
    When user clicks "Schedule New Review Cycle" button
    Then review cycle scheduling modal should be visible
    And all frequency options should be visible
    When user selects "Monthly" from "Frequency" dropdown
    And user sets start date to "12:00:00 AM" on "1st of next month"
    Then date picker should display "12:00:00 AM" in time field
    When user selects "PST (UTC-8)" from "Time Zone" dropdown
    Then time zone should be set to "PST"
    And system should show equivalent time "3:00 AM EST" for "EST"
    And system should show equivalent time "8:00 AM GMT" for "GMT"
    When user clicks "Save Review Cycle" button
    Then success message "Review cycle scheduled successfully" should be displayed in green banner
    When user navigates to calendar view
    Then scheduled review should appear at "12:00 AM PST" on "1st"
    And correct time zone indicator should be displayed

  @edge @regression @priority-high @performance
  Scenario: Schedule maximum number of concurrent review cycles and verify system performance
    Given database has capacity for at least "150" review cycle records
    And system performance monitoring tools are active
    When user navigates to review cycle management page
    Then page should load in under "2" seconds
    When user creates "100" review cycles with different frequencies spanning "12" months using bulk scheduling
    Then system should display progress indicator showing "100 review cycles created successfully"
    When user refreshes review cycle management page
    Then page should load in under "2" seconds
    And pagination or lazy loading should be implemented
    When user navigates to calendar view
    And user scrolls through all months containing scheduled reviews
    Then calendar should render smoothly without lag
    And all "100" review cycles should be displayed with appropriate visual indicators
    When user attempts to schedule additional review cycle
    Then system should accept "101st" review cycle or display message indicating maximum limit reached

  @edge @regression @priority-medium @leap-year
  Scenario: Schedule review cycle on February 29th and verify behavior in non-leap years
    Given current system date is within leap year "2024"
    And system calendar includes "February 29th" as selectable date
    When user clicks "Schedule New Review Cycle" button
    Then review cycle scheduling modal should be visible
    And date picker should show current leap year calendar
    When user selects "Yearly" from "Frequency" dropdown
    And user sets start date to "February 29th, 2024"
    Then date picker should display "February 29th, 2024" in selected date field
    When user sets recurrence to repeat annually for next "5" years
    And user clicks "Save Review Cycle" button
    Then success message should be displayed
    When user navigates to calendar view
    And user advances calendar to "February 2025"
    Then review cycle should appear on "February 28th, 2025"
    And notation "Adjusted from Feb 29 (non-leap year)" should be displayed
    When user advances calendar to "February 2028"
    Then review cycle should appear on "February 29th, 2028"

  @edge @regression @priority-high @validation
  Scenario: Schedule overlapping review cycles with identical start times and verify validation
    Given review cycle exists scheduled for "January 15, 2025" at "9:00 AM"
    And system validation rules for overlapping cycles are active
    When user clicks "Schedule New Review Cycle" button
    Then review cycle scheduling modal should be visible with empty form fields
    When user selects "Weekly" from "Frequency" dropdown
    And user sets start date to "January 15, 2025" at "9:00 AM"
    Then date and time fields should accept the input
    When user fills in "Review Name" field
    And user fills in "Participants" field
    And user fills in "Duration" field
    And user clicks "Save Review Cycle" button
    Then error message "A review cycle is already scheduled for this date and time. Please choose a different time or edit the existing cycle." should be displayed in red banner
    When user modifies start time to "9:01 AM"
    And user clicks "Save Review Cycle" button
    Then system should accept schedule if cycles do not overlap or show error if overlap detected
    When user navigates to calendar view
    Then both review cycles should be displayed if second was accepted
    And visual indication of proximity should be shown

  @edge @regression @priority-medium @unicode @internationalization
  Scenario: Schedule review cycle with special characters and Unicode in cycle name
    Given system supports UTF-8 character encoding
    And database fields support Unicode storage
    When user clicks "Schedule New Review Cycle" button
    Then review cycle scheduling modal should be visible
    And review name input field should be visible
    When user enters "Q1 Performance Review 📊 2025 - 业绩评估 (Überprüfung)" in "Review Name" field
    Then input field should display all characters correctly without corruption
    When user selects "Monthly" from "Frequency" dropdown
    And user sets valid start date
    And user clicks "Save Review Cycle" button
    Then success message "Review cycle scheduled successfully" should be displayed
    And modal should close
    When user verifies review cycle in list view
    Then review cycle name "Q1 Performance Review 📊 2025 - 业绩评估 (Überprüfung)" should be displayed correctly
    And all special characters and emoji should be rendered properly
    When user navigates to calendar view
    And user hovers over scheduled review cycle
    Then tooltip should show full review cycle name with all Unicode characters displayed correctly
    When user edits review cycle
    Then edit modal should open with review name field showing all original characters correctly

  @edge @regression @priority-medium @stress-test
  Scenario: Rapidly create and delete multiple review cycles in quick succession
    Given network connection is stable
    And browser console is open to monitor for errors
    When user navigates to review cycle management page
    Then page should load successfully
    And console should show no errors
    When user rapidly creates "10" review cycles in under "30" seconds
    Then system should process all "10" requests without crashing
    And success messages should be displayed for each request
    When user selects all "10" newly created review cycles
    And user clicks "Delete" button
    Then confirmation dialog "Are you sure you want to delete 10 review cycles?" should be displayed
    And "Confirm" button should be visible
    And "Cancel" button should be visible
    When user clicks "Confirm" button
    Then success message "Successfully deleted 10 review cycles" should be displayed
    And no errors should be displayed
    When user checks browser console
    Then console should show no critical errors
    And all API calls should return successful status codes
    And no memory leaks should be detected
    When user refreshes page
    Then page should load within "2" seconds
    And deleted review cycles should not be displayed

  @edge @regression @priority-low @daylight-saving-time
  Scenario: Schedule review cycle during daylight saving time transition
    Given system is configured for time zone "PST/PDT" that observes daylight saving time
    And test is performed during DST transition period
    When user navigates to review cycle management page at "1:30 AM" on DST transition day
    Then page should load successfully
    And current system time should be displayed correctly
    When user clicks "Schedule New Review Cycle" button
    And user sets start time to "2:30 AM" during lost hour of spring forward
    Then system should prevent selection of non-existent time or automatically adjust to "3:30 AM"
    And notification "Time adjusted for daylight saving transition" should be displayed
    When user selects "Weekly" from "Frequency" dropdown
    And user clicks "Save Review Cycle" button
    Then success message should be displayed
    And review cycle should be saved with DST-aware timestamp
    When user navigates to calendar view
    Then review cycle should appear at "3:30 AM" with DST indicator
    When user checks notification settings
    Then notification scheduler should show correct times adjusted for DST