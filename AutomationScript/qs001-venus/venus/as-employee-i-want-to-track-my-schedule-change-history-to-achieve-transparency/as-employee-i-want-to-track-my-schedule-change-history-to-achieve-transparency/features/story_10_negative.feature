Feature: Schedule Change History Access and Security
  As an employee
  I want to securely access my schedule change history with proper validation
  So that I can review my requests while the system maintains data integrity and security

  @negative @regression @priority-high @security
  Scenario: Unauthorized access attempt to schedule change history page without authentication
    Given user is not logged in to the application
    When user navigates directly to "schedule-history" page URL
    Then user should be redirected to "login" page
    And error message "Please log in to access this page" should be displayed
    And no schedule change history data should be visible
    And no API calls should return data
    When user attempts to access "/api/scheduleChangeRequests/history" endpoint without authentication token
    Then API should return 401 status code
    And API response should contain "Authentication required" error
    And security logs should record the unauthorized access attempt

  @negative @regression @priority-high @validation
  Scenario Outline: Invalid date range filter input validation
    Given user is logged in as authenticated employee
    And user is on "schedule change history" page
    When user enters "<input_date>" in "From Date" field
    And user clicks "Apply Filter" button
    Then validation error message "<error_message>" should be displayed
    And filter should not be applied
    And no API call should be made

    Examples:
      | input_date  | error_message                                                    |
      | 99/99/9999  | Invalid date format. Please use MM/DD/YYYY                       |
      | 12/31/2025  | Date cannot be in the future. Please select a past or current date |

  @negative @regression @priority-high @validation
  Scenario: Date range validation when end date is before start date
    Given user is logged in as authenticated employee
    And user is on "schedule change history" page
    When user enters "03/01/2024" in "From Date" field
    And user enters "02/01/2024" in "To Date" field
    And user clicks "Apply Filter" button
    Then validation error message "End date must be after start date" should be displayed
    And filter should not be applied
    And no API call should be made
    And original unfiltered data should remain displayed

  @negative @regression @priority-high @error-handling
  Scenario: API failure when retrieving schedule change history
    Given user is logged in as authenticated employee
    And API endpoint "/api/scheduleChangeRequests/history" is unavailable
    When user navigates to "schedule change history" page
    Then loading spinner should be visible for up to 2 seconds
    And error message "Unable to load schedule history. Please try again later." should be displayed
    And "Retry" button should be visible
    And browser console should show API error details
    And no sensitive system information should be exposed
    When user clicks "Retry" button
    Then system should make new API request
    And user session should remain active

  @negative @regression @priority-high @error-handling
  Scenario: API timeout when retrieving schedule change history
    Given user is logged in as authenticated employee
    And API endpoint "/api/scheduleChangeRequests/history" is experiencing high latency
    When user navigates to "schedule change history" page
    Then loading spinner should be visible
    And system should wait for configured timeout period
    And error message "Unable to load schedule history. Please try again later." should be displayed
    And "Retry" button should be visible
    And error should be logged on backend for monitoring

  @negative @regression @priority-medium @edge
  Scenario: Employee with no schedule change history
    Given user is logged in as authenticated employee
    And employee has never submitted any schedule change requests
    When user navigates to "schedule change history" page
    Then page should load successfully within 2 seconds
    And empty state message "You have no schedule change requests yet" should be displayed
    And informative icon or illustration should be visible
    And helpful message "To submit a schedule change request, click here" should be displayed
    And link to request submission page should be available
    And page should not show any errors

  @negative @regression @priority-medium @edge
  Scenario: Filter controls behavior with empty history
    Given user is logged in as authenticated employee
    And employee has no schedule change history
    And user is on "schedule change history" page
    When user attempts to apply filters
    Then filter controls should show appropriate messaging
    And message "No results match your filters" should be displayed
    And no errors should be shown

  @negative @regression @priority-high @security
  Scenario Outline: SQL injection prevention through filter inputs
    Given user is logged in as authenticated employee
    And user is on "schedule change history" page
    When user enters "<malicious_input>" in "<filter_field>" field
    And user clicks "Apply Filter" button
    Then input should be sanitized or rejected
    And no unauthorized data should be returned
    And no database errors should be exposed to user
    And system should log attempted injection for security monitoring
    And database integrity should be maintained
    And application should continue to function normally

    Examples:
      | filter_field | malicious_input                           |
      | Date Filter  | ' OR '1'='1' --                           |
      | Status Filter| '; DROP TABLE scheduleChangeRequests; --  |

  @negative @regression @priority-high @security
  Scenario: Verify no data exposure after SQL injection attempt
    Given user is logged in as authenticated employee
    And user is on "schedule change history" page
    When user enters "' OR '1'='1' --" in "Date Filter" field
    And user clicks "Apply Filter" button
    Then no additional records beyond user's own history should be displayed
    And validation error message "Invalid input detected" should be displayed
    And no SQL code should be executed
    And security incident should be logged for review
    When user applies legitimate filter after injection attempt
    Then filter should work correctly
    And user should see only their own valid history data