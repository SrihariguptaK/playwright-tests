Feature: Employee Schedule Access Security and Error Handling
  As an employee
  I want the system to securely protect schedule data and handle errors gracefully
  So that I can only access my own schedule and receive clear feedback when issues occur

  Background:
    Given employee schedule database is available
    And authentication and authorization checks are implemented

  @negative @regression @priority-high @security
  Scenario: Unauthorized user cannot access another employee's schedule via URL manipulation
    Given employee account "emp001" exists in the system
    And employee account "emp002" exists in the system
    And employee "emp002" has scheduled shifts for current week
    And employee "emp001" is logged into the system
    When employee attempts to access schedule page with URL parameter "employeeId" as "emp002"
    Then error message "Access Denied: You do not have permission to view this schedule" should be displayed
    And employee should be redirected to their own schedule page within 2 seconds
    And schedule data for employee "emp002" should not be visible
    And unauthorized access attempt should be logged in audit trail with timestamp and user ID

  @negative @regression @priority-high @security
  Scenario: Unauthorized user cannot access another employee's schedule via direct API call
    Given employee "emp001" is logged into the system
    And employee "emp002" has scheduled shifts in the system
    When employee makes direct API call to "GET /api/schedules/emp002"
    Then API should return 403 status code
    And API response should contain error "Unauthorized access"
    And API response should contain message "You can only view your own schedule"
    And no schedule data should be returned in response
    And security incident should be logged with IP address and attempted resource

  @negative @regression @priority-high @authentication
  Scenario: System handles expired authentication token gracefully
    Given employee is logged into the system
    And employee is viewing their schedule page
    And session timeout is configured for 30 minutes
    When authentication token expires after timeout period
    And employee attempts to change week filter
    Then modal with message "Your session has expired. Please log in again to continue." should be displayed
    And "Login" button should be visible in modal
    When employee clicks "Login" button
    Then employee should be redirected to login page with return URL "/schedule"
    And employee session should be cleared
    And no schedule data should be displayed

  @negative @regression @priority-high @authentication
  Scenario: System rejects invalid authentication token
    Given employee is logged into the system
    And employee is viewing their schedule page
    When employee modifies authentication token to invalid value in browser storage
    And employee attempts to load schedule data
    Then system should return 401 status code
    And error message "Invalid authentication. Please log in again." should be displayed
    And employee should be redirected to login page
    And no schedule data should be displayed

  @negative @regression @priority-high @error-handling
  Scenario: System handles database connection failure with user-friendly error message
    Given employee is logged into the system
    And employee navigates to schedule page
    When database connection fails or times out
    And API request to "GET /api/schedules/{employeeId}" fails
    Then error message "Unable to load schedule at this time. Please try again later." should be displayed
    And "Retry" button should be visible
    And no sensitive error details should be exposed to user
    And technical error details should be logged server-side only
    And employee session should remain active

  @negative @regression @priority-high @error-handling
  Scenario: System allows retry after database connection failure
    Given employee is viewing schedule page
    And error message "Unable to load schedule at this time. Please try again later." is displayed
    And "Retry" button is visible
    When employee clicks "Retry" button
    Then system should attempt to reconnect to database
    And loading indicator should be displayed
    And error should be logged in system monitoring tools

  @negative @regression @priority-medium @validation
  Scenario Outline: System handles invalid week date formats and displays appropriate errors
    Given employee is logged into the system
    And employee is on schedule page
    When employee attempts to access schedule with URL parameter "week" as "<date_value>"
    Then system should detect invalid date format
    And error message "<error_message>" should be displayed
    And schedule should default to "<fallback_display>"
    And invalid date attempt should be logged for security monitoring
    And no system errors or crashes should occur

    Examples:
      | date_value    | error_message                                              | fallback_display |
      | invalid-date  | Invalid date format. Showing current week instead.         | current week     |
      | 2024-13-45    | Invalid date format. Showing current week instead.         | current week     |
      | 1900-01-01    | Cannot view schedules older than 1 year                    | valid range      |
      | 2029-12-31    | Schedules are only available up to 6 months in advance     | valid range      |

  @negative @regression @priority-medium @validation
  Scenario: System prevents selection of dates beyond valid range in date picker
    Given employee is logged into the system
    And employee is on schedule page
    And date picker is displayed
    When employee attempts to select date "5 years in the future" using date picker
    Then system should display message "Schedules are only available up to 6 months in advance"
    And date selection should be limited to valid range
    And schedule should remain on current week

  @negative @regression @priority-medium @edge-case
  Scenario: System displays empty state when employee has no scheduled shifts for selected week
    Given employee is logged into the system
    And employee has no shifts scheduled for week "2024-W15"
    And employee navigates to schedule page
    When employee selects week "2024-W15" using week picker
    Then schedule page should load successfully without errors
    And empty state message "No shifts scheduled for this week" should be displayed
    And helpful icon should be visible in empty state
    And week navigation controls should remain functional
    And "Previous Week" button should be enabled
    And "Next Week" button should be enabled

  @negative @regression @priority-medium @edge-case
  Scenario: System correctly calculates zero hours for week with no scheduled shifts
    Given employee is logged into the system
    And employee has no shifts scheduled for selected week
    And employee is viewing schedule page for empty week
    Then total hours summary should display "0 hours scheduled"
    And no calculation errors should occur
    And UI elements should display correctly without breaking