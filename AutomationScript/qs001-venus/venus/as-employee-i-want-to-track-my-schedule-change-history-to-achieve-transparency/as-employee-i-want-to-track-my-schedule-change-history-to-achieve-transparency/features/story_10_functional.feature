Feature: Employee Schedule Change History Tracking
  As an employee
  I want to track my schedule change history
  So that I can have transparency and accountability for all my requests

  Background:
    Given user is logged in as an authenticated employee
    And employee has schedule change requests in the system

  @functional @regression @priority-high @smoke
  Scenario: Employee successfully accesses schedule change history page and views all past requests
    Given employee has 5 schedule change requests with various statuses
    And user is on the main dashboard
    When user clicks "Schedule History" link in navigation menu
    Then "My Schedule Change History" page should load within 2 seconds
    And page title "My Schedule Change History" should be displayed
    And schedule change requests table should be visible
    And table should display columns "Request ID, Date Submitted, Original Schedule, Requested Schedule, Status, Comments"
    And all 5 schedule change requests should be displayed
    And requests should be ordered chronologically with most recent first
    And "Approved" status should display green badge
    And "Pending" status should display yellow badge
    And "Rejected" status should display red badge
    And manager comments should be visible in "Comments" column
    And pagination controls should appear if more than 10 requests exist
    And no error messages should be displayed

  @functional @regression @priority-high
  Scenario: Employee successfully filters schedule change history by date range
    Given user is on schedule change history page
    And employee has 3 schedule change requests from last month
    And employee has 2 schedule change requests from this month
    And date range filter controls are visible
    When user locates "Date Range" filter section
    Then "From Date" field should be visible
    And "To Date" field should be visible
    When user clicks "From Date" field
    And user selects first day of last month from date picker
    Then selected date should be highlighted in calendar
    And date should appear in "From Date" field in "MM/DD/YYYY" format
    When user clicks "To Date" field
    And user selects last day of last month from date picker
    Then selected date should be highlighted in calendar
    And date should appear in "To Date" field in "MM/DD/YYYY" format
    When user clicks "Apply Filter" button
    Then page should update within 2 seconds
    And table should display 3 schedule change requests
    And summary message "Displaying 3 results for [date range]" should be displayed
    And only requests from last month should be visible
    And requests from this month should not be visible
    And "Clear Filters" button should be visible

  @functional @regression @priority-high
  Scenario Outline: Employee successfully filters schedule change history by status
    Given user is on schedule change history page
    And employee has 2 "Approved" requests
    And employee has 2 "Pending" requests
    And employee has 1 "Rejected" request
    And status filter dropdown is visible
    When user clicks "Status" dropdown
    Then dropdown should expand showing options "All Statuses, Approved, Pending, Rejected"
    When user selects "<status>" from dropdown
    Then "<status>" option should be highlighted and selected
    And dropdown should show "<status>" as current selection
    When user clicks "Apply Filter" button
    Then page should update within 2 seconds
    And table should display <count> schedule change requests
    And all displayed requests should have "<status>" status
    And "<status>" status badge should be displayed with "<color>" color
    And summary message "Displaying <count> <status> requests" should be displayed
    And requests with other statuses should not be visible

    Examples:
      | status   | count | color  |
      | Approved | 2     | green  |
      | Pending  | 2     | yellow |
      | Rejected | 1     | red    |

  @functional @regression @priority-medium
  Scenario: Employee successfully combines date range and status filters simultaneously
    Given user is on schedule change history page
    And employee has 1 "Approved" request from last month
    And employee has 2 "Pending" requests from last month
    And employee has 1 "Approved" request from this month
    And date range and status filters are available
    When user sets "From Date" to first day of last month
    And user sets "To Date" to last day of last month
    Then both date fields should be populated in "MM/DD/YYYY" format
    When user selects "Pending" from "Status" dropdown
    Then status dropdown should show "Pending" as selected
    When user clicks "Apply Filters" button
    Then page should update within 2 seconds
    And table should display 2 schedule change requests
    And all displayed requests should have "Pending" status
    And all displayed requests should be from last month date range
    And summary message "Displaying 2 Pending requests from [date range]" should be displayed
    And approved request from last month should not be visible
    And approved request from this month should not be visible
    And filter combination state should be preserved

  @functional @regression @priority-high
  Scenario: Employee views detailed information for schedule change request including manager comments
    Given user is on schedule change history page
    And schedule change requests are visible
    And at least one request has "Rejected" status with manager comments
    When user locates schedule change request with "Rejected" status
    Then request should display red "Rejected" status badge
    And comments icon or preview text should indicate comments are present
    When user clicks on request row or "View Details" button
    Then request details should expand or open in modal
    And "Request ID" field should be displayed
    And "Submission Date" field should be displayed
    And "Original Schedule" field should be displayed
    And "Requested Schedule" field should be displayed
    And "Status" field should be displayed
    And "Submission Timestamp" field should be displayed
    And "Manager Comments" section should be displayed
    And manager comment text should be visible
    And commenter name should be displayed
    And comment timestamp should be displayed
    And all fields should contain accurate data
    And dates should be formatted consistently
    And no information should be missing or truncated
    And user should be able to close detail view and return to history list