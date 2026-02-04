Feature: Employee Schedule Change Request Management
  As an employee
  I want to submit and track schedule change requests
  So that I can manage my work schedule modifications in a timely and organized manner

  Background:
    Given user is logged in as an authenticated employee with active status
    And user has at least one existing schedule entry in the system
    And browser session is active and not expired

  @functional @regression @priority-high @smoke
  Scenario: Successful schedule change request submission with all valid fields
    Given user is on the schedule change request page at "/schedule-change-request"
    When user clicks "Request Schedule Change" in the main navigation menu
    Then schedule change request form should be visible
    And "Date" field should be visible
    And "Time" field should be visible
    And "Reason" field should be visible
    And "Submit Request" button should be visible
    When user enters "2024-06-15" in "Date" field using date picker
    Then "Date" field should display "06/15/2024" in correct format
    When user enters "09:00 AM" in "Time" field using time picker
    Then "Time" field should display "09:00 AM" in 12-hour format
    When user enters "Medical appointment" in "Reason" text area
    Then "Reason" field should display character count "20/500 characters"
    When user clicks "Submit Request" button
    Then green success banner should appear at top of page
    And success message "Schedule change request submitted successfully. Request ID: SCR-12345" should be displayed
    And form fields should be cleared
    When user navigates to "My Requests" page from navigation menu
    Then newly submitted request should appear in the list
    And request status should be "Pending Approval"
    And request should display date "06/15/2024"
    And request should display time "09:00 AM"
    And request should display reason "Medical appointment"

  @functional @regression @priority-high @negative
  Scenario: Real-time validation displays for incomplete mandatory fields
    Given user is on the schedule change request page
    And form is in its initial empty state
    And JavaScript is enabled in the browser
    When user clicks into "Date" field and clicks outside without entering value
    Then error message "Date is required" should be displayed below "Date" field
    And "Date" field should have red border
    When user clicks into "Time" field and clicks outside without entering value
    Then error message "Time is required" should be displayed below "Time" field
    And "Time" field should have red border
    When user clicks into "Reason" field and clicks outside without entering value
    Then error message "Reason is required (minimum 10 characters)" should be displayed below "Reason" field
    And "Reason" field should have red border
    When user attempts to click "Submit Request" button while all fields are empty
    Then "Submit Request" button should be disabled
    And tooltip "Please complete all required fields" should be displayed on hover
    When user enters "06/15/2024" in "Date" field
    Then error message for "Date" field should disappear
    And red border should be removed from "Date" field
    And green checkmark icon should appear next to "Date" field

  @functional @regression @priority-high
  Scenario: View status of submitted schedule change requests
    Given user is on the dashboard page
    And user has previously submitted 3 schedule change requests with different statuses
    And test data includes request "SCR-001" with status "Pending"
    And test data includes request "SCR-002" with status "Approved"
    And test data includes request "SCR-003" with status "Rejected"
    When user clicks "My Requests" link in main navigation menu
    Then "My Requests" page should load
    And table should be visible with columns "Request ID, Date, Time, Reason, Status, Submitted On, Actions"
    When user locates request "SCR-001" in the table
    Then request "SCR-001" should display status badge "Pending Approval" in yellow color
    When user locates request "SCR-002" in the table
    Then request "SCR-002" should display status badge "Approved" in green color with checkmark icon
    When user locates request "SCR-003" in the table
    Then request "SCR-003" should display status badge "Rejected" in red color with X icon
    And "View Reason" link should be visible for request "SCR-003"
    When user clicks on request ID "SCR-001"
    Then request details modal should open
    And modal should display full request details including "Date, Time, Reason, Submitted On, Current Status, Status History"

  @functional @regression @priority-medium
  Scenario: Notification sent upon successful schedule change request submission
    Given user is logged in with email address "employee@company.com"
    And user is on the schedule change request page
    And email notification service is configured and running
    And user has notification preferences enabled for schedule changes
    When user enters "06/20/2024" in "Date" field
    And user enters "02:00 PM" in "Time" field
    And user enters "Personal appointment" in "Reason" field
    Then all fields should display validation checkmarks
    When user clicks "Submit Request" button
    Then success message "Schedule change request submitted successfully. Request ID: SCR-12346. A confirmation email has been sent to employee@company.com" should be displayed
    And email should be received at "employee@company.com" within 2 minutes
    And email subject should be "Schedule Change Request Submitted - SCR-12346"
    And email should contain request details and submission timestamp
    When user checks in-app notifications bell icon in top-right corner
    Then notification badge should show "1"
    When user clicks notification bell icon
    Then notification "Your schedule change request SCR-12346 has been submitted and is pending approval" should be displayed

  @functional @regression @priority-high @api
  Scenario: API endpoint processes schedule change request correctly
    Given user is authenticated with valid JWT token
    And API endpoint "POST /api/scheduleChangeRequests" is accessible
    And database connection is active
    And user has employee role with userId "EMP-12345"
    When user sends POST request to "/api/scheduleChangeRequests" with authorization header "Bearer {valid_token}"
    And request content type is "application/json"
    And request body contains date "2024-06-25", time "10:00", reason "Family emergency", userId "EMP-12345"
    Then API should return HTTP status code 201
    And response body should contain field "success" with value "true"
    And response body should contain field "requestId" with value "SCR-12347"
    And response body should contain field "status" with value "Pending"
    And response body should contain field "message" with value "Schedule change request created successfully"
    And response body should contain field "timestamp"
    And API response time should be under 2 seconds
    When database table "schedule_change_requests" is queried for requestId "SCR-12347"
    Then record should exist with date "2024-06-25"
    And record should exist with time "10:00"
    And record should exist with reason "Family emergency"
    And record should exist with userId "EMP-12345"
    And record should exist with status "Pending"
    And record should have current createdAt timestamp

  @functional @regression @priority-high @edge
  Scenario Outline: Schedule change request validation with various field combinations
    Given user is on the schedule change request page
    When user enters "<date>" in "Date" field
    And user enters "<time>" in "Time" field
    And user enters "<reason>" in "Reason" field
    And user clicks "Submit Request" button
    Then validation result should be "<result>"
    And message "<message>" should be displayed

    Examples:
      | date       | time     | reason                | result  | message                                      |
      | 2024-06-15 | 09:00 AM | Medical appointment   | success | Schedule change request submitted successfully |
      |            | 09:00 AM | Medical appointment   | error   | Date is required                             |
      | 2024-06-15 |          | Medical appointment   | error   | Time is required                             |
      | 2024-06-15 | 09:00 AM |                       | error   | Reason is required (minimum 10 characters)   |
      | 2024-06-15 | 09:00 AM | Short                 | error   | Reason is required (minimum 10 characters)   |
      | 2023-01-01 | 09:00 AM | Past date test reason | error   | Date must be in the future                   |

  @functional @regression @priority-medium
  Scenario Outline: View schedule change requests with different status types
    Given user is on "My Requests" page
    And user has submitted request "<requestId>" with status "<status>"
    When user locates request "<requestId>" in the table
    Then request "<requestId>" should display status badge "<status>" in "<color>" color
    And status badge should display "<icon>" icon

    Examples:
      | requestId | status           | color  | icon      |
      | SCR-001   | Pending Approval | yellow | none      |
      | SCR-002   | Approved         | green  | checkmark |
      | SCR-003   | Rejected         | red    | X         |
      | SCR-004   | Cancelled        | gray   | none      |