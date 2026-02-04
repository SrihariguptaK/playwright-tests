Feature: Schedule Change Request Validation and Security
  As an employee
  I want the system to validate my schedule change requests and protect against invalid submissions
  So that only complete and secure requests are processed while preventing errors and security vulnerabilities

  Background:
    Given user is logged in as an authenticated employee
    And user is on "Schedule Change Request" page

  @negative @regression @priority-high
  Scenario: Submission is blocked when Date field is left empty
    Given form is in its initial state
    And all validation rules are active
    When user leaves "Date" field empty
    And user enters "03:00 PM" in "Time" field
    And user enters "Doctor appointment" in "Reason" field
    And user clicks "Submit Request" button
    Then form submission should be prevented
    And error message "Date is required" should be displayed below "Date" field
    And "Date" field should have red border
    And focus should move to "Date" field
    And no POST request should be sent to "/api/scheduleChangeRequests" endpoint
    And form data in "Time" field should be preserved
    And form data in "Reason" field should be preserved

  @negative @regression @priority-high
  Scenario: System rejects schedule change request with past date
    Given current date is "2024-01-15"
    And date validation rules include no past dates allowed
    When user enters "2024-01-10" in "Date" field
    And user enters "11:00 AM" in "Time" field
    And user enters "Schedule adjustment needed" in "Reason" field
    And user clicks "Submit Request" button
    Then form submission should be blocked
    And error message "Date cannot be in the past. Please select a current or future date." should be displayed below "Date" field
    And no POST request should be sent to "/api/scheduleChangeRequests" endpoint
    And no schedule change request should be created in database
    And form fields should retain entered values
    And no notification should be sent

  @negative @regression @priority-high
  Scenario: System rejects Reason field with less than minimum character requirement
    Given "Reason" field has minimum character requirement of 10 characters
    And form validation is active
    When user enters "2024-06-30" in "Date" field
    And user enters "01:00 PM" in "Time" field
    And user enters "Sick" in "Reason" field
    And user clicks outside "Reason" field
    Then character counter should show "4/500 characters"
    And error message "Reason must be at least 10 characters long. Current: 4 characters" should be displayed below "Reason" field
    And "Submit Request" button should be disabled
    And tooltip "Please provide a reason with at least 10 characters" should appear on hover over "Submit Request" button
    And form submission should be prevented
    And no POST request should be sent to "/api/scheduleChangeRequests" endpoint
    And no database record should be created

  @negative @regression @priority-high @security
  Scenario Outline: System handles unauthorized access attempt without valid authentication
    Given user is not logged in
    And authentication middleware is active
    And session timeout is set to 30 minutes
    When user attempts to access "/schedule-change-request" URL directly
    Then user should be redirected to "/login" page
    And message "Please log in to access this page" should be displayed

    Examples:
      | scenario_type |
      | direct_access |

  @negative @regression @priority-high @security
  Scenario Outline: System blocks API requests without valid authentication
    Given authentication middleware is active
    When user sends POST request to "/api/scheduleChangeRequests" with "<auth_type>" authentication
    Then API should return HTTP status code <status_code>
    And response body should contain error "<error_type>"
    And response body should contain message "<error_message>"
    And no schedule change request should be created
    And security event should be logged in audit trail

    Examples:
      | auth_type           | status_code | error_type              | error_message                          |
      | no_header           | 401         | Authentication required | No valid authentication token provided |
      | expired_token       | 401         | Token expired           | Please log in again                    |
      | invalid_token       | 401         | Invalid token           | Authentication token is invalid        |

  @negative @regression @priority-high @security
  Scenario: System handles SQL injection attempt in Reason field
    Given input sanitization and parameterized queries are implemented
    And security monitoring is active
    When user enters "2024-07-01" in "Date" field
    And user enters "04:00 PM" in "Time" field
    And user enters "Test reason'; DROP TABLE schedule_change_requests; --" in "Reason" field
    And user clicks "Submit Request" button
    Then success message "Schedule change request submitted successfully" should be displayed
    And database table "schedule_change_requests" should still exist
    And new record should be created with reason field containing "Test reason'; DROP TABLE schedule_change_requests; --" as plain text
    And no SQL commands should be executed
    And database tables should remain intact and unaffected
    And SQL injection attempt should be logged in security audit log

  @negative @regression @priority-medium
  Scenario: System handles API timeout and displays appropriate error message
    Given all required fields are filled with valid data
    And API timeout is configured to 30 seconds
    And network delay is simulated to exceed 30 seconds
    When user enters "2024-07-15" in "Date" field
    And user enters "10:30 AM" in "Time" field
    And user enters "Training session attendance" in "Reason" field
    And user clicks "Submit Request" button
    Then loading spinner should appear on "Submit Request" button with text "Submitting..."
    And user waits for 30 seconds
    And error message "Request timeout. Please check your connection and try again." should be displayed in red banner
    And "Submit Request" button should return to enabled state
    And no record should be created in "schedule_change_requests" table
    And all entered field values should remain in form
    And error should be logged in application error log