Feature: Schedule Change Request Approval and Rejection Workflow
  As an Approver
  I want to perform approval or rejection of schedule changes with proper validation and security
  So that I can ensure efficient workflow while maintaining data integrity and system security

  Background:
    Given user is logged in with "Approver" role
    And at least one pending schedule change request exists in the system

  @negative @regression @priority-high
  Scenario: System prevents rejection when mandatory comment is empty
    Given user is on the request details page
    And system enforces mandatory comments for rejection actions
    When user navigates to pending requests section
    And user selects a pending request to review
    Then request details should be displayed
    And "Reject" button should be visible
    When user clicks "Reject" button
    Then rejection dialog should be displayed
    And rejection comment field should be marked as mandatory with red asterisk
    And "Confirm Rejection" button should be disabled
    When user leaves rejection comment field empty
    And user attempts to click "Confirm Rejection" button
    Then "Confirm Rejection" button should remain disabled
    And button should not be clickable
    When user enters only whitespace characters in rejection comment field
    And user attempts to submit rejection
    Then validation error message "Rejection reason is required" should be displayed in red text
    And error message should appear below comment field
    And form submission should be prevented
    When user attempts to click "Confirm Rejection" button
    Then validation error message "Please provide a valid rejection reason" should be displayed
    And request status should remain "Pending"
    And no notification should be sent to requester
    And no database update should occur for the request
    And user should remain on rejection dialog with error message visible

  @negative @regression @priority-high
  Scenario Outline: Unauthorized user without Approver role cannot access pending requests or perform approval actions
    Given user is logged in with "<role>" role
    And user does not have approval permissions
    And role-based access control is properly configured
    When user attempts to navigate to "<url>" by typing URL directly
    Then access should be denied
    And error message "<error_message>" should be displayed
    And user should be redirected to unauthorized page with status code <status_code>
    When user tries to access approver dashboard from main navigation menu
    Then approver-specific menu items should not be visible
    And approver-specific menu items should be disabled for non-approver users
    When user attempts to make API call "PUT" to "/api/scheduleChangeRequests/<request_id>" with approval payload
    Then API should return status code <api_status_code>
    And API error message "<api_error_message>" should be returned
    When user tries to access request details by direct URL with known request ID
    Then access should be denied
    And error message "You do not have permission to view or modify this request" should be displayed
    And no requests should be approved or rejected by unauthorized user
    And security audit log should record unauthorized access attempt with user ID and timestamp
    And user session should remain active
    And access to approver functions should be blocked
    And no data should be modified or exposed to unauthorized user

    Examples:
      | role            | url                          | error_message                                           | status_code | request_id | api_status_code | api_error_message                              |
      | Regular Employee| /approver/pending-requests   | Access Denied: You do not have permission to view this page | 403         | 123        | 403             | Insufficient permissions to perform this action |
      | Viewer          | /approver/pending-requests   | Access Denied: You do not have permission to view this page | 403         | 456        | 403             | Insufficient permissions to perform this action |

  @negative @regression @priority-high
  Scenario: System handles network failure gracefully during approval submission
    Given user is on the approval confirmation screen
    And a pending request is selected for approval
    And network connectivity can be simulated to fail
    When user selects a pending request
    And user clicks "Approve" button
    And user enters "Approved for implementation" in approval comments field
    Then approval dialog should be displayed
    And approval comments should be entered
    And "Confirm Approval" button should be ready
    When network connection is disconnected
    And user clicks "Confirm Approval" button to submit approval
    Then loading indicator should appear briefly
    And error message "Network error: Unable to submit approval. Please check your connection and try again." should be displayed in red banner
    And request status should remain "Pending" in database
    And no partial update should occur
    When network connection is restored
    And user clicks "Retry" button
    Then approval should be submitted successfully
    And success message should be displayed
    And no data corruption should occur due to network failure
    And error should be logged in system error logs with appropriate details

  @negative @regression @priority-medium
  Scenario: System prevents double submission when approver clicks approve button multiple times rapidly
    Given user is on the approval confirmation screen
    And a pending schedule change request exists
    And system has double-submission prevention mechanism
    When user navigates to pending requests section
    And user selects a pending request to review
    Then request details should be displayed
    And "Approve" button should be visible
    When user clicks "Approve" button
    And user enters "Approved for implementation" in approval comments field
    Then approval dialog should be displayed
    And approval comments should be entered
    When user rapidly clicks "Confirm Approval" button 10 times in quick succession
    Then button should become disabled after first click
    And loading indicator should appear
    And subsequent clicks should be ignored
    When submission completes
    Then request should be approved only once
    And request status should show "Approved" with single timestamp
    And only one notification should be sent to requester
    And database should show single approval entry with one timestamp
    And no duplicate approval records should exist in database
    And system should maintain data integrity
    And race conditions should be prevented

  @negative @regression @priority-high
  Scenario: System handles expired session gracefully when approver attempts to approve request
    Given session timeout is configured to 30 minutes of inactivity
    And a pending request is displayed on screen
    When user navigates to pending requests page
    Then pending requests should be displayed successfully
    When user session expires after configured timeout period
    And user attempts to approve a request by clicking "Approve" button
    And user submits approval
    Then system should detect expired session
    And error message "Your session has expired. Please log in again to continue." should be displayed
    And user should be redirected to login page
    And request status should remain "Pending"
    And no database update should occur
    When user logs in again with valid credentials
    Then request should still be in "Pending" status
    And request should be available for approval
    And no approval action should be processed with expired session token
    And request data should remain unchanged and secure
    And user should be able to complete approval action successfully after re-login

  @negative @regression @priority-medium
  Scenario Outline: System handles invalid or non-existent request ID gracefully
    Given user has access to pending requests section
    And system has valid pending requests in database
    When user attempts to access request details by entering "<request_id>" in URL "<url>"
    Then system should display error page
    And error message "<error_message>" should be displayed
    And HTTP status code should be <status_code>
    When user attempts to approve request via API call "PUT" to "/api/scheduleChangeRequests/<request_id>" with approval payload
    Then API should return status code <api_status_code>
    And API error message "<api_error_message>" should be returned
    And no invalid data should be processed or stored in database
    And appropriate error messages should be displayed to user
    And system should log invalid request attempt for security monitoring
    And user should be redirected back to pending requests list or error page

    Examples:
      | request_id | url                  | error_message                                                      | status_code | api_status_code | api_error_message                                          |
      | 99999999   | /requests/99999999   | Request not found                                                  | 404         | 404             | Schedule change request with ID 99999999 not found         |
      | 99999999   | /requests/99999999   | 404 - The requested schedule change request does not exist         | 404         | 404             | Schedule change request with ID 99999999 not found         |
      | ABC@123    | /requests/ABC@123    | Invalid request ID format                                          | 400         | 400             | Invalid request ID format                                  |

  @negative @regression @priority-medium
  Scenario: System prevents modification of already processed request
    Given user has access to pending requests section
    And a schedule change request has already been approved or rejected
    When user attempts to access processed request by request ID
    Then system should display error message "This request has already been processed and cannot be modified"
    When user attempts to approve already processed request via API call
    Then API should return status code 409
    And API error message should indicate conflict status
    And no invalid data should be processed or stored in database
    And system should log invalid request attempt for security monitoring