Feature: Schedule Change Request Approval and Rejection Workflow
  As an Approver
  I want to perform approval or rejection of schedule change requests
  So that I can manage workflow efficiently and ensure all changes are authorized

  Background:
    Given user is logged in with "Approver" role
    And user has valid session token
    And database connection is active
    And "Schedule Change Requests" table is accessible

  @functional @regression @priority-high @smoke
  Scenario: Approver successfully approves a pending schedule change request with comments
    Given at least one pending schedule change request exists in the system
    And approver has permission to access the pending requests section
    When user navigates to "Dashboard" page
    Then "Dashboard" page should load within 2 seconds
    And overview of pending requests count should be visible
    When user clicks "Pending Requests" tab
    Then list of all pending schedule change requests should be displayed
    And table should display columns "Request ID, Requester Name, Date Submitted, Schedule Details, Action"
    When user clicks on a specific pending request row
    Then request details modal should open
    And complete information should be visible including "requester name, current schedule, proposed schedule, reason for change, submission date"
    When user clicks "Approve" button
    Then comment text area should appear with label "Add approval comments (optional)"
    And "Confirm Approval" button should be enabled
    When user enters "Approved due to valid business justification" in "approval comments" field
    Then text should be entered successfully in comment field
    And character count should be displayed
    When user clicks "Confirm Approval" button
    Then success message "Schedule change request has been approved successfully" should be displayed
    And success message should appear in green banner
    And request status should update to "Approved"
    And page should refresh showing updated pending requests list
    And notification should be sent to requester
    And notification should contain "approval decision, approver name, approval comments, timestamp"
    And request status should be updated to "Approved" in "Schedule Change Requests" table
    And approval decision with comments and timestamp should be recorded in request history
    And approved request should be removed from pending requests list

  @functional @regression @priority-high @smoke
  Scenario: Approver successfully rejects a pending schedule change request with mandatory comments
    Given at least one pending schedule change request exists in the system
    And approver has necessary permissions to reject requests
    And system is connected to notification service
    When user enters "approver@company.com" in "username" field
    And user enters valid password in "password" field
    And user clicks "Login" button
    Then login should be successful
    And approver dashboard should be displayed
    And "Welcome, [Approver Name]" message should be visible
    When user clicks "Pending Requests" menu item in left sidebar
    Then pending requests page should load
    And table with all pending schedule change requests should be displayed
    And requests should be sorted by submission date in descending order
    When user clicks on a specific request row
    Then request details panel should expand
    And full request information should be visible including "requester details, current vs proposed schedule, reason for change"
    When user clicks "Reject" button
    Then rejection comment dialog should appear
    And mandatory text area labeled "Rejection reason (required)" should be visible with red asterisk
    And "Confirm Rejection" button should be disabled
    When user enters "Request conflicts with operational requirements and staffing constraints" in "rejection reason" field
    Then text should be entered successfully
    And character count should show remaining characters
    And "Confirm Rejection" button should be enabled
    When user clicks "Confirm Rejection" button
    Then success message "Schedule change request has been rejected" should be displayed
    And request status should update to "Rejected"
    And request should be removed from pending list
    And request status should be updated to "Rejected" in database with rejection timestamp
    And rejection comments should be saved in history log
    And requester should receive notification containing "rejection decision, reason, approver information"
    And request should no longer appear in pending requests list

  @functional @regression @priority-high
  Scenario: Pending requests list displays all relevant information and filters correctly
    Given multiple pending schedule change requests exist in the system
    And at least 5 requests exist with different submission dates and requesters
    And browser cache is cleared
    When user navigates to pending requests section from approver dashboard
    Then pending requests page should load within 2 seconds
    And table should display columns "Request ID, Requester Name, Submission Date, Current Schedule, Proposed Schedule, Status, Actions"
    And all requests should show "Pending" status badge in yellow or orange color
    And no approved or rejected requests should be visible
    And each row should display complete information including "requester name, dates, action buttons"
    And each row should show formatted submission date in "MM/DD/YYYY" format
    And "Approve" button should be visible and enabled
    And "Reject" button should be visible and enabled
    When user clicks "Submission Date" column header
    Then list should be sorted by submission date in descending order
    And sort indicator arrow icon should appear next to column header
    When user uses search functionality to filter by requester name
    Then list should filter to show only requests matching search criteria
    And result count should be displayed

  @functional @regression @priority-medium
  Scenario: Approval decision history is maintained and accessible for audit purposes
    Given at least one schedule change request has been previously approved or rejected
    And request history feature is enabled in the system
    And user has permission to view historical decisions
    When user navigates to "Request History" section from main navigation menu
    Then history page should load
    And table with all requests should be displayed including "pending, approved, rejected" statuses
    When user selects "Approved" from status filter dropdown
    Then list should update to display only requests with selected status
    And table should show "approval date, approver name, decision comments"
    When user clicks on a previously approved request
    Then request details page should open
    And complete audit trail should be visible including "original submission details, approval decision, approver name, decision timestamp, all comments"
    And decision timestamp should be displayed in format "MM/DD/YYYY HH:MM AM/PM"
    And timestamp should match the actual decision time
    And approver full name should be displayed
    And all comments entered during approval should be visible and complete
    And historical data should remain unchanged and intact
    And audit trail should be complete and accurate

  @functional @regression @priority-high
  Scenario: Notification is sent to requester immediately upon approval with correct content
    Given a pending schedule change request exists submitted by a valid requester
    And notification service is running and configured correctly
    And requester has valid email address
    And requester has notification preferences enabled
    When user navigates to pending requests section
    And user selects a request submitted by a specific requester
    Then request details should be displayed
    And requester email address should be visible
    When user clicks "Approve" button
    And user enters "Approved for next quarter" in "approval comments" field
    And user clicks "Confirm Approval" button
    Then approval should be processed successfully
    And confirmation message should appear
    When user checks requester email inbox within 30 seconds
    Then notification should be received
    And notification subject should be "Your schedule change request has been approved"
    And notification should contain "approver name, approval date/time, approval comments, link to view request details"
    And notification should include "request ID, decision, approver, comments, timestamp"
    And all required fields should be present with accurate information
    When user clicks link in notification
    Then link should redirect to request details page
    And approved status should be visible
    And full approval information should be displayed
    And notification should be successfully delivered via email and in-app notification
    And notification log should record successful delivery with timestamp
    And no duplicate notifications should be sent

  @functional @regression @priority-medium @performance
  Scenario: System performance meets requirement of response time under 2 seconds for approval actions
    Given system is under normal load conditions
    And at least one pending request exists
    And performance monitoring tools are available
    When user starts performance timer and navigates to pending requests section
    Then pending requests page should load
    And timer should record load time
    When user selects a pending request
    And user clicks "Approve" button
    And user measures time from click to success message
    Then approval action should complete within 2 seconds
    And success message should appear
    And timer should show elapsed time less than 2000 milliseconds
    When user checks network tab in browser developer tools
    Then API call "PUT /api/scheduleChangeRequests/{id}" should complete with status 200
    And API response time should be under 2 seconds
    When user repeats approval action for 3 different requests
    Then all approval actions should complete within 2 seconds consistently
    And average response time should be under 1.5 seconds
    And no performance degradation should be observed
    And user experience should be smooth without noticeable delays

  @functional @regression @priority-medium @negative
  Scenario: Rejection cannot be submitted without mandatory comments
    Given at least one pending schedule change request exists in the system
    When user navigates to "Pending Requests" section
    And user clicks on a specific request row
    And user clicks "Reject" button
    Then rejection comment dialog should appear
    And "Rejection reason (required)" field should be marked with red asterisk
    And "Confirm Rejection" button should be disabled
    When user attempts to click "Confirm Rejection" button without entering comments
    Then "Confirm Rejection" button should remain disabled
    And rejection should not be processed
    And validation message should indicate required field

  @functional @regression @priority-high
  Scenario Outline: Approver processes multiple schedule change requests with different decisions
    Given pending schedule change request with ID "<request_id>" exists
    When user navigates to "Pending Requests" section
    And user clicks on request with ID "<request_id>"
    And user clicks "<action>" button
    And user enters "<comments>" in comments field
    And user clicks "Confirm <action>" button
    Then success message "<success_message>" should be displayed
    And request status should update to "<final_status>"
    And notification should be sent to requester
    And request should be removed from pending requests list

    Examples:
      | request_id | action  | comments                                              | success_message                                      | final_status |
      | REQ-001    | Approve | Approved due to valid business justification          | Schedule change request has been approved successfully | Approved     |
      | REQ-002    | Reject  | Request conflicts with operational requirements       | Schedule change request has been rejected            | Rejected     |
      | REQ-003    | Approve | Approved for next quarter implementation              | Schedule change request has been approved successfully | Approved     |
      | REQ-004    | Reject  | Insufficient notice period for schedule change        | Schedule change request has been rejected            | Rejected     |