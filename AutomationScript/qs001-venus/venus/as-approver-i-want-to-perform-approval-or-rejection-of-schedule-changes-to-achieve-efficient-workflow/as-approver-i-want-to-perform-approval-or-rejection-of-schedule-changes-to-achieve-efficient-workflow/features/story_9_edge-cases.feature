Feature: Schedule Change Request Approval Edge Cases
  As an Approver
  I want the system to handle edge cases gracefully during approval workflow
  So that I can reliably process schedule change requests under all conditions

  Background:
    Given user is logged in with "Approver" role

  @edge @regression @priority-medium
  Scenario: Approval comment at maximum character limit boundary
    Given a pending schedule change request exists
    And system has maximum character limit of 1000 for comments
    And user is on the approval dialog screen
    When user navigates to pending requests section
    And user selects a request to approve
    Then request details and approval dialog should be displayed
    When user enters approval comment with exactly 1000 characters
    Then all characters should be accepted
    And character counter should show "1000/1000"
    And "Confirm Approval" button should be enabled
    When user attempts to enter 1 more character beyond maximum limit
    Then additional character should not be accepted
    And validation message "Maximum character limit reached" should be displayed
    When user clicks "Confirm Approval" button
    Then approval should be processed successfully
    And success message should be displayed
    And comment should be saved without truncation
    When user views request history
    Then full comment text with 1000 characters should be visible
    And notification should be sent to requester with complete comment

  @edge @regression @priority-low
  Scenario: Pending requests list with zero items
    Given no pending schedule change requests exist in the system
    And all requests are either approved or rejected
    And user has permission to access pending requests section
    When user navigates to pending requests section
    Then page should load within 2 seconds
    And empty state message "No pending requests at this time" should be displayed
    And table headers should be visible
    And filter options should be visible
    And no data rows should be shown
    When user uses search functionality on empty list
    Then search controls should remain functional
    And "No results found" message should be displayed
    When user applies filter on empty list
    Then filter controls should remain functional
    And "No results found" message should be displayed
    When user refreshes the page
    Then empty state message should persist
    And no errors should occur

  @edge @regression @priority-medium
  Scenario: Approval comment with special characters, Unicode, and emojis
    Given a pending schedule change request exists
    And system supports UTF-8 character encoding
    And user is on the approval dialog screen
    When user navigates to pending requests section
    And user selects a request to approve
    Then approval dialog should be displayed with comment text area
    When user enters approval comment "Approved! @#$%^&*()_+-={}[]|:;<>?,./~`"
    Then all special characters should be accepted
    And special characters should be displayed correctly in text area
    When user adds Unicode and emojis to comment "Approved ✓ 👍 Great work! Café résumé naïve"
    Then Unicode characters should be accepted
    And emojis should be accepted
    And character count should update appropriately
    When user clicks "Confirm Approval" button
    Then approval should be processed successfully without encoding errors
    And success message should be displayed
    When user views request history
    Then all special characters should be preserved and displayed correctly
    And Unicode characters should be displayed correctly
    And emojis should be displayed correctly
    When user views notification email
    Then special characters should render properly
    And emojis should render properly

  @edge @regression @priority-medium
  Scenario: Pending requests list with very large dataset
    Given system contains 1000 pending schedule change requests
    And pagination is implemented for large datasets
    And system is under normal load conditions
    When user navigates to pending requests section
    Then page should load within 2 seconds
    And first page should display 50 requests
    And pagination controls should be visible
    And pagination information should show "Showing 1-50 of 1000 requests"
    When user clicks "Next" button
    Then page 2 should load within 2 seconds
    And correct subset of requests should be displayed
    When user navigates to page 10
    Then page should load within 2 seconds
    And correct subset of requests should be displayed
    When user navigates to last page
    Then page should load within 2 seconds
    And correct subset of requests should be displayed
    When user searches by requester name in large dataset
    Then search results should return within 2 seconds
    And filtered results should be accurate
    And pagination should be updated
    When user sorts by "Submission Date" column
    Then sorting should complete within 2 seconds
    And results should be correctly ordered across all pages
    When user sorts by "Requester Name" column
    Then sorting should complete within 2 seconds
    And results should be correctly ordered across all pages

  @edge @regression @priority-high
  Scenario: Concurrent approval attempts by multiple approvers on same request
    Given 2 users are logged in with "Approver" role in different browser sessions
    And a pending schedule change request with ID "12345" exists
    And system has concurrency control mechanism implemented
    And both approvers are viewing the same request simultaneously
    When approver 1 navigates to pending requests section
    And approver 1 selects request ID "12345" to approve
    Then request details should be displayed for approver 1
    And "Approve" button should be enabled for approver 1
    When approver 2 navigates to pending requests section in different session
    And approver 2 selects request ID "12345" to approve
    Then request details should be displayed for approver 2
    And "Approve" button should be enabled for approver 2
    When approver 1 clicks "Approve" button
    And approver 1 enters comment "Approved by Manager A"
    And approver 1 clicks "Confirm Approval" button
    Then approval should be processed successfully for approver 1
    And success message should be displayed to approver 1
    And request status should update to "Approved"
    When approver 2 clicks "Approve" button immediately after
    And approver 2 clicks "Confirm Approval" button
    Then error message "This request has already been approved by another approver" should be displayed
    And approver 2 approval should be rejected
    When database is checked for approval records
    Then only 1 approval record should exist
    And approval record should contain approver 1 information
    And no duplicate approval records should exist
    And only 1 notification should be sent to requester

  @edge @regression @priority-medium
  Scenario: Notification service unavailable during approval submission
    Given a pending schedule change request exists
    And notification service is unavailable
    And system has retry logic for notifications
    When user navigates to pending requests section
    And user selects a request to approve
    Then request details should be displayed
    When user clicks "Approve" button
    And user enters comment "Approved with notification service down"
    And user clicks "Confirm Approval" button
    Then approval should be processed successfully
    And request status should be updated to "Approved" in database
    And message "Request approved successfully, but notification could not be sent. It will be retried automatically." should be displayed
    When notification queue is checked
    Then failed notification should be added to retry queue
    And notification should contain request details
    When notification service is restored
    Then queued notification should be sent successfully
    And requester should receive notification with all approval details