@negative @error-handling
Feature: As Administrator, I want to perform schedule viewing to achieve better oversight. - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify unauthorized user cannot access schedule viewing page
    Given user is logged in with non-Administrator role (e.g., Employee or Guest role)
    And user does not have 'view_schedules' permission in their role
    And user is on the application dashboard
    And authorization middleware is properly configured
    When attempt to navigate to the schedule viewing page by clicking 'Schedules' menu item or entering URL '/schedule-viewing' directly
    Then access is denied and user is redirected to unauthorized access page or dashboard
    And observe the error message displayed
    Then error message 'Access Denied: You do not have permission to view schedules' appears in red banner at top of page
    And verify the schedule viewing page content is not visible
    Then no schedule data or calendar interface is displayed, only the error message and navigation options
    And user remains logged in but on unauthorized access page or dashboard
    And no schedule data was exposed or accessible
    And access attempt is logged in security audit trail with user ID and timestamp
    And user session remains valid for accessing authorized pages

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify system handles API failure when fetching schedules
    Given user is logged in as Administrator
    And aPI endpoint GET /api/employee-schedules is temporarily unavailable or returning 500 error
    And user navigates to schedule viewing page
    And network connection is active but backend service is down
    When navigate to the schedule viewing page
    Then page loads but shows loading spinner for schedule data
    And wait for API timeout (approximately 30 seconds)
    Then loading spinner stops and error message 'Unable to load schedules. Please try again later.' appears with a 'Retry' button
    And verify calendar interface shows empty state with error indication
    Then calendar framework is visible but shows 'No schedules available' with error icon and explanation text
    And click the 'Retry' button
    Then system attempts to reload schedules, showing loading spinner again
    And user remains on schedule viewing page with error state displayed
    And no partial or corrupted data is shown
    And error is logged in application error logs with API endpoint and error code
    And user can navigate away or retry the operation

  @medium @tc-nega-003
  Scenario: TC-NEGA-003 - Verify export fails gracefully when no schedules are available
    Given user is logged in as Administrator
    And schedule viewing page is loaded
    And filters are applied that result in zero matching schedules
    And calendar displays 'No schedules found' message
    When apply filters that result in no matching schedules (e.g., filter by non-existent employee)
    Then calendar shows empty state with message 'No schedules match your filters'
    And click 'Export' button and select 'Export as CSV'
    Then export button is disabled or clicking it shows warning message 'Cannot export: No schedules to export'
    And attempt to export as PDF
    Then similar warning message appears: 'Cannot export empty schedule. Please adjust your filters.'
    And verify no file download is initiated
    Then no CSV or PDF file is downloaded, and browser download manager shows no new downloads
    And no empty or invalid files are created
    And user remains on schedule viewing page with filters applied
    And warning message is displayed clearly to guide user
    And user can adjust filters to get valid results

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Verify system handles expired session during schedule viewing
    Given user is logged in as Administrator
    And schedule viewing page is loaded and displaying schedules
    And user session is about to expire or has expired
    And session timeout is set to 30 minutes
    When wait for session to expire or manually expire the session token
    Then session expires in the background
    And attempt to apply a filter or export schedules
    Then system detects expired session and displays modal dialog 'Your session has expired. Please log in again.'
    And verify user is redirected to login page after clicking 'OK' on the modal
    Then user is redirected to login page with return URL parameter set to schedule viewing page
    And log in again with valid Administrator credentials
    Then after successful login, user is redirected back to schedule viewing page
    And user is logged out and session is cleared
    And no schedule data remains in browser cache
    And after re-login, user can access schedule viewing page normally
    And session expiration is logged in security audit trail

  @medium @tc-nega-005
  Scenario: TC-NEGA-005 - Verify print functionality handles browser print cancellation
    Given user is logged in as Administrator
    And schedule viewing page is displayed with schedules
    And browser print dialog can be opened
    And at least 5 schedules are visible
    When click 'Print Schedule' button
    Then browser print dialog opens with print preview
    And click 'Cancel' button in the print dialog
    Then print dialog closes and user returns to schedule viewing page
    And verify the schedule viewing page is still functional
    Then calendar is displayed normally, all filters work, and no error messages appear
    And attempt to print again
    Then print dialog opens successfully again without any issues
    And user remains on schedule viewing page
    And no print job was created or sent to printer
    And page functionality is not affected by cancelled print
    And user can continue viewing and interacting with schedules

  @high @tc-nega-006
  Scenario: TC-NEGA-006 - Verify system handles corrupted or invalid schedule data
    Given user is logged in as Administrator
    And database contains at least one schedule record with invalid or null data fields
    And aPI returns schedules including the corrupted record
    And user navigates to schedule viewing page
    When navigate to schedule viewing page
    Then page loads and attempts to render all schedules
    And observe how system handles invalid schedule data
    Then valid schedules are displayed normally, invalid schedules show placeholder text 'Invalid Schedule Data' or are skipped with warning icon
    And check for error notification
    Then warning message appears: 'Some schedules could not be displayed due to data errors. Please contact support.'
    And attempt to export schedules including the invalid data
    Then export completes but invalid records are either excluded or marked as 'Invalid Data' in the exported file
    And valid schedules are displayed and accessible
    And invalid data does not crash the application
    And error is logged with details of corrupted records
    And administrator is notified to fix data integrity issues

