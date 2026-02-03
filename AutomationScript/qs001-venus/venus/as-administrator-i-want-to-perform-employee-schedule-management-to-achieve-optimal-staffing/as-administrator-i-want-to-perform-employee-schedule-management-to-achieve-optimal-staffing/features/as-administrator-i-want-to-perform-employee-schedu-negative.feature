@negative @error-handling
Feature: As Administrator, I want to perform employee schedule management to achieve optimal staffing. - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify system prevents double-booking employee to overlapping shifts
    Given user is logged in as Administrator
    And employee 'John Smith' is already assigned to 'Morning Shift 8AM-4PM' on Monday
    And another shift template 'Extended Morning 7AM-3PM' exists that overlaps with the existing assignment
    And schedule management page is loaded with current week view
    When navigate to schedule management page and verify John Smith is assigned to Monday Morning Shift 8AM-4PM
    Then calendar shows John Smith in Monday 8AM-4PM slot with active assignment indicator
    And select 'Extended Morning 7AM-3PM' template and attempt to drag John Smith to Monday 7AM-3PM slot
    Then system prevents the drop action, red error indicator appears on the slot, tooltip shows 'Cannot assign: Employee has overlapping shift 8AM-4PM'
    And attempt to force assignment by clicking 'Assign Employee' button and selecting John Smith from dropdown for the 7AM-3PM slot
    Then error modal appears with message 'Assignment Conflict: John Smith is already assigned to a shift from 8AM-4PM on Monday. Please remove existing assignment first.' with 'OK' button
    And click 'OK' to dismiss error modal and attempt to click 'Save Schedule' button
    Then save button remains disabled or clicking it shows validation error 'Cannot save: Schedule contains conflicts. Please resolve all conflicts before saving.'
    And no double-booking is created in EmployeeSchedules table, John Smith remains assigned only to 8AM-4PM shift
    And administrator remains on schedule management page with error message visible
    And original schedule assignment remains unchanged and valid
    And validation error is logged in system error log with conflict details

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify unauthorized user cannot access schedule management functionality
    Given user is logged in with 'Employee' role (non-administrator)
    And employee role does not have schedule management permissions in the system
    And schedule management page URL is /admin/schedule-management
    And authorization middleware is active and enforcing role-based access control
    When as Employee user, attempt to navigate directly to /admin/schedule-management by typing URL in browser address bar
    Then page redirects to /unauthorized or /access-denied page with error message 'Access Denied: You do not have permission to access this page. Contact your administrator.'
    And attempt to access schedule management API endpoint directly by sending POST request to /api/employee-schedules with valid schedule data
    Then aPI returns 403 Forbidden status code with JSON response: {"error": "Unauthorized", "message": "Insufficient permissions to manage schedules"}
    And check if schedule management menu item or button is visible in the employee's navigation menu
    Then schedule management option is not visible in navigation menu, only employee-accessible options are shown (My Schedule, Time Off, Profile)
    And no schedule data is modified or accessed by unauthorized user
    And user remains on unauthorized/access denied page or is redirected to their dashboard
    And security event is logged with user ID, attempted action, and timestamp
    And session remains valid but access attempt is blocked

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Verify system handles assignment of inactive or terminated employee gracefully
    Given user is logged in as Administrator
    And employee 'Mark Davis' exists in system with status 'Terminated' or 'Inactive'
    And schedule management page is loaded
    And system should filter out inactive employees from assignment pool
    When navigate to schedule management page and check the available employees list
    Then available employees list shows only active employees, 'Mark Davis' (terminated) is not visible in the list
    And attempt to assign terminated employee by directly calling API: POST /api/employee-schedules with Mark Davis's employee ID
    Then aPI returns 400 Bad Request with error message: {"error": "Invalid Employee", "message": "Cannot assign inactive or terminated employee to shift"}
    And if Mark Davis was previously assigned before termination, attempt to view his existing assignments in the calendar
    Then past assignments show with visual indicator (grayed out or strikethrough) and label 'Employee Inactive', cannot be edited or extended
    And no new assignments are created for terminated employee in EmployeeSchedules table
    And system maintains data integrity by preventing invalid assignments
    And administrator remains on schedule management page with appropriate error feedback
    And existing historical assignments remain viewable but marked as inactive

  @medium @tc-nega-004
  Scenario: TC-NEGA-004 - Verify system handles network failure during schedule save operation
    Given user is logged in as Administrator
    And multiple employees are assigned to shifts with unsaved changes indicated
    And browser developer tools are open to simulate network conditions
    And at least 3 new assignments are pending save
    When make 3 new employee assignments to various shifts in the calendar view
    Then assignments appear in calendar with 'unsaved changes' indicator (orange border or asterisk), save button is enabled
    And open browser developer tools, go to Network tab, and set network throttling to 'Offline' mode
    Then network is disabled, browser shows offline indicator
    And click 'Save Schedule' button to attempt saving the assignments
    Then loading spinner appears briefly, then error message displays: 'Network Error: Unable to save schedule. Please check your connection and try again.' Save button remains enabled for retry
    And re-enable network connection and click 'Save Schedule' button again
    Then schedule saves successfully, success message appears: 'Schedule saved successfully. 3 employees assigned.', unsaved changes indicators disappear
    And assignments are saved to EmployeeSchedules table only after successful network request
    And no partial or corrupted data is saved during network failure
    And administrator remains on schedule management page with all unsaved changes preserved during failure
    And error is logged with network failure details and timestamp

  @medium @tc-nega-005
  Scenario: TC-NEGA-005 - Verify system prevents assignment when shift template is deleted or invalid
    Given user is logged in as Administrator
    And shift template 'Night Shift 12AM-8AM' exists and is selected
    And another administrator deletes the 'Night Shift' template in a separate session
    And schedule management page is open with the now-deleted template selected
    When with 'Night Shift 12AM-8AM' template selected, attempt to assign employee 'Lisa Anderson' to Tuesday night shift
    Then assignment appears to succeed in UI, employee is placed in the shift slot
    And click 'Save Schedule' button to persist the assignment
    Then error message appears: 'Save Failed: The selected shift template no longer exists. Please refresh the page and select a valid template.' Assignment is not saved
    And refresh the page to reload available templates
    Then page reloads, 'Night Shift 12AM-8AM' is no longer in the templates dropdown, unsaved assignment is cleared, warning message shows 'Some templates have been removed. Please review your schedule.'
    And no assignment is created in EmployeeSchedules table with invalid template reference
    And administrator is prompted to refresh and select valid template
    And data integrity is maintained by preventing orphaned template references
    And error is logged with details of deleted template and attempted assignment

  @medium @tc-nega-006
  Scenario: TC-NEGA-006 - Verify system handles concurrent editing conflicts between multiple administrators
    Given two administrators (Admin A and Admin B) are logged in on separate browsers/devices
    And both administrators have the same schedule week open in schedule management page
    And employee 'Robert Taylor' is unassigned and available
    And system implements optimistic locking or conflict detection mechanism
    When admin A assigns 'Robert Taylor' to Monday Morning Shift 8AM-4PM but does not save yet
    Then assignment appears in Admin A's calendar view with unsaved indicator
    And admin B assigns 'Robert Taylor' to Monday Afternoon Shift 12PM-8PM and clicks 'Save Schedule' immediately
    Then admin B's assignment saves successfully, success message appears, Robert Taylor is assigned to Afternoon Shift in database
    And admin A now clicks 'Save Schedule' to save their Morning Shift assignment for Robert Taylor
    Then conflict error appears: 'Conflict Detected: Robert Taylor has been assigned to another shift by another administrator. Please refresh to see current schedule.' Save is blocked
    And admin A clicks 'Refresh' button or reloads the page
    Then page reloads showing Robert Taylor assigned to Afternoon Shift (Admin B's assignment), Admin A's unsaved Morning Shift assignment is cleared
    And only Admin B's assignment persists in EmployeeSchedules table, no double-booking created
    And admin A is notified of conflict and sees current state after refresh
    And data integrity is maintained through conflict detection
    And conflict event is logged with both administrator IDs and timestamp

