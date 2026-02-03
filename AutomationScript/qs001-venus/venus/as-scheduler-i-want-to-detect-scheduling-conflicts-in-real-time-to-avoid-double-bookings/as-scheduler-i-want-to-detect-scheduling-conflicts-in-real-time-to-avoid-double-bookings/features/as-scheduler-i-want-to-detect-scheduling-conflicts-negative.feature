@negative @error-handling
Feature: As Scheduler, I want to detect scheduling conflicts in real-time to avoid double bookings - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify system handles scheduling request with missing required fields
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling form page
    And all form fields are empty by default
    And form validation is enabled
    When leave Resource dropdown unselected (empty)
    Then resource field remains empty with placeholder text 'Select a resource'
    And leave Start Time and End Time fields empty
    Then time fields show placeholder text 'Select time'
    And click 'Check Availability' button without filling any required fields
    Then red error messages appear below each required field: 'Resource is required', 'Start time is required', 'End time is required'. Check Availability action is blocked
    And attempt to click 'Save Schedule' button
    Then 'Save Schedule' button is disabled (grayed out) and clicking produces no action. Tooltip appears stating 'Please fill all required fields'
    And no scheduling request is sent to the server
    And no conflict detection API call is made
    And no data is saved to the database
    And user remains on the scheduling form with validation errors displayed

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify system rejects scheduling request with End Time before Start Time
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling form page
    And resource 'Lab Equipment #5' is available
    And time validation rules are active
    When select 'Lab Equipment #5' from Resource dropdown
    Then resource field displays 'Lab Equipment #5'
    And enter Start Time as '3:00 PM' in the Start Time field
    Then start Time field displays '3:00 PM'
    And enter End Time as '2:00 PM' (1 hour before Start Time) in the End Time field
    Then end Time field displays '2:00 PM'
    And click 'Check Availability' button or tab out of End Time field
    Then red error message appears below End Time field: 'End time must be after start time. Please enter a valid time range.' Conflict detection is not triggered
    And verify 'Save Schedule' button state
    Then 'Save Schedule' button is disabled and cannot be clicked
    And no API call is made to conflict detection endpoint
    And no schedule is created in the database
    And form validation error remains visible until corrected
    And user must correct the time values before proceeding

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Verify system handles conflict detection when database connection fails
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling form page
    And scheduling database connection is temporarily unavailable or timing out
    And error handling mechanisms are in place
    When select 'Conference Room C' from Resource dropdown, enter Start Time '11:00 AM' and End Time '12:00 PM'
    Then all fields display entered values correctly
    And click 'Check Availability' button to trigger conflict detection
    Then loading spinner appears for up to 2 seconds, then yellow warning banner displays: 'Unable to check for conflicts. Database connection error. Please try again or contact support if the issue persists.'
    And verify 'Save Schedule' button state during database error
    Then 'Save Schedule' button is disabled with tooltip 'Cannot save schedule without conflict verification'
    And click 'Retry' button in the warning banner
    Then system attempts to reconnect and check for conflicts again. If still failing, same error message appears
    And no schedule is saved to the database
    And error is logged in system error logs with timestamp and user information
    And user remains on the scheduling form with ability to retry
    And system does not crash or become unresponsive

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Verify system prevents unauthorized user without Scheduler role from creating schedules
    Given user is logged in with 'Viewer' role (no scheduling permissions)
    And user attempts to access scheduling functionality
    And role-based access control is enforced
    And authentication tokens are valid but permissions are restricted
    When navigate to the scheduling dashboard URL directly by typing '/scheduling/dashboard' in the browser
    Then system redirects to 'Access Denied' page with message 'You do not have permission to access scheduling features. Please contact your administrator.'
    And attempt to access the scheduling API endpoint directly using browser console: POST /api/schedule/check with valid schedule data
    Then aPI returns 403 Forbidden status code with JSON response: {"error": "Insufficient permissions", "message": "Scheduler role required"}
    And verify that 'Create New Schedule' button is not visible on any accessible pages
    Then scheduling action buttons are hidden or disabled for users without Scheduler role
    And no scheduling request is processed
    And unauthorized access attempt is logged in security audit log
    And user session remains active but restricted to permitted features
    And no data is modified in the scheduling database

  @medium @tc-nega-005
  Scenario: TC-NEGA-005 - Verify system handles scheduling request with invalid date format and special characters
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling form page
    And input validation is enabled for all fields
    And xSS and SQL injection protection is active
    When select 'Meeting Room 1' from Resource dropdown
    Then resource field displays 'Meeting Room 1'
    And enter Start Time as '<script>alert("XSS")</script>' in the Start Time field
    Then field either strips the script tags and shows empty value, or displays error 'Invalid time format. Please use HH:MM AM/PM format'
    And enter End Time as 'DROP TABLE schedules; --' attempting SQL injection
    Then field validation rejects the input with error message 'Invalid time format. Please enter a valid time.'
    And enter Description field with 10,000 characters of text (exceeding maximum limit)
    Then character counter shows '10000/500 characters' in red, and error message appears: 'Description cannot exceed 500 characters'
    And attempt to click 'Check Availability' button
    Then button is disabled and validation errors prevent any API calls. No malicious code is executed
    And no malicious code is executed or stored in the database
    And all input is properly sanitized and validated
    And security event is logged for attempted injection
    And user remains on form with validation errors displayed

  @medium @tc-nega-006
  Scenario: TC-NEGA-006 - Verify system handles conflict detection timeout when response exceeds 2 seconds
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling form page
    And network latency is simulated or server response is delayed beyond 2 seconds
    And timeout threshold is set to 2 seconds as per performance requirements
    When select 'Auditorium' from Resource dropdown, enter Start Time '7:00 PM' and End Time '9:00 PM'
    Then all fields display entered values correctly
    And click 'Check Availability' button to trigger conflict detection
    Then loading spinner appears and continues for more than 2 seconds
    And wait for timeout to occur (after 2 seconds)
    Then loading spinner stops and yellow warning message appears: 'Conflict check is taking longer than expected. The system may be experiencing high load. Please try again.'
    And verify the state of 'Save Schedule' button
    Then 'Save Schedule' button remains disabled with message 'Conflict verification required before saving'
    And no schedule is saved due to incomplete conflict verification
    And timeout event is logged in system performance logs
    And user can retry the conflict check
    And system remains responsive and does not hang

