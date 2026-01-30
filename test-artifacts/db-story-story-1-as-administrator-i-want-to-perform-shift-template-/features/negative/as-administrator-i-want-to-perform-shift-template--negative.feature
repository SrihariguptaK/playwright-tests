@negative @error-handling
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify system rejects shift template creation with empty required fields
    Given user is logged in as Administrator
    And user is on the Shift Template Management page
    And user has clicked 'Create New Template' button and form is displayed
    When leave Template Name field empty
    Then template Name field remains empty with no default value
    And leave Start Time field unselected
    Then start Time field shows placeholder text 'Select start time' with no value selected
    And leave End Time field unselected
    Then end Time field shows placeholder text 'Select end time' with no value selected
    And click 'Save Template' button with all required fields empty
    Then red validation error messages appear: 'Template Name is required', 'Start Time is required', 'End Time is required'. Template is not saved
    And verify no API call is made to POST /api/shift-templates
    Then network tab shows no POST request to /api/shift-templates endpoint, client-side validation prevents submission
    And no template is created in the database
    And form remains open with validation errors displayed
    And user remains on the template creation form to correct errors

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify system rejects template creation with special characters and SQL injection attempts in Template Name
    Given user is logged in as Administrator
    And user has opened the Create New Template form
    And database connection is active and monitored for SQL injection attempts
    When enter SQL injection string "'; DROP TABLE ShiftTemplates; --" in Template Name field
    Then field accepts the input but system sanitizes it, or validation error appears stating 'Template Name contains invalid characters'
    And enter valid Start Time '09:00 AM' and End Time '05:00 PM'
    Then time fields are populated correctly
    And click 'Save Template' button
    Then either validation error prevents save with message 'Template Name contains invalid characters', or template saves with sanitized name and SQL injection is prevented
    And verify ShiftTemplates table still exists and no SQL injection occurred
    Then database table ShiftTemplates remains intact, no tables were dropped, and no unauthorized SQL commands were executed
    And attempt to create template with XSS payload "<script>alert('XSS')</script>" as Template Name
    Then input is either rejected with validation error or sanitized/escaped before storage, preventing XSS execution
    And database integrity is maintained with no SQL injection damage
    And no malicious scripts are stored or executed
    And security event is logged in system audit trail

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Verify unauthorized user without Administrator role cannot access shift template creation
    Given user is logged in with 'Employee' role (non-administrator)
    And user does not have shift template creation permissions
    And shift Template Management page URL is /shift-templates
    When attempt to navigate directly to /shift-templates URL by typing in browser address bar
    Then system redirects to unauthorized access page or dashboard with error message 'You do not have permission to access this page'
    And attempt to access the page through any navigation menu
    Then 'Shift Template Management' option is not visible in navigation menu for Employee role
    And attempt to make direct API call to POST /api/shift-templates with valid template data using browser console or API tool
    Then aPI returns 403 Forbidden status code with error message 'Insufficient permissions to create shift templates'
    And verify no template is created in the database
    Then shiftTemplates table shows no new entries from unauthorized user attempt
    And user remains on their current authorized page or is redirected to error page
    And no unauthorized template creation occurs
    And unauthorized access attempt is logged in security audit trail with user ID and timestamp

  @medium @tc-nega-004
  Scenario: TC-NEGA-004 - Verify system handles network timeout during template creation gracefully
    Given user is logged in as Administrator
    And user has filled out valid template creation form with all required fields
    And network simulation tool is configured to simulate timeout after 30 seconds
    When enter valid template data: Name 'Network Test', Start Time '09:00 AM', End Time '05:00 PM'
    Then all fields are populated correctly with valid data
    And simulate network timeout condition and click 'Save Template' button
    Then loading spinner appears on Save button with text changing to 'Saving...'
    And wait for timeout to occur (30 seconds)
    Then after timeout, error message appears: 'Network error: Unable to save template. Please check your connection and try again.' with 'Retry' button
    And verify form data is preserved and not lost
    Then all entered data remains in the form fields (Template Name, Start Time, End Time) and user can retry without re-entering
    And click 'Retry' button after network is restored
    Then template saves successfully with message 'Shift template created successfully'
    And template is eventually saved after retry with network restored
    And no duplicate templates are created from multiple retry attempts
    And user experience is maintained with clear error messaging and data preservation

  @high @tc-nega-005
  Scenario: TC-NEGA-005 - Verify system prevents deletion of shift template currently assigned to active schedules
    Given user is logged in as Administrator
    And a shift template named 'Active Shift' exists and is currently assigned to at least one active employee schedule
    And user is on the Shift Template Management page viewing the templates list
    When locate 'Active Shift' template that is in use and click the 'Delete' icon button
    Then confirmation dialog appears with warning message 'This template is currently in use by active schedules and cannot be deleted'
    And verify Delete button in dialog is disabled or shows 'Cannot Delete'
    Then delete button is either disabled (grayed out) or replaced with 'Close' button only
    And attempt to make direct API DELETE call to /api/shift-templates/{id} for the active template
    Then aPI returns 409 Conflict status code with error message 'Cannot delete template: currently in use by X active schedules'
    And verify template still exists in the database and templates list
    Then template 'Active Shift' remains in ShiftTemplates table and is still visible in the templates list
    And template remains in database and is not deleted
    And active schedules using this template are not affected
    And deletion attempt is logged in audit trail with reason for failure

  @medium @tc-nega-006
  Scenario: TC-NEGA-006 - Verify system rejects template with excessively long Template Name exceeding character limit
    Given user is logged in as Administrator
    And user has opened Create New Template form
    And template Name field has a maximum character limit of 100 characters
    When enter a 150-character string in Template Name field: 'A' repeated 150 times
    Then field either truncates input at 100 characters or shows character count '150/100' in red
    And enter valid Start Time '09:00 AM' and End Time '05:00 PM'
    Then time fields are populated correctly
    And click 'Save Template' button
    Then validation error appears: 'Template Name must not exceed 100 characters' and template is not saved
    And reduce Template Name to exactly 100 characters and click Save again
    Then template saves successfully with 100-character name, showing success message
    And only template with valid character length is saved to database
    And database field constraints are enforced
    And user receives clear feedback on character limit violations

  @medium @tc-nega-007
  Scenario: TC-NEGA-007 - Verify system handles server error (500) during template creation with appropriate error message
    Given user is logged in as Administrator
    And user has filled valid template creation form
    And backend server is configured to return 500 Internal Server Error for testing
    When enter valid template data: Name 'Server Error Test', Start Time '09:00 AM', End Time '05:00 PM'
    Then all fields are populated with valid data
    And click 'Save Template' button while server is returning 500 error
    Then loading indicator appears briefly, then error message displays: 'Server error: Unable to create template. Please try again later or contact support.'
    And verify form data is preserved
    Then all entered data remains in form fields and is not lost
    And verify no partial or corrupted data is saved to database
    Then shiftTemplates table shows no new incomplete or corrupted entries
    And verify error is logged with details for debugging
    Then server error log contains entry with timestamp, user ID, error details, and stack trace for troubleshooting
    And no template is created due to server error
    And user can retry after server issue is resolved
    And error is properly logged for system administrators to investigate

