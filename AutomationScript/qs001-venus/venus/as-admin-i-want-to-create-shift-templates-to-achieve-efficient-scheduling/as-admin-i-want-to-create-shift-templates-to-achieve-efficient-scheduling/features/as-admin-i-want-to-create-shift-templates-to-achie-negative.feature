@negative @error-handling
Feature: As Admin, I want to create shift templates to achieve efficient scheduling. - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify system prevents template creation when end time is before start time
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And template creation form is open
    And validation rules are active for time field validation
    When click on 'Create New Template' button
    Then template creation form modal opens with empty fields
    And enter 'Invalid Shift' in Template Name field
    Then template Name field accepts the input
    And enter '05:00 PM' in Start Time field
    Then start Time field displays '05:00 PM'
    And enter '09:00 AM' in End Time field (before start time)
    Then end Time field displays '09:00 AM', validation error message 'End time must be after start time' appears in red text below the field
    And attempt to click 'Save Template' button
    Then 'Save Template' button is disabled or clicking it triggers error message 'Please correct the errors before saving', form does not submit
    And verify no API call is made to POST /api/shifts/templates
    Then network tab shows no POST request to the templates endpoint, no database write occurs
    And no new template is created in the database
    And form remains open with error message displayed
    And user can correct the time values and retry
    And system maintains data integrity by preventing invalid template creation

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify system prevents template creation with empty required fields
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And template creation form is open
    And all fields are empty by default
    When click on 'Create New Template' button
    Then template creation form modal opens with all fields empty
    And leave Template Name field empty
    Then template Name field remains empty with no input
    And leave Start Time field empty
    Then start Time field remains empty with placeholder text visible
    And leave End Time field empty
    Then end Time field remains empty with placeholder text visible
    And click 'Save Template' button without entering any data
    Then validation errors appear: 'Template Name is required', 'Start Time is required', 'End Time is required' in red text below respective fields
    And verify form does not submit and no API call is made
    Then form remains open with error messages, no POST request to /api/shifts/templates, 'Save Template' button remains clickable for retry
    And no template is created in the database
    And form validation prevents submission of incomplete data
    And user remains on the form to complete required fields
    And no partial or null data is written to ShiftTemplates table

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Verify non-admin user cannot access shift template creation functionality
    Given user is logged in with Employee-level authentication (non-admin role)
    And user has valid session token but lacks admin privileges
    And shift Template management page requires admin-level authentication
    And role-based access control is enforced on both frontend and backend
    When attempt to navigate to Shift Template management page URL directly (/admin/shift-templates)
    Then system redirects to unauthorized access page or displays error message 'You do not have permission to access this page'
    And verify 'Create New Template' button is not visible in the UI
    Then if page loads, 'Create New Template' button is hidden or disabled for non-admin users
    And attempt to make direct API call to POST /api/shifts/templates with employee-level authentication token
    Then aPI returns 403 Forbidden status code with error message 'Admin authentication required'
    And verify no template creation form can be accessed through any navigation path
    Then all routes to template creation are blocked, user cannot bypass UI restrictions
    And no unauthorized template creation occurs
    And user session remains active but access is denied to admin functions
    And security audit log records the unauthorized access attempt with user ID and timestamp
    And system maintains proper role-based access control

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Verify system handles template creation failure when database connection is lost
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And template creation form is open with valid data entered
    And database connection can be simulated to fail or timeout
    When enter valid template data: Name 'Test Shift', Start Time '09:00 AM', End Time '05:00 PM', Role 'Cashier'
    Then all fields accept valid input without validation errors
    And simulate database connection failure or timeout (disconnect database or use network throttling)
    Then database connection is unavailable for write operations
    And click 'Save Template' button
    Then loading spinner appears indicating processing, system attempts to save template
    And wait for system response after database timeout
    Then error message 'Unable to save template. Please check your connection and try again.' appears in red banner at top of page
    And verify form data is retained after error
    Then all entered data remains in the form fields, user does not lose their input
    And verify no partial data is written to database
    Then query database to confirm no incomplete or corrupted template record exists
    And no template is created in the database due to connection failure
    And user data is preserved in the form for retry
    And system logs the database connection error with timestamp and error details
    And user can retry submission once connection is restored

  @high @tc-nega-005
  Scenario: TC-NEGA-005 - Verify system prevents deletion of shift template currently assigned to active schedules
    Given user is logged in with Admin-level authentication
    And shift template 'Morning Shift' exists in the system
    And template 'Morning Shift' is currently assigned to at least one employee's active schedule
    And user is on the Shift Template management page
    When locate the 'Morning Shift' template that is currently in use
    Then template 'Morning Shift' is visible in the list, may show indicator that it is in use
    And click the 'Delete' icon button next to the 'Morning Shift' template
    Then confirmation dialog appears with warning message 'This template is currently assigned to active schedules and cannot be deleted'
    And verify 'Confirm' button is disabled or replaced with 'OK' button to dismiss
    Then delete action cannot be confirmed, only option is to close the dialog
    And click 'OK' or 'Cancel' to close the dialog
    Then dialog closes, template remains in the list unchanged
    And verify template still exists in the database
    Then template 'Morning Shift' remains in ShiftTemplates table with all data intact
    And template 'Morning Shift' is not deleted from the database
    And all employee schedules using this template remain intact and functional
    And system maintains referential integrity between templates and schedules
    And admin remains on Shift Template page with no changes to data

  @high @tc-nega-006
  Scenario: TC-NEGA-006 - Verify system handles SQL injection attempts in template name field
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And template creation form is open
    And input sanitization and parameterized queries are implemented
    When click on 'Create New Template' button
    Then template creation form modal opens
    And enter SQL injection string in Template Name field: "'; DROP TABLE ShiftTemplates; --"
    Then field accepts the input as plain text string
    And enter valid Start Time '09:00 AM' and End Time '05:00 PM'
    Then time fields accept valid values
    And click 'Save Template' button
    Then system either sanitizes the input and saves it as literal text, or displays error 'Invalid characters in template name'
    And verify ShiftTemplates table still exists and is not dropped
    Then database table remains intact, no SQL injection executed, all existing templates are still present
    And if template was saved, verify the name is stored as literal string without executing SQL
    Then template name in database contains the exact string entered, treated as text not SQL code
    And database integrity is maintained, no tables are dropped or modified
    And sQL injection attempt is logged in security audit log
    And input sanitization prevents malicious code execution
    And system remains secure and operational

