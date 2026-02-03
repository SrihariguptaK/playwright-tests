@negative @error-handling
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify system prevents creation of shift template with end time before start time
    Given user is logged in as Administrator
    And user is on shift template creation page
    And validation rules are active for time field relationships
    When click 'Create New Template' button
    Then template creation form is displayed with empty fields
    And enter 'Invalid Time Shift' in Template Name field
    Then template Name field accepts input
    And select '05:00 PM' as Start Time
    Then start Time field displays '05:00 PM'
    And select '08:00 AM' as End Time (earlier than start time)
    Then red validation error message appears below End Time field stating 'End time must be after start time'
    And click 'Save Template' button
    Then form submission is blocked, error message persists, and red border appears around End Time field
    And verify no template is created in the templates list
    Then templates list remains unchanged, no new template is added
    And no template is saved to ShiftTemplates database
    And user remains on creation form with error message visible
    And form fields retain entered values for correction
    And error is logged in validation error log

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify system prevents creation of shift template with overlapping break times
    Given user is logged in as Administrator
    And user is on shift template creation page
    And break time overlap validation is enabled
    When click 'Create New Template' button and enter 'Overlapping Break Shift' as Template Name
    Then form is displayed with Template Name populated
    And enter '08:00 AM' as Start Time and '05:00 PM' as End Time
    Then time fields accept valid values without errors
    And click 'Add Break' and enter first break from '12:00 PM' to '01:00 PM'
    Then first break is added successfully to the breaks list
    And click 'Add Break' again and enter second break from '12:30 PM' to '01:30 PM' (overlaps with first break)
    Then red validation error appears stating 'Break times cannot overlap with existing breaks' below the second break time fields
    And attempt to click 'Save Template' button
    Then form submission is prevented, error message remains visible, and overlapping break is highlighted in red
    And no template is saved to database due to validation failure
    And user remains on creation form with error state visible
    And first break remains valid, second break shows error state
    And validation error is logged with details of overlapping times

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Verify system prevents template creation with break time outside shift hours
    Given user is logged in as Administrator
    And user is on shift template creation page
    And break time validation against shift boundaries is active
    When click 'Create New Template' and enter 'Out of Bounds Break' as Template Name
    Then template creation form opens with name field populated
    And enter '09:00 AM' as Start Time and '05:00 PM' as End Time
    Then valid shift times are accepted
    And click 'Add Break' and enter break from '08:00 AM' to '08:30 AM' (before shift start time)
    Then red validation error appears stating 'Break time must be within shift hours (09:00 AM - 05:00 PM)'
    And correct the break to '10:00 AM' to '10:30 AM' and add another break from '05:30 PM' to '06:00 PM' (after shift end time)
    Then first break is accepted, second break shows validation error 'Break time must be within shift hours (09:00 AM - 05:00 PM)'
    And attempt to click 'Save Template' button
    Then form submission is blocked with error message, invalid break is highlighted
    And no template is created in database
    And form remains in error state with validation messages visible
    And user can correct break times and retry submission

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Verify system prevents unauthorized user from accessing shift template creation
    Given user is logged in with 'Employee' role (non-administrator)
    And user does not have shift template creation permissions
    And authorization middleware is active on template creation endpoints
    When attempt to navigate directly to /admin/shift-templates URL by typing in browser address bar
    Then user is redirected to unauthorized access page or dashboard with error message 'You do not have permission to access this page'
    And attempt to access template creation page at /admin/shift-templates/create via direct URL
    Then hTTP 403 Forbidden error is returned, user is redirected with message 'Access denied: Administrator privileges required'
    And use browser developer tools to attempt POST request to /api/shift-templates endpoint with valid template data
    Then aPI returns 403 Forbidden status with JSON response {'error': 'Unauthorized', 'message': 'Administrator role required'}
    And no template is created in database
    And unauthorized access attempt is logged in security audit log with user ID and timestamp
    And user remains on their current authorized page or is redirected to dashboard

  @high @tc-nega-005
  Scenario: TC-NEGA-005 - Verify system prevents template creation with empty or missing required fields
    Given user is logged in as Administrator
    And user is on shift template creation page
    And required field validation is enabled
    When click 'Create New Template' button to open creation form
    Then empty template creation form is displayed
    And leave Template Name field empty and click 'Save Template' button
    Then red validation error 'Template name is required' appears below Template Name field, form submission is blocked
    And enter 'Test Template' in Template Name but leave Start Time empty, then click 'Save Template'
    Then validation error 'Start time is required' appears below Start Time field
    And select '08:00 AM' as Start Time but leave End Time empty, then click 'Save Template'
    Then validation error 'End time is required' appears below End Time field
    And verify all error messages are displayed simultaneously when multiple fields are empty
    Then all required field errors are shown at once, form has red borders around invalid fields
    And no template is saved to database
    And form remains in error state with all validation messages visible
    And user can fill in required fields and resubmit

  @medium @tc-nega-006
  Scenario: TC-NEGA-006 - Verify system handles API failure gracefully during template creation
    Given user is logged in as Administrator
    And user is on shift template creation page with valid data entered
    And aPI endpoint /api/shift-templates is temporarily unavailable or returns 500 error
    When enter valid template data: Name 'API Test Shift', Start Time '09:00 AM', End Time '05:00 PM'
    Then all fields accept valid input without client-side validation errors
    And simulate API failure (or wait for actual failure) and click 'Save Template' button
    Then loading spinner appears briefly, then red error banner displays 'Failed to create template. Please try again later.'
    And verify form data is retained after error
    Then all entered values remain in form fields, user does not lose their input
    And check that no template was created in the templates list
    Then templates list remains unchanged, no partial or duplicate template is created
    And no template is saved to database due to API failure
    And error is logged in system error log with stack trace and timestamp
    And user can retry submission after API is restored
    And form data is preserved for retry attempt

