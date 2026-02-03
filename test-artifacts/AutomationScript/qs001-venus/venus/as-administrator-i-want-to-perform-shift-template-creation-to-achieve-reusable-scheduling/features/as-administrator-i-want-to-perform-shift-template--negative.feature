@negative @error-handling
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify validation error when end time is before or equal to start time
    Given user is logged in as Administrator
    And user is on the shift template creation page
    And template creation form is displayed and empty
    And validation rules enforce start time must be before end time
    When enter 'Invalid Time Shift' in Template Name field
    Then template Name field accepts the input
    And select '05:00 PM' as Start Time
    Then start Time field displays '05:00 PM'
    And select '02:00 PM' as End Time (earlier than start time)
    Then red validation error message appears below End Time field: 'End time must be after start time'
    And attempt to click 'Save Template' button
    Then save button is disabled or clicking it shows error message 'Please fix validation errors before saving' and form is not submitted
    And change End Time to '05:00 PM' (equal to start time)
    Then validation error persists: 'End time must be after start time' or 'Shift duration must be at least 1 minute'
    And no template is created in the database
    And user remains on the creation form with validation errors displayed
    And form data is retained for correction
    And no API call to POST /api/shift-templates is made

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify validation error when break times overlap with each other
    Given user is logged in as Administrator
    And user is on the shift template creation page
    And template form has valid start time '08:00 AM' and end time '05:00 PM' entered
    And system validates that break times cannot overlap
    When enter 'Overlapping Breaks Shift' as Template Name
    Then template Name is accepted
    And click 'Add Break' and enter first break from '12:00 PM' to '01:00 PM'
    Then first break is added successfully without errors
    And click 'Add Break' again and enter second break from '12:30 PM' to '01:30 PM' (overlaps with first break)
    Then red validation error appears: 'Break times cannot overlap with existing breaks' below the second break time fields
    And attempt to click 'Save Template' button
    Then form submission is blocked and error message 'Please resolve break time conflicts before saving' is displayed
    And no template is saved to the database
    And both break entries remain visible in the form for correction
    And validation error remains until overlap is resolved
    And user can remove or edit the conflicting break

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Verify validation error when break time falls outside shift start and end time
    Given user is logged in as Administrator
    And user is on shift template creation page
    And template has Start Time '09:00 AM' and End Time '05:00 PM' entered
    And system validates breaks must fall within shift hours
    When enter 'Invalid Break Shift' as Template Name
    Then name is accepted
    And click 'Add Break' and enter break time from '06:00 PM' to '06:30 PM' (after shift end time)
    Then red validation error appears: 'Break time must be within shift hours (09:00 AM - 05:00 PM)'
    And change break time to '08:00 AM' to '08:30 AM' (before shift start time)
    Then validation error persists: 'Break time must be within shift hours (09:00 AM - 05:00 PM)'
    And attempt to save the template
    Then save is blocked with error message 'Cannot save template with invalid break times'
    And template is not created in the database
    And form remains open with validation errors visible
    And user must correct break times to proceed

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Verify error when unauthorized user attempts to create shift template
    Given user is logged in with 'Employee' role (non-administrator)
    And user does not have shift template creation permissions
    And user attempts to access /admin/shift-templates URL directly
    And security rules restrict template creation to administrators only
    When navigate to /admin/shift-templates URL by typing in browser address bar
    Then user is redirected to access denied page or dashboard with error message 'You do not have permission to access this page'
    And attempt to access the API endpoint POST /api/shift-templates directly using browser developer tools or API client
    Then aPI returns 403 Forbidden status code with error response: {'error': 'Unauthorized access', 'message': 'Administrator role required'}
    And verify no 'Create New Template' button is visible if user somehow accesses the page
    Then template creation controls are hidden or disabled for non-administrator users
    And no template is created in the database
    And security event is logged with user ID and attempted unauthorized action
    And user remains on access denied page or is redirected to appropriate page

  @high @tc-nega-005
  Scenario: TC-NEGA-005 - Verify error when attempting to create template with empty or missing required fields
    Given user is logged in as Administrator
    And user is on the shift template creation page
    And all form fields are empty
    And required fields are: Template Name, Start Time, End Time
    When leave Template Name field empty and click 'Save Template' button
    Then validation error appears: 'Template Name is required' in red text below the field
    And enter 'Test Shift' in Template Name but leave Start Time empty, then click Save
    Then validation error appears: 'Start Time is required'
    And fill Template Name and Start Time '09:00 AM' but leave End Time empty, then click Save
    Then validation error appears: 'End Time is required'
    And verify that Save button remains disabled or form submission is blocked until all required fields are filled
    Then form cannot be submitted and all validation errors are displayed simultaneously
    And no template is created in the database
    And user remains on the form with all validation errors visible
    And form retains any valid data entered for correction

  @high @tc-nega-006
  Scenario: TC-NEGA-006 - Verify error when attempting to delete a shift template that is currently in use
    Given user is logged in as Administrator
    And a shift template named 'Active Shift' exists and is assigned to at least one current or future schedule
    And user is on the shift template management page
    And system prevents deletion of templates in active use
    When locate 'Active Shift' template in the list and click the 'Delete' icon
    Then confirmation dialog appears asking for deletion confirmation
    And click 'Confirm' button in the deletion confirmation dialog
    Then error message appears in red banner: 'Cannot delete template. This template is currently assigned to active schedules.'
    And verify the template still exists in the list
    Then 'Active Shift' template remains in the list unchanged
    And check database to confirm template was not deleted
    Then template record still exists in ShiftTemplates table with all data intact
    And template remains in the database and is not deleted
    And associated schedules continue to reference the template without disruption
    And error is logged indicating attempted deletion of in-use template

