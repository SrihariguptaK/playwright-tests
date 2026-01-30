@negative @error-handling
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Attempt to create shift template with end time before start time
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And template creation form is open
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Invalid Time Shift' in Template Name field
    Then template Name field displays 'Invalid Time Shift'
    And select '05:00 PM' as Start Time
    Then start Time field displays '05:00 PM'
    And select '08:00 AM' as End Time (earlier than start time)
    Then end Time field displays '08:00 AM'
    And click 'Save Template' button
    Then red error message appears below End Time field stating 'End time must be after start time' and template is not saved
    And verify the templates list
    Then 'Invalid Time Shift' does not appear in the templates list
    And no new template is created in the database
    And user remains on the template creation form with error message visible
    And form fields retain entered values for correction

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Attempt to create shift template with empty required fields
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And template creation form is open
    When click 'Create New Template' button
    Then template creation form opens with empty fields
    And leave Template Name field empty
    Then template Name field remains empty
    And leave Start Time field empty
    Then start Time field remains empty
    And leave End Time field empty
    Then end Time field remains empty
    And click 'Save Template' button
    Then red error messages appear: 'Template Name is required' below name field, 'Start Time is required' below start time field, 'End Time is required' below end time field. Template is not saved
    And verify no API call is made to POST /api/shift-templates
    Then network tab shows no POST request was sent
    And no template is created in the database
    And user remains on the form with validation errors displayed
    And save button remains enabled for retry after corrections

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Attempt to create shift template with break time outside of shift hours
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And template creation form is open
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Invalid Break Shift' as Template Name, '09:00 AM' as Start Time, '05:00 PM' as End Time
    Then all fields display entered values
    And click 'Add Break' and enter break time from '06:00 PM' to '06:30 PM' (after shift end time)
    Then break time entry appears showing '06:00 PM - 06:30 PM'
    And click 'Save Template' button
    Then red error message appears: 'Break time must be within shift hours (09:00 AM - 05:00 PM)' and template is not saved
    And no template is created in the database
    And user remains on form with error message
    And break entry remains visible for correction

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Attempt to create shift template with overlapping break times
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And template creation form is open
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Overlapping Breaks' as Template Name, '08:00 AM' as Start Time, '06:00 PM' as End Time
    Then all fields display entered values
    And click 'Add Break' and enter first break from '12:00 PM' to '01:00 PM'
    Then first break entry appears: '12:00 PM - 01:00 PM'
    And click 'Add Break' and enter second break from '12:30 PM' to '01:30 PM' (overlaps with first break)
    Then second break entry appears: '12:30 PM - 01:30 PM'
    And click 'Save Template' button
    Then red error message appears: 'Break times cannot overlap. Please adjust break periods.' and template is not saved
    And no template is created in the database
    And both break entries remain visible with error indication
    And user can edit or remove breaks to resolve conflict

  @high @tc-nega-005
  Scenario: TC-NEGA-005 - Attempt to access shift template creation without administrator permissions
    Given user is logged in with 'Employee' role (non-administrator)
    And user attempts to navigate to /admin/shift-templates URL directly
    When enter URL '/admin/shift-templates' in browser address bar and press Enter
    Then system redirects to access denied page or displays error message 'You do not have permission to access this page'
    And attempt to access the API endpoint directly by sending POST request to /api/shift-templates with valid template data
    Then aPI returns 403 Forbidden status code with error message 'Insufficient permissions'
    And verify no template was created
    Then database query confirms no new template was added
    And no template is created
    And user access attempt is logged in security audit trail
    And user remains on access denied page or is redirected to their authorized home page

  @high @tc-nega-006
  Scenario: TC-NEGA-006 - Attempt to create shift template with SQL injection in template name field
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And template creation form is open
    When click 'Create New Template' button
    Then template creation form opens
    And enter SQL injection string "'; DROP TABLE ShiftTemplates; --" in Template Name field
    Then template Name field displays the entered string
    And enter '09:00 AM' as Start Time and '05:00 PM' as End Time
    Then time fields display entered values
    And click 'Save Template' button
    Then either: (1) Template is saved with the string treated as literal text, or (2) Validation error appears: 'Template name contains invalid characters'
    And verify ShiftTemplates table still exists and contains all previous data
    Then database table is intact, no SQL injection was executed, all existing templates remain
    And database integrity is maintained
    And no SQL injection attack was successful
    And security event is logged if malicious input was detected

  @high @tc-nega-007
  Scenario: TC-NEGA-007 - Attempt to delete a shift template that is currently assigned to active schedules
    Given user is logged in as an Administrator
    And shift template 'Active Shift' exists and is assigned to at least one active employee schedule
    And user is on the shift template management page
    When locate 'Active Shift' template in the list and click the 'Delete' icon button
    Then confirmation dialog appears
    And click 'Delete' button in the confirmation dialog
    Then red error message appears: 'Cannot delete template. This template is currently assigned to active schedules. Please remove all assignments before deleting.'
    And verify the template still exists in the list
    Then 'Active Shift' template remains in the templates list unchanged
    And verify database integrity
    Then template still exists in ShiftTemplates table and all schedule assignments remain intact
    And template 'Active Shift' is not deleted
    And all schedule assignments remain active
    And error message guides user on how to proceed

