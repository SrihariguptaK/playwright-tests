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
    And enter 'Invalid Shift' as Template Name
    Then template Name field populates
    And select '05:00 PM' as Start Time
    Then start Time shows '05:00 PM'
    And select '09:00 AM' as End Time (before start time)
    Then end Time field shows '09:00 AM'
    And click 'Save Template' button
    Then red error message appears: 'End time must be after start time' and template is not saved
    And verify template list
    Then 'Invalid Shift' does not appear in the templates list
    And no template is created in the database
    And form remains open with entered data
    And error message is displayed to guide user correction
    And save button remains enabled for retry

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Attempt to create shift template with break time outside shift hours
    Given user is logged in as an Administrator
    And user has opened the template creation form
    And validation rules are active for break time overlap
    When enter 'Overlap Test' as Template Name, '09:00 AM' as Start Time, '05:00 PM' as End Time
    Then all fields populate correctly
    And click 'Add Break' and enter break from '07:00 AM' to '08:00 AM' (before shift start)
    Then break time entry appears in the form
    And click 'Save Template' button
    Then red error message appears: 'Break times must be within shift hours (09:00 AM - 05:00 PM)'
    And verify the templates list
    Then template 'Overlap Test' is not created and does not appear in the list
    And no template is saved to the database
    And form remains open with validation error displayed
    And user can correct the break time and retry

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Attempt to create shift template with empty required fields
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And template creation form is open
    When click 'Create New Template' button
    Then template creation form opens with empty fields
    And leave Template Name field empty
    Then template Name field remains empty
    And leave Start Time and End Time fields empty
    Then time fields show placeholder text or remain unselected
    And click 'Save Template' button
    Then red error messages appear: 'Template Name is required', 'Start Time is required', 'End Time is required'
    And verify Save button behavior
    Then template is not saved and form remains open with error indicators on required fields
    And no template is created in the database
    And form validation prevents submission
    And required field indicators (red borders or asterisks) are visible
    And user remains on the form to complete required fields

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Attempt to create shift template by unauthorized user without administrator permissions
    Given user is logged in with 'Employee' role (non-administrator)
    And user attempts to access /admin/shift-templates URL directly
    And security permissions are enforced at both UI and API levels
    When navigate to /admin/shift-templates URL in browser
    Then system redirects to unauthorized access page or displays error message 'Access Denied: Administrator privileges required'
    And attempt to send POST request to /api/shift-templates with employee authentication token
    Then aPI returns HTTP 403 Forbidden status with error message 'Insufficient permissions'
    And verify no template creation form is accessible
    Then 'Create New Template' button is not visible or is disabled
    And no template is created
    And user access attempt is logged in security audit trail
    And user remains on unauthorized access page or is redirected to appropriate page for their role

  @high @tc-nega-005
  Scenario: TC-NEGA-005 - Attempt to create shift template with special characters and SQL injection in template name
    Given user is logged in as an Administrator
    And template creation form is open
    And input sanitization is implemented
    When enter "'; DROP TABLE ShiftTemplates; --" in the Template Name field
    Then text is entered in the field
    And enter valid Start Time '08:00 AM' and End Time '04:00 PM'
    Then time fields populate correctly
    And click 'Save Template' button
    Then either: (1) Error message 'Invalid characters in template name' appears, OR (2) Template is saved with sanitized name, OR (3) Special characters are escaped properly
    And verify database integrity by checking ShiftTemplates table still exists
    Then shiftTemplates table is intact and not dropped, SQL injection was prevented
    And if template was saved, verify the stored name in database
    Then name is properly escaped/sanitized and does not contain executable SQL code
    And database remains secure and intact
    And no SQL injection vulnerability is exploited
    And input is either rejected or properly sanitized
    And security event is logged if injection attempt detected

  @medium @tc-nega-006
  Scenario: TC-NEGA-006 - Attempt to delete a shift template that is currently assigned to active schedules
    Given user is logged in as an Administrator
    And a shift template named 'Active Shift' exists
    And template 'Active Shift' is currently assigned to at least one active employee schedule
    And user is on the shift template management page
    When locate 'Active Shift' template in the list and click 'Delete' icon
    Then confirmation dialog appears
    And click 'Confirm' button in the dialog
    Then red error message appears: 'Cannot delete template: Currently assigned to active schedules. Please remove assignments first.'
    And verify template still exists in the list
    Then 'Active Shift' template remains in the list, unchanged
    And verify database record
    Then template record still exists in ShiftTemplates table
    And template is not deleted from database
    And active schedule assignments remain intact
    And error message guides user to remove assignments first
    And template remains available for viewing and editing

  @medium @tc-nega-007
  Scenario: TC-NEGA-007 - Attempt to create shift template when system has reached maximum limit of 100 templates
    Given user is logged in as an Administrator
    And exactly 100 shift templates already exist in the system
    And performance limit of 100 templates is enforced
    And user is on the shift template management page
    When click 'Create New Template' button
    Then either button is disabled with tooltip 'Maximum template limit reached (100)', OR form opens normally
    And if form opens, enter 'Template 101' as name, '08:00 AM' as Start Time, '04:00 PM' as End Time
    Then fields populate with entered data
    And click 'Save Template' button
    Then red error message appears: 'Maximum template limit reached. Please delete unused templates before creating new ones.'
    And verify template count in database
    Then shiftTemplates table still contains exactly 100 records, no new template was added
    And template count remains at 100
    And no new template is created
    And user is informed of the limit and guided to delete unused templates
    And system performance remains stable

