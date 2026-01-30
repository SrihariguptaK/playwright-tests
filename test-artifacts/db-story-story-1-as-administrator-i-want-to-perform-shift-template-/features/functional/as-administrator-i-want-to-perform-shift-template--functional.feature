@functional @smoke
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Verify successful creation of shift template with valid start time, end time, and break times
    Given user is logged in with Administrator role and has permissions to create shift templates
    And user is on the Shift Template Management page at /shift-templates
    And database has less than 100 existing shift templates to ensure performance
    And system time is synchronized and displaying correct timezone
    When click on the 'Create New Template' button located in the top-right corner of the page
    Then shift template creation form modal opens with empty fields for Template Name, Start Time, End Time, and Break Times
    And enter 'Morning Shift' in the Template Name field
    Then text 'Morning Shift' appears in the Template Name field with no validation errors
    And select '08:00 AM' from the Start Time dropdown picker
    Then start Time field displays '08:00 AM' and field is highlighted as filled
    And select '05:00 PM' from the End Time dropdown picker
    Then end Time field displays '05:00 PM' and no validation error appears since end time is after start time
    And click 'Add Break' button and enter break time from '12:00 PM' to '01:00 PM'
    Then break time entry appears showing '12:00 PM - 01:00 PM' with no overlap validation errors
    And click the 'Save Template' button at the bottom of the form
    Then green success banner appears at top of page displaying 'Shift template created successfully' and modal closes automatically
    And verify the newly created template appears in the shift templates list
    Then template 'Morning Shift' is visible in the list showing Start Time: 08:00 AM, End Time: 05:00 PM, Break: 12:00 PM - 01:00 PM
    And new shift template 'Morning Shift' is saved in ShiftTemplates database table with all entered details
    And template appears in the templates list and is available for selection in scheduling workflows
    And administrator remains on the Shift Template Management page with updated list visible
    And success confirmation message is logged in system audit trail with timestamp and admin user ID

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Verify administrator can create shift template with multiple break periods
    Given user is logged in as Administrator with shift template creation permissions
    And user is on the Shift Template Management page
    And no existing template with the name 'Extended Shift' exists in the system
    When click 'Create New Template' button
    Then template creation form opens with all required fields visible
    And enter 'Extended Shift' as Template Name, '07:00 AM' as Start Time, and '11:00 PM' as End Time
    Then all fields are populated correctly with no validation errors
    And click 'Add Break' button and add first break from '10:00 AM' to '10:15 AM'
    Then first break entry appears in the breaks section showing '10:00 AM - 10:15 AM'
    And click 'Add Break' button again and add second break from '02:00 PM' to '02:30 PM'
    Then second break entry appears below first break showing '02:00 PM - 02:30 PM' with no overlap errors
    And click 'Add Break' button again and add third break from '06:00 PM' to '06:30 PM'
    Then third break entry appears showing '06:00 PM - 06:30 PM', all breaks are within shift time boundaries
    And click 'Save Template' button
    Then success message 'Shift template created successfully' appears and form closes
    And template 'Extended Shift' is saved with all three break periods in the database
    And template appears in list showing all break times correctly
    And total break duration is calculated and displayed (1 hour 15 minutes total)

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Verify administrator can edit an existing shift template and changes are saved
    Given user is logged in as Administrator
    And at least one shift template named 'Morning Shift' exists in the system with Start Time: 08:00 AM, End Time: 05:00 PM
    And user is on the Shift Template Management page viewing the list of templates
    When locate 'Morning Shift' template in the list and click the 'Edit' icon button next to it
    Then edit template form opens pre-populated with existing values: Template Name: 'Morning Shift', Start Time: 08:00 AM, End Time: 05:00 PM
    And change the End Time from '05:00 PM' to '06:00 PM'
    Then end Time field updates to show '06:00 PM' with no validation errors
    And click 'Add Break' and add a new break from '03:00 PM' to '03:15 PM'
    Then new break appears in the breaks list showing '03:00 PM - 03:15 PM'
    And click 'Save Changes' button
    Then success message 'Shift template updated successfully' appears in green banner at top of page
    And verify the updated template in the list
    Then template 'Morning Shift' now shows End Time: 06:00 PM and includes the new break time
    And template changes are persisted in ShiftTemplates database table
    And updated template reflects new end time and additional break in all views
    And edit action is logged in audit trail with timestamp and admin user ID

  @high @tc-func-004
  Scenario: TC-FUNC-004 - Verify administrator can delete a shift template that is no longer in use
    Given user is logged in as Administrator with delete permissions
    And a shift template named 'Old Shift' exists and is not currently assigned to any active schedules
    And user is on the Shift Template Management page
    When locate 'Old Shift' template in the templates list
    Then template 'Old Shift' is visible in the list with Delete icon button enabled
    And click the 'Delete' icon button next to 'Old Shift' template
    Then confirmation dialog appears with message 'Are you sure you want to delete this shift template? This action cannot be undone.' with 'Cancel' and 'Delete' buttons
    And click 'Delete' button in the confirmation dialog
    Then confirmation dialog closes and success message 'Shift template deleted successfully' appears in green banner
    And verify 'Old Shift' template is removed from the templates list
    Then template 'Old Shift' no longer appears in the list and total template count decreases by 1
    And template 'Old Shift' is removed from ShiftTemplates database table
    And template is no longer available for selection in any scheduling workflows
    And deletion action is logged in audit trail with timestamp and admin user ID

  @medium @tc-func-005
  Scenario: TC-FUNC-005 - Verify system displays all created templates in a list view with correct details
    Given user is logged in as Administrator
    And at least 5 different shift templates exist in the system with varying start times, end times, and breaks
    And user navigates to the Shift Template Management page
    When observe the shift templates list on the page load
    Then all existing templates are displayed in a table/list format with columns: Template Name, Start Time, End Time, Break Times, Actions
    And verify each template row displays complete information
    Then each template shows accurate Template Name, formatted Start Time (HH:MM AM/PM), formatted End Time (HH:MM AM/PM), and all break periods
    And check that action buttons (Edit, Delete) are present for each template
    Then each template row has visible and enabled Edit and Delete icon buttons
    And verify the total count of templates is displayed
    Then page header shows 'Total Templates: X' where X matches the actual number of templates in the list
    And all templates remain in their original state
    And user remains on the Shift Template Management page
    And no data modifications occur during viewing

  @high @tc-func-006
  Scenario: TC-FUNC-006 - Verify validation that start time must be before end time when creating template
    Given user is logged in as Administrator
    And user is on the Shift Template Management page
    And user has clicked 'Create New Template' button and form is open
    When enter 'Test Shift' in Template Name field
    Then template Name field shows 'Test Shift'
    And select '05:00 PM' from the Start Time dropdown
    Then start Time field displays '05:00 PM'
    And select '08:00 AM' from the End Time dropdown (earlier than start time)
    Then red validation error message appears below End Time field stating 'End time must be after start time'
    And attempt to click 'Save Template' button
    Then 'Save Template' button is disabled and cannot be clicked, or clicking shows error message 'Please fix validation errors before saving'
    And change End Time to '11:00 PM' (after start time)
    Then validation error message disappears and 'Save Template' button becomes enabled
    And no template is saved to the database due to validation failure
    And form remains open with corrected values
    And user can proceed to save after fixing validation errors

  @high @tc-func-007
  Scenario: TC-FUNC-007 - Verify break times validation ensures breaks do not overlap with shift boundaries
    Given user is logged in as Administrator
    And user has opened the Create New Template form
    And template Name is 'Validation Test', Start Time is '09:00 AM', End Time is '05:00 PM'
    When click 'Add Break' button and attempt to add break from '08:00 AM' to '09:30 AM' (starts before shift start time)
    Then red validation error appears stating 'Break time must be within shift hours (09:00 AM - 05:00 PM)'
    And clear the invalid break and add break from '04:00 PM' to '06:00 PM' (ends after shift end time)
    Then red validation error appears stating 'Break time must be within shift hours (09:00 AM - 05:00 PM)'
    And clear the invalid break and add valid break from '12:00 PM' to '01:00 PM' (within shift hours)
    Then break is added successfully with no validation errors, showing '12:00 PM - 01:00 PM' in breaks list
    And attempt to add another break from '12:30 PM' to '01:30 PM' (overlaps with existing break)
    Then validation error appears stating 'Break times cannot overlap with existing breaks'
    And only valid breaks within shift boundaries are accepted
    And form prevents saving until all break validations pass
    And user receives clear feedback on validation failures

