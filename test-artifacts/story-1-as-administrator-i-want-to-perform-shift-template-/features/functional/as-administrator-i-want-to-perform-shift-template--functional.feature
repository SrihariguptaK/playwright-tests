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
    Given user is logged in with Administrator role and has permission to create shift templates
    And user is on the shift template management page at /admin/shift-templates
    And shiftTemplates database table is accessible and has less than 100 existing templates
    And browser is Chrome version 90+ or equivalent modern browser
    When click the 'Create New Template' button located in the top-right corner of the shift template management page
    Then shift template creation form is displayed with fields for Template Name, Start Time, End Time, and Break Times
    And enter 'Morning Shift' in the Template Name field
    Then template Name field displays 'Morning Shift' with no validation errors
    And select '08:00 AM' from the Start Time dropdown picker
    Then start Time field displays '08:00 AM' and no validation errors appear
    And select '05:00 PM' from the End Time dropdown picker
    Then end Time field displays '05:00 PM' and system validates that end time is after start time
    And click 'Add Break' button and enter break time from '12:00 PM' to '01:00 PM'
    Then break time is added to the template with start '12:00 PM' and end '01:00 PM', displayed in the breaks list
    And click the 'Save Template' button at the bottom of the form
    Then green success banner appears at top of page with message 'Shift template created successfully' and form is cleared
    And verify the newly created template appears in the templates list
    Then template 'Morning Shift' is visible in the list with Start Time '08:00 AM', End Time '05:00 PM', and Break '12:00 PM - 01:00 PM'
    And new shift template 'Morning Shift' is saved in ShiftTemplates database table with correct times
    And user remains on shift template management page with updated list of templates
    And template creation form is reset to empty state
    And success notification is logged in system audit trail with administrator user ID and timestamp

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Verify creation of shift template with multiple break periods
    Given user is logged in as Administrator with shift template creation permissions
    And user is on the shift template creation page
    And no existing template with the same name exists in the system
    When click 'Create New Template' button on shift template management page
    Then template creation form opens with all required fields visible
    And enter 'Extended Shift' in Template Name field, '07:00 AM' as Start Time, and '11:00 PM' as End Time
    Then all fields accept input without validation errors, 16-hour shift duration is calculated and displayed
    And click 'Add Break' button and add first break from '10:00 AM' to '10:15 AM'
    Then first break is added and displayed in breaks section with 15-minute duration
    And click 'Add Break' button again and add second break from '02:00 PM' to '02:30 PM'
    Then second break is added below first break, both breaks are visible in the list
    And click 'Add Break' button again and add third break from '06:00 PM' to '06:45 PM'
    Then third break is added, all three breaks are displayed in chronological order
    And click 'Save Template' button
    Then success message 'Shift template created successfully' appears, template is saved with all three breaks
    And template 'Extended Shift' is saved with three separate break periods in the database
    And template appears in the list showing all break times correctly
    And total break duration is calculated and stored (1 hour 30 minutes)

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Verify editing of existing shift template updates all fields correctly
    Given user is logged in as Administrator
    And at least one shift template 'Morning Shift' exists in the system with Start Time '08:00 AM' and End Time '05:00 PM'
    And user is on the shift template management page viewing the list of templates
    When locate 'Morning Shift' template in the list and click the 'Edit' icon button next to it
    Then template edit form opens with pre-populated fields showing current values: Name 'Morning Shift', Start '08:00 AM', End '05:00 PM'
    And change Template Name to 'Updated Morning Shift' and Start Time to '07:30 AM'
    Then fields update with new values, no validation errors appear
    And modify existing break time from '12:00 PM - 01:00 PM' to '12:30 PM - 01:30 PM'
    Then break time is updated in the form, duration remains 1 hour
    And click 'Update Template' button
    Then blue success banner displays 'Shift template updated successfully' message
    And verify updated template in the list
    Then template now shows 'Updated Morning Shift' with Start Time '07:30 AM' and updated break time '12:30 PM - 01:30 PM'
    And template is updated in ShiftTemplates database with new values
    And original template ID remains unchanged, only field values are modified
    And update action is logged in audit trail with timestamp and administrator ID
    And any schedules using this template are not automatically updated (out of scope)

  @high @tc-func-004
  Scenario: TC-FUNC-004 - Verify deletion of shift template removes it from the system
    Given user is logged in as Administrator with delete permissions
    And at least one shift template 'Test Template' exists and is not currently assigned to any schedules
    And user is on shift template management page with templates list visible
    When locate 'Test Template' in the templates list and click the 'Delete' icon button (trash icon)
    Then confirmation modal appears with message 'Are you sure you want to delete this template? This action cannot be undone.'
    And click 'Confirm Delete' button in the modal
    Then modal closes and red success banner appears with message 'Shift template deleted successfully'
    And verify 'Test Template' is no longer visible in the templates list
    Then template is removed from the list, total template count decreases by 1
    And refresh the page using browser refresh button
    Then page reloads and 'Test Template' remains absent from the list, confirming deletion persisted
    And template 'Test Template' is permanently deleted from ShiftTemplates database table
    And deletion is logged in system audit trail with administrator ID and timestamp
    And user remains on shift template management page
    And template count in database is reduced by 1

  @medium @tc-func-005
  Scenario: TC-FUNC-005 - Verify viewing list of all created shift templates displays complete information
    Given user is logged in as Administrator
    And at least 5 different shift templates exist in the system with varying start times, end times, and breaks
    And user navigates to shift template management page at /admin/shift-templates
    When observe the shift templates list on the management page
    Then all templates are displayed in a table or card layout with columns for Template Name, Start Time, End Time, Break Times, and Actions
    And verify each template row displays complete information including template name, start time, end time, and all break periods
    Then each template shows all fields populated correctly with readable time format (12-hour with AM/PM)
    And check that Edit and Delete action buttons are visible for each template
    Then each template row has 'Edit' and 'Delete' icon buttons that are clickable and properly styled
    And verify the total count of templates is displayed at the top of the list
    Then template count shows 'Showing 5 templates' or similar indicator matching actual number of templates
    And all templates remain in their current state (no data modified)
    And user remains on shift template management page
    And list view is ready for further interactions (create, edit, delete)

  @medium @tc-func-006
  Scenario: TC-FUNC-006 - Verify shift template creation with break time at shift boundaries
    Given user is logged in as Administrator
    And user is on shift template creation page
    And system allows breaks to be scheduled at the start or end of shifts
    When click 'Create New Template' button
    Then template creation form is displayed
    And enter 'Boundary Break Shift' as Template Name, '09:00 AM' as Start Time, '06:00 PM' as End Time
    Then all fields accept input without errors
    And add break from '09:00 AM' to '09:15 AM' (break starting exactly at shift start time)
    Then break is accepted and added to the template without validation errors
    And add second break from '05:45 PM' to '06:00 PM' (break ending exactly at shift end time)
    Then second break is accepted and both breaks are displayed in the list
    And click 'Save Template' button
    Then template is saved successfully with confirmation message 'Shift template created successfully'
    And template is saved with breaks at shift boundaries
    And template appears in list with both boundary breaks correctly displayed
    And no validation errors are recorded for boundary break times

