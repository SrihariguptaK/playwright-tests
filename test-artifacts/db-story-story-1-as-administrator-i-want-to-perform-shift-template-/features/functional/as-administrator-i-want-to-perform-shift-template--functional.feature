@functional @smoke
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Successfully create a new shift template with valid start time, end time, and break times
    Given user is logged in as an Administrator with template creation permissions
    And user is on the shift template management page at /admin/shift-templates
    And database has fewer than 100 existing templates
    And browser supports time input fields
    When click the 'Create New Template' button in the top-right corner of the page
    Then template creation form modal opens with empty fields for Template Name, Start Time, End Time, and Break Times
    And enter 'Morning Shift' in the Template Name field
    Then text 'Morning Shift' appears in the Template Name field
    And select '08:00 AM' in the Start Time field using the time picker
    Then start Time field displays '08:00 AM'
    And select '05:00 PM' in the End Time field using the time picker
    Then end Time field displays '05:00 PM'
    And click 'Add Break' button and enter break time from '12:00 PM' to '01:00 PM'
    Then break time entry appears showing '12:00 PM - 01:00 PM' with a delete icon
    And click the 'Save Template' button at the bottom of the form
    Then green success banner appears at top of page with message 'Shift template created successfully' and modal closes
    And verify the templates list on the main page
    Then new template 'Morning Shift' appears in the templates list showing Start: 08:00 AM, End: 05:00 PM, Break: 12:00 PM - 01:00 PM
    And new shift template 'Morning Shift' is saved in ShiftTemplates database table
    And template appears in the list of all templates on the management page
    And user remains on the shift template management page
    And template is available for selection in scheduling workflows

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Create shift template with multiple break periods and verify all breaks are saved
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And system supports multiple break periods per template
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Extended Shift' in Template Name, '07:00 AM' as Start Time, '11:00 PM' as End Time
    Then all fields display entered values correctly
    And click 'Add Break' and enter first break from '10:00 AM' to '10:15 AM'
    Then first break entry appears: '10:00 AM - 10:15 AM'
    And click 'Add Break' again and enter second break from '01:00 PM' to '02:00 PM'
    Then second break entry appears: '01:00 PM - 02:00 PM'
    And click 'Add Break' again and enter third break from '06:00 PM' to '06:30 PM'
    Then third break entry appears: '06:00 PM - 06:30 PM'
    And click 'Save Template' button
    Then success message 'Shift template created successfully' appears
    And locate 'Extended Shift' in the templates list and click to view details
    Then template details show all three break periods: 10:00 AM - 10:15 AM, 01:00 PM - 02:00 PM, 06:00 PM - 06:30 PM
    And template 'Extended Shift' is saved with all three break periods
    And all break times are stored correctly in the database
    And template is visible in the templates list with break count indicator

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Edit an existing shift template and verify changes are saved
    Given user is logged in as an Administrator
    And at least one shift template 'Morning Shift' exists with Start: 08:00 AM, End: 05:00 PM
    And user is on the shift template management page
    When locate 'Morning Shift' template in the list and click the 'Edit' icon button
    Then edit template form opens pre-populated with existing values: Template Name: 'Morning Shift', Start: 08:00 AM, End: 05:00 PM
    And change the End Time from '05:00 PM' to '06:00 PM'
    Then end Time field updates to display '06:00 PM'
    And click 'Add Break' and enter new break from '03:00 PM' to '03:15 PM'
    Then new break entry appears: '03:00 PM - 03:15 PM'
    And click 'Save Changes' button
    Then green success banner displays 'Shift template updated successfully' and form closes
    And verify 'Morning Shift' template in the list
    Then template shows updated End Time: 06:00 PM and includes the new break period
    And template 'Morning Shift' is updated in the database with new End Time and break
    And updated template appears correctly in the templates list
    And audit log records the template modification with timestamp and administrator ID

  @high @tc-func-004
  Scenario: TC-FUNC-004 - Delete an existing shift template and verify it is removed from the system
    Given user is logged in as an Administrator
    And at least one shift template 'Test Template' exists and is not currently assigned to any schedules
    And user is on the shift template management page
    When locate 'Test Template' in the templates list and click the 'Delete' icon button
    Then confirmation dialog appears with message 'Are you sure you want to delete this template? This action cannot be undone.' with 'Cancel' and 'Delete' buttons
    And click the 'Delete' button in the confirmation dialog
    Then confirmation dialog closes and green success banner appears with message 'Shift template deleted successfully'
    And verify the templates list
    Then 'Test Template' no longer appears in the templates list
    And refresh the page by pressing F5
    Then page reloads and 'Test Template' is still not present in the list, confirming deletion persisted
    And template 'Test Template' is removed from the ShiftTemplates database table
    And template is no longer available for selection in scheduling workflows
    And deletion is logged in the audit trail with administrator ID and timestamp

  @medium @tc-func-005
  Scenario: TC-FUNC-005 - View list of all created shift templates with complete details
    Given user is logged in as an Administrator
    And at least 5 different shift templates exist in the system
    And user navigates to the shift template management page
    When observe the templates list section on the page
    Then all 5 templates are displayed in a table/list format with columns: Template Name, Start Time, End Time, Break Times, Actions
    And verify each template row displays complete information
    Then each row shows template name, formatted start time (HH:MM AM/PM), formatted end time (HH:MM AM/PM), number of breaks or break details, and action buttons (Edit, Delete)
    And click on a template name to expand details
    Then template details expand showing full break schedule with start and end times for each break period
    And verify the templates are sorted by creation date (newest first)
    Then most recently created template appears at the top of the list
    And all templates remain in their current state
    And user remains on the shift template management page
    And no data is modified

  @medium @tc-func-006
  Scenario: TC-FUNC-006 - Create shift template without break times and verify it saves successfully
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And break times are optional for template creation
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'No Break Shift' in Template Name field
    Then template Name field displays 'No Break Shift'
    And enter '09:00 AM' as Start Time and '12:00 PM' as End Time
    Then start Time shows '09:00 AM' and End Time shows '12:00 PM'
    And do not add any break times, click 'Save Template' button directly
    Then success message 'Shift template created successfully' appears and form closes
    And locate 'No Break Shift' in the templates list
    Then template appears with Start: 09:00 AM, End: 12:00 PM, and Break Times column shows 'None' or is empty
    And template 'No Break Shift' is saved in database without break times
    And template is available for use in scheduling
    And template appears correctly in the list view

  @medium @tc-func-007
  Scenario: TC-FUNC-007 - Verify system handles creation of 100th template without performance degradation
    Given user is logged in as an Administrator
    And exactly 99 shift templates already exist in the system
    And user is on the shift template management page
    And system performance baseline is established (page load < 2 seconds)
    When note the current page load time and responsiveness
    Then page loads within 2 seconds and is responsive
    And click 'Create New Template' button
    Then form opens within 1 second
    And enter '100th Template' as name, '08:00 AM' as Start Time, '04:00 PM' as End Time
    Then all fields accept input without delay
    And click 'Save Template' button and measure response time
    Then template saves within 2 seconds and success message appears
    And verify the templates list loads with all 100 templates
    Then list displays all 100 templates within 3 seconds with pagination or scrolling functionality
    And attempt to create a 101st template
    Then system either allows creation (if limit is soft) or displays message 'Maximum template limit reached (100)' and prevents creation
    And system maintains performance with 100 templates loaded
    And all templates remain accessible and functional
    And no performance degradation is observed in page load or interactions

