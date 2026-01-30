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
    And system is connected to the ShiftTemplates database table
    When click the 'Create New Template' button in the top-right corner of the page
    Then shift template creation form modal opens with empty fields for Template Name, Start Time, End Time, and Break Times
    And enter 'Morning Shift' in the Template Name field
    Then text 'Morning Shift' appears in the Template Name input field
    And select '08:00 AM' from the Start Time dropdown picker
    Then start Time field displays '08:00 AM'
    And select '05:00 PM' from the End Time dropdown picker
    Then end Time field displays '05:00 PM' and no validation error appears
    And click 'Add Break' button and enter break time from '12:00 PM' to '01:00 PM'
    Then break time entry appears showing '12:00 PM - 01:00 PM' with a delete icon
    And click the 'Save Template' button at the bottom of the form
    Then green success banner appears at top of page with message 'Template created successfully' and modal closes
    And verify the templates list on the main page
    Then 'Morning Shift' template appears in the list with Start Time '08:00 AM', End Time '05:00 PM', and Break '12:00 PM - 01:00 PM'
    And new shift template 'Morning Shift' is saved in the ShiftTemplates database table
    And template appears in the list of all templates on the management page
    And administrator remains logged in and on the shift template management page
    And template is available for selection in scheduling workflows

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Successfully create a shift template with multiple break periods
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And no template with the name 'Extended Shift' exists
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Extended Shift' as Template Name, '06:00 AM' as Start Time, '10:00 PM' as End Time
    Then all fields populate correctly with entered values
    And click 'Add Break' and add first break from '10:00 AM' to '10:15 AM'
    Then first break appears in the breaks list
    And click 'Add Break' again and add second break from '02:00 PM' to '02:30 PM'
    Then second break appears below the first break in the list
    And click 'Add Break' again and add third break from '06:00 PM' to '06:15 PM'
    Then third break appears in the list, all three breaks are visible
    And click 'Save Template' button
    Then success message 'Template created successfully' appears and form closes
    And template 'Extended Shift' is saved with three separate break periods
    And all break times are stored correctly in the database
    And template appears in the list showing all three breaks

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Successfully edit an existing shift template and save changes
    Given user is logged in as an Administrator
    And at least one shift template named 'Evening Shift' exists with Start Time '02:00 PM' and End Time '10:00 PM'
    And user is on the shift template management page
    When locate 'Evening Shift' template in the list and click the 'Edit' icon button
    Then edit template form opens pre-populated with existing values: Name 'Evening Shift', Start '02:00 PM', End '10:00 PM'
    And change End Time from '10:00 PM' to '11:00 PM'
    Then end Time field updates to show '11:00 PM'
    And add a new break from '06:00 PM' to '06:30 PM'
    Then break entry appears in the breaks section
    And click 'Save Changes' button
    Then success message 'Template updated successfully' appears in green banner
    And verify the updated template in the list
    Then 'Evening Shift' now shows End Time as '11:00 PM' and includes the new break period
    And template changes are persisted in the ShiftTemplates database
    And updated template reflects new End Time and break period
    And template edit history is logged in the system audit trail

  @medium @tc-func-004
  Scenario: TC-FUNC-004 - Successfully delete an existing shift template
    Given user is logged in as an Administrator
    And a shift template named 'Temporary Shift' exists in the system
    And template is not currently assigned to any active schedules
    And user is on the shift template management page
    When locate 'Temporary Shift' template in the list and click the 'Delete' icon button
    Then confirmation dialog appears with message 'Are you sure you want to delete this template? This action cannot be undone.'
    And click 'Confirm' button in the confirmation dialog
    Then dialog closes and success message 'Template deleted successfully' appears in green banner
    And verify the templates list
    Then 'Temporary Shift' template no longer appears in the list
    And refresh the page
    Then template list reloads and 'Temporary Shift' is still not present, confirming deletion
    And template 'Temporary Shift' is removed from the ShiftTemplates database
    And template is no longer available for scheduling
    And deletion action is logged in the system audit trail with timestamp and administrator ID

  @medium @tc-func-005
  Scenario: TC-FUNC-005 - Successfully view list of all created shift templates with complete details
    Given user is logged in as an Administrator
    And at least 5 different shift templates exist in the system
    And user navigates to the shift template management page
    When observe the main shift template management page
    Then page displays a table/list with columns: Template Name, Start Time, End Time, Break Times, Actions (Edit/Delete)
    And verify all templates are displayed in the list
    Then all 5+ templates appear with their respective details clearly visible
    And check that each template shows complete information
    Then each row displays template name, formatted start time, formatted end time, and break periods (if any)
    And verify action buttons are present for each template
    Then each template row has visible 'Edit' and 'Delete' action buttons/icons
    And all templates remain unchanged in the database
    And user remains on the template management page
    And page is ready for further template management actions

  @medium @tc-func-006
  Scenario: TC-FUNC-006 - Successfully create shift template without break times
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And system allows templates without breaks
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Short Shift' as Template Name
    Then template Name field shows 'Short Shift'
    And select '09:00 AM' as Start Time and '01:00 PM' as End Time
    Then both time fields populate correctly
    And do not add any break times, leave breaks section empty
    Then breaks section remains empty with no validation errors
    And click 'Save Template' button
    Then success message appears: 'Template created successfully'
    And verify template in the list
    Then 'Short Shift' appears with Start '09:00 AM', End '01:00 PM', and Break Times column shows 'None' or is empty
    And template is saved without break times in the database
    And template is available for use in scheduling
    And no validation errors are present

  @high @tc-func-007
  Scenario: TC-FUNC-007 - Verify API endpoint POST /api/shift-templates successfully creates template
    Given user has valid Administrator authentication token
    And aPI endpoint POST /api/shift-templates is accessible
    And database connection is active
    And request includes valid authorization headers
    When send POST request to /api/shift-templates with JSON body: {"name": "API Test Shift", "startTime": "07:00", "endTime": "15:00", "breaks": [{"start": "11:00", "end": "11:30"}]}
    Then aPI returns HTTP 201 Created status code
    And verify response body contains created template data
    Then response includes template ID, name 'API Test Shift', startTime '07:00', endTime '15:00', and breaks array
    And query the database ShiftTemplates table for the new template ID
    Then template record exists in database with all correct field values
    And navigate to shift template management page in UI
    Then 'API Test Shift' appears in the templates list
    And template is persisted in ShiftTemplates database table
    And template is visible in the UI
    And aPI response matches database record
    And template can be edited and deleted through UI

