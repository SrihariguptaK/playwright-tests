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
    And user is on the shift template management page at /admin/shift-templates
    And shiftTemplates database table is accessible and has less than 100 existing templates
    And browser is Chrome/Firefox/Safari latest version
    When click on the 'Create New Template' button located in the top-right corner of the page
    Then shift template creation form is displayed with fields for Template Name, Start Time, End Time, and Break Times
    And enter 'Morning Shift' in the Template Name field
    Then template Name field accepts the input and displays 'Morning Shift'
    And select '08:00 AM' from the Start Time dropdown picker
    Then start Time field displays '08:00 AM' and no validation errors appear
    And select '05:00 PM' from the End Time dropdown picker
    Then end Time field displays '05:00 PM' and no validation errors appear
    And click 'Add Break' button and enter break time from '12:00 PM' to '01:00 PM'
    Then break time is added to the form showing '12:00 PM - 01:00 PM' with no validation errors
    And click the 'Save Template' button at the bottom of the form
    Then green success banner appears at the top of the page with message 'Shift template created successfully' and form closes
    And verify the template list on the shift template management page
    Then 'Morning Shift' template appears in the list with start time '08:00 AM', end time '05:00 PM', and break '12:00 PM - 01:00 PM'
    And new shift template 'Morning Shift' is saved in ShiftTemplates database table with correct times
    And user remains on the shift template management page with the updated list visible
    And template is available for selection in scheduling workflows
    And system logs the template creation action with administrator user ID and timestamp

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Verify creation of shift template with multiple break periods
    Given user is logged in as Administrator with shift template creation permissions
    And user is on the shift template management page
    And no existing template with the name 'Double Break Shift' exists
    And system supports multiple breaks per shift template
    When click 'Create New Template' button
    Then template creation form opens with empty fields
    And enter 'Double Break Shift' in Template Name field, '07:00 AM' as Start Time, and '07:00 PM' as End Time
    Then all fields accept input without validation errors
    And click 'Add Break' button and add first break from '10:00 AM' to '10:15 AM'
    Then first break is added and displayed in the breaks section
    And click 'Add Break' button again and add second break from '03:00 PM' to '03:30 PM'
    Then second break is added and both breaks are displayed without overlap validation errors
    And click 'Save Template' button
    Then success message 'Shift template created successfully' appears and template is saved
    And template 'Double Break Shift' is saved with two separate break periods in the database
    And template appears in the list showing both break times
    And template can be edited or deleted from the management page

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Verify editing of existing shift template with updated times
    Given user is logged in as Administrator
    And at least one shift template named 'Evening Shift' exists with start time '02:00 PM' and end time '10:00 PM'
    And user is on the shift template management page viewing the list of templates
    And template is not currently assigned to any active schedules
    When locate 'Evening Shift' template in the list and click the 'Edit' icon/button next to it
    Then edit form opens pre-populated with existing template data: name 'Evening Shift', start '02:00 PM', end '10:00 PM'
    And change the End Time from '10:00 PM' to '11:00 PM'
    Then end Time field updates to '11:00 PM' without validation errors
    And add a new break time from '06:00 PM' to '06:30 PM'
    Then break is added to the template and displayed in the breaks section
    And click 'Update Template' button
    Then success message 'Shift template updated successfully' appears in green banner
    And verify the updated template in the list
    Then 'Evening Shift' now shows end time as '11:00 PM' and includes the new break period
    And template changes are persisted in the ShiftTemplates database table
    And updated template reflects new times in all views
    And audit log records the modification with administrator ID and timestamp

  @medium @tc-func-004
  Scenario: TC-FUNC-004 - Verify deletion of shift template that is not in use
    Given user is logged in as Administrator with delete permissions
    And a shift template named 'Test Template' exists in the system
    And template 'Test Template' is not assigned to any current or future schedules
    And user is on the shift template management page
    When locate 'Test Template' in the template list and click the 'Delete' icon/button
    Then confirmation dialog appears with message 'Are you sure you want to delete this template? This action cannot be undone.'
    And click 'Confirm' button in the confirmation dialog
    Then success message 'Shift template deleted successfully' appears and dialog closes
    And verify the template list
    Then 'Test Template' is no longer visible in the list of shift templates
    And attempt to search for 'Test Template' using the search functionality
    Then no results found for 'Test Template'
    And template is removed from ShiftTemplates database table
    And template is no longer available for scheduling workflows
    And deletion action is logged in system audit trail with administrator ID

  @medium @tc-func-005
  Scenario: TC-FUNC-005 - Verify viewing complete list of all created shift templates with pagination
    Given user is logged in as Administrator
    And at least 15 shift templates exist in the system
    And user navigates to the shift template management page
    And pagination is set to display 10 templates per page
    When observe the shift template list on the management page
    Then first 10 templates are displayed in a table/grid format showing Template Name, Start Time, End Time, and Break Times columns
    And verify pagination controls at the bottom of the list
    Then pagination shows 'Page 1 of 2' with 'Next' button enabled and 'Previous' button disabled
    And click the 'Next' button to navigate to page 2
    Then page 2 loads showing the remaining 5 templates, 'Previous' button is now enabled
    And click on any template name to view details
    Then template details modal/panel opens showing complete information including all break times
    And all templates remain in the database unchanged
    And user can navigate back to page 1 using pagination controls
    And template list accurately reflects current database state

  @medium @tc-func-006
  Scenario: TC-FUNC-006 - Verify shift template creation with minimum valid duration (1 hour shift)
    Given user is logged in as Administrator
    And user is on the shift template creation page
    And system allows minimum shift duration of 1 hour
    And no template named 'Short Shift' exists
    When click 'Create New Template' button
    Then template creation form is displayed
    And enter 'Short Shift' as Template Name, '09:00 AM' as Start Time, and '10:00 AM' as End Time
    Then all fields accept the input and no validation errors appear
    And leave break times empty and click 'Save Template' button
    Then success message appears: 'Shift template created successfully'
    And verify 'Short Shift' appears in the template list
    Then template is listed with 1-hour duration displayed correctly
    And template 'Short Shift' is saved in database with 1-hour duration
    And template is available for use in scheduling
    And no break times are associated with this template

