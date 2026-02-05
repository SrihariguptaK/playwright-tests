@functional @smoke
Feature: As Admin, I want to create shift templates to achieve efficient scheduling. - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Verify successful creation of shift template with valid start and end times
    Given user is logged in with Admin-level authentication credentials
    And user is on the Shift Template management page
    And shiftTemplates database table is accessible and operational
    And no existing template with duplicate name exists in the system
    When navigate to the Shift Template section from the main dashboard menu
    Then shift Template page loads successfully displaying existing templates list and 'Create New Template' button
    And click on the 'Create New Template' button in the top-right corner
    Then template creation form modal appears with fields for Template Name, Start Time, End Time, and Role Assignment
    And enter 'Morning Shift' in Template Name field, '09:00 AM' in Start Time field, and '05:00 PM' in End Time field
    Then all input fields accept the values without validation errors, time pickers display correctly formatted times
    And select 'Cashier' from the Role dropdown menu
    Then role 'Cashier' is selected and displayed in the Role Assignment field
    And click the 'Save Template' button at the bottom of the form
    Then success message 'Shift template created successfully' appears in green banner at top of page, form closes automatically
    And verify the newly created template appears in the templates list
    Then template 'Morning Shift' is visible in the list with correct start time (09:00 AM), end time (05:00 PM), and role (Cashier)
    And new shift template 'Morning Shift' is saved in ShiftTemplates database table with correct time values
    And template is available for assignment to employees in scheduling workflows
    And admin user remains on Shift Template page with updated templates list displayed
    And aPI POST request to /api/shifts/templates completed successfully with 201 status code

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Verify admin can edit existing shift template and save changes successfully
    Given user is logged in with Admin-level authentication
    And at least one shift template 'Evening Shift' exists in the system with start time 02:00 PM and end time 10:00 PM
    And user is on the Shift Template management page
    And database connection is active and stable
    When locate the 'Evening Shift' template in the templates list
    Then template 'Evening Shift' is visible with current details displayed
    And click the 'Edit' icon button next to the 'Evening Shift' template
    Then edit template form modal opens pre-populated with existing values: Template Name 'Evening Shift', Start Time '02:00 PM', End Time '10:00 PM'
    And change the End Time from '10:00 PM' to '11:00 PM'
    Then end Time field updates to show '11:00 PM', no validation errors appear
    And change the Role from 'Cashier' to 'Manager'
    Then role dropdown updates to display 'Manager' as selected value
    And click the 'Save Changes' button
    Then success message 'Shift template updated successfully' appears in green banner, modal closes automatically
    And verify the updated template in the templates list
    Then template 'Evening Shift' now displays End Time as '11:00 PM' and Role as 'Manager'
    And shift template 'Evening Shift' is updated in database with new end time 11:00 PM and role Manager
    And previous version of template is not retained (or archived based on system design)
    And all existing employee assignments using this template reflect the updated times
    And admin remains on Shift Template page with refreshed data

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Verify admin can delete existing shift template successfully
    Given user is logged in with Admin-level authentication
    And at least one shift template 'Night Shift' exists in the system
    And template 'Night Shift' is not currently assigned to any active employee schedules
    And user is on the Shift Template management page
    When locate the 'Night Shift' template in the templates list
    Then template 'Night Shift' is visible in the list with all details displayed
    And click the 'Delete' icon button (trash icon) next to the 'Night Shift' template
    Then confirmation dialog appears with message 'Are you sure you want to delete this template? This action cannot be undone.'
    And click 'Confirm' button in the confirmation dialog
    Then success message 'Shift template deleted successfully' appears in green banner, confirmation dialog closes
    And verify the template is removed from the templates list
    Then template 'Night Shift' is no longer visible in the templates list, list updates automatically
    And shift template 'Night Shift' is removed from ShiftTemplates database table
    And template is no longer available for assignment to employees
    And admin remains on Shift Template page with updated templates list
    And system audit log records the deletion action with admin user ID and timestamp

  @high @tc-func-004
  Scenario: TC-FUNC-004 - Verify admin can assign shift template to multiple employees quickly
    Given user is logged in with Admin-level authentication
    And at least one shift template 'Morning Shift' exists in the system
    And at least three employees exist in the system: 'John Doe', 'Jane Smith', 'Bob Johnson'
    And user is on the Employee Scheduling page
    When navigate to the Employee Scheduling section from the main menu
    Then employee Scheduling page loads displaying calendar view and employee list
    And select employees 'John Doe', 'Jane Smith', and 'Bob Johnson' by checking their checkboxes
    Then all three employees are highlighted with checkmarks, bulk action toolbar appears at top
    And click 'Assign Template' button in the bulk action toolbar
    Then template selection dropdown appears showing all available templates including 'Morning Shift'
    And select 'Morning Shift' template from the dropdown
    Then template 'Morning Shift' is selected, date range picker appears for assignment period
    And select date range from '01/15/2024' to '01/19/2024' (5 days)
    Then date range is selected and displayed, 'Apply Template' button becomes enabled
    And click 'Apply Template' button
    Then success message 'Template assigned to 3 employees for 5 days' appears, calendar updates showing the shifts
    And all three employees have 'Morning Shift' template assigned for the specified date range in the database
    And calendar view displays the shifts for all three employees with correct times (09:00 AM - 05:00 PM)
    And employees receive notifications about their new shift assignments
    And admin remains on Employee Scheduling page with updated calendar view

  @medium @tc-func-005
  Scenario: TC-FUNC-005 - Verify shift template creation with multiple roles assigned
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And system supports multiple role assignments per template
    And roles 'Cashier', 'Stock Clerk', and 'Floor Manager' exist in the system
    When click on the 'Create New Template' button
    Then template creation form modal appears with all required fields
    And enter 'Multi-Role Shift' in Template Name field, '08:00 AM' in Start Time, '04:00 PM' in End Time
    Then all fields accept the input values without errors
    And click 'Add Role' button and select 'Cashier' from dropdown
    Then role 'Cashier' is added to the roles list, 'Add Role' button remains available
    And click 'Add Role' button again and select 'Stock Clerk' from dropdown
    Then role 'Stock Clerk' is added to the roles list below 'Cashier'
    And click 'Add Role' button again and select 'Floor Manager' from dropdown
    Then role 'Floor Manager' is added to the roles list, all three roles are visible
    And click 'Save Template' button
    Then success message appears, template is saved with all three roles associated
    And template 'Multi-Role Shift' is saved in database with associations to all three roles
    And template appears in list showing all assigned roles
    And template can be assigned to employees with any of the three roles
    And admin remains on Shift Template page

