Feature: Assign Shift Templates to Employees
  As an Admin
  I want to assign shift templates to employees
  So that I can streamline the scheduling process and ensure efficient shift coverage

  Background:
    Given user is logged in with "Admin" level authentication
    And "Employee Schedule" page is loaded
    And database connection is active and "EmployeeSchedules" table is accessible

  @functional @regression @priority-high @smoke
  Scenario: Successful assignment of shift template to employee with confirmation message
    Given employee "John Doe" exists in the system with no current shift assignments
    And shift template "Morning Shift (8AM-4PM)" exists and is active
    When user navigates to "Employee Schedule" section
    And user selects employee "John Doe" from the employee list
    Then employee details panel should be visible on the right side
    And panel should display "John Doe" current schedule and personal information
    When user clicks "Assign Shift Template" button in the employee details panel
    Then modal dialog should open displaying available shift templates
    And modal should display template names, times, and descriptions
    When user selects "Morning Shift (8AM-4PM)" template from the dropdown list
    And user chooses start date as "2024-01-15"
    Then template should be highlighted in blue
    And start date field should show "2024-01-15"
    And "Confirm Assignment" button should be enabled
    When user clicks "Confirm Assignment" button
    Then success message "Shift template successfully assigned to John Doe" should be displayed
    And modal should close automatically
    And calendar should display "Morning Shift (8AM-4PM)" on "2024-01-15"
    And shift block should show color-coded template with template name visible
    And shift assignment should be saved in "EmployeeSchedules" table for employee "John Doe"
    And assignment should be logged in system audit trail with timestamp and admin user ID

  @functional @regression @priority-high
  Scenario: Real-time update of employee schedule after template assignment
    Given employee "Jane Smith" exists with existing shift assignment
    And employee "Jane Smith" has "Evening Shift (4PM-12AM)" assigned on "2024-01-20"
    And multiple shift templates are available in the system
    And user is viewing "Jane Smith" schedule
    When user notes the current schedule displaying "Evening Shift (4PM-12AM)" on "2024-01-20"
    Then calendar view should show "Evening Shift" assignment with time range and color coding
    When user selects employee "Jane Smith" from employee list
    And user clicks "Assign Shift Template" button
    Then assignment modal should open with available templates listed
    When user selects "Night Shift (12AM-8AM)" template
    And user sets start date to "2024-01-22"
    And user clicks "Confirm Assignment" button
    Then success message "Shift template successfully assigned to Jane Smith" should be displayed
    And modal should close automatically
    And calendar should automatically update without page refresh
    And calendar should display "Evening Shift (4PM-12AM)" on "2024-01-20"
    And calendar should display "Night Shift (12AM-8AM)" on "2024-01-22"
    When user opens a second browser window
    And user logs in as "Admin" in second window
    And user navigates to "Jane Smith" schedule in second window
    Then second browser window should display "Evening Shift (4PM-12AM)" on "2024-01-20"
    And second browser window should display "Night Shift (12AM-8AM)" on "2024-01-22"
    And both shift assignments should be persisted in "EmployeeSchedules" table
    And real-time synchronization should be confirmed across multiple browser sessions

  @functional @regression @priority-high
  Scenario: Editing of assigned shift template for an employee
    Given employee "Mike Johnson" exists in the system
    And employee "Mike Johnson" has "Morning Shift (8AM-4PM)" assigned on "2024-01-25"
    And user is viewing "Mike Johnson" schedule
    And edit permissions are enabled for "Admin" role
    When user clicks on assigned "Morning Shift (8AM-4PM)" block on "2024-01-25"
    Then shift details popover should appear
    And popover should display shift name, time range, date
    And popover should display "Edit" and "Delete" buttons
    When user clicks "Edit" button in the shift details popover
    Then edit shift modal should open
    And modal should be pre-populated with template "Morning Shift (8AM-4PM)"
    And modal should be pre-populated with date "2024-01-25"
    When user changes shift template to "Afternoon Shift (12PM-8PM)" from the dropdown
    And user keeps the same date
    Then dropdown should display "Afternoon Shift (12PM-8PM)" as selected
    And "Save Changes" button should be enabled
    When user clicks "Save Changes" button
    Then success message "Shift updated successfully for Mike Johnson" should be displayed
    And modal should close automatically
    And calendar should display "Afternoon Shift (12PM-8PM)" on "2024-01-25"
    And calendar should not display "Morning Shift (8AM-4PM)" on "2024-01-25"
    And shift should display updated time range and color coding
    And "EmployeeSchedules" table should be updated with "Afternoon Shift (12PM-8PM)" for "Mike Johnson" on "2024-01-25"
    And previous "Morning Shift" assignment should be replaced not duplicated
    And edit action should be logged in audit trail with timestamp and change details

  @functional @regression @priority-medium
  Scenario: Assignment of shift template to multiple employees sequentially
    Given employee "Alice Brown" exists in the system
    And employee "Bob White" exists in the system
    And employee "Carol Green" exists in the system
    And shift template "Weekend Shift (9AM-5PM)" is available and active
    When user selects employee "Alice Brown" from the employee list
    Then "Alice Brown" details and schedule should be displayed in the employee panel
    When user assigns "Weekend Shift (9AM-5PM)" template to "Alice Brown" for date "2024-01-27"
    And user confirms the assignment
    Then success message should be displayed
    And "Alice Brown" calendar should show "Weekend Shift (9AM-5PM)" on "2024-01-27"
    When user selects employee "Bob White" from the employee list without refreshing page
    Then "Bob White" details and current schedule should be displayed
    And "Alice Brown" panel should be replaced
    When user assigns "Weekend Shift (9AM-5PM)" template to "Bob White" for date "2024-01-27"
    And user confirms the assignment
    Then success message should be displayed
    And "Bob White" calendar should show "Weekend Shift (9AM-5PM)" on "2024-01-27"
    When user selects employee "Carol Green" from the employee list
    Then "Carol Green" details and current schedule should be displayed
    When user assigns "Weekend Shift (9AM-5PM)" template to "Carol Green" for date "2024-01-27"
    And user confirms the assignment
    Then success message should be displayed
    And "Carol Green" calendar should show "Weekend Shift (9AM-5PM)" on "2024-01-27"
    When user navigates to calendar overview
    Then calendar overview should display "Alice Brown" with "Weekend Shift (9AM-5PM)" on "2024-01-27"
    And calendar overview should display "Bob White" with "Weekend Shift (9AM-5PM)" on "2024-01-27"
    And calendar overview should display "Carol Green" with "Weekend Shift (9AM-5PM)" on "2024-01-27"
    And all three employees should have "Weekend Shift (9AM-5PM)" saved in "EmployeeSchedules" table for "2024-01-27"
    And no scheduling conflicts should exist for any employee

  @functional @regression @priority-medium
  Scenario: Calendar view displays employee schedules correctly after multiple assignments
    Given employee "David Lee" exists with no current assignments
    And shift template "Morning Shift (8AM-4PM)" exists
    And shift template "Evening Shift (4PM-12AM)" exists
    And shift template "Night Shift (12AM-8AM)" exists
    And calendar view is set to "weekly" view mode
    When user selects employee "David Lee"
    And user assigns "Morning Shift (8AM-4PM)" for "Monday" "2024-01-15"
    Then assignment should succeed
    And success message should be displayed
    And calendar should show "Morning Shift (8AM-4PM)" on "Monday"
    When user assigns "Evening Shift (4PM-12AM)" to "David Lee" for "Wednesday" "2024-01-17"
    Then assignment should succeed
    And calendar should show "Morning Shift (8AM-4PM)" on "Monday"
    And calendar should show "Evening Shift (4PM-12AM)" on "Wednesday"
    When user assigns "Night Shift (12AM-8AM)" to "David Lee" for "Friday" "2024-01-19"
    Then assignment should succeed
    And calendar should display all three shifts across the week with different color codes
    When user switches calendar view from "weekly" to "monthly" view
    Then monthly calendar view should load showing "January 2024"
    And all three assigned shifts should be visible on their respective dates
    When user hovers over each shift block in the calendar
    Then tooltip should appear for each shift
    And tooltip should display shift name, time range, employee name, and date
    And all three shift assignments should be stored in "EmployeeSchedules" table
    And calendar view should accurately represent all assignments with proper visual distinction