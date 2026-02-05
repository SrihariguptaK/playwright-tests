Feature: Employee Shift Template Assignment Edge Cases
  As an Admin
  I want the system to handle edge cases in shift template assignments
  So that scheduling remains reliable under extreme conditions and unusual scenarios

  Background:
    Given admin user is logged in
    And user is on "Employee Schedule" page

  @edge @regression @priority-medium
  Scenario: System handles assignment of maximum allowed shifts to single employee
    Given employee "Max Capacity" exists with no current assignments
    And system has maximum limit of 31 shifts per employee per month
    And sufficient shift templates are available
    When user selects employee "Max Capacity" from employee list
    Then employee details and empty schedule should be displayed
    When user assigns shift templates for consecutive days from "2024-03-01" to "2024-03-31"
    Then each assignment should succeed with success message
    And calendar should display 31 shift assignments
    When user attempts to assign shift for date "2024-04-01"
    Then system should display warning "Employee has maximum shifts assigned for this period" or allow assignment based on business rules
    When user views calendar with all assigned shifts
    Then calendar should render all shifts properly with readable labels
    And shifts should display with proper spacing and no overlapping visual elements
    And page should remain responsive
    And calendar should load within 2 seconds
    And browser should show no freezing or memory issues
    And all 31 shift assignments should be stored in EmployeeSchedules table

  @edge @regression @priority-high
  Scenario: System handles 100 concurrent shift assignments from multiple admins
    Given 100 admin user accounts are created and authenticated
    And 100 different employees exist in system
    And sufficient shift templates are available
    And performance testing environment is configured
    When automated test simulates 100 concurrent admin users accessing "Employee Schedule" section simultaneously
    Then test script should be ready with 100 concurrent user sessions
    When all 100 admins assign different shift templates to different employees at same time
    Then system should process all 100 assignment requests without crashing
    And system should process all 100 assignment requests without timing out
    And 95 percent of API requests to "POST /api/employees/schedule" should complete within 3 seconds
    And no requests should fail with 500 errors
    And all requests should return appropriate success or error responses
    And EmployeeSchedules table should contain exactly 100 new shift assignment records
    And database should contain no duplicate assignments
    And database should contain no missing assignments
    And no database deadlocks should have occurred
    And all transactions should have completed successfully
    And data integrity should be maintained
    And each admin should see their own assignment reflected in real-time
    And no stale data should be displayed to any user

  @edge @regression @priority-low
  Scenario: Shift assignment with employee name containing special characters and Unicode
    Given employee "José O'Brien-Müller 李明" exists in system
    And shift template "Standard Shift (9AM-5PM)" is available
    When user searches for employee "José O'Brien-Müller 李明" in employee list search field
    Then employee should be found and displayed correctly
    And all special characters and Unicode should be rendered properly
    When user selects employee "José O'Brien-Müller 李明" from list
    Then employee details panel should open
    And employee name should display as "José O'Brien-Müller 李明" with all special characters intact
    When user assigns "Standard Shift (9AM-5PM)" template for date "2024-02-25"
    And user confirms assignment
    Then success message "Shift template successfully assigned to José O'Brien-Müller 李明" should be displayed
    And employee name should be rendered correctly in message
    When user views calendar
    Then calendar should display shift with employee name "José O'Brien-Müller 李明"
    And employee name should be properly encoded without character corruption
    When user queries EmployeeSchedules table
    Then database record should contain employee name with all special characters properly stored
    And employee name should be stored using UTF-8 encoding

  @edge @regression @priority-medium
  Scenario: Shift assignment at exact midnight boundary
    Given employee "Night Worker" exists in system
    And shift template "Midnight Shift (12:00 AM - 8:00 AM)" exists with start time at midnight
    And system timezone is configured
    When user selects employee "Night Worker"
    And user clicks "Assign Shift Template" button
    Then assignment modal should open
    When user selects "Midnight Shift (12:00 AM - 8:00 AM)" template
    And user sets date to "2024-02-28"
    Then template and date should be selected
    And shift should show start time at "12:00 AM" on "2024-02-28"
    When user confirms assignment
    Then success message should appear
    And assignment should be confirmed
    When user views calendar
    Then calendar should show shift block starting exactly at midnight boundary
    And shift should be properly positioned on "February 28th"
    When user assigns "Late Night Shift (8:00 PM - 12:00 AM)" template for date "2024-02-27"
    And user confirms assignment
    Then assignment should succeed
    And calendar should show "Late Night Shift" ending at "11:59:59 PM" on "Feb 27"
    And calendar should show "Midnight Shift" starting at "12:00:00 AM" on "Feb 28"
    And no overlap conflict should be detected
    When user queries EmployeeSchedules table
    Then "Midnight Shift" record should show start_time as "2024-02-28 00:00:00"
    And "Midnight Shift" record should show end_time as "2024-02-28 08:00:00"
    And proper timezone handling should be applied

  @edge @regression @priority-low
  Scenario: System behavior when employee list is empty
    Given database EmployeeSchedules table exists
    But no employee records exist in system
    And shift templates exist in system
    When user navigates to "Employee Schedule" section
    Then page should load successfully
    And empty state message "No employees found. Please add employees to begin scheduling." should be displayed
    And "Add Employee" button or link should be visible
    When user views employee list panel
    Then employee list should show empty state illustration or message
    And no error messages should be displayed
    When user views calendar
    Then calendar should display with no shift assignments
    And message "No schedules to display" should be shown
    When user attempts to access assignment functionality
    Then assignment buttons should be disabled or hidden
    Or clicking should show message "Please select an employee first"
    And browser console should show no JavaScript errors
    And application should handle empty state gracefully