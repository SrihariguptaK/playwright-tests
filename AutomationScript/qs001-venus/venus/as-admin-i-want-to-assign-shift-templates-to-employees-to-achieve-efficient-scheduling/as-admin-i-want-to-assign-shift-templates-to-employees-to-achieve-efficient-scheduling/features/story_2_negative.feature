Feature: Shift Template Assignment Validation and Error Handling
  As an Admin
  I want the system to prevent invalid shift assignments and handle errors gracefully
  So that scheduling integrity is maintained and data corruption is avoided

  Background:
    Given admin user is logged in with valid credentials
    And user is on "Employee Schedule" page

  @negative @regression @priority-high
  Scenario: System prevents double scheduling with overlapping shift times
    Given employee "Sarah Connor" exists in the system
    And employee "Sarah Connor" has "Morning Shift (8AM-4PM)" assigned on "2024-02-01"
    And shift template "Extended Morning Shift (7AM-3PM)" exists that overlaps with existing shift
    And user is viewing "Sarah Connor" schedule
    When user verifies calendar shows "Morning Shift (8AM-4PM)" on "2024-02-01"
    And user clicks "Assign Shift Template" button
    And user selects "Extended Morning Shift (7AM-3PM)" from shift template dropdown
    And user enters "2024-02-01" in "Date" field
    And user clicks "Confirm Assignment" button
    Then error message "Cannot assign shift: Employee Sarah Connor is already scheduled during this time period (8AM-4PM on 2024-02-01)" should be displayed
    And assignment modal should remain open
    And calendar should display only "Morning Shift (8AM-4PM)" on "2024-02-01"
    And no duplicate shift entry should exist in database for "Sarah Connor" on "2024-02-01"
    And failed assignment attempt should be logged in system error logs

  @negative @regression @priority-high
  Scenario: Error handling when attempting to assign shift without selecting a template
    Given employee "Tom Hardy" exists in the system
    When user selects employee "Tom Hardy" from employee list
    And user clicks "Assign Shift Template" button
    And user enters "2024-02-10" in "Date" field
    And user leaves shift template dropdown empty
    And user clicks "Confirm Assignment" button
    Then validation error message "Please select a shift template" should be displayed below template dropdown
    And no API call should be made to "POST /api/employees/schedule"
    And no shift assignment should be created in database
    And assignment modal should remain open
    And "Tom Hardy" schedule should remain unchanged

  @negative @regression @priority-high
  Scenario: Error handling when non-admin user attempts to access shift assignment functionality
    Given user account "regular_user@company.com" exists with "Employee" role
    And user is logged out
    And user logs in as "regular_user@company.com"
    When user attempts to navigate to "/employee-schedule" URL directly
    Then user should see "403 Forbidden" page
    And error message "Access Denied: Admin privileges required" should be displayed
    When user attempts to send POST request to "/api/employees/schedule" with valid shift data
    Then API should return status code "403"
    And API response should contain error "Unauthorized"
    And API response should contain message "Admin authentication required"
    And "Employee Schedule" link should not be visible in navigation menu
    And unauthorized access attempt should be logged with user ID and timestamp

  @negative @regression @priority-medium
  Scenario: Error handling when assigning shift with past date
    Given employee "Emma Watson" exists in the system
    And current system date is "2024-02-15"
    And shift template "Day Shift (9AM-5PM)" is available
    When user selects employee "Emma Watson" from employee list
    And user clicks "Assign Shift Template" button
    And user selects "Day Shift (9AM-5PM)" from shift template dropdown
    And user enters "2024-01-15" in "Date" field
    And user clicks "Confirm Assignment" button
    Then warning message "Warning: You are assigning a shift to a past date (2024-01-15). Please confirm this is intentional." should be displayed
    And "Cancel" button should be visible
    And "Proceed Anyway" button should be visible
    When user clicks "Cancel" button
    Then assignment modal should close
    And no shift assignment should be created for past date in database
    And "Emma Watson" schedule should remain unchanged

  @negative @regression @priority-high
  Scenario: Error handling when database connection fails during shift assignment
    Given employee "Chris Evans" exists in the system
    And shift template "Night Shift (10PM-6AM)" is available
    And database connection is simulated to fail
    When user selects employee "Chris Evans" from employee list
    And user clicks "Assign Shift Template" button
    And user selects "Night Shift (10PM-6AM)" from shift template dropdown
    And user enters "2024-02-20" in "Date" field
    And user clicks "Confirm Assignment" button
    Then loading spinner should appear briefly
    And error message "System error: Unable to save shift assignment. Please try again later." should be displayed
    And calendar should not show "Night Shift (10PM-6AM)" assignment for "Chris Evans"
    And previous schedule state should be maintained
    And error should be logged with timestamp and error type "Database Connection Failure"
    And no partial data should be written to database
    And no corrupted data should exist in "EmployeeSchedules" table

  @negative @regression @priority-medium
  Scenario: Error handling when attempting to assign deleted or inactive shift template
    Given employee "Natalie Portman" exists in the system
    And shift template "Deprecated Shift (6AM-2PM)" is marked as inactive in database
    When user selects employee "Natalie Portman" from employee list
    And user clicks "Assign Shift Template" button
    Then "Deprecated Shift (6AM-2PM)" should not appear in shift template dropdown
    And only active templates should be visible in dropdown
    When user attempts to call API "POST /api/employees/schedule" with inactive template ID
    Then API should return status code "400"
    And API response should contain error message "Invalid template: Template is inactive or does not exist"
    And no assignment should be created in database for "Natalie Portman"
    And "Natalie Portman" schedule should remain unchanged