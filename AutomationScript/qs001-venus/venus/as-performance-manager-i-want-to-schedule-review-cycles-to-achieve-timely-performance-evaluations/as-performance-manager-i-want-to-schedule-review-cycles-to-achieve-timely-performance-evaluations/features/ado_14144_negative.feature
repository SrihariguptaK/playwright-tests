Feature: Schedule Review Cycles with Validation and Error Handling
  As a Performance Manager
  I want to schedule review cycles with proper validation and error handling
  So that I can ensure data integrity and prevent scheduling conflicts

  Background:
    Given user is logged in as "Performance Manager"
    And user is on "Review Cycle Management" page

  @negative @regression @priority-high
  Scenario: Attempt to schedule review cycle with overlapping dates and verify validation error
    Given an existing review cycle "Daily Check-in" is scheduled with "Daily" frequency starting from today
    And validation rules for overlapping cycles are active
    When user clicks "Create New Review Cycle" button
    Then "Review cycle creation modal" should be visible
    And all form fields should be empty
    When user selects "Daily" from "Frequency" dropdown
    And user enters today's date in "Start Date" field
    And user enters "Duplicate Daily Review" in "Review Cycle Name" field
    And user clicks "Save Schedule" button
    Then error message "Cannot create review cycle: Overlapping schedule detected with existing cycle Daily Check-in. Please choose a different frequency or start date." should be displayed
    And error message should appear in red banner at top of modal
    And "Save Schedule" button should be enabled
    And form fields should retain entered values
    And calendar view should display only "Daily Check-in" cycle
    And "Active Schedules" list should display only "Daily Check-in" cycle
    And no new review cycle should be created in database
    And system should log validation failure with overlap conflict details

  @negative @regression @priority-high
  Scenario: Attempt to schedule review cycle without required fields and verify validation errors
    Given no form fields are pre-filled
    And client-side validation is active
    And server-side validation is active
    When user clicks "Create New Review Cycle" button
    Then "Review cycle creation modal" should be visible
    And no validation errors should be displayed initially
    When user clicks "Save Schedule" button without entering any data
    Then error message "Frequency is required" should be displayed below "Frequency" dropdown
    And error message "Start date is required" should be displayed below "Start Date" field
    And error message "Review cycle name is required" should be displayed below "Review Cycle Name" field
    And all validation errors should be displayed in red text
    And modal should remain open
    And no API call should be made to "/api/review-cycles/schedule" endpoint
    And no success message should be displayed
    And calendar view should show no new entries
    And no new review cycle should be created in database
    And no notification jobs should be created

  @negative @regression @priority-high
  Scenario: Attempt to schedule review cycle with past start date and verify error handling
    Given "Review cycle creation modal" is open
    And current system date is accessible
    And date validation rules prevent past dates
    When user selects "Weekly" from "Frequency" dropdown
    Then "Frequency" field should display "Weekly"
    And day of week selector should be visible
    When user enters past date in "Start Date" field
    And user enters "Past Date Test Review" in "Review Cycle Name" field
    And user clicks "Save Schedule" button
    Then error message "Start date cannot be in the past. Please select a current or future date." should be displayed
    And error message should appear in red text below "Start Date" field
    And no new review cycle should appear in calendar view
    And no new review cycle should appear in "Active Schedules" list
    And no review cycle should be saved to database
    And modal should remain open with error message visible
    And system should log validation failure with attempted past date value

  @negative @regression @priority-high
  Scenario: Attempt to access review cycle scheduling without proper permissions and verify access denial
    Given user is logged in as "Employee"
    And user does not have "schedule_review_cycles" permission
    And role-based access control is enforced on frontend and backend
    And user is on "Dashboard" page
    When user navigates to "/review-cycles/schedule" URL directly
    Then user should be redirected to "403 Forbidden" page
    And error message "Access Denied: You do not have permission to schedule review cycles. Please contact your administrator." should be displayed
    When user checks main navigation menu
    Then "Review Cycles" link should not be visible
    And "Schedule Reviews" link should not be visible
    When user attempts API call to "POST /api/review-cycles/schedule" endpoint with valid data
    Then API should return "403" status code
    And response body should contain error message "Insufficient permissions to perform this action"
    And no review cycle should be created in database
    And security log should record unauthorized access attempt with user ID and timestamp
    And user session should remain active

  @negative @regression @priority-medium
  Scenario: Attempt to delete a review cycle that has already started and verify prevention
    Given a review cycle "Q1 Performance Review" exists with start date in the past
    And at least one review instance from cycle is completed or in progress
    When user locates "Q1 Performance Review" in "Active Schedules" list
    And user clicks on "Q1 Performance Review" cycle
    Then review cycle details panel should be visible
    And cycle status should display "In Progress" or "Active"
    When user clicks "Delete" button in details panel
    Then error message "Cannot delete review cycle: This cycle has already started and contains completed or in-progress reviews. You can only deactivate it." should be displayed
    And "Delete" button should be disabled
    And "Q1 Performance Review" should remain visible in "Active Schedules" list
    And "Q1 Performance Review" should remain visible in calendar view
    And all scheduled reviews should remain intact
    And "Deactivate" button should be visible as alternative action
    And review cycle should remain in database with status unchanged
    And system should log failed deletion attempt with reason "Cycle already started"

  @negative @regression @priority-medium
  Scenario: Attempt to schedule review cycle with invalid frequency value and verify error handling
    Given user has browser developer tools access
    And "Review cycle creation modal" is open
    And API validation is active on backend
    When user opens browser developer tools
    And user inspects "Frequency" dropdown element
    Then frequency dropdown HTML element should be visible in inspector
    And valid options "Daily, Weekly, Monthly" should be available
    When user manually modifies frequency dropdown value to "Hourly" using browser console
    Then dropdown value should be changed to "Hourly" in DOM
    When user enters tomorrow's date in "Start Date" field
    And user enters "Invalid Frequency Test" in "Review Cycle Name" field
    And user clicks "Save Schedule" button
    Then error message "Invalid frequency selected. Please choose from: Daily, Weekly, or Monthly." should be displayed
    And no new review cycle should appear in calendar view
    And no review cycle should be created with invalid frequency value in database
    And modal should remain open
    And system should log validation failure with invalid frequency value details

  @negative @regression @priority-medium
  Scenario: Attempt to schedule review cycle during system maintenance and verify graceful error handling
    Given "Review cycle creation modal" is open
    And backend API is temporarily unavailable
    And network timeout is set to "30" seconds
    When user selects "Monthly" from "Frequency" dropdown
    And user enters next month's date in "Start Date" field
    And user enters "Maintenance Test Review" in "Review Cycle Name" field
    And user enables notifications
    And backend unavailability is simulated
    And user clicks "Save Schedule" button
    Then loading spinner should appear on "Save Schedule" button
    When user waits for request to timeout
    Then error message "Unable to schedule review cycle. The system is currently unavailable. Please try again later." should be displayed
    And "Retry" button should be visible
    And no new review cycle should appear in calendar view
    When user refreshes the page
    Then attempted cycle should not appear in "Active Schedules" list
    When user clicks "Retry" button
    And backend is still unavailable
    Then same error message should appear again
    And no review cycle should be created in database
    And form data should be preserved
    And system should log failed attempt with "503 Service Unavailable" error details