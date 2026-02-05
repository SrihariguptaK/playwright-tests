Feature: Schedule Review Cycles for Performance Evaluations
  As a Performance Manager
  I want to schedule review cycles with customizable frequency and notifications
  So that I can ensure timely performance evaluations and maintain performance oversight

  Background:
    Given user is logged in as "Performance Manager" with review scheduling permissions
    And user is on "Review Cycle Management" page

  @functional @regression @priority-high @smoke
  Scenario: Successfully schedule a daily review cycle with notification settings
    Given no existing review cycles are scheduled for the current period
    And system time is set to a valid business date
    When user clicks "Create New Review Cycle" button
    Then review cycle creation modal should be visible
    And "Frequency" field should be visible
    And "Start Date" field should be visible
    And "Notification Settings" field should be visible
    And "Description" field should be visible
    When user selects "Daily" from "Frequency" dropdown
    Then "Frequency" field should display "Daily"
    And daily-specific options should be visible
    When user sets start date to tomorrow in date picker
    And user sets time to "09:00 AM"
    Then "Start Date" field should show tomorrow's date in "MM/DD/YYYY" format
    And time field should display "09:00 AM"
    When user enables "Send Notification" toggle
    And user selects "24 hours before review" from notification timing dropdown
    Then notification toggle should be active
    And notification timing dropdown should display "24 hours before"
    When user enters "Daily Performance Check-in" in "Review Cycle Name" field
    And user clicks "Save Schedule" button
    Then success message "Review cycle scheduled successfully" should be displayed
    And review cycle creation modal should be hidden
    And new review cycle should appear in calendar view
    And review cycle should be saved in database with status "Active"
    And notification job should be created for 24 hours before each review

  @functional @regression @priority-high
  Scenario: Successfully schedule a weekly review cycle and verify calendar view display
    Given calendar view is set to "Month" view mode
    And no conflicting weekly review cycles exist
    When user clicks "Create New Review Cycle" button
    Then review cycle creation modal should be visible
    When user selects "Weekly" from "Frequency" dropdown
    And user selects "Monday" from "Day of Week" dropdown
    Then "Frequency" field should display "Weekly"
    And "Day of Week" dropdown should display "Monday"
    When user sets start date to next Monday
    And user enters "Weekly Team Review" in "Review Cycle Name" field
    And user clicks "Save Schedule" button
    Then success message "Review cycle scheduled successfully" should be displayed
    And review cycle creation modal should be hidden
    And calendar view should show recurring Monday markers for weekly review cycle
    When user navigates through calendar months using next arrow
    Then calendar should display weekly review markers on every Monday for next 3 months
    And "Weekly Team Review" label should be visible on hover
    And weekly review cycle should be saved with recurrence pattern "Every Monday"
    And review cycle should appear in "Active Schedules" list with frequency "Weekly"

  @functional @regression @priority-high
  Scenario: Successfully schedule a monthly review cycle with custom notification timing
    Given at least 1 employee exists in the system
    And email notification service is configured and active
    When user clicks "Create New Review Cycle" button
    Then review cycle creation modal should be visible
    When user selects "Monthly" from "Frequency" dropdown
    And user selects "1st day of month" from "Day of Month" dropdown
    Then "Frequency" field should display "Monthly"
    And "Day of Month" dropdown should display "1st day of month"
    When user enables "Send Notification" toggle
    And user selects "72 hours before review" from notification timing dropdown
    Then notification settings should be expanded
    And notification timing dropdown should display "72 hours before"
    And email template preview should be visible
    When user enters "Monthly Performance Evaluation" in "Review Cycle Name" field
    And user enters "Comprehensive monthly review of team performance" in "Description" field
    And user clicks "Save Schedule" button
    Then success message "Review cycle scheduled successfully" should be displayed
    And review cycle creation modal should be hidden
    And monthly review should appear on calendar on 1st of each month
    When user clicks on newly created review cycle in calendar view
    Then review cycle details panel should be visible
    And frequency should display "Monthly"
    And notification timing should display "72 hours before"
    And description should display "Comprehensive monthly review of team performance"
    And notification jobs should be scheduled for 72 hours before each monthly review date

  @functional @regression @priority-high
  Scenario: Edit an existing scheduled review cycle and verify changes are reflected
    Given active review cycle "Weekly Team Review" exists scheduled for "Monday"
    And calendar view is visible
    And no reviews from this cycle are currently in progress
    When user clicks on "Weekly Team Review" cycle in calendar view
    Then review cycle details panel should be visible
    And frequency should display "Weekly"
    And day should display "Monday"
    When user clicks "Edit" button in details panel
    Then edit review cycle modal should be visible
    And all current values should be pre-populated in form fields
    When user selects "Bi-weekly" from "Frequency" dropdown
    And user selects "Friday" from "Day of Week" dropdown
    Then "Frequency" dropdown should display "Bi-weekly"
    And "Day of Week" dropdown should display "Friday"
    When user selects "48 hours before" from notification timing dropdown
    And user clicks "Save Changes" button
    Then success message "Review cycle updated successfully" should be displayed
    And edit review cycle modal should be hidden
    And calendar should refresh showing reviews on alternating Fridays
    When user clicks on updated review cycle in calendar view
    Then review cycle details panel should be visible
    And frequency should display "Bi-weekly"
    And day should display "Friday"
    And notification timing should display "48 hours before"
    And review cycle should be updated in database with new settings
    And old notification jobs should be cancelled
    And new notification jobs should be created for 48 hours before each bi-weekly Friday

  @functional @regression @priority-medium
  Scenario: Delete a scheduled review cycle and verify removal from calendar
    Given user has delete permissions
    And scheduled review cycle "Daily Performance Check-in" exists
    And review cycle has not started yet
    And no completed reviews exist for the cycle
    When user clicks on "Daily Performance Check-in" in "Active Schedules" list
    Then review cycle details panel should be visible
    And "Delete" button should be visible
    When user clicks "Delete" button
    Then confirmation dialog should be visible
    And confirmation message "Are you sure you want to delete this review cycle? This action cannot be undone." should be displayed
    And "Cancel" button should be visible
    And "Delete" button should be visible
    When user clicks "Delete" button in confirmation dialog
    Then success message "Review cycle deleted successfully" should be displayed
    And confirmation dialog should be hidden
    And "Daily Performance Check-in" should not appear in "Active Schedules" list
    And calendar view should not show any markers for "Daily Performance Check-in"
    And review cycle should be marked as deleted in database
    And all future scheduled review instances should be cancelled
    And all associated notification jobs should be removed

  @functional @regression @priority-high @notification
  Scenario: Verify notification is sent to users prior to scheduled review cycle
    Given review cycle "Monthly Performance Evaluation" is scheduled for tomorrow at "10:00 AM"
    And notification is set to "24 hours before"
    And test user email account is accessible
    And email notification service is running
    When user verifies review cycle in calendar view
    Then calendar should show review scheduled for tomorrow
    And notification icon should indicate "24 hours before" notification is enabled
    When system time advances to 24 hours before scheduled review
    Then notification badge should show 1 new notification
    When user clicks notification bell icon
    Then notification should display "Upcoming Review: Monthly Performance Evaluation scheduled for tomorrow at 10:00 AM"
    When user checks registered email inbox
    Then email should be received with subject "Reminder: Performance Review Scheduled for Tomorrow"
    And email should contain review cycle name "Monthly Performance Evaluation"
    And email should contain date and time
    And email should contain preparation instructions
    When user clicks on notification in app
    Then notification should expand showing full review details
    And "View Review Cycle" link should be visible
    When user clicks "View Review Cycle" link
    Then user should navigate to review cycle details page
    And notification should be marked as sent in database
    And in-app notification should remain visible until dismissed