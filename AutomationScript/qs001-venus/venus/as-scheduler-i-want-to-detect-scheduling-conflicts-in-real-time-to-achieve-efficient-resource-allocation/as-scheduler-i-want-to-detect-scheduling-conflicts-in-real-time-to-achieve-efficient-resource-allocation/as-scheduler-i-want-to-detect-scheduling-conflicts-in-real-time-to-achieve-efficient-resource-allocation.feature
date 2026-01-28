Feature: Conflict Detection Algorithm

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Validate conflict detection with overlapping schedules
    Given User is authenticated and logged into the scheduling system
    Given At least one existing booking is present in the scheduling database
    Given User has permissions to create new scheduling requests
    Given API endpoint /api/schedule/check is accessible and operational
    Given Scheduling database is online and responsive
    When Navigate to the scheduling interface and access the new booking form
    Then New booking form is displayed with all required fields (date, time, resource, duration)
    And Enter scheduling details that overlap with an existing booking (same resource, overlapping time slot)
    Then Form accepts the input and displays entered values correctly
    And Submit the scheduling request by clicking the Submit button
    Then System processes the request and performs conflict detection within 2 seconds
    And Observe the system response for conflict detection alert
    Then System detects the conflict and displays an alert message to the user indicating the scheduling conflict with details of the overlapping booking
    And Navigate to the conflict log section in the system
    Then Conflict log interface is displayed with list of all detected conflicts
    And Check the conflict log for the newly detected conflict entry
    Then Conflict is recorded in the system with timestamp, conflicting schedules, resource details, and user information
    And Review the alert message displayed to the user
    Then Alert provides clear information about the conflict and offers actionable options for resolution (e.g., modify time, select different resource, cancel request)

  Scenario: Ensure no false positives in conflict detection
    Given User is authenticated and logged into the scheduling system
    Given Existing bookings are present in the scheduling database
    Given User has permissions to create new scheduling requests
    Given API endpoint /api/schedule/check is accessible and operational
    Given Scheduling database is online and responsive
    When Navigate to the scheduling interface and access the new booking form
    Then New booking form is displayed with all required fields available for input
    And Enter scheduling details that do not overlap with any existing bookings (different time slot or different resource)
    Then Form accepts the input and all entered values are displayed correctly
    And Submit the scheduling request by clicking the Submit button
    Then System processes the request and performs conflict detection check within 2 seconds
    And Observe the system response for any conflict alerts
    Then System does not detect any conflicts and proceeds with booking creation without displaying any conflict alerts
    And Verify that a success confirmation message is displayed
    Then System displays a success message confirming the booking has been created successfully
    And Navigate to the conflict log section in the system
    Then Conflict log interface is displayed showing existing conflict entries
    And Check the conflict log for any new entries related to the submitted request
    Then No new entries are added to the conflict log for this non-conflicting booking request
    And Review the user interface for any alert messages
    Then No conflict alert is generated or displayed to the user
    And Verify the new booking appears in the schedule view
    Then New booking is successfully created and visible in the scheduling calendar/list view

  # Accessibility Test Scenarios
  Scenario: Keyboard Navigation
    When the user navigates using keyboard only
    Then all interactive elements should be accessible via keyboard
    And focus indicators should be clearly visible

  Scenario: Screen Reader Compatibility
    When the user accesses the page with a screen reader
    Then all content should be properly announced
    And ARIA labels should be present for all interactive elements

  Scenario: Color Contrast
    Then all text should meet WCAG AA color contrast standards
    And important information should not rely solely on color

