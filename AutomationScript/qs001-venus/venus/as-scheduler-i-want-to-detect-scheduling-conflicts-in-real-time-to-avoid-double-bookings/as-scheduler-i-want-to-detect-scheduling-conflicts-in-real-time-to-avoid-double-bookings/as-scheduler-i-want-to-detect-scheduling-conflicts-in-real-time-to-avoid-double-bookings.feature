Feature: Conflict Detection Algorithm

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Validate conflict detection for overlapping events
    Given User is authenticated and logged into the scheduling system
    Given User has permission to create and schedule events
    Given Event database is accessible and operational
    Given No existing events are scheduled in the 10:00-12:00 time slot
    Given System conflict detection feature is enabled
    When Navigate to the scheduling interface and select 'Create New Event'
    Then Event creation form is displayed with all required fields (title, start time, end time, participants)
    And Enter event details: Title='Meeting A', Start Time='10:00', End Time='11:00', and click 'Schedule'
    Then Event 'Meeting A' is scheduled successfully and appears in the calendar view for the 10:00-11:00 time slot
    And Verify the first event is saved by refreshing the calendar view
    Then Event 'Meeting A' remains visible in the calendar at 10:00-11:00 time slot
    And Click 'Create New Event' again to schedule a second event
    Then Event creation form is displayed again with empty fields ready for new input
    And Enter event details: Title='Meeting B', Start Time='10:30', End Time='11:30', and click 'Schedule'
    Then System detects the overlap between 10:30-11:00 with existing 'Meeting A' and prevents immediate scheduling
    And Check for conflict alert notification on the screen
    Then User receives a conflict alert notification within 2 seconds indicating overlap with 'Meeting A' from 10:30 to 11:00
    And Review the conflict details displayed in the alert
    Then Alert shows both conflicting events with their time slots: 'Meeting A (10:00-11:00)' and 'Meeting B (10:30-11:30)' with the overlapping period highlighted
    And Verify that 'Meeting B' was not added to the calendar
    Then Only 'Meeting A' appears in the calendar; 'Meeting B' is not scheduled

  Scenario: Ensure no conflict detection for non-overlapping events
    Given User is authenticated and logged into the scheduling system
    Given User has permission to create and schedule events
    Given Event database is accessible and operational
    Given No existing events are scheduled in the 10:00-13:00 time slot
    Given System conflict detection feature is enabled
    When Navigate to the scheduling interface and select 'Create New Event'
    Then Event creation form is displayed with all required fields (title, start time, end time, participants)
    And Enter event details: Title='Meeting A', Start Time='10:00', End Time='11:00', and click 'Schedule'
    Then Event 'Meeting A' is scheduled successfully without any conflict alerts and appears in the calendar view for the 10:00-11:00 time slot
    And Verify the first event is saved by checking the calendar view
    Then Event 'Meeting A' is visible in the calendar at 10:00-11:00 time slot with confirmed status
    And Click 'Create New Event' to schedule a second event immediately after the first
    Then Event creation form is displayed again with empty fields ready for new input
    And Enter event details: Title='Meeting B', Start Time='11:00', End Time='12:00', and click 'Schedule'
    Then System processes the request and completes the conflict check within 2 seconds without detecting any overlap
    And Verify that 'Meeting B' is scheduled successfully
    Then Event 'Meeting B' is scheduled successfully and appears in the calendar view for the 11:00-12:00 time slot immediately following 'Meeting A'
    And Check for any conflict alert notifications on the screen or notification panel
    Then No conflict alert is displayed; user does not receive any conflict notification
    And Verify both events are visible in the calendar view
    Then Both 'Meeting A' (10:00-11:00) and 'Meeting B' (11:00-12:00) are displayed consecutively in the calendar without any conflict indicators
    And Check the event database or event list to confirm both events are saved
    Then Both events are successfully saved in the system with correct time slots and no conflict flags

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

