Feature: User Notification System

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Validate notification delivery for detected conflicts
    Given User account is active and logged into the system
    Given User has valid notification preferences configured (email, SMS, or in-app)
    Given User has at least one existing scheduled event in the calendar
    Given Notification service is running and operational
    Given User has granted necessary permissions for receiving notifications
    When Create a new event that overlaps with an existing event in the user's calendar to trigger a scheduling conflict
    Then System detects the scheduling conflict and generates a notification within 2 seconds
    And Navigate to user profile settings and check the configured notification preferences
    Then User's preferred notification channel (email, SMS, or in-app) is displayed and active
    And Verify that the notification is sent via the user's preferred channel by checking the respective inbox/notification center
    Then Notification is successfully delivered through the preferred channel within 2 seconds of conflict detection
    And Open the received notification and review its content
    Then Notification contains all relevant conflict details including: conflicting event names, date and time of both events, duration of overlap, and a direct link to resolve the conflict
    And Verify the notification delivery status in the system logs or admin panel
    Then Notification delivery status shows as 'Delivered' with timestamp matching the conflict detection time

  # Edge Case Test Scenarios
  Scenario: Ensure notifications are not sent for non-conflicting events
    Given User account is active and logged into the system
    Given User has notification preferences configured
    Given User's calendar is accessible and functional
    Given Notification service is running and operational
    Given No existing scheduling conflicts are present in the user's calendar
    When Schedule the first event in the user's calendar with a specific date, start time, and end time (e.g., Meeting A from 10:00 AM to 11:00 AM)
    Then First event is successfully created and saved in the calendar without any conflicts detected
    And Schedule a second event in the user's calendar that does not overlap with the first event (e.g., Meeting B from 2:00 PM to 3:00 PM on the same day)
    Then Second event is successfully created and saved in the calendar. System confirms no scheduling conflict exists between the two events
    And Access the notification logs via admin panel or API endpoint to check for any conflict notifications generated
    Then Notification logs show no conflict notifications were generated or sent for these two events
    And Check the user's notification center, email inbox, and SMS messages (based on configured preferences)
    Then User has not received any conflict notifications. No new notifications appear in any of the notification channels
    And Verify the system's conflict detection logic by reviewing event timestamps and overlap calculations
    Then System correctly identifies that the events do not overlap and no conflict detection is triggered

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

