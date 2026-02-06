Feature: Schedule Change Notification Delivery for Edge Cases
  As a User
  I want to receive notifications for schedule changes even in edge case scenarios
  So that I stay informed about my commitments regardless of system conditions

  Background:
    Given user is logged into the system with valid credentials
    And user has notification preferences enabled for schedule changes
    And email service and in-app notification service are operational

  @edge @regression @priority-high
  Scenario: Multiple rapid schedule changes within seconds deliver all notifications accurately
    Given user has at least one scheduled appointment in the system
    When user modifies appointment time from "2:00 PM" to "3:00 PM"
    And within 5 seconds user modifies the same appointment from "3:00 PM" to "4:00 PM"
    And within another 5 seconds user modifies the same appointment from "4:00 PM" to "5:00 PM"
    And user waits for 1 minute
    Then user should receive 3 notifications in email inbox
    And user should receive 3 notifications in in-app notification center
    And each notification should contain accurate schedule change details
    And notification for first change should show time change from "2:00 PM" to "3:00 PM"
    And notification for second change should show time change from "3:00 PM" to "4:00 PM"
    And notification for third change should show time change from "4:00 PM" to "5:00 PM"
    And each notification should have correct timestamp
    And no duplicate notifications should be present
    And notification history should show all 3 changes in chronological order
    And user's schedule should reflect final appointment time of "5:00 PM"

  @edge @regression @priority-medium
  Scenario: Schedule change at midnight boundary delivers notification with correct date and time
    Given user has a scheduled appointment for the next day
    And system time is set to "11:59:50 PM"
    And notification services are running and operational
    When user waits until system time reaches "11:59:55 PM"
    And user modifies the appointment scheduled for tomorrow
    And system clock transitions from "11:59:59 PM" to "12:00:00 AM"
    And user waits for 1 minute
    Then notification should be delivered to email
    And notification should be delivered to in-app notification center
    And notification timestamp should reflect correct date after midnight transition
    And notification content should display correct date for modified appointment
    And no timezone-related errors should occur
    And no date calculation issues should be present
    And notification log should record correct timestamp

  @edge @regression @priority-medium
  Scenario: New notification delivers successfully when user has 100+ pending unread notifications
    Given user has 100 unread notifications in notification center
    And user has not acknowledged any existing notifications
    And email inbox has storage capacity available
    When user navigates to notification center
    And user creates schedule change by modifying an existing appointment
    And user waits for 1 minute
    Then new notification should appear in notification center
    And total unread notifications count should be 101
    And email notification should be delivered successfully
    And new notification should be displayed at top of notification list
    And notification should contain correct schedule change details
    And notification center should load within 3 seconds
    And system performance should remain stable

  @edge @regression @priority-high
  Scenario: Notification displays special characters and Unicode correctly in appointment details
    Given user has an appointment with title "Meeting @ O'Brien's Café ☕ - Q&A Session (R&D)"
    And notification services support UTF-8 encoding
    And email client supports HTML and Unicode characters
    When user modifies appointment time from "2:00 PM" to "3:30 PM"
    And user waits for 1 minute
    Then in-app notification should display appointment title "Meeting @ O'Brien's Café ☕ - Q&A Session (R&D)"
    And email notification should display appointment title "Meeting @ O'Brien's Café ☕ - Q&A Session (R&D)"
    And all special characters should render correctly: "@ ' é ☕ & ( )"
    And notification should include time change details "Changed from 2:00 PM to 3:30 PM"
    And no encoding errors should be present
    And no HTML injection vulnerabilities should be present
    And no XSS vulnerabilities should be present
    And Unicode emoji should render correctly across all notification channels
    And accented characters should render correctly across all notification channels

  @edge @regression @priority-high
  Scenario: In-app notification delivers when email address becomes invalid before notification delivery
    Given user has email address "user@example.com"
    And user has a scheduled appointment in the system
    And user has both email and in-app notifications enabled
    When user modifies scheduled appointment time from "10:00 AM" to "11:00 AM"
    And within 10 seconds user's email address is updated to invalid format "invalid-email-format"
    And user waits for 1 minute
    Then email notification delivery should fail
    And system should log email delivery failure
    And in-app notification should be delivered successfully
    And in-app notification should contain complete schedule change details
    And system logs should show email delivery failure with error message
    And system logs should show in-app notification successful delivery
    And notification delivery status records should be maintained
    And system should not crash due to email delivery failure
    When user's email address is corrected to valid format
    And user triggers another schedule change
    Then subsequent notifications should be delivered to both email and in-app channels

  @edge @regression @priority-high
  Scenario: System handles 1000 simultaneous schedule changes across different users
    Given system has 1000 active user accounts with scheduled appointments
    And all users have notification preferences enabled
    And system load testing environment is configured
    And database connection pool has sufficient capacity
    When automated script triggers 1000 schedule changes simultaneously
    And user waits for 2 minutes
    Then all 1000 schedule changes should be saved to database successfully
    And notification system should process all 1000 notifications without crashing
    And at least 95 percent of users should receive in-app notifications within 1 minute
    And at least 95 percent of users should receive email notifications within 2 minutes
    And system CPU usage should remain below 80 percent
    And memory usage should remain within acceptable limits
    And no database deadlocks should occur
    And random sample of 10 notifications should contain correct schedule change details
    And no notifications should be lost
    And no notifications should be duplicated
    And database integrity should be maintained without data corruption