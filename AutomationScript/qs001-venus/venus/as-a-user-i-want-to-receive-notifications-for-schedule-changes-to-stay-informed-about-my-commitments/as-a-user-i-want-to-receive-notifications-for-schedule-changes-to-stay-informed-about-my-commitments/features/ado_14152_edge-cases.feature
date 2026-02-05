Feature: Schedule Change Notification Delivery for Edge Cases
  As a User
  I want to receive notifications for schedule changes even in edge case scenarios
  So that I stay informed about my commitments regardless of system conditions or data complexity

  Background:
    Given user is logged into the system with valid credentials
    And email notification service is operational
    And in-app notification service is operational

  @edge @regression @priority-high
  Scenario: Notification delivery when multiple schedule changes occur within 1 second
    Given user has 5 scheduled appointments in the schedule database
    And user has notification preferences enabled for both email and in-app alerts
    When administrator navigates to schedule management page
    And administrator simultaneously updates 5 different appointments for the same user within 1 second
    And user waits for 2 minutes
    Then user should receive 5 email notifications within 1 minute of the changes
    And in-app notification center should display all 5 schedule changes
    And all notifications should show timestamps within 1 minute of the actual schedule change time
    And all 5 schedule changes should be reflected in user's schedule
    And notification delivery logs should show successful dispatch of all notifications
    And no duplicate notifications should be sent for the same schedule change

  @edge @regression @priority-medium
  Scenario Outline: Notification handling when user email address contains special characters and Unicode
    Given user account exists with email address "<email>"
    And user has 1 scheduled appointment
    And email notification service supports international email addresses
    When administrator navigates to user management page
    And administrator verifies user email address is "<email>"
    And administrator updates user scheduled appointment time from "<original_time>" to "<new_time>"
    And user waits for 1 minute
    Then email notification should be successfully sent to "<email>" without encoding errors
    And in-app notification should display the schedule change with correct details
    And email should be received in inbox with properly formatted schedule change details
    And no email encoding or delivery errors should be logged in the system

    Examples:
      | email                              | original_time | new_time |
      | user+test@domain.co.uk             | 2:00 PM       | 3:00 PM  |
      | user.name+tag@sub-domain.com       | 2:00 PM       | 3:00 PM  |
      | tëst+user@sub-domain.com           | 2:00 PM       | 3:00 PM  |
      | user@tëst.com                      | 2:00 PM       | 3:00 PM  |

  @edge @regression @priority-high
  Scenario: Notification behavior when schedule is changed during email service outage
    Given user has active schedule with appointments
    And system has retry mechanism configured for failed email notifications
    When administrator simulates email service outage by disabling email notification service
    And email service status shows as unavailable in system monitoring
    And administrator updates user scheduled appointment from "10:00 AM" to "11:00 AM"
    Then in-app notification should be delivered successfully within 1 minute
    And email notification should be queued for retry with failed status logged
    And retry attempts should be scheduled
    When administrator re-enables email notification service after 5 minutes
    And email service status shows as available in system monitoring
    And user waits for retry mechanism to process queued notifications
    Then queued email notification should be successfully sent to user email address
    And email notification should be received with schedule change details
    And system logs should show retry attempts and final successful delivery
    And no notifications should be lost or duplicated

  @edge @regression @priority-medium
  Scenario: Notification content when schedule change includes extremely long text fields and special characters
    Given user has 1 scheduled appointment
    And appointment fields support up to 1000 characters for description
    And email and in-app notification templates are configured
    When user navigates to appointment and opens edit form
    And user updates appointment description with 950 characters including special characters "@#$%^&*(), quotes, apostrophes, emojis, line breaks, and HTML-like tags"
    And user changes appointment time from "1:00 PM" to "2:00 PM"
    And user waits for 1 minute
    Then email notification should display full description with all special characters properly escaped
    And no HTML injection should occur in email
    And emojis should render correctly in email
    And text should not be truncated in email
    And in-app notification should display schedule change with full description
    And special characters should be properly rendered in notification
    And no XSS vulnerabilities should exist in notification
    And text should wrap appropriately in the UI
    When user clicks on the notification to view full details
    Then full notification details page should display all content correctly without truncation or rendering errors

  @edge @regression @priority-medium
  Scenario: Notification delivery when user has 100+ unread notifications in notification center
    Given user account exists with 100 unread notifications in notification center
    And user has active scheduled appointments
    And notification center has pagination configured
    When administrator verifies user has exactly 100 unread notifications
    And administrator updates user scheduled appointment from "9:00 AM" to "10:00 AM"
    And user waits for 1 minute
    Then email notification should be sent successfully within 1 minute
    And notification center should load successfully showing notification count of 101
    And newest notification should appear at the top of the list
    And new schedule change notification should be marked as unread
    When user scrolls through all notifications
    Then notification center should perform smoothly without lag
    And all 101 notifications should be accessible
    And new notification should remain accessible
    And notification center UI should remain responsive

  @edge @regression @priority-high
  Scenario: Notification behavior when user account is disabled immediately after schedule change
    Given user account is active with valid email address
    And user has 1 scheduled appointment
    And administrator has permissions to disable user accounts
    When administrator updates user scheduled appointment from "3:00 PM" to "4:00 PM"
    And administrator immediately disables user account within 5 seconds
    And user account status changes to "Disabled" in the system
    And user waits for 2 minutes
    Then system logs should show notification processing attempt with appropriate handling for disabled account
    And notification delivery should follow business rules for disabled accounts
    When administrator re-enables user account
    And user logs in successfully
    And user checks in-app notification center
    Then notification handling should be consistent with defined business rules for disabled accounts
    And schedule change should be persisted in database regardless of account status
    And no system errors or exceptions should have occurred during notification processing

  @edge @regression @priority-medium
  Scenario: Notification delivery across different time zones when schedule change occurs at midnight boundary
    Given user account is configured with timezone set to "Pacific Time"
    And system server is running in "UTC" timezone
    And user has scheduled appointment at "11:59 PM" in "PT" timezone
    When administrator navigates to user schedule
    And appointment is displayed with time "11:59 PM PT" in user timezone
    And administrator changes appointment time from "11:59 PM PT" to "12:15 AM PT"
    And user waits for 1 minute
    Then email notification should display schedule change with correct times in "PT" timezone
    And email should show time change from "11:59 PM" to "12:15 AM"
    And date transition should be shown in email
    And timezone indicator "PT" should be included in email
    And in-app notification should show times in user configured timezone "PT"
    And date change should be clearly indicated in notification
    And notification timestamp should be displayed in user timezone
    And notification timestamp should be within 1 minute of actual schedule change time
    And database should show appointment times stored in "UTC" with correct conversion
    And no timezone conversion errors should have occurred