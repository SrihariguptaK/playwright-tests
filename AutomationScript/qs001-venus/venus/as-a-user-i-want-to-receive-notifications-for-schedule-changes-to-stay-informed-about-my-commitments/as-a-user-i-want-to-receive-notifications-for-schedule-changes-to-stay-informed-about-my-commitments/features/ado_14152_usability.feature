Feature: Schedule Change Notifications
  As a User
  I want to receive notifications for schedule changes
  So that I can stay informed about my commitments and adjust my plans accordingly

  Background:
    Given user account is active with valid email address
    And user has at least one scheduled appointment in the system
    And user is logged into the application

  @usability @priority-critical @smoke @functional
  Scenario: Real-time notification delivery with complete schedule change details
    Given notification preferences are enabled for schedule changes
    And user has an appointment scheduled at "2:00 PM"
    When user modifies the appointment time from "2:00 PM" to "3:00 PM"
    Then system should display visual indicator showing change is being processed
    And in-app notification should appear within 1 minute
    And notification badge counter should be visible
    And notification timestamp should be displayed
    And notification should show "Original: 2:00 PM → New: 3:00 PM"
    When user clicks on the in-app notification
    Then notification should expand showing full details
    And appointment name should be displayed
    And old schedule details should be displayed
    And new schedule details should be displayed
    And reason for change should be displayed if available
    And delivery status indicators should be shown for email channel
    And delivery status indicators should be shown for in-app channel
    When user checks email inbox
    Then email notification should be received within 1 minute
    And email timestamp should match in-app notification timestamp
    And email subject line should indicate schedule change
    And email content should show before and after comparison
    When user navigates to notification history section
    Then all notifications should be listed chronologically
    And read or unread status should be displayed for each notification
    And notification timestamps should be visible
    And user should be able to filter by "schedule changes" type

  @usability @priority-high @functional
  Scenario: User manages notification preferences with reversible actions
    Given notification settings page is accessible from main navigation
    And user has received at least 2 schedule change notifications
    And default notification settings are enabled for email
    And default notification settings are enabled for in-app alerts
    When user navigates to notification settings page
    Then settings page should display toggle for "email notifications"
    And settings page should display toggle for "in-app alerts"
    And current state should be clearly visible as "ON" or "OFF"
    When user disables "email notifications" toggle
    And user keeps "in-app alerts" toggle enabled
    And user clicks "Save" button
    Then "Settings saved successfully" message should be displayed
    And undo option should be available for 10 seconds
    And updated preference state should be shown immediately
    When user triggers a new schedule change
    Then in-app notification should be received
    But email notification should not be sent
    When user views the in-app notification
    Then "Dismiss" option should be available
    And "Snooze" option should be available with "15 min" choice
    And "Snooze" option should be available with "1 hour" choice
    And "Snooze" option should be available with "custom" choice
    And "Mark as Read" option should be available
    When user navigates to notification history
    And user selects a read notification
    Then context menu should allow toggling read or unread status
    And visual indicator should update immediately
    When user returns to notification settings
    And user clicks "Restore defaults" button
    Then confirmation dialog should display "Are you sure you want to restore default settings?"
    When user confirms restore defaults action
    Then all notification channels should reset to default state

  @usability @priority-high @functional
  Scenario: Notification provides complete context without requiring navigation
    Given user has multiple appointments scheduled across different dates
    And user has an appointment with title, date, time, location, attendees and description
    And appointment is scheduled 3 days in the future
    When schedule change occurs for the appointment
    Then notification should be generated
    And notification should be delivered via email channel
    And notification should be delivered via in-app channel
    When user views the in-app notification without clicking through
    Then appointment title should be displayed
    And before and after date comparison should be shown
    And before and after time comparison should be shown
    And location should be displayed
    And list of attendees should be displayed
    And reason for change should be displayed
    And "View Full Details" button should be available
    And "Accept Change" button should be available
    And "Decline" button should be available
    And changed information should be highlighted in different color
    And conflicts should be flagged if any exist
    And initiator of change should be displayed
    When user opens email notification
    Then email should contain identical information as in-app notification
    And email should display formatted before and after table
    And email should include calendar attachment in ".ics" format
    And email should provide direct link to appointment in system
    When user navigates to notification history
    And user selects a notification from 1 week ago
    Then notification should retain all original details
    And current status should be shown as "accepted" or "declined"
    And link to current appointment state should be provided
    And change history should be accessible

  @usability @priority-high @functional @edge
  Scenario: Recurring appointment change notification displays scope and impact
    Given user has a recurring appointment scheduled
    When schedule change occurs for the recurring appointment
    Then notification should indicate "This is a recurring appointment"
    And scope of change should be clearly stated as "this instance only" or "all future instances"
    And visual calendar preview should show affected dates
    And user should be able to understand impact without additional navigation

  @usability @priority-high @negative
  Scenario: Notification preferences persist across user sessions
    Given user has customized notification preferences
    And user has disabled "email notifications"
    When user logs out of the application
    And user logs back into the application
    And user navigates to notification settings page
    Then "email notifications" toggle should remain disabled
    And all customized preferences should be preserved

  @usability @priority-medium @functional
  Scenario Outline: Notification delivery respects user channel preferences
    Given user has configured notification preferences
    And "<channel>" is set to "<status>"
    When schedule change occurs for user appointment
    Then notification delivery should match expected behavior for "<channel>" with "<status>"

    Examples:
      | channel              | status   |
      | email notifications  | enabled  |
      | email notifications  | disabled |
      | in-app alerts        | enabled  |
      | in-app alerts        | disabled |

  @usability @priority-medium @functional
  Scenario: User performs quick actions directly from notification
    Given user receives schedule change notification
    And notification displays quick action buttons
    When user clicks "Accept Change" button from notification
    Then change should be accepted without navigating to appointment details
    And confirmation message should be displayed
    And notification status should update to "Change Accepted"

  @usability @priority-medium @functional
  Scenario: Notification history allows filtering and status management
    Given user has received multiple notifications of different types
    When user navigates to notification history section
    And user applies filter for "schedule changes" type
    Then only schedule change notifications should be displayed
    When user selects multiple notifications
    Then bulk actions should be available
    And user should be able to mark selected notifications as read
    And user should be able to delete selected notifications