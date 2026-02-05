Feature: Schedule Change Notifications
  As a User
  I want to receive notifications for schedule changes
  So that I can stay informed about my commitments and adjust my plans accordingly

  Background:
    Given user account is active and authenticated
    And notification service is operational

  @undefined @usability @priority-critical @smoke
  Scenario: Real-time notification delivery with complete schedule change details
    Given user has at least one scheduled appointment in the system
    And notification preferences are enabled for both email and in-app alerts
    And user has an appointment scheduled at "2:00 PM"
    When user modifies the appointment time from "2:00 PM" to "3:30 PM"
    Then system should immediately display a processing indicator
    And in-app notification should appear within 1 minute
    And in-app notification should display appointment name
    And in-app notification should show old time "2:00 PM" and new time "3:30 PM"
    And in-app notification should display timestamp of when notification was sent
    And in-app notification should display visual indicator distinguishing it from other notification types
    And email notification should be received within 1 minute
    And email subject line should clearly indicate schedule change
    And email body should contain old time "2:00 PM" and new time "3:30 PM"
    And email should display timestamp of change
    When user navigates to notification history section
    Then schedule change notification should be visible in history
    And notification should display delivery status "Sent via Email"
    And notification should display delivery status "Delivered In-App"
    And notification should display timestamp
    And system should show loading indicators during any processing delays

  @undefined @usability @priority-high @functional
  Scenario: User control over notification preferences by channel
    Given user is logged into the system
    And both email and in-app notification channels are enabled
    When user navigates to notification settings page
    Then settings page should display option to enable or disable email notifications
    And settings page should display option to enable or disable in-app notifications
    And "Save" button should be visible
    And "Cancel" button should be visible
    When user disables email notifications
    And user keeps in-app notifications enabled
    And user clicks "Save" button
    And user triggers a schedule change
    Then in-app notification should be received
    And email notification should not be sent
    And settings should be respected without requiring logout

  @undefined @usability @priority-high @functional
  Scenario: Undo dismissed notification within time window
    Given user is logged into the system
    And user has 3 unread notifications
    When user dismisses a schedule change notification
    Then "Undo" button should be visible for 10 seconds
    When user clicks "Undo" button within the time window
    Then notification should be restored to its previous state
    And notification read status should be preserved
    And "Notification restored" message should be displayed

  @undefined @usability @priority-high @functional
  Scenario: Toggle notification read and unread status
    Given user is logged into the system
    And user has at least one notification
    When user marks a notification as read
    And user attempts to mark it as unread again
    Then context menu should allow toggling between read and unread states
    And visual indicator should update immediately

  @undefined @usability @priority-high @functional
  Scenario: Access recently dismissed notifications
    Given user is logged into the system
    And user has dismissed notifications within 30 days
    When user navigates to "Recently Deleted" section
    Then dismissed notifications should be visible
    And option to restore should be available for each notification

  @undefined @usability @priority-high @recognition
  Scenario: Complete context visibility for schedule time change notification
    Given user has multiple appointments scheduled
    And user receives a notification about schedule time change
    When user views the notification in notification panel without clicking through
    Then notification should display appointment title
    And notification should display original date and time with strikethrough
    And notification should display new date and time highlighted
    And notification should display location if applicable
    And notification should display organizer names
    And notification should display participant names
    And notification should display reason for change if provided

  @undefined @usability @priority-high @recognition
  Scenario: Clear cancelled appointment notification details
    Given user has multiple appointments scheduled
    When user receives a notification about cancelled appointment
    Then notification should clearly show "CANCELLED" status
    And notification should display original appointment date
    And notification should display original appointment time
    And notification should display original appointment title

  @undefined @usability @priority-high @recognition
  Scenario: Historical notifications retain full context
    Given user has notifications from 2 weeks ago
    When user opens notification history
    And user scans through past notifications
    Then each historical notification should display old values
    And each historical notification should display new values
    And each historical notification should display appointment details
    And notifications should be grouped by "Today"
    And notifications should be grouped by "Yesterday"
    And notifications should be grouped by "Last Week"

  @undefined @usability @priority-high @recognition
  Scenario: Expanded notification view with complete details and actions
    Given user has at least one notification
    When user clicks on a notification to view full details
    Then expanded view should display complete appointment card
    And expanded view should display full description
    And expanded view should display participants
    And expanded view should display location
    And expanded view should display attachments
    And "View Calendar" button should be visible
    And "Acknowledge" button should be visible
    And "Dismiss" button should be visible

  @undefined @usability @priority-high @recognition
  Scenario: Multiple changes to same appointment shown with timeline
    Given user has an appointment that changed multiple times
    When user receives notification for the appointment
    Then notification should display change history timeline
    And timeline should show progression "2:00 PM → 3:00 PM → 3:30 PM"
    And notification should not create separate confusing notifications

  @undefined @usability @priority-high @edge
  Scenario Outline: Notification preferences respected for different channel combinations
    Given user is logged into the system
    And email notifications are "<email_status>"
    And in-app notifications are "<inapp_status>"
    When user triggers a schedule change
    Then email notification should be "<email_received>"
    And in-app notification should be "<inapp_received>"

    Examples:
      | email_status | inapp_status | email_received | inapp_received |
      | enabled      | enabled      | received       | received       |
      | enabled      | disabled     | received       | not received   |
      | disabled     | enabled      | not received   | received       |
      | disabled     | disabled     | not received   | not received   |

  @undefined @usability @priority-medium @negative
  Scenario: Notification delivery status visible when email fails
    Given user has at least one scheduled appointment in the system
    And notification preferences are enabled for both email and in-app alerts
    And email service is temporarily unavailable
    When user modifies an appointment time
    Then in-app notification should be received within 1 minute
    When user navigates to notification history section
    Then notification should display delivery status "Delivered In-App"
    And notification should display delivery status "Email Failed"