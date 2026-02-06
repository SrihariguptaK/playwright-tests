Feature: Schedule Change Notifications
  As a User
  I want to receive notifications for schedule changes
  So that I can stay informed about my commitments and adjust my plans accordingly

  Background:
    Given user is registered and logged into the system with valid credentials
    And notification service is running and operational
    And user has notification preferences enabled for schedule changes

  @functional @regression @priority-high @smoke
  Scenario: User receives email and in-app notification when schedule is updated
    Given user has an appointment scheduled for tomorrow at "2:00 PM"
    And user's email address is verified and active in the system
    When user navigates to "Schedule Management" page
    And user selects the existing appointment scheduled for tomorrow
    And user clicks "Edit Appointment" button
    And user changes the appointment time from "2:00 PM" to "3:30 PM"
    And user clicks "Save Changes" button
    Then success message "Schedule updated successfully" should be displayed
    And appointment should show new time "3:30 PM"
    And user waits for 60 seconds
    And red notification badge should appear on bell icon with count 1
    When user clicks notification bell icon
    Then notification should display "Your appointment on [date] has been changed from 2:00 PM to 3:30 PM"
    When user opens registered email inbox
    Then email notification should be received with subject "Schedule Change Alert"
    And email should contain original time "2:00 PM"
    And email should contain new time "3:30 PM"
    And email should contain appointment date and description
    And notification record should be created in database with delivery status "sent"

  @functional @regression @priority-high
  Scenario: Notification includes all required schedule change details
    Given user is authenticated and has an active session
    And user has appointment scheduled for next Monday at "10:00 AM" with "Dr. Smith" in "Room 101"
    And notification system is configured to include full change details
    When administrator accesses the schedule management system
    And administrator locates user's appointment for next Monday
    And administrator changes appointment time to "11:30 AM"
    And administrator changes provider to "Dr. Johnson"
    And administrator changes location to "Room 205"
    And administrator clicks "Update Schedule" button
    Then confirmation dialog should display "Confirm schedule changes? User will be notified."
    When administrator clicks "Confirm" button
    Then system should display "Schedule updated and notification sent" message
    And appointment should reflect all new values
    When user clicks notification bell icon
    Then notification should display title "Schedule Change Alert"
    And notification should include original date and time "Next Monday 10:00 AM"
    And notification should include new date and time "Next Monday 11:30 AM"
    And notification should include original provider "Dr. Smith"
    And notification should include new provider "Dr. Johnson"
    And notification should include original location "Room 101"
    And notification should include new location "Room 205"
    When user checks email notification
    Then email should contain identical information as in-app notification
    And email should display "What Changed" section with all modified fields
    And email should show before and after values for each changed field

  @functional @regression @priority-high
  Scenario: User can acknowledge receipt of schedule change notification
    Given user has received unacknowledged schedule change notification
    And notification appears in notification center with unread status
    And user has permission to acknowledge notifications
    When user clicks notification bell icon in top-right corner
    Then notification dropdown panel should open
    And unacknowledged notification should appear with blue highlight
    And "Acknowledge" button should be visible
    When user reads notification showing schedule change from "2:00 PM" to "4:00 PM"
    Then full notification content should be displayed with timestamp
    And change details should be visible
    When user clicks "Acknowledge" button
    Then button should change to "Acknowledged" with checkmark icon
    And blue highlight should be removed
    And notification should move to "Read" section
    And success message "Notification acknowledged" should be displayed
    When user closes notification panel and reopens it
    Then acknowledged notification should appear in "Read Notifications" section
    And notification should display with gray text
    And notification should show "Acknowledged on [timestamp]" label
    And notification badge count should decrease by 1
    When user navigates to "Notification History" page
    Then notification should display with status "Acknowledged"
    And acknowledgment timestamp should be visible
    And user who acknowledged should be displayed

  @functional @regression @priority-high @performance
  Scenario: Notifications are sent within 1 minute of schedule change detection
    Given user has active account with verified email address
    And user has scheduled appointment in the system
    And system clock is synchronized and accurate
    And notification service performance monitoring is enabled
    When user records current system time as "10:15:30 AM"
    And user updates appointment from "9:00 AM" to "10:00 AM"
    And user clicks "Save Changes" button
    Then system should display "Schedule updated successfully" message
    And change should be saved with timestamp "10:15:32 AM"
    When user monitors notification bell icon for 60 seconds
    Then notification badge should appear within 60 seconds
    And notification timestamp should indicate generation within 1 minute
    When user checks email inbox
    Then email should be received with timestamp between "10:15:32 AM" and "10:16:32 AM"
    When user accesses notification service logs
    Then logs should show schedule change detected at "10:15:32 AM"
    And logs should show notification generated at "10:15:35 AM"
    And logs should show email queued at "10:15:36 AM"
    And logs should show in-app notification delivered at "10:15:37 AM"
    And all timestamps should be within 1 minute of schedule change

  @functional @regression @priority-medium
  Scenario: User can view past schedule change notifications in notification history
    Given user has received 5 schedule change notifications over past 30 days
    And notification history feature is enabled for user account
    And user has permission to access notification history page
    When user clicks user profile icon in top-right corner
    And user selects "Notification History" from dropdown menu
    Then "Notification History" page should load
    And page should display list with columns "Date, Time, Type, Details, Status, Actions"
    And list should show all schedule change notifications sorted by most recent first
    And page should display at least 5 notifications
    And each notification should show notification date and time
    And each notification should show type "Schedule Change"
    And each notification should show brief description of change
    And each notification should show status as "Acknowledged" or "Unacknowledged"
    And each notification should show "View Details" link
    When user clicks "View Details" link on most recent notification
    Then modal should open showing complete notification details
    And modal should display original schedule
    And modal should display new schedule
    And modal should display all changed fields
    And modal should display timestamp of change
    And modal should display who made the change
    And modal should display acknowledgment status
    When user applies date filter for "Last 7 Days"
    And user clicks "Apply Filter" button
    Then list should refresh to show only notifications from past 7 days
    And older notifications should be hidden
    And filter indicator should show "Last 7 Days" is active
    When user clicks "Export" button
    Then CSV file should download with filename "notification_history_[date].csv"
    And file should contain all filtered notifications with complete details

  @functional @regression @priority-high @validation
  Scenario: Notification is sent only for confirmed schedule changes not draft changes
    Given user is logged in as administrator with schedule modification rights
    And user has confirmed appointment scheduled for next Wednesday at "1:00 PM"
    And system supports draft mode for schedule changes
    And notification service is configured to send only for confirmed changes
    When user navigates to "Schedule Management" page
    And user selects appointment scheduled for next Wednesday
    Then appointment details page should display status "Confirmed"
    And appointment should show time "1:00 PM"
    When user clicks "Edit Appointment" button
    And user changes time to "2:00 PM"
    And user clicks "Save as Draft" button
    Then system should display message "Changes saved as draft"
    And appointment should show status "Draft Changes Pending"
    And original time "1:00 PM" should still display with draft indicator
    When user waits for 2 minutes
    And user checks in-app notifications
    And user checks email inbox
    Then no notification should be sent to user
    And notification bell icon should show no new notifications
    And email inbox should have no schedule change notification
    When user returns to draft appointment
    And user clicks "Review Draft Changes" button
    And user clicks "Confirm Changes" button
    Then confirmation dialog should display "Confirm schedule change? User will be notified."
    When user clicks "Confirm" button in dialog
    Then system should display "Schedule updated and notification sent"
    And appointment status should change to "Confirmed"
    And time should show "2:00 PM"
    When user waits for 1 minute
    And user checks in-app notifications
    And user checks email inbox
    Then user should receive in-app notification about schedule change
    And user should receive email notification about schedule change
    And notification should include change from "1:00 PM" to "2:00 PM"
    And notification should include confirmed change details
    And notification log should show single notification sent only after confirmation