Feature: Schedule Change Notifications
  As a User
  I want to receive notifications for schedule changes
  So that I stay informed about my commitments and can adjust my plans accordingly

  Background:
    Given user is logged into the system with valid credentials
    And notification service is running and operational

  @functional @regression @priority-high @smoke
  Scenario: User receives both email and in-app notifications when schedule is updated
    Given user has at least one scheduled appointment in the system
    And user's email address is verified and configured in profile settings
    And notification preferences are enabled for both email and in-app alerts
    And user has an appointment scheduled for tomorrow at "2:00 PM"
    When user navigates to "Schedule" page
    And user selects the existing appointment
    And user clicks "Edit Appointment" button
    And user changes the appointment time from "2:00 PM" to "3:30 PM"
    And user clicks "Save Changes" button
    Then success message "Appointment updated successfully" should be displayed
    And user waits for "1" minute
    And notification bell icon should display badge count "1"
    When user clicks notification bell icon
    Then notification panel should be visible
    And notification message "Your appointment has been rescheduled from 2:00 PM to 3:30 PM" should be displayed
    And notification should include timestamp
    And email should be received within "1" minute
    And email subject should be "Schedule Change Alert"
    And email should contain original time "2:00 PM"
    And email should contain new time "3:30 PM"
    And email should contain appointment date
    And email should contain appointment description

  @functional @regression @priority-high
  Scenario: Notification includes complete details of schedule change including date, time, and description
    Given user has a scheduled appointment titled "Team Meeting" on "January 15, 2025" at "10:00 AM"
    And notification service is configured and running
    And user has notification permissions enabled
    When user navigates to "Schedule Management" page
    And user locates the "Team Meeting" appointment scheduled for "January 15, 2025" at "10:00 AM"
    And user clicks "Edit" button next to the appointment
    And user modifies the date to "January 16, 2025"
    And user modifies the time to "11:30 AM"
    And user clicks "Save" button
    Then appointment updates successfully
    And confirmation message should be displayed
    When user clicks notification bell icon within "1" minute
    Then notification panel should be visible
    And notification should display red unread indicator
    And notification content should contain "Schedule Change Alert: Team Meeting has been rescheduled"
    And notification should contain original date "January 15, 2025"
    And notification should contain original time "10:00 AM"
    And notification should contain new date "January 16, 2025"
    And notification should contain new time "11:30 AM"
    And notification should contain description "Team Meeting"
    When user opens the email notification in inbox
    Then email should contain formatted section "Original Schedule"
    And email should contain formatted section "New Schedule"
    And email should contain formatted section "Appointment Title"
    And email should contain formatted section "Change Timestamp"

  @functional @regression @priority-high
  Scenario: User can acknowledge receipt of notification and notification status updates accordingly
    Given user has received at least one unread schedule change notification
    And notification appears in notification panel with "unread" status
    And notification bell icon shows unread count badge
    When user clicks notification bell icon
    Then notification panel should be visible
    And most recent notification should be displayed at the top
    And notification should be marked as "unread" in bold text
    When user clicks "Acknowledge" button next to the notification
    Then "Acknowledge" button should change to "Acknowledged" with checkmark icon
    And notification text should change from bold to regular weight
    And notification badge count should decrease by "1"
    When user closes the notification panel
    And user clicks notification bell icon again
    Then previously acknowledged notification should be visible
    And notification should show "Acknowledged" status
    And notification should display acknowledgment timestamp
    When user navigates to "Notification History" page
    Then notification should be displayed with status "Acknowledged"
    And acknowledgment timestamp should be visible
    And original notification details should be visible

  @functional @regression @priority-high @performance
  Scenario: Notifications are sent within 1 minute when multiple schedule changes occur simultaneously
    Given user has administrator privileges
    And user has "5" scheduled appointments for the upcoming week
    And all appointments are confirmed and active
    And system time is synchronized and accurate
    And notification service has sufficient capacity for bulk notifications
    When user navigates to "Bulk Schedule Management" page
    And user selects all "5" appointments using checkboxes
    Then all "5" appointments should be highlighted
    And "Bulk Actions" menu should be enabled
    When user clicks "Bulk Actions" dropdown
    And user selects "Reschedule All" option
    And user sets new date to be "2" days later than current dates
    Then bulk reschedule dialog should be visible
    And dialog should show all "5" appointments with new proposed dates
    When user records current system time
    And user clicks "Confirm Bulk Reschedule" button
    Then success message "5 appointments rescheduled successfully. Notifications are being sent." should be displayed
    When user clicks notification bell icon within "1" minute
    Then notification badge should show "5"
    And notification panel should display "5" separate notifications
    And all notifications should be timestamped within "1" minute of confirmation
    When user checks email inbox within "1" minute
    Then "5" separate email notifications should be received
    And all emails should have send timestamps within "1" minute of confirmation
    And each notification should contain accurate before and after schedule information
    And each notification should show original date and time
    And each notification should show new date "2" days later

  @functional @regression @priority-medium
  Scenario: User can view past notifications in notification history with complete details
    Given user has received at least "10" schedule change notifications over the past "30" days
    And some notifications are acknowledged
    And some notifications are unread
    And user has access to Notification History feature
    When user clicks on user profile icon
    And user selects "Notification History" from dropdown menu
    Then "Notification History" page should be visible
    And notification list should display at least "10" notifications
    And notifications should be sorted by date with most recent first
    And list should show column "Date/Time"
    And list should show column "Notification Type"
    And list should show column "Status"
    And list should show column "Details"
    When user clicks on the oldest notification in the list
    Then notification should expand showing complete information
    And notification should display original schedule
    And notification should display new schedule
    And notification should display appointment title
    And notification should display timestamp of change
    And notification should display acknowledgment status
    When user selects "Unread Only" from filter dropdown
    Then list should refresh to show only unread notifications
    And all acknowledged notifications should be hidden
    When user clears the filter
    And user selects date range for past "7" days using date range picker
    Then list should display only notifications from past "7" days
    And count indicator should show number of results

  @functional @regression @priority-high @negative
  Scenario: Notification is sent when schedule is cancelled
    Given user has a confirmed appointment scheduled for "Client Presentation" on "January 20, 2025" at "3:00 PM"
    And notification preferences are enabled
    And user has permission to cancel appointments
    When user navigates to "Schedule" page
    And user locates the "Client Presentation" appointment on "January 20, 2025" at "3:00 PM"
    Then appointment should be displayed with status "Confirmed"
    And all appointment details should be visible
    When user clicks "Cancel Appointment" button
    Then confirmation dialog should be visible
    And dialog should display message "Are you sure you want to cancel this appointment? This action cannot be undone."
    When user clicks "Yes, Cancel Appointment" button in confirmation dialog
    Then dialog should close
    And success message "Appointment cancelled successfully. Notification sent." should be displayed
    And appointment should be removed from schedule or marked as "Cancelled"
    When user clicks notification bell icon within "1" minute
    Then notification panel should be visible
    And notification message "Schedule Change Alert: Client Presentation scheduled for January 20, 2025 at 3:00 PM has been cancelled." should be displayed
    When user checks email inbox
    Then email should be received with subject "Appointment Cancelled"
    And email should contain appointment title "Client Presentation"
    And email should contain original date "January 20, 2025"
    And email should contain original time "3:00 PM"
    And email should contain cancellation timestamp
    And email should contain cancellation reason field