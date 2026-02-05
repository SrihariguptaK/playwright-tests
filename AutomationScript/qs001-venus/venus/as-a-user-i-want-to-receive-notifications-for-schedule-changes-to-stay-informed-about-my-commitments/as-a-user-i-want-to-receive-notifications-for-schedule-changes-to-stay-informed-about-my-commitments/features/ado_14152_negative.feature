Feature: Schedule Change Notification Failure Handling
  As a User
  I want the system to handle notification failures gracefully
  So that I am still informed of schedule changes even when notification services experience issues

  Background:
    Given user is logged into the system
    And user has at least one scheduled appointment

  @negative @regression @priority-high
  Scenario: System handles notification failure gracefully when email service is unavailable
    Given email service is temporarily unavailable
    And in-app notification service is operational
    And system has error handling configured for email failures
    When user navigates to schedule page
    And user modifies appointment time from "10:00 AM" to "11:00 AM"
    And user clicks "Save" button
    Then appointment should be saved successfully
    And message "Appointment updated. Note: Email notification could not be sent at this time." should be displayed
    When user checks notification bell icon within 1 minute
    Then in-app notification should be delivered successfully
    And notification should show schedule change details
    When user checks email inbox after 2 minutes
    Then no email should be received
    When user navigates to "Notification History" page
    Then notification record should show status "Partially Delivered"
    And notification details should show "In-app: Success, Email: Failed - Service Unavailable"
    When email service is restored
    Then system should attempt to retry sending failed email notification
    And email should be delivered within 5 minutes
    And email should contain note "Delayed delivery due to temporary service issue"

  @negative @regression @priority-high
  Scenario: System behavior when user has invalid or missing email address in profile
    Given user profile email field is set to "invalid-email-format"
    And notification service is operational
    And email validation is enforced in the system
    When user navigates to "User Profile" page
    Then email field should display invalid value with warning icon
    When user navigates to "Schedule" page
    And user modifies existing appointment time
    And user clicks "Save Changes" button
    Then appointment should be saved successfully
    And warning message "Appointment updated. Email notification could not be sent - invalid email address. Please update your profile." should be displayed
    When user checks notification bell icon within 1 minute
    Then in-app notification should be delivered successfully
    And notification should contain message "Please update your email address in profile settings to receive email notifications."
    When user checks email inbox
    Then no email notification should be received
    When user navigates to "Notification History" page
    Then notification should show status "Partially Delivered"
    And notification details should show "In-app: Success, Email: Failed - Invalid recipient address"

  @negative @regression @priority-medium
  Scenario: System handles notification when user session expires during schedule change
    Given user session timeout is set to 30 minutes
    And user has been idle for 29 minutes
    And user has scheduled appointment open in edit mode
    And auto-save is disabled
    When user modifies appointment time from "2:00 PM" to "3:00 PM" without saving
    Then appointment edit form should show modified time "3:00 PM"
    And changes should not be saved yet
    When user waits for 1 minute for session to expire
    And user clicks "Save Changes" button
    Then error message "Your session has expired. Please log in again to save changes." should be displayed
    And user should be redirected to login page
    When user logs in with valid credentials
    Then user should successfully log in
    And user should be redirected to dashboard
    When user navigates to the appointment that was being edited
    Then appointment should show original time "2:00 PM"
    When user checks notification bell icon
    And user checks email inbox
    Then no notification should be sent

  @negative @regression @priority-high
  Scenario: Notification system handles database connection failure during notification creation
    Given database connection can be simulated to fail for notification table writes
    And application has database error handling configured
    And notification service is running
    When database connection to notification table is blocked
    And user modifies appointment time from "1:00 PM" to "2:00 PM"
    And user clicks "Save Changes" button
    Then appointment update should succeed
    And error message "Appointment saved, but notification could not be recorded. Please check your notifications manually." should be displayed
    When user checks notification bell icon within 1 minute
    Then notification bell should show error indicator
    When user refreshes schedule page
    Then appointment should display new time "2:00 PM"
    When user checks system error logs
    Then error log should contain entry "Failed to create notification record - Database connection error"
    And error log should include timestamp and error details
    When database connection is restored
    Then system recovery process should detect missing notification
    And system should create notification retroactively

  @negative @regression @priority-medium
  Scenario: System behavior when user has disabled notification preferences but schedule change occurs
    Given user has navigated to "Settings" page
    And user has navigated to "Notification Preferences" section
    And user has disabled "Email Notifications" toggle
    And user has disabled "In-App Notifications" toggle
    And notification preferences are saved with both options set to "OFF"
    When user verifies notification preferences
    Then "Email Notifications" toggle should show "OFF" state
    And "In-App Notifications" toggle should show "OFF" state
    And status text should read "Notifications Disabled"
    When user navigates to "Schedule" page
    And user modifies appointment time from "9:00 AM" to "10:00 AM"
    And user clicks "Save" button
    Then appointment should be saved successfully
    And message "Appointment updated" should be displayed
    When user checks notification bell icon within 1 minute
    Then no notification badge should appear on bell icon
    When user clicks notification bell icon
    Then empty state message "No notifications. You have disabled notifications in settings." should be displayed
    When user checks email inbox after 2 minutes
    Then no email notification should be received
    When user navigates to "Notification History" page
    Then page should show message "Notification preferences disabled. Recent schedule changes: [list of changes with timestamps]"

  @negative @regression @priority-medium
  Scenario: Notification system handles extremely long appointment descriptions without breaking display
    Given user has permission to create and modify appointments
    And system has character limit of 5000 characters for appointment descriptions
    And notification templates are configured to handle variable-length content
    When user creates new appointment with title "Test Appointment"
    And user enters description containing 4500 characters with special characters and line breaks
    Then appointment should be created successfully
    And long description should be saved
    When user modifies appointment time from "1:00 PM" to "2:00 PM"
    And user clicks "Save Changes" button
    Then appointment should be saved successfully
    And notification generation should begin
    When user clicks notification bell icon within 1 minute
    And user opens schedule change notification
    Then in-app notification should display truncated description with first 200 characters
    And notification should show "... [View Full Details]" link
    And no UI breaking or overflow issues should occur
    When user clicks "[View Full Details]" link
    Then modal should open displaying complete appointment description
    And all 4500 characters should be visible with scroll functionality
    When user checks email notification in inbox
    Then email should be received with properly formatted content
    And description should be truncated with link to view full details
    And email layout should not be broken
    When user verifies email in multiple email clients
    Then email should render properly in all tested clients
    And no broken formatting should occur
    And no missing content should occur