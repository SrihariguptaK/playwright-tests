Feature: Schedule Change Notification Error Handling
  As a User
  I want the system to handle notification failures gracefully
  So that I am still informed about schedule changes even when technical issues occur

  Background:
    Given notification service is configured and active
    And system has error handling and logging enabled

  @negative @regression @priority-high
  Scenario: System handles notification failure when user email address is invalid
    Given user account exists with email address "testuser@invalid@domain.com"
    And user has scheduled appointment at "3:00 PM"
    When administrator modifies user schedule from "3:00 PM" to "4:00 PM"
    And administrator clicks "Save Changes" button
    Then schedule change should be saved successfully
    And "Schedule updated" message should be displayed
    And notification service logs should show email attempt failed with error "Invalid email address format"
    And error should be logged with timestamp and user ID and notification ID
    When user logs in and checks notification bell icon
    Then in-app notification should display schedule change from "3:00 PM" to "4:00 PM"
    And warning banner "Email notification could not be delivered. Please update your email address." should be displayed
    When user navigates to notification history page
    Then notification status should show "Partially Delivered - In-app: Success, Email: Failed (Invalid Address)"
    And retry option should be available

  @negative @regression @priority-high
  Scenario: System prevents notification acknowledgment without valid authentication
    Given user is logged in
    And user has unacknowledged schedule change notification in notification center
    And "Acknowledge" button is enabled
    When user deletes authentication session token from browser storage
    And user clicks "Acknowledge" button without refreshing page
    Then error message "Session expired. Please log in again to acknowledge notification." should be displayed
    And user should be redirected to login page
    When user logs in with valid credentials
    And user navigates to notification center
    Then notification should still appear as "Unacknowledged"
    When user clicks "Acknowledge" button with valid authentication
    Then notification status should change to "Acknowledged"
    And confirmation message "Notification acknowledged successfully" should be displayed

  @negative @regression @priority-high
  Scenario: System handles notification service downtime during schedule change
    Given user has scheduled appointment at "10:00 AM"
    And notification service is stopped or unavailable
    When system health dashboard is checked
    Then notification service status should show "Unavailable"
    When administrator modifies user schedule from "10:00 AM" to "11:00 AM"
    And administrator clicks "Save Changes" button
    Then schedule change should be saved successfully in database
    And "Schedule updated" message should be displayed
    And warning "Notification service temporarily unavailable" may be shown
    And notification should be queued for retry with status "Pending - Service Unavailable"
    And retry attempts should be scheduled
    And error should be logged with timestamp and details
    When user checks notifications within 1 minute
    Then no notification should be delivered to user
    And notification bell icon should show no new notifications
    And email inbox should have no new messages
    When notification service is restarted
    And retry mechanism processes queued notifications
    Then notification service status should change to "Available"
    And queued notification should be delivered within 2 to 3 minutes
    When user checks in-app notifications and email inbox
    Then user should receive both email and in-app notification about schedule change
    And notification should include note "Delayed delivery due to system maintenance"
    And notification history should show delivery timestamp and delay reason

  @negative @regression @priority-medium
  Scenario: System prevents notification spam from multiple rapid schedule changes
    Given user has scheduled appointment for "next Monday at 9:00 AM"
    And system has rate limiting or notification batching configured
    And administrator has permission to make schedule changes
    When administrator accesses user appointment scheduled for "next Monday at 9:00 AM"
    Then appointment details page should display current time as "9:00 AM"
    When administrator rapidly changes appointment time from "9:00 AM" to "9:30 AM"
    And administrator changes appointment time from "9:30 AM" to "10:00 AM"
    And administrator changes appointment time from "10:00 AM" to "10:30 AM"
    And administrator changes appointment time from "10:30 AM" to "11:00 AM"
    And administrator changes appointment time from "11:00 AM" to "11:30 AM" within 30 seconds
    Then all 5 schedule changes should be saved successfully
    And final appointment time should show "11:30 AM"
    When user checks email inbox within 2 minutes
    Then user should receive only one consolidated email notification
    And email should state "Your appointment has been changed multiple times. Final time: 11:30 AM (originally 9:00 AM)"
    When user checks in-app notification center
    Then single notification should show message "Schedule updated multiple times. Latest change: 11:30 AM"
    And expandable section should show change history
    When notification service logs are reviewed
    Then logs should show system detected multiple rapid changes
    And logs should show batching logic was applied
    And log entry should show "Rate limit applied: 5 changes batched into 1 notification"

  @negative @regression @priority-high
  Scenario: System handles notification when user account is disabled after schedule change
    Given user account exists with active status
    And user has scheduled appointment at "2:00 PM"
    When administrator modifies user schedule from "2:00 PM" to "3:00 PM"
    And schedule change is saved
    Then notification should be queued for delivery
    When administrator disables user account before notification delivery
    Then user account status should change to "Disabled"
    And user should be logged out if currently active
    And account should no longer be accessible
    When notification service attempts delivery of queued notification
    Then notification service should detect user account is disabled
    And error "Cannot deliver notification - User account disabled" should be logged
    And notification should be marked as "Undeliverable"
    When notification logs and error tracking system are checked
    Then error log should show entry with notification ID and user ID
    And notification status should be "Failed - Account Disabled"
    And no email should be sent
    When user account is re-enabled
    Then user account status should change to "Active"
    And system should not automatically retry old failed notifications
    And notification should remain in "Failed" state with reason logged

  @negative @regression @priority-medium
  Scenario Outline: System handles malformed schedule change data in notification payload
    Given notification generation logic can be tested with corrupted data
    And error handling and validation are implemented in notification service
    When schedule change record is created with "<data_condition>"
    And notification generation process is triggered
    Then notification service should detect "<validation_error>"
    And error "<error_message>" should be logged
    And no notification should be sent to user
    And system should prevent sending incomplete or misleading information

    Examples:
      | data_condition                          | validation_error        | error_message                                                    |
      | null original_time and null new_time    | missing required fields | Cannot generate notification - Missing required fields           |
      | empty appointment description           | missing required fields | Cannot generate notification - Missing required fields           |

  @negative @regression @priority-medium
  Scenario Outline: System sanitizes malicious content in notification payload
    Given notification service has content sanitization enabled
    When schedule change is created with appointment description "<malicious_content>"
    And notification generation process is triggered
    Then notification service should sanitize and escape special characters
    And notification should be generated with sanitized content
    And no script execution or SQL injection should occur
    When delivered notification content is verified
    Then email and in-app notification should display content as "<sanitized_display>"
    And no code execution should occur
    And content should be safely rendered

    Examples:
      | malicious_content              | sanitized_display                      |
      | <script>alert("XSS")</script>  | &lt;script&gt;alert("XSS")&lt;/script&gt; |
      | DROP TABLE users;--            | DROP TABLE users;--                    |
      | '; DELETE FROM appointments;-- | '; DELETE FROM appointments;--         |