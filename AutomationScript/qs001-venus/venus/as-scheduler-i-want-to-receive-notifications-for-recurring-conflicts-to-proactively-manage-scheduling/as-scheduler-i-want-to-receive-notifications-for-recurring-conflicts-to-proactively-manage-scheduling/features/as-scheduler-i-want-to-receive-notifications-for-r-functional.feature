@functional @smoke
Feature: As Scheduler, I want to receive notifications for recurring conflicts to proactively manage scheduling - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Verify system identifies and notifies user of recurring conflicts based on historical data
    Given user is logged in as Scheduler with valid authentication token
    And historical conflict database contains at least 3 instances of the same conflict pattern within the last 30 days
    And user has default notification preferences enabled for recurring conflicts
    And system has completed analysis of historical conflict data within the last hour
    When navigate to the Scheduling Dashboard page
    Then dashboard loads successfully displaying the main scheduling interface with notification bell icon in top-right corner
    And trigger a scheduling conflict that matches an existing recurring pattern (e.g., schedule Resource A for Room 101 on Monday 9 AM when it has conflicted 3+ times previously)
    Then system analyzes the conflict against historical data and identifies it as a recurring conflict within 5 seconds
    And click on the notification bell icon in the top-right corner
    Then notification panel opens displaying a new notification with title 'Recurring Conflict Detected' and red indicator badge showing '1' unread notification
    And click on the recurring conflict notification to view details
    Then notification expands showing detailed information including: conflict type, resources involved (Resource A, Room 101), time slot (Monday 9 AM), frequency (occurred 4 times in last 30 days), and suggested actions
    And review the 'View Conflict History' link within the notification
    Then link is clickable and displays tooltip 'See all instances of this recurring conflict'
    And notification is marked as delivered in the system logs with timestamp
    And user remains on the Scheduling Dashboard with notification panel open
    And recurring conflict data is stored in user's notification history
    And system continues monitoring for additional recurring conflicts

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Verify user can customize notification preferences for recurring conflicts
    Given user is logged in as Scheduler with administrative privileges
    And user is on the main Scheduling Dashboard page
    And default notification settings are currently active (email and in-app notifications enabled)
    And browser supports local storage for saving user preferences
    When click on the user profile icon in the top-right corner and select 'Notification Preferences' from the dropdown menu
    Then notification Preferences page loads displaying sections for different notification types including 'Recurring Conflicts' section
    And locate the 'Recurring Conflicts' section and verify available options: 'In-App Notifications', 'Email Notifications', 'SMS Notifications', and 'Notification Frequency' dropdown
    Then all four options are visible with checkboxes for notification channels and dropdown showing options: 'Immediate', 'Daily Digest', 'Weekly Digest'
    And uncheck 'Email Notifications', keep 'In-App Notifications' checked, and select 'Daily Digest' from the Notification Frequency dropdown
    Then checkboxes update to reflect selections, dropdown displays 'Daily Digest' as selected value
    And scroll down and click the 'Save Preferences' button at the bottom of the page
    Then green success message appears at top of page stating 'Your notification preferences have been saved successfully' and page remains on Notification Preferences
    And navigate back to Scheduling Dashboard and trigger a recurring conflict scenario
    Then in-app notification appears in notification bell, but no email is sent immediately (verified by checking email inbox)
    And user preferences are saved to database with timestamp of last update
    And email notification channel is disabled for recurring conflicts for this user
    And in-app notifications remain active and will be delivered as daily digest
    And user remains logged in and on the Scheduling Dashboard

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Verify notification contains accurate details about recurring conflict frequency and pattern
    Given user is logged in as Scheduler
    And historical database contains exactly 5 instances of the same conflict: Resource 'Conference Room A' conflicting with 'Team Meeting' every Monday at 10:00 AM
    And system has successfully identified this as a recurring conflict pattern
    And user has in-app notifications enabled
    When trigger the 6th instance of the recurring conflict by scheduling 'Team Meeting' in 'Conference Room A' for Monday at 10:00 AM
    Then system detects the recurring pattern and generates a notification within 5 seconds
    And open the notification panel by clicking the notification bell icon
    Then notification panel displays the recurring conflict notification with title 'Recurring Conflict: Conference Room A - Team Meeting'
    And click on the notification to expand full details
    Then notification expands showing: Conflict Type: 'Resource Double Booking', Resources: 'Conference Room A, Team Meeting', Frequency: 'Occurs every Monday at 10:00 AM', Historical Occurrences: '6 times in the last 42 days', Last Occurrence: [current date]
    And click on the 'View Pattern Analysis' button within the notification
    Then modal window opens displaying a timeline chart showing all 6 occurrences with dates, a pattern summary stating 'Weekly recurrence on Mondays', and suggested resolution: 'Consider permanent booking or alternative resource'
    And notification data matches actual historical conflict records in database
    And frequency calculation is accurate (6 occurrences over 42 days)
    And pattern analysis is stored for future reference
    And user can access this notification from notification history

  @high @tc-func-004
  Scenario: TC-FUNC-004 - Verify user can take corrective action directly from recurring conflict notification
    Given user is logged in as Scheduler with edit permissions
    And a recurring conflict notification is present in the notification panel
    And the conflicting schedule items are still in draft or editable state
    And system has identified suggested alternative time slots
    When open the notification panel and click on the recurring conflict notification
    Then notification expands showing conflict details and action buttons: 'Resolve Conflict', 'View Alternatives', 'Ignore', and 'Set Reminder'
    And click the 'View Alternatives' button
    Then modal opens displaying 3-5 alternative time slots or resources that do not have conflicts, each with a 'Select' button
    And click 'Select' on the first alternative option (e.g., Tuesday 10:00 AM instead of Monday 10:00 AM)
    Then confirmation dialog appears asking 'Apply this change to resolve the recurring conflict?' with 'Confirm' and 'Cancel' buttons
    And click 'Confirm' button in the confirmation dialog
    Then schedule is updated with the new time slot, success message displays 'Conflict resolved successfully. Schedule updated to Tuesday 10:00 AM', and notification is marked as resolved with green checkmark
    And navigate to the Schedule Calendar view
    Then calendar displays the updated schedule with the meeting moved to Tuesday 10:00 AM, and no conflict indicator is shown
    And schedule database is updated with the new time slot
    And conflict is marked as resolved in the conflicts table
    And notification status changes to 'Resolved' with timestamp
    And audit log records the corrective action taken by the user

  @high @tc-func-005
  Scenario: TC-FUNC-005 - Verify GET /api/conflicts/recurring endpoint returns accurate recurring conflict data
    Given user is authenticated with valid JWT token
    And aPI endpoint GET /api/conflicts/recurring is accessible
    And database contains at least 3 different recurring conflict patterns for the authenticated user
    And test environment has network connectivity to API server
    When send GET request to /api/conflicts/recurring with valid authentication token in header
    Then aPI responds with HTTP status code 200 OK within 5 seconds
    And examine the response body JSON structure
    Then response contains array of recurring conflicts, each object includes fields: conflictId, conflictType, resources, frequency, occurrences, lastOccurrence, pattern, suggestedActions
    And verify the 'occurrences' count for the first conflict in the response
    Then occurrences count matches the actual number of instances in the historical database (e.g., if database shows 4 instances, API returns occurrences: 4)
    And check the 'pattern' field for pattern recognition accuracy
    Then pattern field contains accurate description such as 'Weekly on Mondays at 10:00 AM' or 'Every 3 days at 14:00' matching the actual historical pattern
    And verify response includes pagination metadata if more than 10 conflicts exist
    Then response includes metadata object with fields: totalCount, currentPage, pageSize, totalPages
    And aPI request is logged in system access logs with timestamp
    And no data is modified in the database (GET request is read-only)
    And authentication token remains valid for subsequent requests
    And response data can be used to populate UI notifications

  @medium @tc-func-006
  Scenario: TC-FUNC-006 - Verify multiple notification channels deliver recurring conflict alerts simultaneously
    Given user is logged in as Scheduler
    And user has enabled all notification channels: in-app, email, and SMS in preferences
    And user's email address and phone number are verified in the system
    And a recurring conflict pattern exists and is about to be triggered
    When trigger a recurring conflict by creating a schedule that matches an existing conflict pattern
    Then system identifies the recurring conflict within 5 seconds and initiates notification process
    And check the in-app notification bell icon
    Then notification bell shows red badge with '1' and clicking it displays the recurring conflict notification with full details
    And check the email inbox associated with the user account within 30 seconds
    Then email received with subject 'Recurring Conflict Alert: [Conflict Details]' containing conflict information, frequency data, and link to view in application
    And check the mobile phone for SMS message within 30 seconds
    Then sMS received with text: 'Recurring conflict detected: [Brief description]. View details at [short link]'
    And verify all three notifications contain consistent information about the same conflict
    Then conflict ID, resource names, time slot, and frequency information are identical across all three notification channels
    And all three notification channels have successfully delivered the alert
    And notification delivery status is logged for each channel with timestamps
    And user can access conflict details from any notification channel
    And notification preferences remain unchanged

