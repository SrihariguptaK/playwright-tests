Feature: Attendance Anomaly Alert System - Negative Scenarios
  As a User
  I want the attendance alert system to handle edge cases and failures gracefully
  So that alert integrity is maintained and system remains reliable under adverse conditions

  @negative @regression @priority-high
  Scenario: System prevents duplicate alerts for same anomaly within threshold period
    Given user is logged into the system
    And user has arrived late at "9:20 AM" which is "20" minutes late
    And system has detected the late arrival anomaly at "9:21 AM"
    And alert has been sent to user and manager
    And alert delivery is confirmed for both recipients
    And system continues monitoring attendance data every "1" minute
    When system runs attendance analysis again at "9:22 AM"
    And system detects the same late arrival anomaly
    Then system should identify that alert for this anomaly has already been sent within last "24" hours
    And system should check alert deduplication rules and alert history
    And system should find existing alert record with status "Sent" and timestamp "9:21 AM"
    And no new alert should be generated or sent to user or manager
    And no new email notification should be sent
    And no new in-app notification should appear
    And notification count should remain unchanged for both user and manager
    And alert database should show only "1" alert record for this anomaly
    And API logs at "/api/attendance/alerts" should show deduplication logic was triggered
    And API logs should contain message "Alert suppressed - duplicate anomaly within threshold period"
    When system runs analysis again at "9:25 AM" and "9:30 AM"
    Then no additional alerts should be generated for the same late arrival anomaly
    And deduplication should remain effective throughout the day

  @negative @regression @priority-high
  Scenario: System handles email service failure gracefully with retry mechanism
    Given user has arrived late at "9:25 AM" triggering a late arrival anomaly
    And system has detected the anomaly and created alert record in database
    And email service is down or unreachable
    And in-app notification service is operational
    And system is configured to retry failed email deliveries
    When system attempts to send email notification to "user@company.com"
    Then email delivery should fail with error "SMTP connection timeout"
    And error should be logged in system logs with timestamp and error details
    When system attempts to send email notification to "manager@company.com"
    Then email delivery should fail with error "Email service unavailable"
    And failure should be logged separately for manager notification
    And system should still deliver in-app notifications despite email failure
    And in-app notifications should be successfully delivered to both user and manager
    And notifications should appear with status "Delivered (In-App Only)"
    And warning icon should indicate email delivery pending
    When user checks alert record status via "/api/attendance/alerts/{alertId}"
    Then alert status should show "Partially Delivered"
    And status details should show "In-app: Success, Email: Failed - Retry scheduled"
    And retry count should be "0"
    And next retry should be scheduled in "5" minutes
    When user waits for "5" minutes for automatic retry attempt
    And email service remains down
    Then system should attempt email delivery again
    And delivery should fail again
    And retry count should increment to "1"
    And next retry should be scheduled in "15" minutes
    When email service is restored
    And system waits for next retry attempt
    Then system should successfully deliver emails on retry attempt
    And alert status should update to "Fully Delivered"
    And email delivery timestamp should be recorded
    And retry count should show final value of "2"

  @negative @regression @priority-high
  Scenario: System rejects unauthorized alert acknowledgment attempt
    Given user "john.doe@company.com" has received an attendance anomaly alert for late arrival
    And alert is visible in user notification center with status "Unacknowledged"
    And user "jane.smith@company.com" is logged into the system with standard user permissions
    And user "jane.smith@company.com" is not the alert recipient's manager
    And user "jane.smith@company.com" has no administrative privileges
    When user "jane.smith@company.com" navigates to alert detail page by entering URL "/attendance/alerts/ALT-2024-001234"
    Then system should display error page with message "Access Denied: You do not have permission to view this alert"
    And HTTP status code "403" should be returned
    When user "jane.smith@company.com" attempts to acknowledge alert by sending POST request to "/api/attendance/alerts/ALT-2024-001234/acknowledge"
    Then API should return error response with status code "403"
    And response JSON body should contain error "Unauthorized"
    And response message should be "You are not authorized to acknowledge this alert"
    And response should include alert ID "ALT-2024-001234"
    And alert status should remain "Unacknowledged" in database
    And no acknowledgment timestamp should be recorded
    And no acknowledging user ID should be set
    And security log should contain entry "Unauthorized alert acknowledgment attempt"
    And security log should include user "jane.smith@company.com"
    And security log should include alert "ALT-2024-001234"
    And security log should include owner "john.doe@company.com"
    And security log should show action "Blocked"
    When user "john.doe@company.com" logs in and views the alert
    Then alert should show status "Unacknowledged"
    And user "john.doe@company.com" should be able to successfully acknowledge the alert

  @negative @regression @priority-high
  Scenario: System escalates alert to fallback recipient when manager is not assigned
    Given user account exists with user ID "USR-12345"
    And user has no manager assigned in organizational hierarchy
    And manager_id field is "NULL" for this user
    And user arrives late at "9:30 AM" triggering a late arrival anomaly
    And alert configuration requires notification to both user and manager
    When system detects late arrival anomaly for user "USR-12345"
    And system initiates alert generation process
    Then alert record should be created in database with anomaly details
    And alert should include user ID and detection timestamp
    When system queries organizational hierarchy to retrieve manager information
    Then query should return "NULL" for manager_id field
    And system should log warning "No manager assigned for user USR-12345"
    When system attempts to send alert notification to the user
    Then alert should be successfully sent to user via email and in-app notification
    And alert should include all anomaly details and suggested actions
    When system handles missing manager by escalating to fallback recipient
    Then alert should be sent to fallback recipient "hr@company.com"
    And alert should include additional context "Alert escalated - No manager assigned for employee [User Name] (USR-12345)"
    And email subject should include tag "[No Manager Assigned]"
    And alert status should show "Delivered with Escalation"
    And delivery log should show user notification "Success"
    And delivery log should show manager notification "Escalated to HR (no manager assigned)"
    And escalation timestamp should be recorded
    And system log should show warning level entry "Manager notification escalated due to missing manager assignment"
    And log should include user "USR-12345"
    And log should include alert "ALT-2024-001235"
    And log should show escalated to "HR Department"
    And no system errors or exceptions should be thrown

  @negative @regression @priority-medium
  Scenario: System does not trigger false positive alerts within acceptable thresholds
    Given user expected arrival time is "9:00 AM"
    And grace period of "15" minutes is configured
    And user arrives at "9:12 AM" which is "12" minutes after expected time
    And arrival time is within grace period
    And system is configured to trigger late arrival alerts only after "15" minute threshold
    And attendance monitoring system is running and analyzing data
    When user checks in at "9:12 AM" using the attendance system
    Then system should record check-in time as "9:12 AM"
    And system should calculate delay as "12" minutes from expected arrival time
    When system analyzes attendance data
    And system compares delay "12" minutes against threshold "15" minutes
    Then system should determine that "12" minutes is within acceptable threshold
    And system should not classify this as an anomaly
    And no alert should be generated in the alerts database
    And no new alert record should be created
    And database query for alerts on this date should return empty result
    And no attendance anomaly alert should appear in user notification center
    And notification count should remain at previous value
    And no alert should be sent to manager regarding this arrival time
    And manager notification center should show no new attendance alerts
    When user reviews system logs at "/api/attendance/analysis/logs"
    Then log entry should show "Attendance analyzed"
    And log should include user "USR-12345"
    And log should show arrival "9:12 AM"
    And log should show delay "12 minutes"
    And log should show status "Within threshold"
    And log should show action "No alert generated"

  @negative @regression @priority-high
  Scenario: System handles database connection failure with message queue fallback
    Given user has triggered an attendance anomaly with early departure at "3:45 PM"
    And expected departure time is "5:00 PM"
    And system has detected the anomaly
    And system is in the process of generating alert
    And system has message queue configured for resilience
    And alert generation process is at database write stage
    When system detects early departure anomaly
    And system prepares alert data with alert ID "ALT-2024-001236"
    And alert data includes user "USR-12345"
    And alert data includes type "Early Departure"
    And alert data includes time "3:45 PM"
    And alert data includes expected time "5:00 PM"
    Then alert data should be prepared in memory with all required fields
    When system attempts to write alert record to "attendance_alerts" database table
    And database connection becomes unavailable
    Then database write operation should fail with error "Connection timeout"
    And exception should be caught by error handling layer
    And system error handler should trigger fallback mechanism
    And alert data should be serialized and written to message queue
    And alert status should be set to "Pending Database Write"
    And error should be logged "Alert generation failed - Database unavailable - Alert queued for retry: ALT-2024-001236"
    And no notification should be sent to user or manager
    And no email or in-app notification should be sent
    And system should prevent partial alert delivery to maintain data consistency
    When database connection is restored after "3" minutes
    Then system should detect database availability
    And automatic retry mechanism should be triggered
    And system should process queued alert from temporary storage
    And alert record should be successfully written to database
    And original timestamp should be preserved
    And alert status should change from "Pending Database Write" to "Sent"
    And notifications should be sent to user and manager
    And alert record should contain all original data
    And alert should show correct anomaly detection time "3:45 PM"
    And alert should show correct user ID "USR-12345"
    And alert should include complete anomaly details
    And no data corruption or loss should occur