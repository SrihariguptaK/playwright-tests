Feature: Schedule Change Notification Security
  As a system administrator
  I want to ensure notification system security and data protection
  So that users' sensitive information remains protected from unauthorized access and malicious attacks

  Background:
    Given the notification system is operational
    And the schedule database is accessible

  @security @authorization @idor @priority-critical
  Scenario: Prevent unauthorized access to other users' notification history via IDOR
    Given user account "UserA" exists with valid session
    And user account "UserB" exists with valid session
    And "UserA" has received notifications with known notification IDs
    And API endpoint "/api/notifications" is accessible
    When "UserB" authenticates and obtains valid session token
    And "UserB" intercepts API request to "/api/notifications" and identifies "UserA" notification ID
    And "UserB" sends GET request to "/api/notifications/{UserA_notification_id}" using their session
    Then system should return "403" status code
    And error message "Forbidden" should be displayed
    And "UserB" should not see "UserA" notification content
    When "UserB" attempts to modify "user_id" parameter to "UserA" ID in request
    Then system should validate session ownership
    And system should reject request with "403" status code
    When "UserB" attempts sequential notification ID enumeration with increments
    Then system should consistently deny access to notifications not belonging to "UserB"
    And security logs should record all unauthorized access attempts
    And "UserB" should only access their own notifications

  @security @xss @injection @priority-critical
  Scenario Outline: Prevent Cross-Site Scripting in notification content display
    Given user account with schedule modification privileges exists
    And test user account to receive notifications exists
    When user creates schedule change with payload "<xss_payload>" in "<field_name>"
    And notification generation is triggered for the schedule change
    Then in-app notification should display payload as plain text
    And script tags should be HTML-encoded as "&lt;script&gt;"
    And no JavaScript execution should occur
    When email notification HTML source is checked
    Then email content should show encoded HTML entities
    And script should not execute when email is opened
    And Content-Security-Policy headers should be present in notification display pages
    And CSP headers should restrict inline script execution
    And user session cookies should remain secure
    And all notification content should be properly sanitized

    Examples:
      | xss_payload                                      | field_name           |
      | <script>alert(document.cookie)</script>Meeting   | schedule title       |
      | <img src=x onerror=alert(1)>                     | schedule description |
      | <svg/onload=alert(1)>                            | schedule description |
      | javascript:alert(1)                              | schedule description |
      | <iframe src="javascript:alert(1)">               | schedule title       |

  @security @information-disclosure @priority-high
  Scenario: Prevent information disclosure via notification API response leakage
    Given multiple user accounts with different schedules exist
    And API endpoint "/api/notifications/send" is accessible
    And test accounts with valid and invalid authentication tokens exist
    And network traffic interception tool is configured
    When API request is sent to "/api/notifications/send" with invalid notification ID
    Then generic error message "Resource not found" should be returned
    And system details should not be revealed in error message
    And valid ID patterns should not be exposed
    When API response headers are analyzed for sensitive information
    Then response headers should contain minimal information
    And "X-Powered-By" header should not be present
    And server version should not be exposed
    And internal IP addresses should not be disclosed
    When notification list is requested with pagination parameter "limit" set to "999999"
    Then system should enforce maximum pagination limits
    And only authorized user notifications should be returned
    And rate limiting should be applied
    When "/api/notifications/send" is accessed with missing authentication token
    Then "401" status code should be returned
    And generic "Unauthorized" error should be displayed
    And endpoint existence should not be revealed
    And user account validity should not be disclosed
    When response times are measured for valid versus invalid user IDs
    Then response times should be consistent regardless of user ID validity
    And user enumeration should be prevented
    When notification payload is inspected for PII of other participants
    Then notifications should contain only information relevant to authenticated user
    And other participants PII should not be exposed
    And no sensitive system information should be disclosed
    And error messages should remain generic and non-revealing
    And API responses should contain only authorized data