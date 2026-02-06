Feature: Schedule Change Notification Security
  As a system administrator
  I want to ensure the notification system is secure against unauthorized access and malicious attacks
  So that users' sensitive schedule information remains protected and notifications are delivered safely

  @security @priority-critical @idor @negative
  Scenario: Prevent unauthorized access to other users' notifications through IDOR vulnerability
    Given user account "User A" exists in the system
    And user account "User B" exists in the system
    And both users have active schedules with recent changes
    And both users are authenticated
    And notification IDs are observable in API requests
    When "User A" logs in to the system
    And "User A" triggers a schedule change to generate a notification
    Then "User A" should receive notification with unique notification ID
    When user captures the API request to "/api/notifications/send" endpoint
    Then API request structure should be documented showing notification ID parameter
    When "User B" logs in to the system
    And "User B" triggers a schedule change to generate a notification
    Then "User B" should receive notification with different notification ID
    When "User B" attempts to access "User A" notification by manipulating notification ID parameter
    Then system should return "403" status code
    And unauthorized access should be prevented
    When user attempts sequential notification ID enumeration
    Then all unauthorized access attempts should be blocked with proper error codes
    And security events should be logged in audit trail
    When user verifies notification content in email and in-app alerts
    Then notification should contain only authenticated user's own schedule information
    And no data leakage from other users should be present
    And all unauthorized access attempts should be logged in security audit trail
    And no sensitive information from other users should be exposed
    And user sessions should remain valid and unaffected

  @security @priority-critical @authentication @negative
  Scenario: Enforce proper authentication on notification API endpoint and prevent unauthorized access
    Given notification API endpoint "/api/notifications/send" is accessible
    And valid user account exists with active schedule
    And authentication mechanism is implemented
    And test environment allows API testing tools
    When user attempts to access "/api/notifications/send" endpoint without authentication credentials
    Then system should return "401" status code
    And access to the endpoint should be denied
    When user attempts to access the endpoint with expired authentication token
    Then system should return "401" status code
    And error message should indicate token expiration
    When user attempts to access the endpoint with malformed authentication token
    Then system should return "401" status code
    And invalid token attempt should be logged as security event
    When user attempts to replay valid authentication token from previous session after logout
    Then system should reject the token
    And system should return "401" status code
    And token invalidation on logout should be confirmed
    When user attempts authentication bypass by manipulating request headers
    Then all bypass attempts should fail with "401" status code
    When user verifies notification viewing endpoints require authentication
    Then only authenticated users should view their own notifications
    And cross-user access should be prevented
    And all unauthorized access attempts should be logged with timestamps and source IPs
    And no notifications should be sent or accessed without valid authentication
    And system security posture should remain intact

  @security @priority-critical @xss @injection @negative
  Scenario Outline: Protect notification system against XSS injection attacks in schedule content
    Given user account with permission to create schedule entries exists
    And notification system is active and configured for email and in-app alerts
    And test environment allows schedule modification
    And user has access to view rendered notifications in both formats
    When user creates schedule entry with "<payload>" in "<field>" field
    Then system should accept the input and store the schedule entry
    When user modifies the schedule entry to trigger a notification
    And user observes the email notification content
    Then email notification should display sanitized content
    And script tags should be encoded or stripped
    And script should not execute
    When user views the in-app notification
    Then in-app notification should render safe content without executing JavaScript
    And no alert popup should appear
    And notification should be properly sanitized in the UI
    When user verifies notification API responses include security headers
    Then "Content-Type" header should be "application/json"
    And "X-Content-Type-Options" header should be "nosniff"
    And "X-XSS-Protection" header should be present
    And all security headers should prevent MIME-type sniffing
    And no malicious scripts should be executed in any notification context
    And schedule data should remain intact with sanitized content
    And security logs should capture input validation events

    Examples:
      | field       | payload                                      |
      | title       | <script>alert("XSS")</script>Meeting Title   |
      | description | <img src=x onerror=alert("XSS")>             |
      | description | <svg/onload=alert("XSS")>                    |
      | title       | <body onload=alert("XSS")>                   |
      | description | <iframe src="javascript:alert('XSS')">       |

  @security @priority-critical @xss @stored @negative
  Scenario: Verify protection against stored XSS attacks across multiple users
    Given user account "User A" with permission to create schedule entries exists
    And user account "User B" exists in the system
    And notification system is active and configured
    When "User A" creates schedule entry with "<script>alert('XSS')</script>Malicious Meeting" in "title" field
    And "User A" modifies the schedule entry to trigger a notification
    And "User B" logs in to the system
    And "User B" views the notification
    Then "User B" should receive sanitized notification
    And no script execution should occur
    And stored XSS protection should be confirmed