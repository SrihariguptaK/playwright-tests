Feature: Task Comment Security and Access Control
  As an Employee
  I want secure commenting functionality on tasks
  So that team communication is protected from security vulnerabilities and unauthorized access

  Background:
    Given user is authenticated as an employee
    And comment functionality is enabled

  @security @negative @priority-critical @xss @injection
  Scenario: Prevent Cross-Site Scripting injection in comment field
    Given user has access to task details page
    And browser developer tools are available for inspection
    When user navigates to task details page
    Then comment input field should be visible
    When user enters "<script>alert('XSS')</script>" in "Comment" field
    And user clicks "Save" button
    Then comment should be submitted to POST endpoint
    And script should NOT execute
    And comment should be displayed as plain text with HTML entities encoded
    And displayed comment should contain "&lt;script&gt;" text
    When user enters "<img src=x onerror=alert('XSS')>" in "Comment" field
    And user clicks "Save" button
    Then payload should be sanitized and rendered as harmless text
    And no script execution should occur
    When user enters "<svg onload=alert('XSS')>" in "Comment" field
    And user clicks "Save" button
    Then payload should be sanitized and rendered as harmless text
    And no script execution should occur
    When user enters "javascript:alert('XSS')" in "Comment" field
    And user clicks "Save" button
    Then payload should be sanitized and rendered as harmless text
    And no script execution should occur
    When user enters "<iframe src='javascript:alert(\"XSS\")'></iframe>" in "Comment" field
    And user clicks "Save" button
    Then payload should be sanitized and rendered as harmless text
    And no script execution should occur
    When different employee logs in and views the task with injected comments
    Then no scripts should execute for the second user
    And all malicious content should be neutralized
    When user inspects HTML source code of displayed comment
    Then all special characters should be HTML-encoded
    And Content-Security-Policy headers should be present
    And no malicious scripts should be stored in database in executable form
    And application should log security event for attempted XSS injection
    And all comments should remain viewable as safe text content

  @security @negative @priority-critical @authorization @access-control
  Scenario: Prevent unauthorized comment access and manipulation through broken access control
    Given multiple employee accounts exist with different access levels
    And tasks exist with varying access permissions
    And API testing tool is configured
    And valid authentication tokens are available for test accounts
    When user authenticates as "Employee A"
    And user identifies task with ID "123" that "Employee A" has legitimate access to
    Then "Employee A" should see task "123"
    And comment input field should be visible
    When user captures POST request to "/api/tasks/123/comments" endpoint
    Then request should show task ID and comment payload and authentication headers
    When user authenticates as "Employee B" who does NOT have access to task "123"
    And user obtains authentication token for "Employee B"
    Then "Employee B" should NOT see task "123" in their task list
    When user sends POST request to "/api/tasks/123/comments" with "Employee B" token
    Then API should return "403" status code
    And comment should NOT be created
    And error message should not reveal task existence
    When user attempts to post comment without authentication token
    Then API should return "401" status code
    And comment should NOT be created
    When user attempts IDOR attack with "Employee A" token by accessing task IDs "124, 125, 126"
    Then API should return "403" status code for unauthorized tasks
    And only tasks within "Employee A" scope should accept comments
    When user attempts to manipulate request by changing task ID in URL while keeping original task ID in request body
    Then API should validate URL parameter matches authorization scope
    And API should reject mismatched or unauthorized requests
    When user sends request with expired authentication token
    Then API should return "401" status code
    And token validation should fail
    And comment should NOT be created
    When user sends request with tampered authentication token
    Then API should return "401" status code
    And token validation should fail
    And comment should NOT be created
    And no unauthorized comments should be created in database
    And security events should be logged for all unauthorized access attempts
    And task access permissions should remain unchanged
    And audit trail should capture all failed authorization attempts with user details

  @security @negative @priority-critical @sql-injection @injection
  Scenario Outline: Prevent SQL injection in comment submission and retrieval
    Given database contains existing comments and task data
    And API endpoint POST "/api/tasks/{id}/comments" is accessible
    And SQL injection testing tools are configured
    When user navigates to task details page
    Then comment input field should be visible
    When user enters "<payload>" in "Comment" field
    And user clicks "Save" button
    Then payload should be treated as literal string
    And no additional comments should be displayed
    And no database error messages should be exposed
    And comments table should remain intact
    And command should not execute
    And response time should remain under "2" seconds
    And no SQL injection should occur
    And database integrity should be maintained
    And no tables should be dropped or modified
    And no sensitive data should be exposed through injection attempts
    And all SQL injection attempts should be logged as security events
    And comments table should contain only legitimate comment data

    Examples:
      | payload                                                          |
      | ' OR '1'='1                                                      |
      | '; DROP TABLE comments; --                                       |
      | ' UNION SELECT username, password, email FROM users --           |
      | '; WAITFOR DELAY '00:00:05'--                                    |
      | %27%20OR%20%271%27%3D%271                                        |

  @security @negative @priority-critical @sql-injection @injection
  Scenario: Prevent SQL injection through task ID parameter manipulation
    Given database contains existing comments and task data
    And API endpoint POST "/api/tasks/{id}/comments" is accessible
    When user intercepts API request
    And user injects SQL payload "123' OR '1'='1" in task ID parameter
    Then API should validate task ID format
    And API should reject non-numeric input
    And API should return "400" status code
    And no SQL error messages should be exposed in responses
    And no database structure should be exposed in responses
    And no query details should be exposed in responses