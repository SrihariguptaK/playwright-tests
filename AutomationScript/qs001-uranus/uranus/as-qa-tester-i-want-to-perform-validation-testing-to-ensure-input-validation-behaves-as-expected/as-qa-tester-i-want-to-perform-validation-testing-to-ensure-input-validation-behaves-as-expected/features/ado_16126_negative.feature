Feature: Input Validation Security and Error Handling
  As a QA Tester
  I want to perform comprehensive validation testing
  So that input validation behaves securely and prevents malicious attacks and data corruption

  @negative @regression @priority-high @security
  Scenario: Verify validation handles SQL injection attempts in text input fields
    Given test form with text input fields is loaded and accessible
    And user is logged in with standard user permissions
    And database monitoring tool is active to detect unauthorized queries
    And security testing is approved and documented in test plan
    And backup of test database is available for restoration if needed
    When user enters "'; DROP TABLE users; --" in "Username" field
    And user clicks "Submit" button
    Then client-side validation should reject input
    And error message "Username contains invalid characters" should be displayed
    And form should not submit
    When user bypasses client-side validation using browser console
    And user sends POST request with SQL injection payload directly to server
    Then server should return HTTP 400 Bad Request
    And error message "Invalid input detected" should be displayed
    And payload should be sanitized and not executed
    When user verifies database tables remain intact by querying "users" table
    Then database query should return expected results
    And "users" table should exist with all records intact
    And no data loss should have occurred
    When user checks server security logs for SQL injection attempt detection
    Then security log should contain entry with severity "CRITICAL"
    And log entry should include timestamp, source IP, and blocked SQL injection payload details
    When user tests SQL injection pattern "1' OR '1'='1" in "Username" field
    And user tests SQL injection pattern "admin'--" in "Username" field
    And user tests SQL injection pattern "'; SELECT * FROM users WHERE ''='" in "Username" field
    Then all SQL injection attempts should be blocked by server-side validation
    And appropriate error messages should be returned
    And no database queries should be executed
    And database integrity should be maintained with no unauthorized modifications
    And all SQL injection attempts should be logged in security audit trail
    And application should remain functional and secure after attack attempts
    And security incident report should be generated for review

  @negative @regression @priority-high @security
  Scenario Outline: Verify validation handles XSS attempts in input fields
    Given test form is loaded in browser with developer tools open
    And user has valid session and is authenticated
    And Content Security Policy headers are configured on server
    And XSS testing payloads are prepared and documented
    And test is conducted in isolated test environment
    When user enters "<xss_payload>" in "<field_name>" field
    And user submits form
    Then input should be sanitized
    And script tags should be encoded as "&lt;script&gt;"
    And no JavaScript alert should execute
    And validation error may display
    When user checks browser console for JavaScript errors or CSP violations
    Then console should show CSP violation warnings if script execution was attempted
    And no actual script execution should occur
    When user verifies stored data in database
    Then database query should show XSS payloads are stored as encoded strings
    And data should not contain executable code
    When user retrieves and displays stored data on another page
    Then data should display as plain text with visible encoded characters
    And no scripts should execute when data is rendered
    And no XSS vulnerabilities should be exploitable in validation inputs
    And all malicious scripts should be sanitized and encoded properly
    And application security posture should be maintained against XSS attacks
    And security test results should be documented with payload samples

    Examples:
      | xss_payload                              | field_name  |
      | <script>alert('XSS')</script>            | Name        |
      | <img src=x onerror=alert('XSS')>         | Description |
      | <iframe src="javascript:alert('XSS')">   | Name        |
      | <body onload=alert('XSS')>               | Description |

  @negative @regression @priority-high @security
  Scenario: Verify validation handles XSS attempts via URL parameters
    Given test form is loaded in browser with developer tools open
    And user has valid session and is authenticated
    And Content Security Policy headers are configured on server
    When user loads page with URL parameter "?name=<script>alert('XSS')</script>"
    Then URL parameter should be sanitized before rendering
    And script should not execute
    And page should display encoded value or validation error

  @negative @regression @priority-high @boundary
  Scenario: Verify validation handles extremely long input strings exceeding maximum length limits
    Given test form with defined maximum length constraints is loaded
    And test data generator tool is available to create long strings
    And browser performance monitoring is active
    And maximum field lengths are documented as Username 50 characters, Description 500 characters, Email 100 characters
    When user generates and enters 10000 character string in "Username" field with max 50 characters
    And user attempts to submit form
    Then client-side validation should display error "Username must not exceed 50 characters"
    And input should be truncated or rejected
    And form should not submit
    When user bypasses client-side validation
    And user sends POST request with 10000 character username directly to API
    Then server should return HTTP 400 Bad Request
    And error message "Username exceeds maximum length of 50 characters" should be displayed
    And data should not be saved
    When user enters exactly 51 characters in "Username" field
    Then validation error should display "Username must not exceed 50 characters (currently 51)"
    And character counter should show "51/50" in red
    When user enters 50 emoji characters in "Username" field
    Then validation should correctly count multi-byte characters
    And 50 character limit should be enforced regardless of byte size
    And appropriate error should display if exceeded
    When user monitors browser performance while handling extremely long input strings
    Then browser should remain responsive
    And no freezing or crashing should occur
    And validation should process within 200 milliseconds
    And no memory leaks should be detected
    When user verifies database field constraints prevent storage of oversized data
    Then database should reject insert or update with error
    And data integrity should be maintained
    And no truncation should occur silently
    And all maximum length constraints should be enforced at client and server levels
    And application should handle extreme input lengths gracefully without crashes
    And database integrity should be protected by field-level constraints
    And performance should remain acceptable even with boundary-testing inputs

  @negative @regression @priority-medium @internationalization
  Scenario Outline: Verify validation handles special characters and Unicode in input fields
    Given test form is loaded with various input field types
    And character encoding is set to UTF-8 in browser and server
    And test data set includes special characters "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
    And Unicode test data includes Chinese, Arabic, Emoji, and RTL text
    When user enters "<input_value>" in "<field_name>" field
    And user submits form
    Then validation should behave as "<expected_behavior>"
    And result message "<result_message>" should be displayed
    And character encoding should remain consistent throughout input, storage, and retrieval
    And no data corruption or encoding issues should occur with special character inputs

    Examples:
      | input_value       | field_name  | expected_behavior                          | result_message                                    |
      | !@#$%^&*()        | Username    | rejected                                   | Username can only contain letters and numbers     |
      | 测试用户名        | Name        | accepted                                   | success                                           |
      | 😀🎉💻           | Description | accepted and stored correctly              | success                                           |
      | مرحبا بك         | Address     | accepted with proper RTL text direction    | success                                           |
      | User123!@#中文😀 | Username    | rejected based on field validation rules   | Username can only contain letters and numbers     |

  @negative @regression @priority-medium @internationalization
  Scenario: Verify validation handles null byte and control characters in input fields
    Given test form is loaded with various input field types
    And character encoding is set to UTF-8 in browser and server
    When user enters null byte character "\0" in "Comments" field
    And user enters other control characters in "Comments" field
    Then validation should reject control characters
    And error message "Invalid characters detected" should be displayed
    And input should be sanitized before processing

  @negative @regression @priority-high @concurrency
  Scenario: Verify validation handles concurrent form submissions and race conditions
    Given test form is loaded in 3 browser tabs
    And user is logged in with same session across all tabs
    And network throttling is disabled for accurate timing
    And server-side duplicate submission prevention is implemented
    And database transaction isolation level is documented
    When user fills out identical form data in 3 separate browser tabs with same user session
    Then all 3 tabs should show form filled with identical data
    And validation should pass in all tabs
    And submit buttons should be enabled
    When user clicks "Submit" button in all 3 tabs simultaneously within 100 milliseconds
    Then only one submission should be processed successfully
    And other submissions should be rejected with error "Duplicate submission detected"
    When user rapidly clicks "Submit" button 10 times in quick succession
    Then submit button should be disabled after first click
    And only one submission should be processed
    And subsequent clicks should be ignored
    And loading indicator should display
    When user verifies database to check for duplicate records from concurrent submissions
    Then database should contain only one record from the submission
    And no duplicate entries should exist
    And transaction logs should show proper locking
    When user checks server logs for concurrent request handling
    Then logs should show multiple requests received
    And duplicate detection should be triggered
    And only one request should be processed
    And others should be rejected with appropriate status codes
    When user submits form and immediately submits again before first request completes
    Then second submission should be queued or rejected
    And user should see message "Submission in progress"
    And no race condition should create duplicate data
    And no duplicate records should be created from concurrent submissions
    And application should handle race conditions gracefully without data corruption
    And user should receive clear feedback about submission status
    And database integrity should be maintained under concurrent access scenarios

  @negative @regression @priority-high @authentication
  Scenario: Verify validation handles expired sessions during form submission
    Given user is logged in with active session
    And test form is loaded and filled with valid data
    And session timeout is configured to 30 minutes
    And session management mechanism is documented
    And test environment allows manual session manipulation
    When user fills out form with valid data
    And user manually expires session by clearing session cookie
    Then session should be expired
    And user authentication token should be invalid
    When user clicks "Submit" button to attempt form submission with expired session
    Then server should return HTTP 401 Unauthorized
    And error message "Your session has expired. Please log in again." should be displayed
    And form data should be preserved
    When user verifies redirect to login page
    Then user should be redirected to "/login?returnUrl=/form-page"
    And login page should display with message about session expiration
    When user logs in again with valid credentials
    Then user should be redirected back to form page
    And previously entered data should be restored from session storage or cache
    And no data should be submitted with expired or invalid authentication
    And user should receive clear guidance to re-authenticate
    And form data should be preserved and recoverable after re-authentication
    And security should be maintained by rejecting unauthenticated requests

  @negative @regression @priority-high @authentication
  Scenario: Verify validation handles invalid authentication token during form submission
    Given user is logged in with active session
    And test form is loaded and filled with valid data
    When user modifies auth token in browser storage to invalid value
    And user submits form
    Then server should reject request with HTTP 401
    And error message "Authentication failed" should be displayed
    And user should be prompted to log in again
    When user verifies form data preservation
    Then form data should be preserved in browser local storage or session storage
    And data should be restored after successful re-authentication

  @negative @regression @priority-high @network
  Scenario: Verify validation handles network failures during form submission
    Given test form is loaded with valid data entered
    And browser developer tools network tab is open
    And network throttling capability is available in browser
    And server timeout settings are documented as 30 second timeout
    And error handling mechanism for network failures is implemented
    When user fills form with valid data
    And user enables "Offline" mode in browser network settings
    And user clicks "Submit" button
    Then client-side should detect no network connection
    And error message "No internet connection. Please check your network and try again." should be displayed
    And form data should be preserved
    When user re-enables network
    And user sets network throttling to "Slow 3G"
    And user submits form
    Then loading indicator should display
    And after 30 seconds timeout should occur
    And error message "Request timed out. Please try again." should appear
    And submit button should be re-enabled
    When user uses browser developer tools to block specific API endpoint
    And user submits form
    Then request should fail with network error
    And user should see message "Unable to submit form. Please try again later."
    And form should remain editable with data intact
    When user verifies form data retention after network failure
    Then all form field values should remain populated
    And user should be able to click "Submit" again without re-entering data
    And validation state should be preserved
    When user restores connection after network failure
    And user clicks "Submit" again
    Then form should submit successfully on retry
    And data should be saved correctly
    And success message should display
    And no duplicate submissions should occur
    And application should handle network failures gracefully without data loss
    And user should receive clear actionable error messages for network issues
    And form data should be preserved for retry attempts
    And no partial data should be saved during network failures

  @negative @regression @priority-high @network
  Scenario: Verify validation handles server errors during form submission
    Given test form is loaded with valid data entered
    And browser developer tools network tab is open
    When user simulates server returning HTTP 500 Internal Server Error during validation processing
    And user submits form
    Then error message "An error occurred while processing your request. Please try again." should be displayed
    And technical error details should not be exposed to user
    And form data should remain intact