Feature: Input Validation Security Testing
  As a QA Tester
  I want to perform comprehensive security validation testing
  So that the application is protected against injection attacks, tampering, DoS, and information disclosure

  Background:
    Given application input forms are accessible and functional
    And both client-side and server-side validation are implemented
    And test environment database contains sample data
    And security testing tools are configured

  @security @injection @priority-critical @negative
  Scenario: SQL Injection prevention in input validation fields
    Given all input fields in the application are identified and documented
    When user injects SQL payload "' OR '1'='1" in input field
    Then client-side validation should block malicious input immediately
    And clear error message should be displayed
    And server-side validation should reject payload with "400" status code
    And sanitized error message should be returned
    And no SQL query execution should occur
    And database should remain unchanged

  @security @injection @priority-critical @negative
  Scenario Outline: SQL Injection attack prevention with multiple payloads
    Given all input fields in the application are identified
    When user injects SQL payload "<sql_payload>" in "<field_name>" field
    Then client-side validation should block malicious input immediately
    And server-side validation should reject payload with "400" status code
    And no SQL query execution should occur
    And database should remain unchanged
    And security event should be logged for monitoring

    Examples:
      | field_name    | sql_payload                                              |
      | username      | ' OR '1'='1                                              |
      | email         | '; DROP TABLE users--                                    |
      | search        | ' UNION SELECT NULL, username, password FROM users--     |
      | comment       | 1' AND '1'='1                                            |

  @security @xss @priority-critical @negative
  Scenario Outline: XSS attack prevention in input validation fields
    Given all input fields in the application are identified
    When user injects XSS payload "<xss_payload>" in "<field_name>" field
    Then input should be sanitized on both client and server side
    And script tags should be escaped or removed
    And no JavaScript execution should occur
    And output should be HTML-encoded when displayed

    Examples:
      | field_name | xss_payload                           |
      | comment    | <script>alert('XSS')</script>         |
      | bio        | <img src=x onerror=alert('XSS')>      |
      | message    | <svg/onload=alert('XSS')>             |
      | title      | <iframe src=javascript:alert('XSS')>  |

  @security @injection @priority-critical @negative
  Scenario: Bypass client-side validation using browser tools
    Given client-side validation is active on input forms
    When user bypasses client-side validation using browser developer tools
    And user sends malicious SQL payload "'; DROP TABLE users--" directly to server
    Then server-side validation should independently catch malicious payload
    And server should reject request with "400" status code
    And safe error message should be returned
    And security event should be logged for monitoring

  @security @injection @priority-critical @negative
  Scenario Outline: Encoded and obfuscated injection payload detection
    Given validation logic is configured to decode input before validation
    When user injects encoded payload "<encoded_payload>" with encoding type "<encoding_type>"
    Then all encoding variations should be detected and blocked
    And validation should decode input before validation check
    And malicious payload should be rejected
    And security event should be logged

    Examples:
      | encoding_type    | encoded_payload                                    |
      | URL-encoded      | %27%20OR%20%271%27%3D%271                          |
      | Unicode-encoded  | \u0027\u0020OR\u0020\u0027\u0031\u0027\u003D\u0027 |
      | Double-encoded   | %2527%2520OR%2520%25271%2527%253D%25271            |
      | Hex-encoded      | 0x27204F522027312733442731                         |

  @security @information-disclosure @priority-high @negative
  Scenario: Error messages do not reveal system information
    Given malicious payloads are submitted to input fields
    When validation errors occur
    Then generic user-friendly error messages should be displayed
    And no database structure information should be exposed
    And no technology stack details should be revealed
    And no file paths should be visible
    And no stack traces should be exposed to end users

  @security @tampering @priority-critical @negative
  Scenario: Server-side validation with JavaScript disabled
    Given validation constraints are documented for all input fields
    When user disables JavaScript in browser
    And user attempts to submit form with invalid data "invalid@@@email" in "Email" field
    Then server-side validation should independently reject invalid input
    And appropriate error message should be displayed
    And no data should be processed or stored

  @security @tampering @priority-critical @negative
  Scenario: Input tampering using HTTP proxy interception
    Given HTTP proxy tool is configured to intercept requests
    And user submits valid form with "john@example.com" in "Email" field
    When user intercepts request using HTTP proxy
    And user modifies "Email" field value to "malicious<script>alert(1)</script>@test.com"
    And modified request is sent to server
    Then server should validate all input independently
    And modified data should be rejected
    And tampering attempt should be logged
    And original validation constraints should be enforced

  @security @tampering @priority-critical @edge
  Scenario Outline: Boundary value manipulation detection
    Given validation constraints define maximum length of "<max_length>" for "<field_name>" field
    When user submits input exceeding boundary with "<test_value>" in "<field_name>" field
    Then server-side validation should catch boundary violation
    And buffer overflow protection should be active
    And input should be rejected with appropriate error message

    Examples:
      | field_name | max_length | test_value                                                    |
      | username   | 50         | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |
      | age        | 3          | -999                                                          |
      | amount     | 10         | 99999999999                                                   |
      | zipcode    | 10         | abcd!@#$%^                                                    |

  @security @tampering @priority-critical @negative
  Scenario: Hidden form field injection for privilege escalation
    Given user has standard user privileges
    When user intercepts form submission using HTTP proxy
    And user injects hidden field "isAdmin" with value "true"
    And user injects hidden field "role" with value "administrator"
    And modified request is sent to server
    Then server should ignore unexpected parameters
    And only whitelisted fields should be processed
    And no privilege escalation should occur
    And security event should be logged

  @security @tampering @priority-high @negative
  Scenario: Parameter pollution attack prevention
    Given form contains "amount" field with value "10"
    When user submits request with duplicate parameter "amount" with value "10000"
    Then application should handle parameter pollution securely
    And application should use first or last value consistently
    Or application should reject ambiguous request
    And no unintended behavior should occur
    And security event should be logged

  @security @dos @priority-high @negative
  Scenario Outline: Large payload size limit enforcement
    Given application has maximum payload size limit configured
    And performance monitoring tools are active
    When user submits extremely large input payload of "<payload_size>" to validation endpoint
    Then application should enforce maximum payload size limits
    And request should be rejected with "413" status code
    And server resources should remain stable
    And response time should stay within "3" seconds threshold

    Examples:
      | payload_size |
      | 10MB         |
      | 50MB         |
      | 100MB        |

  @security @dos @priority-high @negative
  Scenario: Regular Expression Denial of Service prevention
    Given regex validation patterns have complexity limits and timeouts
    And baseline CPU usage is documented
    When user submits input "(a+)+b" with string "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" designed for catastrophic backtracking
    Then validation should complete within "1" second or timeout gracefully
    And CPU usage should not spike above "80" percent
    And no application hang should occur
    And no application crash should occur

  @security @dos @priority-high @negative
  Scenario: Rate limiting and throttling mechanism validation
    Given rate limiting is configured for "100" requests per minute per IP
    When user submits "1000" rapid-fire validation requests per second from single IP
    Then rate limiting should be enforced
    And excess requests should receive "429" status code
    And legitimate users should not be affected
    And IP-based throttling should activate

  @security @dos @priority-high @negative
  Scenario Outline: Excessive special characters handling
    Given input parsing is configured with efficiency and memory bounds
    When user submits input containing "<character_count>" "<character_type>" characters
    Then input parsing should remain efficient and bounded
    And memory usage should remain stable
    And no memory leaks should be detected
    And invalid characters should be handled gracefully without crashes

    Examples:
      | character_type      | character_count |
      | special characters  | 10000           |
      | Unicode characters  | 50000           |
      | null bytes          | 1000            |

  @security @dos @priority-high @negative
  Scenario: Recursive structure and circular reference detection
    Given recursive depth limit is enforced at "10" levels maximum
    When user submits JSON input with circular references
    Or user submits XML input with recursive structures exceeding "15" levels
    Then circular references should be detected and rejected
    And validation should terminate within timeout period
    And no infinite loops should occur
    And appropriate error message should be displayed

  @security @information-disclosure @priority-high @negative
  Scenario: Generic error messages without technical details
    Given various invalid inputs are prepared for testing
    When user submits invalid input "invalid@@@data" to validation endpoint
    Then error message should be generic and user-friendly
    And no stack traces should be exposed
    And no file paths should be revealed
    And no database errors should be visible
    And no technology stack details should be disclosed
    And HTTP headers should not reveal server versions

  @security @information-disclosure @priority-high @negative
  Scenario: User enumeration prevention through consistent error messages
    Given test accounts with existing and non-existing usernames are prepared
    When user submits validation request with existing username "john@example.com"
    And user submits validation request with non-existing username "nonexistent@example.com"
    Then error messages should be identical for both scenarios
    And timing differences should be negligible within "50" milliseconds
    And no user enumeration should be possible

  @security @information-disclosure @priority-high @negative
  Scenario: Database information leakage prevention in SQL injection errors
    Given SQL injection payloads are prepared for testing
    When user triggers validation error with SQL injection attempt "' OR 1=1--"
    Then no database error messages should be returned to client
    And generic validation error should be displayed
    And database errors should be logged server-side only
    And no SQL query fragments should be visible

  @security @information-disclosure @priority-high @negative
  Scenario: Internal validation logic disclosure prevention
    Given malformed data types are prepared for testing
    When user submits malformed data "12345" to "Email" field expecting email format
    Then error message should provide minimal guidance
    And internal validation logic should not be revealed
    And field names in errors should match user-facing labels
    And database column names should not be exposed
    And validation rules should not be explicitly stated

  @security @information-disclosure @priority-high @negative
  Scenario: HTTP response headers security validation
    Given security headers configuration is documented
    When user examines HTTP response headers from validation endpoints
    Then sensitive headers "Server" should be removed or obfuscated
    And sensitive headers "X-Powered-By" should be removed or obfuscated
    And sensitive headers "X-AspNet-Version" should be removed or obfuscated
    And response timing should be consistent regardless of validation outcome
    And no version information should be exposed
    And security headers should be properly configured

  @security @information-disclosure @priority-high @negative
  Scenario Outline: Debug mode exploitation prevention
    Given application is deployed in production environment
    When user attempts to enable debug mode using parameter "<debug_parameter>" with value "<debug_value>"
    Or user attempts to enable debug mode using header "<debug_header>" with value "<debug_value>"
    Then debug mode should remain disabled
    And no verbose error output should be enabled
    And application behavior should be consistent
    And security event should be logged

    Examples:
      | debug_parameter | debug_header | debug_value |
      | debug           | X-Debug      | true        |
      | verbose         | X-Verbose    | 1           |
      | trace           | X-Trace      | on          |