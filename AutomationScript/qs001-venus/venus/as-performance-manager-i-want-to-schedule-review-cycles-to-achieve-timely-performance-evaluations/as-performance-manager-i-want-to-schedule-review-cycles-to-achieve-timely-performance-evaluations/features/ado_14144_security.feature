Feature: Review Cycle Scheduling Security Controls
  As a Security Administrator
  I want to ensure review cycle scheduling has proper authorization and input validation
  So that only authorized managers can schedule reviews and the system is protected from malicious attacks

  Background:
    Given the review cycles management system is available
    And the API endpoint "/api/review-cycles/schedule" is accessible
    And the review cycles database table exists with test data

  @security @negative @priority-critical @vertical-privilege-escalation
  Scenario: Non-manager user cannot schedule review cycles through UI
    Given a test user account with "Employee" role is created
    And a valid Performance Manager account exists with review cycle scheduling permissions
    When the non-manager user authenticates successfully
    And the non-manager user receives a valid session token
    And the non-manager user attempts to access "/review-cycles/schedule" page directly
    Then the system should deny access with "403" status code
    And the user should be redirected to unauthorized page

  @security @negative @priority-critical @vertical-privilege-escalation
  Scenario: Non-manager user cannot schedule review cycles through API
    Given a test user account with "Employee" role is authenticated
    And the non-manager user has a valid authentication token
    When the non-manager user sends POST request to "/api/review-cycles/schedule" endpoint
    And the request includes "quarterly" as frequency
    And the request includes "2024-01-01" as start date
    And the request includes non-manager user ID as manager ID
    Then the API should return "403" status code
    And the error message should indicate insufficient permissions
    And no review cycle should be created in the database

  @security @negative @priority-critical @vertical-privilege-escalation
  Scenario: Non-manager cannot schedule review cycles using another manager's ID
    Given a test user account with "Employee" role is authenticated
    And a valid Performance Manager with ID "201" exists
    When the non-manager user sends POST request to "/api/review-cycles/schedule" endpoint
    And the request includes "quarterly" as frequency
    And the request includes "2024-01-01" as start date
    And the request includes "201" as manager ID
    And the request uses non-manager authentication token
    Then the API should return "403" status code
    And the server-side role verification should reject the request
    And no review cycle should be created for manager ID "201"

  @security @negative @priority-critical @vertical-privilege-escalation
  Scenario: Tampered JWT token with modified role claim is rejected
    Given a test user account with "Employee" role is authenticated
    And the user has a valid JWT token with role claim "employee"
    When the user attempts to modify the JWT token role claim to "performance_manager"
    And the modified token does not have proper signature
    And the user sends request with the tampered token
    Then the system should reject the token with "401" status code
    And the error message should indicate unauthorized access

  @security @negative @priority-critical @vertical-privilege-escalation
  Scenario: Unauthorized access attempts are logged in security audit trail
    Given a test user account with "Employee" role is authenticated
    And security audit logging is enabled
    When the non-manager user attempts to access "/review-cycles/schedule" page
    And the non-manager user attempts to call "/api/review-cycles/schedule" endpoint
    Then all unauthorized access attempts should be captured in audit logs
    And the audit log entries should include user ID
    And the audit log entries should include timestamp
    And the audit log entries should include attempted action
    And the audit log entries should have appropriate severity level

  @security @negative @priority-critical @sql-injection
  Scenario: SQL injection in frequency field is prevented
    Given a valid Performance Manager is authenticated
    And the user navigates to review cycle scheduling page
    When the user enters "quarterly'; DROP TABLE review_cycles; --" in "frequency" field
    And the user enters "2024-01-01" in "start date" field
    And the user attempts to save the review cycle
    Then the system should sanitize the input
    And the entire string should be treated as literal text
    And the system should reject with validation error or save harmlessly
    And no SQL statement should be executed against the database

  @security @negative @priority-critical @sql-injection
  Scenario Outline: SQL injection attempts in API parameters are blocked
    Given a valid Performance Manager is authenticated
    And API testing tool is configured
    When the user sends POST request to "/api/review-cycles/schedule" endpoint
    And the request includes "<frequency>" as frequency
    And the request includes "<startDate>" as start date
    And the request includes "<managerId>" as manager ID
    Then the API should return "<statusCode>" status code
    And the response should include input validation error
    And no SQL query should be executed
    And no data exfiltration should occur

    Examples:
      | frequency                                  | startDate                  | managerId                                                    | statusCode |
      | monthly                                    | 2024-01-01' OR '1'='1      | 123                                                          | 400        |
      | quarterly                                  | 2024-01-01                 | 123 UNION SELECT username, password FROM users--            | 400        |
      | quarterly'; WAITFOR DELAY '00:00:10'--     | 2024-01-01                 | 123                                                          | 400        |

  @security @negative @priority-critical @sql-injection
  Scenario: Time-based blind SQL injection does not cause delays
    Given a valid Performance Manager is authenticated
    And response time monitoring is enabled
    When the user sends POST request to "/api/review-cycles/schedule" endpoint
    And the request includes "quarterly'; WAITFOR DELAY '00:00:10'--" as frequency
    And the request includes "2024-01-01" as start date
    And the request includes "123" as manager ID
    Then the response should return immediately without delay
    And parameterized queries should be confirmed in use
    And the response time should be under "2" seconds

  @security @negative @priority-critical @sql-injection
  Scenario: SQL injection attempts are logged without executing malicious queries
    Given a valid Performance Manager is authenticated
    And database monitoring tools are configured
    And application logging is enabled
    When the user attempts SQL injection in review cycle parameters
    Then database logs should contain only legitimate parameterized queries
    And application logs should show validation errors for malicious inputs
    And database integrity should be maintained
    And no tables should be dropped or modified
    And no sensitive data should be exposed in error messages

  @security @negative @priority-critical @horizontal-privilege-escalation
  Scenario: Manager can only view their own review cycles
    Given Performance Manager A with ID "101" exists
    And Performance Manager B with ID "102" exists
    And Manager A has created review cycle with ID "RC-2024-001"
    And Manager B has created review cycle with ID "RC-2024-002"
    When Manager B authenticates and navigates to review cycles calendar view
    Then Manager B should see only review cycle "RC-2024-002"
    And Manager B should not see review cycle "RC-2024-001"

  @security @negative @priority-critical @horizontal-privilege-escalation
  Scenario: Manager cannot access another manager's review cycle via API
    Given Performance Manager A with ID "101" has created review cycle "RC-2024-001"
    And Performance Manager B with ID "102" is authenticated
    When Manager B sends GET request to "/api/review-cycles/RC-2024-001" endpoint
    Then the API should return "403" status code or "404" status code
    And access to Manager A's review cycle should be prevented

  @security @negative @priority-critical @horizontal-privilege-escalation
  Scenario: Manager cannot edit another manager's review cycle
    Given Performance Manager A with ID "101" has created review cycle "RC-2024-001"
    And Performance Manager B with ID "102" is authenticated
    When Manager B sends PUT request to "/api/review-cycles/RC-2024-001" endpoint
    And the request includes modified frequency data
    Then the API should return "403" status code
    And the error message should indicate insufficient permissions
    And no data should be modified in the database
    And review cycle "RC-2024-001" should remain unchanged

  @security @negative @priority-critical @horizontal-privilege-escalation
  Scenario: Manager cannot delete another manager's review cycle
    Given Performance Manager A with ID "101" has created review cycle "RC-2024-001"
    And Performance Manager B with ID "102" is authenticated
    When Manager B sends DELETE request to "/api/review-cycles/RC-2024-001" endpoint
    Then the API should return "403" status code
    And review cycle "RC-2024-001" should remain intact in database

  @security @negative @priority-critical @horizontal-privilege-escalation
  Scenario: Unauthorized cross-manager access attempts are audited
    Given Performance Manager A with ID "101" has created review cycle "RC-2024-001"
    And Performance Manager B with ID "102" is authenticated
    And security audit logging is enabled
    When Manager B attempts to access review cycle "RC-2024-001"
    And Manager B attempts to edit review cycle "RC-2024-001"
    And Manager B attempts to delete review cycle "RC-2024-001"
    Then Manager A's review cycle data should remain unchanged in database
    And audit logs should contain entries for Manager B's unauthorized access attempts
    And audit log entries should include timestamps
    And Manager B should not be able to access or manipulate Manager A's data