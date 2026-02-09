Feature: Administrator Permission Assignment Security Controls
  As an Administrator
  I want secure permission assignment with proper authorization and audit controls
  So that role configurations maintain security integrity and compliance requirements

  Background:
    Given application is deployed and accessible
    And audit logging system is enabled and operational

  @security @negative @priority-critical @elevation-of-privilege
  Scenario: Non-admin user cannot assign permissions via direct API call
    Given test user account with non-admin role exists and is authenticated
    And valid role ID exists in the system
    When user authenticates as non-administrator user
    And user captures authentication token
    And user sends POST request to "/api/roles/{valid_role_id}/permissions" endpoint with non-admin token
    And request contains permission payload with "DELETE_USER" and "MODIFY_ROLES" permissions
    Then API should return "403" status code
    And error message indicating insufficient privileges should be displayed
    When user attempts to modify Authorization header by tampering with token
    And user resends the request with tampered token
    Then API should return "401" status code
    And token validation failure message should be displayed
    When user verifies database for permission assignments on target role
    Then no unauthorized permission changes should be persisted in database
    When user checks security audit logs for attempted unauthorized access
    Then security log should contain entry with timestamp and user ID
    And log entry should show attempted action with "ACCESS_DENIED" status

  @security @negative @priority-critical @sql-injection
  Scenario Outline: SQL injection attempts in permission assignment are blocked
    Given administrator account is authenticated
    And permission assignment API endpoint is accessible
    And database contains multiple roles and permissions
    When administrator authenticates and obtains valid admin token
    And administrator sends POST request to "/api/roles/<malicious_role_id>/permissions" endpoint
    And request contains permission payload with "<permission_name>" permission
    Then API should return "<status_code>" status code
    And "<error_type>" error should be displayed
    And no SQL query should be executed with malicious input
    When administrator verifies database integrity
    Then all database tables should exist
    And no unauthorized data modifications should be present
    And permissions table structure should be unchanged
    And all injection attempts should be logged as security events

    Examples:
      | malicious_role_id                          | permission_name                    | status_code | error_type              |
      | 1' OR '1'='1                               | READ_DATA                          | 400         | input validation error  |
      | 1 UNION SELECT * FROM users--              | READ_DATA                          | 400         | input validation error  |
      | 1'; WAITFOR DELAY '00:00:10'--             | READ_DATA                          | 400         | input validation error  |
      | valid-role-id                              | READ'; DROP TABLE permissions;--   | 400         | validation error        |

  @security @negative @priority-critical @authorization @idor
  Scenario: Administrator cannot modify permissions for roles outside their scope
    Given multi-tenant role structure exists
    And administrator account with limited scope for "Department A" is created
    And role exists in "Department A" with ID "role-100"
    And role exists in "Department B" with ID "role-200"
    And authorization boundaries are defined in the system
    When administrator authenticates as "Department A" administrator
    And administrator captures authentication token
    And administrator identifies authorized role ID "role-100" from "Department A"
    And administrator identifies unauthorized role ID "role-200" from "Department B"
    And administrator sends POST request to "/api/roles/role-100/permissions" endpoint with "Department A" admin token
    And request contains valid permission payload
    Then API should return "200" status code
    And permissions should be successfully assigned to "Department A" role
    And confirmation message should be displayed
    When administrator attempts to assign permissions to "Department B" role
    And administrator sends POST request to "/api/roles/role-200/permissions" endpoint with same token
    Then API should return "403" status code
    And error message "Insufficient permissions to modify this role" should be displayed
    When administrator verifies database for "Department B" role permissions
    Then "Department B" role permissions should remain unchanged
    When administrator checks audit logs for unauthorized access attempt
    Then audit log should contain entry with "Department A" admin ID
    And log entry should show attempted role ID "role-200"
    And log entry should show action "ASSIGN_PERMISSIONS" with status "DENIED"

  @security @functional @priority-high @audit @non-repudiation
  Scenario: Permission assignment creates comprehensive immutable audit trail
    Given administrator account "admin1@example.com" is authenticated
    And multiple roles with different permission sets exist
    And baseline audit log state is captured
    When administrator authenticates as "admin1@example.com"
    And administrator records authentication timestamp
    And administrator assigns permissions "CREATE_USER" and "DELETE_USER" to role "Manager"
    And administrator sends POST request to "/api/roles/manager-role-id/permissions" endpoint
    And administrator notes exact timestamp of request
    Then API should return "200" status code
    And confirmation message should be displayed
    And permissions should be successfully assigned
    When administrator queries audit logs for permission assignment event
    Then audit log entry should exist with user ID "admin1"
    And audit log entry should contain username "admin1@example.com"
    And audit log entry should contain role ID "manager-role-id"
    And audit log entry should contain role name "Manager"
    And audit log entry should contain permissions added "CREATE_USER" and "DELETE_USER"
    And audit log entry should contain timestamp in ISO 8601 format
    And audit log entry should contain source IP address
    And audit log entry should contain user agent
    And audit log entry should contain action result "SUCCESS"
    When administrator attempts to modify audit log entry using administrator privileges
    Then audit log entry cannot be modified
    And system should prevent tampering with appropriate error message
    When administrator performs conflicting permission assignment to same role
    Then audit log should contain entry for failed assignment
    And log entry should show action "ASSIGN_PERMISSIONS" with result "FAILED"
    And log entry should contain error reason "Conflicting permissions detected"
    And log entry should contain permissions attempted
    When administrator verifies log integrity using cryptographic signatures
    Then log integrity verification should pass
    And no tampering should be detected
    When administrator exports audit logs for compliance reporting
    Then audit logs should be exported in standard format
    And all permission assignment events should be included with complete metadata