Feature: Permission Assignment Validation and Error Handling
  As an Administrator
  I want the system to validate and handle errors during permission assignment
  So that role configurations remain secure and data integrity is maintained

  Background:
    Given administrator is authenticated with valid admin credentials

  @negative @regression @priority-high
  Scenario: System rejects permission assignment when no permissions are selected
    Given administrator is on the permission configuration page
    And role "Guest" exists in the system with no current permissions
    And available permissions list is displayed
    And no permission checkboxes are selected
    When administrator selects "Guest" role from the role selection dropdown
    Then "Guest" role details panel should display with empty current permissions section
    When administrator clicks "Assign Permissions" button without selecting any permissions
    Then error message "Error: Please select at least one permission to assign" should be displayed
    And error banner should be displayed in "red" color at the top of the page
    And current permissions section should remain empty for "Guest" role
    And all form fields should remain enabled and accessible
    And no permissions should be assigned to "Guest" role in the database
    And failed assignment attempt should be logged with reason "No permissions selected"

  @negative @regression @priority-high
  Scenario: System rejects permission assignment without admin authentication
    Given user is logged in with non-admin role "Standard User"
    And role "Editor" exists in the system
    And user does not have admin-level permissions
    When user navigates to "/admin/permissions" page
    Then "Access Denied" page should be displayed
    And error message "You do not have permission to access this resource. Admin privileges required." should be displayed
    When user sends POST request to "/api/roles/role-123/permissions" with "Standard User" authentication token
    Then API should return HTTP status code 403
    And response should contain error "Unauthorized"
    And response should contain message "Admin authentication required for permission assignment"
    And no permissions should be modified in the database
    And unauthorized access attempt should be logged in security audit log

  @negative @regression @priority-high
  Scenario: System handles permission assignment for non-existent role ID gracefully
    Given administrator is on the permission configuration page
    And role ID "role-99999" does not exist in the database
    And permission "Read" exists in the system
    And permission "Write" exists in the system
    When administrator sends POST request to "/api/roles/role-99999/permissions" with permissions "perm-read,perm-write"
    Then API should return HTTP status code 404
    And response should contain error "Role Not Found"
    And response should contain message "Role with ID 'role-99999' does not exist"
    And response should contain status code 404
    And no database records should be created in role_permissions table for role "role-99999"
    And error log entry should exist with severity "WARNING" and message "Attempted permission assignment to non-existent role"

  @negative @regression @priority-high
  Scenario: System rejects permission assignment with invalid permission IDs
    Given administrator is on the permission configuration page
    And role "Tester" with ID "role-555" exists in the system
    And permission ID "perm-invalid-123" does not exist in the permissions table
    And permission ID "perm-nonexistent" does not exist in the permissions table
    And permission "perm-valid-001" exists in the system
    When administrator sends POST request to "/api/roles/role-555/permissions" with permissions "perm-invalid-123,perm-nonexistent,perm-valid-001"
    Then API should return HTTP status code 400
    And response should contain error "Invalid Permissions"
    And response should contain message "The following permission IDs do not exist: perm-invalid-123, perm-nonexistent"
    And response should contain invalid permissions list "perm-invalid-123,perm-nonexistent"
    And no permissions should be assigned to role "role-555" in the database
    And transaction should be rolled back completely
    And error log entry should exist with severity "ERROR" and message "Permission assignment failed: invalid permission IDs"

  @negative @regression @priority-medium
  Scenario: System handles database connection failure during permission assignment
    Given administrator is on the permission configuration page
    And role "Analyst" exists in the system
    And permission "View-Reports" is available for assignment
    And permission "Export-Data" is available for assignment
    And database connection can be simulated to fail
    When administrator selects "Analyst" role from the role selection dropdown
    And administrator checks "View-Reports" permission checkbox
    And administrator checks "Export-Data" permission checkbox
    And database connection failure is simulated
    And administrator clicks "Assign Permissions" button
    Then error message "System Error: Unable to assign permissions. Please try again later. If the problem persists, contact support." should be displayed
    And error banner should be displayed in "red" color
    And error message should not expose sensitive database information
    And error log should contain detailed technical information "Database connection timeout"
    And no permissions should be assigned to "Analyst" role in the database
    And no partial data should be saved to the database
    And system should remain stable and operational

  @negative @regression @priority-high
  Scenario: System rejects permission assignment with SQL injection attempt in role ID
    Given administrator is authenticated with valid credentials
    And role "Admin" with ID "role-admin-001" exists in the system
    And system has SQL injection protection mechanisms in place
    When administrator sends POST request to "/api/roles/role-admin-001' OR '1'='1/permissions" with permissions "perm-001"
    Then API should return HTTP status code 400
    And response should contain error "Invalid Request"
    And response should contain message "Invalid role ID format"
    And no database records should be modified or exposed
    And no unauthorized queries should be executed
    And security log entry should exist with severity "CRITICAL" and message "Potential SQL injection attempt detected"
    And security alert should be triggered for potential attack attempt

  @negative @regression @priority-medium
  Scenario: System handles session timeout during permission assignment process
    Given administrator is on the permission configuration page
    And role "Support" exists in the system
    And permission "Ticket-View" is selected for assignment
    And permission "Ticket-Respond" is selected for assignment
    And admin session timeout is set to 30 minutes
    When administrator selects "Support" role from the role selection dropdown
    And administrator checks "Ticket-View" permission checkbox
    And administrator checks "Ticket-Respond" permission checkbox
    And admin session expires
    And administrator clicks "Assign Permissions" button
    Then error message "Your session has expired. Please log in again to continue." should be displayed
    And "Login" button should be visible
    And API should return HTTP status code 401
    And response should contain error "Session Expired"
    And response should contain message "Your session has expired. Please authenticate again."
    And no permissions should be assigned to "Support" role in the database
    And session expiration should be logged in audit trail
    When administrator clicks "Login" button
    Then administrator should be redirected to login page