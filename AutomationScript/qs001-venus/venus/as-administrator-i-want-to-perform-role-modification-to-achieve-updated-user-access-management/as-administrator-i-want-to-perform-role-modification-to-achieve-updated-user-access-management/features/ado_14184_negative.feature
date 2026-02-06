Feature: Role Modification Security and Validation
  As an Administrator
  I want the system to enforce strict security and validation rules during role modification
  So that unauthorized access is prevented and data integrity is maintained

  Background:
    Given the role management system is available
    And API endpoint "PUT /api/roles/{id}" is configured

  @negative @regression @priority-high @security
  Scenario: System rejects role modification attempt by non-admin user without proper authentication
    Given user is logged in with "Standard User" role without admin privileges
    And role "Content Editor" exists in the system
    And API endpoint requires admin authentication
    When user attempts to navigate to "/admin/role-management" page directly
    Then "Access Denied" page should be displayed
    And error message "You do not have permission to access this resource" should be displayed
    When user attempts to call API endpoint "PUT /api/roles/123" with modified permissions
    Then API should return HTTP status code 403
    And API error response "Insufficient privileges. Admin authentication required." should be returned
    And no changes should be saved to roles table
    And "Content Editor" role permissions should remain unchanged
    And security violation attempt should be logged in security audit trail with user ID and timestamp

  @negative @regression @priority-high @validation
  Scenario: System handles role modification with empty or null permission values
    Given administrator is logged in and on role management page
    And role "Test Role" exists with 2 permissions assigned
    And role modification form is accessible
    When administrator selects "Test Role" from roles list
    Then role modification form should open showing current permissions checked
    When administrator unchecks all permission checkboxes
    Then all checkboxes should be unchecked
    And form should show 0 permissions selected
    When administrator clicks "Save Changes" button
    Then validation error "At least one permission must be assigned to a role" should be displayed
    And red error banner should appear at top of form
    And form submission should be blocked
    And "Test Role" permissions should remain unchanged in database
    And no audit log entry should be created for failed modification attempt
    And administrator should remain on role modification form

  @negative @regression @priority-high @database
  Scenario: System handles role modification when database connection is lost during save operation
    Given administrator is logged in and on role modification form
    And role "Operations Manager" is selected for modification
    And database connection can be simulated to fail during transaction
    When administrator modifies "Operations Manager" role by adding "delete" permission
    Then "delete" permission checkbox should be checked
    And form should show pending changes
    When database connection failure is simulated
    And administrator clicks "Save Changes" button
    Then system should attempt to save but encounter database connection error
    And error message "Unable to save changes. Database connection error. Please try again." should be displayed
    And red error banner should be displayed
    And "Operations Manager" role permissions should remain unchanged in database
    And no partial updates should be applied
    And database error should be logged in system error logs with timestamp and error details
    And administrator should remain on modification form with error message displayed
    And form should retain the attempted changes

  @negative @regression @priority-high @security @sql-injection
  Scenario: System rejects role modification with SQL injection attempt in role name or permissions
    Given administrator is logged in with admin privileges
    And role modification form is accessible
    And system has SQL injection protection enabled
    And input validation and parameterized queries are implemented
    When administrator selects any existing role and opens modification form
    Then role modification form should open with current role details
    When administrator attempts to modify role name to "Admin'; DROP TABLE roles; --"
    Then system should sanitize input
    And validation error "Invalid characters in role name" should be displayed
    When administrator attempts to submit form with malicious input
    Then form submission should be blocked with error message
    And roles table should remain intact
    And all existing roles should remain in database
    And no SQL injection should be executed
    And security incident should be logged with attempted malicious input details
    And role modification should be rejected
    And no changes should be saved

  @negative @regression @priority-medium @session
  Scenario: System handles role modification when session expires during modification process
    Given administrator is logged in and on role modification form
    And role "HR Manager" is selected for modification
    And session timeout is configured
    When administrator opens role modification form for "HR Manager" role
    And administrator adds "approve" permission
    Then "approve" permission checkbox should be checked
    And form should show unsaved changes
    When session expires or session token is manually expired
    And administrator clicks "Save Changes" button
    Then system should detect expired session
    And error message "Your session has expired. Please log in again." should be displayed
    And "HR Manager" role permissions should remain unchanged in database
    And no modifications should be applied
    And user should be redirected to login page
    And attempted changes should be lost and not persisted
    And session expiration should be logged in authentication logs

  @negative @regression @priority-medium @validation @boundary
  Scenario: System rejects role modification when attempting to assign permissions that exceed maximum allowed limit
    Given administrator is logged in and on role management page
    And system has maximum permission limit configured as 15 permissions per role
    And role "Super User" exists with 14 permissions already assigned
    And at least 3 additional permission options are available to select
    When administrator selects "Super User" role to open modification form
    Then role modification form should display showing 14 permissions currently checked
    When administrator attempts to add "Manage Billing" permission
    And administrator attempts to add "System Configuration" permission
    Then both checkboxes should be checked
    And form should show 16 permissions selected
    When administrator clicks "Save Changes" button
    Then validation error "Maximum permission limit exceeded. A role can have maximum 15 permissions." should be displayed
    And error banner should appear in red
    And form submission should be blocked
    And "Save Changes" button should be disabled
    And "Super User" role should retain original 14 permissions in database
    And no changes should be saved due to validation failure
    And administrator should remain on modification form with error message displayed
    And validation error should be logged for monitoring purposes

  @negative @regression @priority-medium @concurrency
  Scenario: System handles concurrent role modification attempts by multiple administrators
    Given administrator "Admin1" is logged in
    And administrator "Admin2" is logged in
    And both administrators have access to role management section
    And role "Finance Manager" exists with permissions "read, write, approve"
    And both administrators open the same role for modification at the same time
    When "Admin1" selects "Finance Manager" role and opens modification form
    And "Admin1" adds "delete" permission
    Then "Admin1" form should show "Finance Manager" with "read, write, approve, delete" permissions selected
    When "Admin2" selects "Finance Manager" role and opens modification form
    And "Admin2" removes "approve" permission
    Then "Admin2" form should show "Finance Manager" with "read, write" permissions selected
    When "Admin1" clicks "Save Changes" button first
    Then "Admin1" should see success message
    And "Finance Manager" role should be updated to "read, write, approve, delete"
    When "Admin2" clicks "Save Changes" button immediately after "Admin1"
    Then system should detect conflict
    And error message "This role has been modified by another user. Please refresh and try again." should be displayed
    And "Finance Manager" role should show "read, write, approve, delete" permissions in database
    And "Admin2" changes should not be applied to prevent data loss
    And only "Admin1" modifications should be saved in database
    And both modification attempts should be logged in audit trail with conflict notation