Feature: Administrator Permission Assignment for Role Configuration
  As an Administrator
  I want to assign permissions to roles
  So that I can ensure users have the correct access levels and maintain system security

  Background:
    Given administrator is logged in with valid admin credentials
    And permissions table in the database is accessible and operational

  @functional @regression @priority-high @smoke
  Scenario: Successfully assign multiple permissions to a single role
    Given administrator is on the permission configuration section page
    And role "Editor" exists in the system
    And permissions "Read", "Write", "Delete", and "Publish" are available in the system
    When administrator clicks "Permissions" in the admin navigation menu
    Then permission configuration page loads successfully displaying list of available roles
    When administrator selects "Editor" from the roles dropdown list
    Then role details panel appears showing current permissions assigned to "Editor" role
    When administrator checks the checkboxes for "Read", "Write", and "Publish" permissions
    Then selected permission checkboxes are visually marked as checked with blue checkmarks
    When administrator clicks "Assign Permissions" button
    Then loading indicator appears briefly
    And green confirmation banner displays message "Permissions successfully assigned to Editor role" at the top of the page
    And assigned permissions "Read", "Write", and "Publish" appear in "Current Permissions" section for "Editor" role
    And permission assignment activity is logged in the audit log with timestamp and admin user ID
    And confirmation message remains visible for 5 seconds before auto-dismissing

  @functional @regression @priority-high
  Scenario: Display confirmation message upon successful permission assignment
    Given administrator is on the permission configuration section
    And role "Contributor" exists in the system
    And permission "Comment" is available to assign
    When administrator selects "Contributor" from the role selection dropdown
    Then "Contributor" role is selected and role details panel displays with current permissions
    When administrator selects "Comment" permission checkbox from the available permissions list
    Then "Comment" permission checkbox is checked and highlighted
    When administrator clicks "Assign Permissions" button
    Then system processes the request and displays green success banner at the top of the page
    And confirmation message contains text "Permissions successfully assigned to Contributor role"
    And confirmation message has green background with white text and success icon
    And confirmation message includes role name "Contributor"
    And "Comment" permission is successfully assigned to "Contributor" role in the database
    And confirmation message auto-dismisses after 5 seconds

  @functional @regression @priority-high @audit
  Scenario: Log permission assignment activity for audit purposes
    Given administrator is logged in with username "admin@company.com"
    And administrator is on the permission configuration page
    And role "Manager" exists with ID "role-123"
    And permissions "Approve" and "Review" are available with IDs "perm-456" and "perm-789"
    And audit logging system is enabled and operational
    When administrator selects "Manager" from the role dropdown
    Then "Manager" role details are displayed with current permissions list
    When administrator checks "Approve" and "Review" permissions checkboxes
    Then both permission checkboxes are checked and visually highlighted
    When administrator clicks "Assign Permissions" button
    Then green confirmation message "Permissions successfully assigned to Manager role" appears
    When administrator navigates to "Audit Logs" section by clicking "Audit Logs" in the admin menu
    Then audit logs page loads displaying recent system activities
    When administrator filters audit logs by activity type "Permission Assignment" within the last 5 minutes
    Then audit log entry is displayed showing timestamp
    And audit log entry shows admin user "admin@company.com"
    And audit log entry shows action "Permission Assignment"
    And audit log entry shows role "Manager (role-123)"
    And audit log entry shows permissions "Approve (perm-456), Review (perm-789)"
    And audit log entry shows status "Success"
    And audit log includes IP address, session ID, and browser information
    And audit log is accessible for compliance reporting and can be exported

  @functional @regression @priority-high @negative
  Scenario: Prevent assignment of conflicting permissions
    Given administrator is on the permission configuration page
    And role "Viewer" exists in the system
    And conflicting permissions are defined where "Read-Only" conflicts with "Full-Edit"
    And permission conflict validation rules are configured in the system
    And role "Viewer" currently has "Read-Only" permission assigned
    When administrator selects "Viewer" from the role selection dropdown
    Then "Viewer" role details display showing "Read-Only" permission in the current permissions section
    When administrator attempts to check "Full-Edit" permission checkbox
    Then system immediately displays warning tooltip stating "This permission conflicts with Read-Only permission"
    When administrator clicks "Assign Permissions" button to attempt submission
    Then system displays red error banner stating "Cannot assign permissions: Full-Edit conflicts with existing Read-Only permission. Please remove conflicting permissions first."
    And "Assign Permissions" button remains enabled
    And no database changes occur
    And "Viewer" role still only has "Read-Only" permission
    And conflict validation attempt is logged in the system logs for security monitoring

  @functional @regression @priority-medium @performance
  Scenario: Permission assignment completes within 2 seconds performance requirement
    Given administrator is on the permission configuration page
    And role "Developer" exists in the system
    And permissions "Code-Read", "Code-Write", "Deploy", "Debug", and "Configure" are available
    And system is under normal load conditions
    And network latency is within acceptable range
    When administrator selects "Developer" from the role dropdown
    Then "Developer" role details panel loads and displays current permissions
    When administrator checks all permissions "Code-Read", "Code-Write", "Deploy", "Debug", and "Configure"
    Then all 5 permission checkboxes are checked and highlighted
    When administrator notes the current timestamp and clicks "Assign Permissions" button
    Then loading spinner appears immediately indicating processing has started
    And confirmation message "Permissions successfully assigned to Developer role" appears within 2 seconds
    And all 5 permissions are displayed in the current permissions section
    And total operation time from button click to confirmation is less than or equal to 2 seconds
    And system performance metrics are recorded for monitoring

  @functional @regression @priority-medium
  Scenario: Modify existing role permissions by adding new permissions
    Given administrator is on the permission configuration page
    And role "Moderator" exists with existing permissions "View-Content" and "Flag-Content"
    And additional permissions "Ban-User" and "Delete-Comment" are available to assign
    When administrator selects "Moderator" from the role selection dropdown
    Then "Moderator" role details display showing current permissions "View-Content" and "Flag-Content"
    When administrator checks "Ban-User" and "Delete-Comment" permissions checkboxes
    Then both new permission checkboxes are checked while existing permissions remain displayed
    When administrator clicks "Assign Permissions" button
    Then green confirmation banner appears with message "Permissions successfully assigned to Moderator role"
    And current permissions section displays "View-Content", "Flag-Content", "Ban-User", and "Delete-Comment" for "Moderator" role
    And "Moderator" role now has 4 permissions total in the database
    And previous permissions "View-Content" and "Flag-Content" remain unchanged
    And permission modification is logged in audit trail showing both old and new permission sets

  @functional @regression @priority-high @api
  Scenario: POST API endpoint successfully processes permission assignment
    Given administrator has valid authentication token
    And role with ID "role-999" exists in the database
    And permissions with IDs "perm-111", "perm-222", and "perm-333" exist in the permissions table
    And API endpoint "POST /api/roles/role-999/permissions" is accessible
    And administrator has admin-level API access permissions
    When administrator sends POST request to "/api/roles/role-999/permissions" with permission IDs "perm-111", "perm-222", "perm-333" and valid authentication token
    Then API returns HTTP status code 200
    And response body contains "success" field with value "true"
    And response body contains "message" field with value "Permissions successfully assigned"
    And response body contains "roleId" field with value "role-999"
    And response body contains "assignedPermissions" array with values "perm-111", "perm-222", "perm-333"
    And response body contains "timestamp" field with ISO-8601 format
    When administrator queries the database for role_id "role-999" in role_permissions table
    Then database query returns 3 records with permission_ids "perm-111", "perm-222", "perm-333"
    And audit log contains entry with action "PERMISSION_ASSIGNED" for role_id "role-999"
    And audit log entry includes permission_ids array, admin user ID, and matching timestamp
    And API response time is less than 2 seconds