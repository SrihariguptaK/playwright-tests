Feature: Role Modification for User Access Management
  As an Administrator
  I want to modify existing roles and their permissions
  So that I can ensure roles are always up-to-date with current organizational needs and maintain proper access control

  Background:
    Given administrator is logged in with valid admin credentials
    And database connection is active and roles table is accessible

  @functional @regression @priority-high @smoke
  Scenario: Successfully modify existing role permissions
    Given administrator is on "Role Management" page
    And role "Content Editor" exists with permissions "read, write"
    When administrator clicks on "Content Editor" role from roles list
    Then role modification form should display current permissions "read, write"
    When administrator checks "Delete" checkbox in permissions section
    Then "Delete" checkbox should be checked
    And form should show unsaved changes indicator
    When administrator clicks "Save Changes" button
    Then loading spinner should be displayed for up to 2 seconds
    And success message "Role modified successfully" should be displayed
    And "Content Editor" role should display permissions "read, write, delete"
    And role modification should be logged in audit trail with timestamp and admin user ID
    And users assigned to "Content Editor" role should have updated permissions effective immediately

  @functional @regression @priority-high @audit
  Scenario: Role modification logs activity for compliance audit purposes
    Given administrator is logged in as "admin@company.com" with admin privileges
    And role "Project Manager" exists with permissions "read, write, approve"
    And audit logging system is enabled and functional
    And administrator is on "Role Management" page
    When administrator clicks on "Project Manager" role from roles list
    Then role modification form should display current permissions "read, write, approve"
    When administrator unchecks "Approve" checkbox
    Then "Approve" checkbox should be unchecked
    And form should indicate pending changes
    When administrator clicks "Save Changes" button
    Then success message "Role modified successfully" should be displayed
    When administrator navigates to "Audit Logs" page
    And administrator filters logs by "Role Modification" activity type
    And administrator searches for "Project Manager" role
    Then audit log entry should display timestamp
    And audit log entry should display admin user "admin@company.com"
    And audit log entry should display action "Role Modified"
    And audit log entry should display role name "Project Manager"
    And audit log entry should display changes "Removed: approve permission"
    And log entry should contain complete details including user ID and before/after permission states

  @functional @regression @priority-high @negative @validation
  Scenario: System prevents role modifications with conflicting permissions
    Given administrator is on "Role Management" page
    And role "Data Viewer" exists with "read-only" flag set to true
    And system has validation rules configured to prevent read-only roles from having write/delete permissions
    And conflicting permission validation is enabled
    When administrator clicks on "Data Viewer" role from roles list
    Then role modification form should display "read-only" flag enabled
    And only "read" permission checkbox should be checked
    When administrator attempts to check "Write" permission checkbox
    Then inline validation error "Cannot assign write permission to read-only role" should be displayed
    When administrator clicks "Save Changes" button without resolving conflict
    Then form submission should be blocked
    And error message "Conflicting permissions detected. Please resolve errors before saving." should be displayed
    And "Save Changes" button should be disabled
    When administrator unchecks "Write" permission checkbox
    Then validation error should clear
    And error message should disappear
    And "Save Changes" button should be enabled
    And "Data Viewer" role should remain unchanged in database with only read permission

  @functional @regression @priority-medium @performance
  Scenario: Role modification completes within 2 seconds performance requirement
    Given administrator is on "Role Management" page
    And role "Sales Representative" exists with 5 permissions assigned
    And system is under normal load conditions
    And network latency is within normal parameters
    When administrator clicks on "Sales Representative" role
    Then role modification form should display current 5 permissions
    When administrator checks "Export Data" checkbox
    And administrator checks "Generate Reports" checkbox
    Then form should show 7 total permissions selected
    When administrator clicks "Save Changes" button and starts timer
    Then loading indicator should be displayed
    And success message "Role modified successfully" should be displayed within 2 seconds
    And "Sales Representative" role should be updated with 7 permissions in database
    And performance metric should be logged showing modification completed within SLA
    And system should remain responsive for next operation

  @functional @regression @priority-medium
  Scenario: Modify multiple permissions simultaneously for a single role
    Given administrator is on "Role Management" page
    And role "Customer Support" exists with permissions "read, create, update"
    And all permission options are available
    When administrator clicks on "Customer Support" role from roles list
    Then role modification form should display current permissions "read, create, update"
    When administrator checks "Delete" checkbox
    And administrator checks "Export" checkbox
    Then form should show 5 total permissions selected
    When administrator unchecks "Create" checkbox
    Then form should show 4 permissions selected
    When administrator clicks "Save Changes" button
    Then loading indicator should be displayed
    And success message "Role modified successfully" should be displayed
    And "Customer Support" role should display permissions "read, update, delete, export"
    And single audit log entry should capture all permission changes in one transaction
    And all users with "Customer Support" role should receive updated permissions immediately
    And role list should refresh showing updated permission count

  @functional @regression @priority-medium @ui-validation
  Scenario: Role modification form displays current permissions accurately before modification
    Given administrator is on "Role Management" page
    And role "Marketing Manager" exists with permissions "read, write, approve, export"
    And database contains accurate permission data for "Marketing Manager" role
    When administrator clicks on "Marketing Manager" role from roles list
    Then role modification form should display role name "Marketing Manager" in header
    And exactly 4 checkboxes should be checked: "Read, Write, Approve, Export"
    And all other permission checkboxes should be unchecked
    And form should display "4 permissions assigned" count indicator
    When administrator clicks "Cancel" button
    Then form should close and return to role management list
    And "Marketing Manager" role should remain unchanged in database
    And no audit log entry should be created for cancelled modification