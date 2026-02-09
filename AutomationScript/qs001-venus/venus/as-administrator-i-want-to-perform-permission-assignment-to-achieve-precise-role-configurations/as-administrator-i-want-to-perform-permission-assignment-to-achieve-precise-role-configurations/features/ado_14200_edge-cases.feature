Feature: Permission Assignment to Roles for Precise Access Control
  As an Administrator
  I want to perform permission assignment to roles
  So that I can achieve precise role configurations and maintain security compliance

  Background:
    Given administrator is logged in with full admin privileges
    And administrator is on the permission configuration section page

  @edge @regression @priority-high
  Scenario: Assign maximum number of permissions to a single role
    Given test role "MaxPermRole" exists with zero permissions assigned
    And system has 100 or more permissions available in the permissions table
    And database connection is stable and responsive
    When administrator clicks "Manage Permissions" button
    Then permission management interface should load successfully
    And list of available roles should be visible
    When administrator selects "MaxPermRole" from roles dropdown
    Then role details panel should display current permissions as empty
    And available permissions list should show all 100 or more permissions
    When administrator clicks "Select All" checkbox
    Then all permission checkboxes should be checked
    And permission counter should show "100+ permissions selected"
    When administrator clicks "Submit" button
    Then loading indicator should appear
    And system should process the request within 2 seconds
    And green confirmation banner should display "Permissions successfully assigned to MaxPermRole"
    And role should show all 100 or more permissions assigned
    And permission assignment activity should be logged in audit trail with timestamp and admin user ID
    And system performance should remain stable with no degradation

  @edge @regression @priority-medium
  Scenario: Assign permissions with special characters and Unicode in permission names
    Given test role "UnicodeTestRole" exists in the system
    And permissions with special characters exist in the system
    And browser supports Unicode character rendering
    When administrator selects "UnicodeTestRole" from roles dropdown
    Then role details panel should open showing available permissions
    And permissions with special characters should be visible
    When administrator checks "Read/Write Access" permission
    And administrator checks "Admin@System" permission
    And administrator checks "User_Management" permission
    And administrator checks "データ管理" permission
    And administrator checks "Gestión™" permission
    Then all 5 permissions should be selected with checkmarks
    And special characters and Unicode should display correctly without corruption
    When administrator clicks "Submit" button
    Then system should validate and process the assignment
    And loading indicator should appear
    And confirmation message should display "Permissions successfully assigned to UnicodeTestRole"
    And all special characters and Unicode should be rendered properly in confirmation
    And all 5 permissions should be correctly stored in database without encoding issues
    And permission names should display correctly in role details view
    And audit log should capture permission names with special characters accurately

  @edge @regression @priority-high
  Scenario: Rapid successive permission assignments to same role within performance window
    Given test role "RapidTestRole" exists with no permissions assigned
    And network latency is minimal under 100 milliseconds
    And browser console is open to monitor API calls
    And at least 10 different permissions are available for assignment
    When administrator selects "RapidTestRole" from roles dropdown
    Then role details panel should display with empty permissions list
    When administrator quickly selects "Permission A" permission
    And administrator quickly selects "Permission B" permission
    And administrator quickly selects "Permission C" permission
    And administrator clicks "Submit" button
    Then first API call should be initiated to "/api/roles/{id}/permissions"
    And loading indicator should appear
    When administrator immediately selects "Permission D" permission within 0.5 seconds
    And administrator immediately selects "Permission E" permission within 0.5 seconds
    And administrator immediately selects "Permission F" permission within 0.5 seconds
    And administrator clicks "Submit" button again
    Then system should either queue the second request or display "Previous assignment in progress, please wait" message
    And system should handle concurrent requests gracefully without data corruption
    And role should have either first set or second set of permissions assigned
    And no corrupted mix of permissions should exist
    And appropriate confirmation message should be displayed
    And database should maintain data integrity with no duplicate entries
    And audit log should show both assignment attempts with clear timestamps

  @edge @regression @priority-medium
  Scenario: Assign permissions when database connection is slow but within SLA
    Given test role "SlowDBRole" exists in the system
    And database response time is throttled to 1.8 seconds
    And network monitoring tools are active to measure response times
    When administrator selects "SlowDBRole" from roles dropdown
    Then role details panel should load within 1.8 seconds
    And current permissions should be displayed
    When administrator selects "User.Read" permission
    And administrator selects "User.Write" permission
    And administrator selects "Admin.Read" permission
    And administrator selects "Report.View" permission
    And administrator selects "Report.Export" permission
    Then selection counter should show "5 permissions selected"
    When administrator clicks "Submit" button
    Then loading spinner should appear immediately
    And "Submit" button should be disabled to prevent double-submission
    And operation should complete within 2 seconds
    And green banner should display "Permissions successfully assigned to SlowDBRole"
    And all 5 permissions should be assigned to the role
    And all 5 permissions should be correctly saved in database
    And no timeout errors should occur during the operation
    And audit log should record the assignment with accurate timestamp and duration

  @edge @regression @priority-medium
  Scenario: Assign zero permissions to a role that previously had permissions
    Given test role "EmptyPermRole" exists with 10 permissions already assigned
    And system allows roles to exist with zero permissions
    When administrator selects "EmptyPermRole" from roles dropdown
    Then role details panel should display 10 currently assigned permissions with checkmarks
    When administrator clicks "Deselect All" button
    Then all checkboxes should be unchecked
    And counter should show "0 permissions selected"
    And warning message "Role will have no permissions" may be displayed
    When administrator clicks "Submit" button
    Then confirmation dialog should appear with message "Are you sure you want to remove all permissions from this role?"
    When administrator clicks "Confirm" button in dialog
    Then system should process the request
    And loading indicator should appear
    And confirmation message should display "Permissions updated for EmptyPermRole"
    And role should show 0 permissions assigned
    And role should still exist in the system
    And audit log should record the removal of all permissions with before and after state

  @edge @regression @priority-high
  Scenario: Assign permissions while session is about to expire
    Given administrator session timeout is set to 30 minutes
    And current session has 30 seconds remaining before expiration
    And role "SessionTestRole" is selected in permission configuration
    And 3 permissions are selected and ready to submit
    And session timeout warning mechanism is active
    When administrator verifies "SessionTestRole" is selected
    Then role details panel should show 3 permissions selected
    And session warning may appear in top banner
    When administrator clicks "Submit" button
    Then system should initiate POST request to "/api/roles/{id}/permissions"
    And loading indicator should appear
    And system should either complete assignment before session expires or extend session automatically or display session expired error
    Then permission assignment should be atomic with all 3 permissions saved or none saved
    And no partial save should occur
    And if successful audit log should record the assignment with correct timestamp

  @edge @regression @priority-low
  Scenario: Assign permissions to role with maximum length role name
    Given test role exists with 255 character name "ThisIsAnExtremelyLongRoleNameDesignedToTestTheSystemBoundariesAndEnsureThatTheUIAndDatabaseCanHandleMaximumLengthRoleNamesWithoutAnyIssuesOrTruncationProblemsThisNameContinuesForAVeryLongTimeToReachTheMaximumCharacterLimitOf255CharactersExactly123456"
    And role name is visible or truncated with tooltip in UI
    And 5 permissions are available for assignment
    When administrator opens the roles dropdown in permission configuration section
    Then dropdown should display all roles including the 255 character role name
    And long role name should be truncated with ellipsis and full name in tooltip on hover
    When administrator selects the role with 255 character name from dropdown
    Then role details panel should open
    And role name should display correctly with truncation in header
    And full name should be visible on hover or in breadcrumb
    When administrator selects "Read" permission
    And administrator selects "Write" permission
    And administrator selects "Delete" permission
    And administrator selects "Admin" permission
    And administrator selects "Execute" permission
    Then counter should show "5 permissions selected"
    When administrator clicks "Submit" button
    Then system should process the request without errors
    And loading indicator should appear
    And confirmation message should display with truncated role name and tooltip
    And all 5 permissions should be successfully assigned to the role
    And database should store the full role name and permission associations correctly
    And audit log should contain full 255 character role name without truncation