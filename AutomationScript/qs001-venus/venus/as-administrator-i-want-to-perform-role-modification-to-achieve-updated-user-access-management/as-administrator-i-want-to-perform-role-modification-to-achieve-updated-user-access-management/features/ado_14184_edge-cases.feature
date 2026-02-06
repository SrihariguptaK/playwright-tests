Feature: Role Modification with Edge Case Handling
  As an Administrator
  I want to modify existing roles with edge case scenarios
  So that the system handles boundary conditions and concurrent operations reliably

  Background:
    Given administrator is logged in with full admin privileges
    And role management page is accessible

  @edge @regression @priority-high
  Scenario: Modify role with maximum allowed permissions boundary
    Given test role "MaxPermRole" exists with 50 permissions assigned
    And system allows maximum of 100 permissions per role
    And database has 100 total available permissions configured
    When administrator navigates to role management section
    And administrator clicks on "MaxPermRole" to open edit form
    Then role modification form should display 50 permissions selected
    When administrator selects all remaining 50 available permissions
    Then permission selector should show "100/100 selected"
    When administrator enters "Testing maximum permission boundary" in "Notes" field
    And administrator clicks "Save Changes" button
    Then system should process request within 2 seconds
    And success message "Role MaxPermRole successfully updated with 100 permissions" should be displayed
    And role details page should show all 100 permissions listed
    And role "MaxPermRole" should be saved in database with 100 permissions
    And audit log should contain entry with "ROLE_MODIFIED" action

  @edge @regression @priority-medium
  Scenario: Modify role name with special characters and Unicode
    Given test role "BasicRole" exists with 5 standard permissions
    And system supports UTF-8 character encoding
    When administrator clicks on "BasicRole" in the roles list
    Then role edit form should display with current role name "BasicRole"
    When administrator changes role name to "Admin-Role_2024 (Tëst) 管理者 🔒"
    Then name field should accept all special characters and Unicode without validation errors
    When administrator adds permission "user.view" to existing permissions
    Then permission counter should show "6 permissions selected"
    When administrator clicks "Save Changes" button
    Then system should validate and process request within 2 seconds
    And role name "Admin-Role_2024 (Tëst) 管理者 🔒" should display correctly without character corruption
    And all special characters and emoji should render properly
    And role should be saved with Unicode name exactly as entered
    And audit log should record modification with proper character encoding

  @edge @regression @priority-high
  Scenario: Simultaneous role modification by multiple administrators
    Given two administrators "Admin1" and "Admin2" are logged in from different browser sessions
    And both administrators have role modification permissions
    And test role "ConcurrentTestRole" exists with permissions "user.read, user.write"
    And role management page is open in both browser sessions
    And system implements optimistic or pessimistic locking mechanism
    When "Admin1" opens "ConcurrentTestRole" for editing
    And "Admin1" adds permission "user.delete"
    Then "Admin1" edit form should show 3 permissions selected
    When "Admin2" opens "ConcurrentTestRole" for editing
    And "Admin2" adds permission "user.admin"
    Then "Admin2" edit form should show 3 permissions selected
    When "Admin1" clicks "Save Changes" button first
    Then "Admin1" should see success message "Role ConcurrentTestRole successfully updated"
    And role should have permissions "user.read, user.write, user.delete"
    When "Admin2" clicks "Save Changes" button after 2 seconds
    Then system should detect conflict
    And warning message "This role was modified by another administrator. Please review the current permissions before saving." should be displayed
    And option to reload or force save should be available
    When "Admin2" clicks "Reload Current Version" button
    Then form should refresh showing current permissions "user.read, user.write, user.delete"
    When "Admin2" adds "user.admin" permission again
    And "Admin2" clicks "Save Changes" button
    Then success message should be displayed
    And role should have all 4 permissions "user.read, user.write, user.delete, user.admin"
    And audit log should show two separate modification entries with timestamps

  @edge @regression @priority-medium
  Scenario: Modify role with extremely long description at character limit boundary
    Given test role "DescriptionTestRole" exists with a short description
    And role description field has maximum character limit of 1000 characters
    And browser displays character count for text areas
    When administrator clicks on "DescriptionTestRole" to open modification form
    Then edit form should display with character counter showing current count
    When administrator clears existing description
    And administrator pastes exactly 1000 characters of text into description field
    Then text area should accept all 1000 characters
    And counter should display "1000/1000 characters"
    And no validation error should appear
    When administrator attempts to type one additional character
    Then system should prevent input beyond 1000 characters
    And counter should remain at "1000/1000"
    And visual indicator should show limit reached
    When administrator removes 50 characters
    And administrator adds permission "report.generate" to the role
    Then character counter should update to "950/1000"
    And permission should be added successfully
    When administrator clicks "Save Changes" button
    Then system should save successfully within 2 seconds
    And confirmation message "Role DescriptionTestRole successfully updated" should be displayed
    When administrator reopens the role to verify description
    Then description field should show exactly 950 characters as entered
    And no text truncation should have occurred

  @edge @regression @priority-high
  Scenario: Modify role during high system load with concurrent operations
    Given system is under simulated high load with 50 concurrent user sessions
    And test role "LoadTestRole" exists with 10 permissions
    And performance monitoring tools are active
    And database connection pool has 20 active connections out of 25 maximum
    When administrator navigates to role management
    And administrator clicks on "LoadTestRole" to open edit form
    Then form should load within 3 seconds despite high load
    And form should display current 10 permissions
    When administrator adds permissions "audit.read, audit.write, system.config, backup.create, backup.restore"
    Then permissions should be selected successfully
    And counter should show "15 permissions selected"
    When administrator updates role description to "Modified during high load test - performance validation"
    Then description field should accept input without lag or UI freezing
    When administrator clicks "Save Changes" button
    Then system should process request within 2 seconds
    And loading indicator should display during processing
    And success message "Role LoadTestRole successfully updated" should be displayed
    And audit log should show modification entry with correct timestamp
    And all 15 permissions should be correctly saved in database
    And system should remain stable with no connection pool exhaustion

  @edge @regression @priority-medium
  Scenario: Modify role by removing all permissions then adding them back
    Given test role "EmptyPermRole" exists with 8 permissions assigned
    And role is not currently assigned to any active users
    And system allows roles to exist with zero permissions temporarily
    When administrator opens "EmptyPermRole" in role modification form
    Then edit form should display 8 currently assigned permissions
    When administrator clicks "Deselect All" button
    Then all permissions should be unchecked
    And counter should show "0 permissions selected"
    And warning message "Role will have no permissions. Users with this role will have no access." should appear
    When administrator clicks "Save Changes" with zero permissions
    Then confirmation dialog "Are you sure you want to save this role with no permissions? This may affect user access." should be displayed
    When administrator clicks "Confirm" button
    Then role should be saved with zero permissions
    And success message "Role EmptyPermRole updated successfully" should appear
    And audit log should record the change
    When administrator immediately reopens "EmptyPermRole"
    And administrator adds permissions "user.read, role.read, audit.read, report.read, dashboard.view"
    Then permissions should be selected successfully
    And counter should show "5 permissions selected"
    When administrator clicks "Save Changes" button
    Then success message should be displayed
    And role should have 5 permissions
    And modification should complete within 2 seconds
    And audit log should contain two entries for both modifications

  @edge @regression @priority-high
  Scenario: Modify role with session timeout occurring during modification
    Given administrator session timeout is set to 15 minutes
    And administrator has been idle for 14 minutes and 30 seconds
    And test role "TimeoutTestRole" is open in edit mode with unsaved changes
    And role has 3 permissions currently
    And administrator has added 2 more permissions unsaved
    And system implements session timeout with warning mechanism
    When administrator waits for 30 seconds with unsaved changes
    Then session timeout warning modal should appear with message "Your session is about to expire in 30 seconds. Would you like to extend your session?"
    And "Extend Session" and "Logout" buttons should be displayed
    When administrator clicks "Extend Session" button
    Then session should be extended
    And modal should close
    And user should remain on role edit form
    And all unsaved changes should be preserved with 5 permissions selected
    When administrator adds permission "system.monitor"
    Then permission should be added successfully
    And counter should show "6 permissions selected"
    When administrator clicks "Save Changes" button
    Then system should validate active session
    And system should process request successfully
    And success message "Role TimeoutTestRole successfully updated" should be displayed
    And role should have 6 permissions saved correctly
    And audit log should show single modification entry with current timestamp
    And session extension event should be logged separately