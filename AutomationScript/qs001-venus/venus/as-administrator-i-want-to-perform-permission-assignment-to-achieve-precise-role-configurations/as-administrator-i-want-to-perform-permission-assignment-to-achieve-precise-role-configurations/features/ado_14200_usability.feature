Feature: Administrator Permission Assignment with Real-Time Feedback and Error Prevention
  As an Administrator
  I want to perform permission assignment with real-time feedback and conflict prevention
  So that I can achieve precise role configurations while maintaining security and avoiding errors

  Background:
    Given administrator is authenticated with admin privileges
    And at least one role exists in the system
    And permission configuration section is accessible

  @usability @functional @priority-critical @smoke
  Scenario: System provides real-time feedback during permission assignment validation and submission
    Given multiple permissions are available for assignment
    When administrator navigates to permission configuration section
    Then page should load with clear indication of current section
    And available roles should be displayed
    When administrator selects a role to modify permissions
    Then system should display visual feedback showing which role is selected
    And current permissions for selected role should be loaded
    When administrator begins assigning multiple permissions to the role
    Then each permission selection should show immediate visual feedback
    And checkmark or color change should be displayed for selected permissions
    And permission counter should update in real-time
    When administrator submits the permission assignment form
    Then system should display loading indicator
    And "Validating permissions..." status message should be displayed
    When administrator observes the validation and submission process
    Then progress indicator should show validation completion
    And "Updating role permissions..." message should be displayed during API call
    When administrator waits for process completion
    Then confirmation message "Permissions successfully assigned" should be displayed
    And role name should be shown in confirmation message
    And timestamp should be displayed
    And summary of changes should be visible

  @usability @functional @negative @priority-critical @smoke
  Scenario: System prevents conflicting permission assignments before submission
    Given system has defined conflicting permission rules
    And a role is selected for permission modification
    And permission assignment interface is displayed
    When administrator selects "read_only" permission
    Then permission should be selected
    And conflicting permissions should be automatically disabled
    And conflicting permissions should be visually marked as unavailable
    When administrator attempts to select a conflicting permission
    Then system should prevent selection
    And inline warning message "This permission conflicts with read_only. Please deselect read_only first." should be displayed
    When administrator hovers over disabled conflicting permissions
    Then tooltip should appear explaining why permission is unavailable
    And tooltip should show which permission is causing the conflict
    When administrator tries to assign "delete_all" and "bypass_audit" permissions together
    Then warning dialog should be displayed
    And dialog should show "This combination may pose security risks. Are you sure you want to proceed?"
    And explanation of the security risk should be provided
    When administrator observes the submit button state with conflicts
    Then submit button should be disabled
    And tooltip "Cannot submit: Conflicting permissions detected" should be displayed
    And submit button should remain disabled until conflicts are resolved

  @usability @functional @priority-high
  Scenario: Permission assignment interface minimizes memory load through recognition aids
    Given multiple roles exist with varying permission sets
    And permission assignment history exists in the system
    And at least 10 permissions are available in the system
    When administrator navigates to permission configuration section
    And administrator selects a role
    Then role name should be displayed prominently
    And currently assigned permissions should be clearly marked
    And available permissions should be visible
    And permission categories should be displayed for easy scanning
    When administrator reviews the permission list without clicking
    Then each permission should show name and brief description
    And icon or visual indicator should be displayed for each permission
    And current assignment status should be visible without navigation
    When administrator hovers over info icon next to a permission
    Then detailed tooltip should appear
    And full permission description should be shown
    And actions enabled by permission should be displayed
    And potential security implications should be visible
    And list of other roles with this permission should be shown
    When administrator looks for visual indicators of permission relationships
    Then system should display visual grouping with color coding
    And related permissions should be shown with indentation
    And permission dependencies should be visible
    When administrator checks for visibility of recent changes
    Then "Recently modified" indicator should be displayed
    And last 5 permission changes should be shown with timestamps
    And administrator who made each change should be visible
    When administrator searches for permissions
    Then search box should be prominently visible
    And placeholder text should show example searches
    And filters should be available for permission categories
    And exact permission names should not be required for search

  @usability @negative @priority-high
  Scenario Outline: Error messages are helpful and guide administrators to recover from permission assignment errors
    Given permission assignment interface is accessible
    When administrator encounters "<error_scenario>"
    Then error message "<error_message>" should be displayed
    And error should appear near the relevant field or section
    And error icon should be displayed
    And error should use warning color styling
    And error message should be in plain language without technical jargon
    And actionable next steps should be provided
    And all selected permissions should remain selected after error
    And administrator should be able to fix issue without re-entering data

    Examples:
      | error_scenario                          | error_message                                                                                                                                    |
      | conflicting permissions submitted       | Permission conflict detected: Permission A cannot be assigned with Permission B. Please remove one of these permissions and try again.           |
      | network failure during submission       | Unable to save permissions due to connection issue. Your changes have been saved locally. Click 'Retry' to attempt saving again.                 |
      | permissions exceed role capacity limits | This role can have maximum 10 permissions. Currently selected: 12. Please deselect 2 permissions.                                                |
      | insufficient privileges for assignment  | You do not have permission to assign Admin Permission. This requires Super Admin privileges. Contact support@example.com to request this change. |

  @usability @negative @priority-high
  Scenario: Network failure error provides retry functionality
    Given permission assignment interface is accessible
    And administrator has selected permissions for a role
    When administrator submits permission assignment form
    And network failure occurs during submission
    Then error message "Unable to save permissions due to connection issue. Your changes have been saved locally." should be displayed
    And "Retry" button should be prominently displayed
    When administrator clicks "Retry" button
    Then system should attempt to save permissions again
    And loading indicator should be displayed

  @usability @negative @priority-high
  Scenario: Permission capacity limit error shows current selection details
    Given permission assignment interface is accessible
    And role has maximum capacity of 10 permissions
    When administrator selects 12 permissions for the role
    And administrator submits permission assignment form
    Then error message "This role can have maximum 10 permissions. Currently selected: 12. Please deselect 2 permissions." should be displayed
    And counter showing current versus maximum should be visible
    And list of selected permissions should be displayed for easy review