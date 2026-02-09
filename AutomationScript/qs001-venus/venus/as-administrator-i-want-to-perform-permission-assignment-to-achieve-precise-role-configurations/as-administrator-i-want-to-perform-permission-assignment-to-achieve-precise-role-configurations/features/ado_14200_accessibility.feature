Feature: Accessible Permission Assignment for Role Configuration
  As an Administrator
  I want to assign permissions to roles using accessible interfaces
  So that all users including those with disabilities can manage role configurations effectively

  Background:
    Given administrator is authenticated and logged in
    And administrator is on "Permission Configuration" page

  @accessibility @a11y @priority-high @keyboard-navigation @smoke
  Scenario: Complete keyboard navigation through permission assignment workflow without mouse
    Given test role "KeyboardTestRole" exists with 2 permissions already assigned
    And mouse input is disabled for testing
    And at least 10 permissions are available in the system
    When administrator presses Tab key repeatedly to navigate to "Manage Permissions" button
    Then focus should move through page elements with visible focus indicator
    And "Manage Permissions" button should have "2px solid blue outline" focus ring
    When administrator presses Enter key to activate "Manage Permissions" button
    Then permission management interface should open
    And focus should automatically move to first interactive element
    When administrator presses Tab to reach roles dropdown
    And administrator presses Space key to open dropdown
    And administrator uses Arrow Down key to navigate to "KeyboardTestRole"
    And administrator presses Enter to select role
    Then dropdown should open with focus on first role
    And Arrow keys should navigate through roles with visual highlight
    And "KeyboardTestRole" should be selected
    And role details panel should be displayed
    When administrator presses Tab to navigate to permissions list
    And administrator uses Arrow keys to move through permission checkboxes
    And administrator presses Space to check 3 additional permissions
    Then focus should move to each permission checkbox with visible focus indicator
    And Space key should toggle checkbox state
    And "5 permissions selected" count should be displayed
    When administrator presses Tab to navigate to "Submit" button
    And administrator presses Enter to submit the form
    Then "Submit" button should receive focus with clear indicator
    And Enter key should activate submission
    And loading state should be announced
    When administrator presses Tab after submission
    Then focus should move to confirmation message or logical element
    And confirmation message should be accessible via Tab navigation
    And administrator should be able to continue navigating with keyboard
    And all permission assignment actions should be completed successfully
    And focus indicators should be visible throughout entire workflow
    And no keyboard traps should occur
    And permissions should be saved correctly in database

  @accessibility @a11y @priority-high @screen-reader @smoke
  Scenario: Screen reader announces all permission assignment actions and state changes
    Given screen reader "NVDA" is active
    And test role "ScreenReaderRole" exists in the system
    And screen reader speech output is being monitored
    And page has proper ARIA labels and live regions implemented
    When administrator navigates to permission configuration section using screen reader commands
    Then screen reader should announce "Permission Configuration, heading level 1"
    And screen reader should announce "main content region" landmark
    And screen reader should announce available interactive elements
    When administrator navigates to and activates "Manage Permissions" button
    Then screen reader should announce "Manage Permissions, button" before activation
    And screen reader should announce "Permission management dialog opened" after activation
    When administrator navigates to roles dropdown using screen reader commands
    And administrator opens dropdown
    Then screen reader should announce "Select role, combo box, collapsed"
    And screen reader should announce "expanded" when opened
    And screen reader should announce number of available options
    When administrator selects "ScreenReaderRole" from dropdown using arrow keys
    Then screen reader should announce each role name as arrow keys navigate
    And screen reader should announce "ScreenReaderRole, selected" when Enter is pressed
    And screen reader should announce "Role details loaded" when panel updates
    When administrator navigates to permissions list
    And administrator checks 3 permission checkboxes
    Then screen reader should announce "User.Read, checkbox, not checked" before activation
    And screen reader should announce "checked" after Space key press
    And live region should announce "X permissions selected" after each change
    When administrator navigates to and activates "Submit" button
    Then screen reader should announce "Submit, button"
    And screen reader should announce "Processing permission assignment" loading state
    And screen reader should announce "Permissions successfully assigned to ScreenReaderRole, alert" success message
    When administrator navigates through updated role details
    Then screen reader should announce updated permission count
    And screen reader should announce newly assigned permissions in logical reading order
    And all interactive elements should have proper accessible names
    And state changes should be announced via ARIA live regions
    And administrator should complete entire workflow using screen reader without visual reference

  @accessibility @a11y @priority-high @focus-management @smoke
  Scenario: Focus management and focus trap prevention in permission assignment modal
    Given permission assignment interface opens in modal dialog
    And test role "FocusTestRole" is available for selection
    And keyboard is the only input method being used
    When administrator opens permission management modal using Enter key on "Manage Permissions" button
    Then modal should open
    And focus should automatically move to first interactive element inside modal
    And background content should be inert
    When administrator presses Tab repeatedly to navigate through modal elements
    Then focus should cycle through close button, role dropdown, permission checkboxes, "Submit" button, "Cancel" button
    And focus should return to close button after last element
    And focus should remain trapped within modal
    When administrator presses Shift+Tab to navigate backwards
    Then focus should move in reverse order through all interactive elements
    And focus should cycle from first to last element when reaching beginning
    When administrator attempts to Tab to elements outside modal
    Then focus should remain trapped within modal
    And background should be marked with "aria-hidden" attribute set to "true"
    When administrator selects "FocusTestRole"
    And administrator checks 3 permissions
    And administrator presses Enter on "Submit" button
    Then form should submit
    And loading state should maintain focus management
    And focus should remain in modal during processing
    When modal closes after successful submission
    Then focus should return to "Manage Permissions" button
    When administrator reopens modal
    And administrator presses Escape key
    Then modal should close
    And focus should return to "Manage Permissions" button
    And no changes should be saved
    And focus should not be lost or moved to body element at any point

  @accessibility @a11y @priority-high @color-contrast @wcag-aa
  Scenario Outline: Color contrast compliance for permission assignment UI elements
    Given color contrast analyzer tool is available
    And permission assignment interface is fully loaded
    And test role with some permissions assigned is selected
    When administrator measures contrast ratio of "<element>" against background
    Then contrast ratio should be at least "<minimum_ratio>"
    And element should meet WCAG 2.1 AA standard
    And information should not be conveyed by color alone

    Examples:
      | element                                      | minimum_ratio |
      | page heading text                            | 4.5:1         |
      | role dropdown text default state             | 4.5:1         |
      | role dropdown text hover state               | 4.5:1         |
      | role dropdown text focus state               | 4.5:1         |
      | role dropdown text selected state            | 4.5:1         |
      | role dropdown border                         | 3:1           |
      | permission checkbox labels                   | 4.5:1         |
      | permission checkbox borders                  | 3:1           |
      | permission checkbox checked indicator        | 3:1           |
      | Submit button text default state             | 4.5:1         |
      | Submit button text hover state               | 4.5:1         |
      | Submit button text focus state               | 4.5:1         |
      | Submit button text disabled state            | 4.5:1         |
      | Submit button border                         | 3:1           |
      | Cancel button text default state             | 4.5:1         |
      | success message text                         | 4.5:1         |
      | success message icon                         | 3:1           |
      | error message text                           | 4.5:1         |
      | error message icon                           | 3:1           |
      | focus indicator on buttons                   | 3:1           |
      | focus indicator on checkboxes                | 3:1           |
      | focus indicator on dropdowns                 | 3:1           |

  @accessibility @a11y @priority-high @color-contrast @wcag-aa @smoke
  Scenario: Success and error messages meet contrast requirements and use multiple indicators
    Given color contrast analyzer tool is available
    And permission assignment interface is fully loaded
    When administrator triggers success confirmation message
    Then success message text should have "4.5:1" contrast against green background
    And success icon should have "3:1" contrast
    And success should be indicated by icon and text not color alone
    When administrator triggers error state by assigning conflicting permissions
    Then error message text should have "4.5:1" contrast against red background
    And error icon should have "3:1" contrast
    And error should be indicated by icon and text not color alone

  @accessibility @a11y @priority-medium @zoom @responsive
  Scenario: Permission assignment interface usability at 200% browser zoom level
    Given browser zoom is set to "100%" initially
    And test role "ZoomTestRole" exists with 5 permissions available
    And browser window is set to "1920x1080" resolution
    When administrator sets browser zoom to "200%"
    Then page content should scale to "200%"
    And all elements should remain visible and functional
    And no horizontal scrolling should be required for main content
    When administrator navigates to permission configuration section
    And administrator clicks "Manage Permissions" button
    Then button should be fully visible and clickable at "200%" zoom
    And permission management interface should open without layout breaking
    When administrator opens roles dropdown
    And administrator selects "ZoomTestRole"
    Then dropdown should be fully functional at "200%" zoom
    And all role names should be readable
    And dropdown should not extend beyond viewport
    And scrolling within dropdown should work if needed
    When administrator scrolls through permissions list
    And administrator checks 3 permission checkboxes
    Then permissions list should be scrollable if needed
    And checkboxes and labels should be properly aligned and clickable
    And text should not overlap or truncate inappropriately
    When administrator verifies all form controls are visible
    Then "Submit" button should be visible without horizontal scroll
    And "Cancel" button should be visible without horizontal scroll
    And all buttons should be properly sized and clickable
    And no UI elements should be cut off or hidden
    When administrator clicks "Submit" button
    Then confirmation message should display properly at "200%" zoom
    And text should be readable
    And message should not overflow viewport
    And close button should be accessible
    When administrator resizes browser window while at "200%" zoom
    Then layout should adapt responsively
    And content should reflow appropriately
    And no loss of functionality or content should occur
    And all functionality should remain accessible at "200%" zoom level

  @accessibility @a11y @priority-high @aria @live-regions @screen-reader
  Scenario: ARIA live regions announce dynamic permission assignment status updates
    Given screen reader is active
    And permission management interface is open
    And test role "ARIATestRole" is selected
    And ARIA live regions are implemented for dynamic content updates
    And screen reader verbosity is set to medium level
    When administrator checks first permission checkbox
    Then screen reader should announce "User.Read, checked" immediately
    And ARIA live region should announce "1 permission selected" within 2 seconds
    When administrator checks two more permission checkboxes in quick succession
    Then each checkbox state should be announced
    And live region should update to "2 permissions selected"
    And live region should update to "3 permissions selected"
    And announcements should not interrupt each other
    When administrator unchecks one permission
    Then screen reader should announce "User.Read, not checked"
    And live region should announce "2 permissions selected"
    And count should update dynamically
    When administrator clicks "Submit" button
    Then live region should announce "Processing permission assignment"
    And screen reader should indicate busy state if aria-busy is used
    When submission completes successfully
    Then ARIA live region with role alert should announce "Permissions successfully assigned to ARIATestRole"
    And announcement should interrupt other speech due to assertive priority
    When administrator triggers validation error by assigning conflicting permissions
    Then ARIA live region should announce "Cannot assign conflicting permissions: Admin and ReadOnly"
    And error should be announced with assertive priority
    When administrator navigates away from and back to updated role details
    Then screen reader should announce "ARIATestRole, 2 permissions assigned"
    And all dynamic content changes should be announced via ARIA live regions
    And announcements should use appropriate politeness levels

  @accessibility @a11y @priority-high @error-handling @form-validation @screen-reader
  Scenario: Error messages for conflicting permissions are accessible and associated with form controls
    Given screen reader is active
    And test role "ErrorTestRole" exists in the system
    And conflicting permissions "Admin" and "ReadOnly" exist in system
    And form validation is implemented with ARIA error handling
    When administrator selects "ErrorTestRole"
    And administrator assigns conflicting permission "Admin"
    And administrator assigns conflicting permission "ReadOnly"
    And administrator clicks "Submit" button
    Then form validation should prevent submission
    And error message "Cannot assign conflicting permissions: Admin and ReadOnly" should be displayed
    And error message should be associated with permission checkboxes via aria-describedby
    When administrator uses screen reader to navigate to permission checkboxes with errors
    Then screen reader should announce "Admin, checkbox, checked, invalid, Cannot assign conflicting permissions: Admin and ReadOnly"
    And "aria-invalid" attribute should be set to "true" on relevant controls
    And error icon should appear next to conflicting permissions
    And error text should be displayed with sufficient contrast "4.5:1"
    And error should be indicated by icon and text not color alone
    When validation error occurs
    Then focus should move to first invalid field or error summary
    And error summary should have role alert or be in ARIA live region
    When administrator unchecks one of the conflicting permissions
    Then error message should disappear or update
    And "aria-invalid" attribute should be set to "false" on controls
    And screen reader should announce "Error resolved" via live region
    And all error messages should be programmatically associated with form controls
    And invalid controls should have "aria-invalid" attribute set to "true"
    And errors should be indicated by multiple means not color alone

  @accessibility @a11y @priority-high @error-handling @network-error
  Scenario: Network error messages are accessible and provide actionable guidance
    Given screen reader is active
    And test role "ErrorTestRole" exists in the system
    And form validation is implemented with ARIA error handling
    When administrator selects "ErrorTestRole"
    And administrator assigns 3 valid permissions
    And network connection is disconnected
    And administrator clicks "Submit" button
    Then network error message "Unable to save permissions. Please check your connection and try again" should be displayed
    And error should have role alert
    And error should be announced by screen reader
    And error should provide actionable guidance
    And error message should be specific and actionable
    And error message should provide guidance on how to fix issue

  @accessibility @a11y @priority-high @error-handling @form-validation @multiple-errors
  Scenario: Error summary provides clear instructions for multiple validation errors
    Given screen reader is active
    And test role "ErrorTestRole" exists in the system
    And form validation is implemented with ARIA error handling
    When administrator triggers multiple validation errors
    Then error summary should provide clear instructions for resolution
    And error messages should be specific and actionable
    And error messages should provide guidance on how to fix errors
    And error summary should include error count