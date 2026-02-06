Feature: Role Modification Accessibility Compliance
  As an Administrator
  I want to modify user roles with full accessibility support
  So that all users including those with disabilities can manage role permissions effectively

  Background:
    Given administrator is authenticated and logged in
    And administrator is on "Role Management" page at "/admin/roles"

  @accessibility @a11y @keyboard-navigation @priority-high @smoke
  Scenario: Complete keyboard navigation through role modification workflow
    Given test role "KeyboardNavRole" exists with 5 permissions
    And mouse input is disabled for keyboard-only testing
    And screen zoom level is set to 100 percent
    And browser supports standard keyboard navigation
    When administrator presses Tab key repeatedly to navigate to "KeyboardNavRole" role
    Then focus indicator should be visible on "KeyboardNavRole" with minimum "2" pixel border
    And focus indicator should have high contrast color
    When administrator presses Enter key to open role modification form
    Then role edit form should open
    And focus should automatically move to "Role Name" field
    And focus indicator should be clearly visible
    When administrator presses Tab key to move focus to permissions section
    And administrator uses Arrow Down key to navigate through permission checkboxes
    Then focus should move to first permission checkbox
    And each focused checkbox should have visible focus indicator
    And Space bar should toggle checkbox selection
    When administrator presses Space bar to toggle 2 permissions
    And administrator presses Tab to move to "Description" field
    Then checkboxes should toggle correctly with Space bar
    And focus should move to "Description" textarea with visible focus indicator
    And permission counter should update to reflect changes
    When administrator types "Modified via keyboard navigation test" in "Description" field
    And administrator presses Tab to reach "Save Changes" button
    Then text should be entered successfully in "Description" field
    And focus should move to "Save Changes" button with clear focus indicator
    And button should show focused state
    When administrator presses Enter key to submit the form
    Then form should submit successfully
    And success message should appear and receive focus
    And focus management should return to logical location
    When administrator presses Tab key to navigate through success message
    Then focus should move logically through all interactive elements
    And no keyboard traps should exist
    And administrator should be able to navigate back to roles list using Tab and Shift+Tab

  @accessibility @a11y @screen-reader @aria @priority-high @smoke
  Scenario: Screen reader compatibility and ARIA announcements for role modification
    Given screen reader is enabled
    And screen reader is configured to announce all ARIA live regions and labels
    And test role "ScreenReaderRole" exists with 4 permissions
    And audio output is enabled
    When administrator navigates to role management page
    Then screen reader should announce "Role Management, main region"
    And page heading "Role Management" should be announced with heading level "H1"
    And navigation landmarks should be properly identified
    When administrator navigates to "ScreenReaderRole" using screen reader commands
    Then screen reader should announce "ScreenReaderRole, button"
    And role description should be announced if present
    And current permissions count "4 permissions assigned" should be announced
    When administrator activates the role to open modification form
    Then screen reader should announce "Edit Role form, dialog"
    And form field "Role Name" should be announced as "Role Name, edit text, ScreenReaderRole"
    And form field "Permissions" should be announced as "Permissions, group"
    And form field "Description" should be announced as "Description, edit text"
    When administrator navigates to permissions section
    Then each permission checkbox should be announced with label and state
    And group label "Permissions" should be announced
    And total count "4 of 20 permissions selected" should be announced
    When administrator toggles 2 permission checkboxes
    Then screen reader should announce state changes for each checkbox
    And ARIA live region should announce "Permissions updated, 5 selected"
    When administrator navigates to "Save Changes" button and activates it
    Then button should be announced as "Save Changes, button"
    And ARIA live region should announce "Success: Role ScreenReaderRole successfully updated" with assertive politeness
    When administrator attempts to create conflicting permission
    Then error message "Error: Conflicting permissions detected. Please review your selections." should be announced via ARIA live region with assertive politeness
    And error should be associated with relevant form field

  @accessibility @a11y @focus-management @modal @priority-high
  Scenario: Focus management and focus trap prevention in role modification modal
    Given test role "FocusTestRole" exists
    And role modification opens in modal dialog overlay
    And keyboard navigation is the primary input method
    And background content is visible
    When administrator activates "FocusTestRole" to open modification modal
    Then modal should open with overlay
    And focus should automatically move to first focusable element in modal
    And background content should be visually dimmed
    And background content should be marked as inert with "aria-hidden" attribute set to "true"
    When administrator presses Tab key repeatedly to cycle through modal elements
    Then focus should move through all focusable elements within modal
    And focus should stay within modal boundaries
    When administrator continues pressing Tab after reaching last focusable element
    Then focus should wrap back to first focusable element
    And focus should never escape to background content
    When administrator presses Shift+Tab from first focusable element
    Then focus should move backward to last focusable element
    And reverse tabbing should maintain focus within modal
    When administrator presses Escape key
    Then modal should close immediately
    And focus should return to "FocusTestRole" trigger element
    And background content should become interactive again
    When administrator reopens modal and makes changes to permissions
    And administrator clicks "Cancel" button
    Then modal should close
    And unsaved changes should be discarded
    And focus should return to "FocusTestRole" trigger element
    When administrator reopens modal and makes changes
    And administrator clicks "Save Changes" button
    Then modal should close after successful save
    And focus should move to success message or updated role in list
    And focus should never be lost or sent to top of page

  @accessibility @a11y @color-contrast @visual @priority-high @wcag-aa
  Scenario Outline: Color contrast and visual accessibility for role modification interface
    Given administrator is on role management page
    And color contrast analyzer tool is available
    And test role "ContrastTestRole" is visible in roles list
    And page is viewed at 100 percent zoom
    And browser is set to default colors
    When administrator measures contrast ratio of "<element_type>" against background
    Then contrast ratio should be at least "<minimum_ratio>" for "<text_size>" text
    And element should be clearly readable

    Examples:
      | element_type                  | minimum_ratio | text_size   |
      | role name text                | 4.5:1         | normal      |
      | form labels                   | 4.5:1         | normal      |
      | input field borders           | 3:1           | UI component|
      | placeholder text              | 4.5:1         | normal      |
      | focus indicators              | 3:1           | UI component|
      | error message text            | 4.5:1         | normal      |
      | success message text          | 4.5:1         | normal      |

  @accessibility @a11y @color-contrast @visual @priority-high @wcag-aa
  Scenario: Visual indicators beyond color for role modification states
    Given administrator is on role management page
    And test role "ContrastTestRole" is open for editing
    When administrator checks permission checkboxes
    Then checked checkboxes should use checkmark icon in addition to color
    And unchecked boxes should have clear empty state
    And states should be distinguishable in grayscale mode
    When administrator triggers validation error
    Then error state should be indicated by icon or text in addition to red color
    And error borders should have sufficient contrast
    When administrator successfully saves role
    Then success state should use icon or text in addition to green color
    When administrator enables Windows High Contrast Mode
    Then all text should remain visible and readable
    And interactive elements should be distinguishable
    And focus indicators should be visible
    And no information should be conveyed by color alone

  @accessibility @a11y @zoom @text-scaling @priority-medium @wcag-aa
  Scenario Outline: Text scaling and zoom accessibility for role modification
    Given administrator is on role management page at 100 percent zoom
    And test role "ZoomTestRole" exists with 6 permissions
    And screen resolution is set to "1920x1080"
    When administrator increases browser zoom to "<zoom_level>" percent
    Then page should scale to "<zoom_level>" percent
    And all content should remain visible
    And no horizontal scrolling should be required for main content
    And text should be readable and not truncated
    When administrator navigates to "ZoomTestRole" in roles list
    Then roles list should remain usable
    And role names should be fully visible
    And action buttons should be accessible and not overlapping
    When administrator opens "ZoomTestRole" modification form
    Then form should open properly scaled
    And all form fields should be visible and accessible
    And no content should be cut off or hidden
    When administrator navigates through form fields
    Then all form labels should be fully visible and readable
    And input fields should be appropriately sized
    And checkboxes and labels should not be overlapping
    When administrator scrolls through permissions list and selects 3 permissions
    Then permissions list should be scrollable if needed
    And checkboxes should remain aligned with labels
    And no text truncation should occur
    And permission counter should update and be visible
    When administrator clicks "Save Changes" button
    Then button should be fully visible and accessible
    And button text should not be truncated
    And button should be large enough to click easily with minimum "44" by "44" pixel touch target
    When administrator views success message
    Then success message should be fully readable
    And message should not be cut off or hidden
    And close button should be accessible if present

    Examples:
      | zoom_level |
      | 150        |
      | 200        |
      | 250        |

  @accessibility @a11y @aria @live-regions @screen-reader @priority-high
  Scenario: ARIA live regions and dynamic content announcements for real-time updates
    Given administrator is logged in with screen reader active
    And test role "LiveRegionRole" is open in modification form
    And screen reader is configured to announce ARIA live regions
    When administrator selects permission checkbox with screen reader active
    Then ARIA live region should announce "Permission user.delete added, 5 permissions selected" within "2" seconds
    And announcement should be clear and contextual
    When administrator deselects same permission checkbox
    Then ARIA live region should announce "Permission user.delete removed, 4 permissions selected"
    And counter update should be announced automatically
    When administrator enters invalid data in "Role Name" field and tabs out
    Then ARIA live region with "assertive" politeness should announce "Error: Role name contains invalid characters" immediately
    And error should be announced without requiring navigation to error message
    When administrator corrects the validation error
    Then ARIA live region should announce "Role name is valid"
    And positive feedback should be provided for successful correction
    When administrator selects 4 permissions rapidly in quick succession
    Then ARIA live region with "polite" politeness should batch announcements appropriately
    And final state "7 permissions selected" should be announced
    When administrator clicks "Save Changes" button
    Then ARIA live region should announce "Saving role changes..." during processing
    And ARIA live region should announce "Success: Role LiveRegionRole successfully updated" after completion
    When administrator triggers server error by simulating network failure
    Then ARIA live region with "assertive" politeness should announce "Error: Unable to save role. Please check your connection and try again." immediately
    And error should provide actionable guidance

  @accessibility @a11y @mobile @touch-targets @priority-medium
  Scenario: Mobile accessibility and touch target sizing for role modification on tablet
    Given administrator is logged in on tablet device with "768" pixel width viewport
    And test role "MobileAccessRole" exists with 5 permissions
    And touch input is primary interaction method
    And device is in portrait orientation
    When administrator navigates to role management page on tablet
    Then all interactive elements should have minimum "44" by "44" pixel touch targets
    And adequate spacing of minimum "8" pixels should exist between touch targets
    When administrator taps on "MobileAccessRole" to open modification form
    Then form should open in mobile-optimized layout
    And tap target should be easy to activate without accidental adjacent taps
    And form fields should be appropriately sized for touch input
    When administrator taps on "Role Name" input field
    Then virtual keyboard should appear
    And input field should have minimum "44" pixel height
    And field label should remain visible when keyboard is open
    And zoom should not be triggered on focus with font-size "16" pixels or larger
    When administrator scrolls through permissions list and taps checkboxes
    Then checkboxes should have minimum "44" by "44" pixel touch targets
    And checkbox labels should be tappable to toggle state
    And scrolling should be smooth without accidental checkbox activation
    And adequate spacing should prevent mis-taps
    When administrator taps on "Description" textarea and enters multi-line text
    Then textarea should expand appropriately for content
    And virtual keyboard should not obscure textarea
    And text entry should be smooth without lag
    And textarea should have minimum "44" pixel height
    When administrator rotates device to landscape orientation
    Then form should adapt to landscape layout
    And all fields should remain accessible
    And touch targets should maintain minimum size
    And no content should be cut off or inaccessible
    When administrator taps "Save Changes" button
    Then button should have minimum "44" by "44" pixel size
    And button should provide visual feedback on tap
    And success message should appear and be readable on mobile viewport
    When administrator enables mobile screen reader
    Then swipe gestures should navigate between elements correctly
    And double-tap should activate elements
    And all elements should have proper labels announced
    And rotor controls should work as expected