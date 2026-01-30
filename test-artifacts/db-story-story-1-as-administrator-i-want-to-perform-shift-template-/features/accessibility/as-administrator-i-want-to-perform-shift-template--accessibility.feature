@accessibility @a11y @wcag
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify complete keyboard navigation through shift template creation workflow using Tab, Enter, and Escape keys
    Given user is logged in as Administrator
    And user is on Shift Template Management page
    And screen reader is not active (testing keyboard-only navigation)
    And browser is set to show focus indicators
    When press Tab key repeatedly to navigate through page elements until 'Create New Template' button receives focus
    Then visible focus indicator (blue outline or highlight) appears on 'Create New Template' button
    And press Enter key to activate 'Create New Template' button
    Then template creation form modal opens and focus automatically moves to first form field (Template Name)
    And type 'Keyboard Test' in Template Name field, then press Tab to move to Start Time field
    Then focus moves to Start Time dropdown with visible focus indicator, Template Name contains 'Keyboard Test'
    And press Enter or Space to open Start Time dropdown, use Arrow keys to select '09:00 AM', press Enter to confirm
    Then start Time dropdown opens, Arrow keys navigate through time options, Enter selects '09:00 AM' and closes dropdown
    And press Tab to move to End Time field, repeat selection process to choose '05:00 PM'
    Then focus moves to End Time field, time selection works with keyboard, '05:00 PM' is selected
    And press Tab to navigate to 'Add Break' button and press Enter
    Then break time fields appear and focus moves to first break time field
    And use keyboard to add break from '12:00 PM' to '01:00 PM', then Tab to 'Save Template' button and press Enter
    Then break is added successfully, focus moves to Save button, Enter key saves template and shows success message
    And press Escape key to close success message or modal
    Then modal closes and focus returns to 'Create New Template' button or first element in templates list
    And entire workflow is completable using only keyboard
    And focus order is logical and follows visual layout
    And focus is never trapped and always visible
    And template is successfully created using keyboard only

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader announces all form fields, labels, errors, and success messages correctly
    Given user is logged in as Administrator
    And nVDA or JAWS screen reader is active and running
    And user is on Shift Template Management page
    And screen reader verbosity is set to default level
    When navigate to 'Create New Template' button using screen reader navigation commands
    Then screen reader announces: 'Create New Template, button' with role and state information
    And activate button and navigate to Template Name field
    Then screen reader announces: 'Template Name, edit, required' indicating field label, type, and required status
    And navigate to Start Time field without entering data
    Then screen reader announces: 'Start Time, combobox, required, collapsed' with instructions 'Press Alt+Down to open'
    And attempt to save form with empty required fields
    Then screen reader announces each validation error: 'Error: Template Name is required', 'Error: Start Time is required', 'Error: End Time is required' with error role
    And fill all required fields correctly and save template
    Then screen reader announces: 'Success: Shift template created successfully' with alert or status role
    And navigate to newly created template in the list
    Then screen reader announces template details: 'Morning Shift, Start Time: 09:00 AM, End Time: 05:00 PM, Break: 12:00 PM to 01:00 PM, Edit button, Delete button'
    And navigate to Edit and Delete buttons for the template
    Then screen reader announces: 'Edit Morning Shift template, button' and 'Delete Morning Shift template, button' with context
    And all interactive elements have proper ARIA labels and roles
    And screen reader users receive all necessary information
    And error and success messages are announced via ARIA live regions
    And context is provided for all buttons and controls

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify focus management and focus trap in modal dialog during template creation
    Given user is logged in as Administrator
    And user is on Shift Template Management page
    And keyboard navigation is being used
    When use keyboard to open 'Create New Template' modal dialog
    Then modal opens and focus automatically moves to first focusable element (Template Name field or Close button)
    And press Tab repeatedly to cycle through all focusable elements in the modal
    Then focus cycles through: Template Name, Start Time, End Time, Add Break button, Save Template button, Cancel button, Close (X) button
    And continue pressing Tab after reaching last focusable element (Close button)
    Then focus wraps back to first focusable element (Template Name field), creating a focus trap within modal
    And press Shift+Tab from first element
    Then focus moves backward to last focusable element (Close button), reverse focus trap works correctly
    And attempt to Tab to elements outside the modal (page header, navigation)
    Then focus remains trapped within modal, cannot reach elements outside modal while it is open
    And press Escape key to close modal
    Then modal closes and focus returns to 'Create New Template' button that originally opened the modal
    And open modal again, click Cancel button
    Then modal closes and focus returns to 'Create New Template' button
    And focus is properly trapped within modal when open
    And focus returns to trigger element when modal closes
    And users cannot accidentally interact with background content
    And escape key provides keyboard method to close modal

  @high @tc-acce-004
  Scenario: TC-ACCE-004 - Verify color contrast ratios meet WCAG 2.1 Level AA standards (4.5:1 for normal text)
    Given user is on Shift Template Management page
    And color contrast analyzer tool is available (browser extension or standalone)
    And page is displayed at 100% zoom in standard lighting conditions
    When use color contrast analyzer to check contrast ratio of 'Create New Template' button text against button background
    Then contrast ratio is at least 4.5:1 for normal text or 3:1 for large text (18pt+), meets WCAG AA standards
    And check contrast ratio of form field labels (Template Name, Start Time, End Time) against page background
    Then all label text has contrast ratio of at least 4.5:1 against background
    And check contrast ratio of placeholder text in input fields
    Then placeholder text has contrast ratio of at least 4.5:1 (not relying on 3:1 exception for disabled text)
    And check contrast ratio of error messages (red text) against background
    Then error message text has contrast ratio of at least 4.5:1, error is not conveyed by color alone (includes icon or text indicator)
    And check contrast ratio of success message (green text/background) against its background
    Then success message text has contrast ratio of at least 4.5:1, success is not conveyed by color alone
    And check contrast ratio of focus indicators (outline/border) against background
    Then focus indicator has contrast ratio of at least 3:1 against adjacent colors (WCAG 2.1 non-text contrast requirement)
    And all text meets WCAG AA contrast requirements
    And users with low vision can read all content
    And color is not the only means of conveying information
    And focus indicators are clearly visible

  @medium @tc-acce-005
  Scenario: TC-ACCE-005 - Verify page functionality and readability at 200% browser zoom level
    Given user is logged in as Administrator
    And user is on Shift Template Management page
    And browser zoom is set to 100% initially
    And browser window is at standard desktop resolution (1920x1080)
    When increase browser zoom to 200% using Ctrl/Cmd + Plus or browser zoom controls
    Then page content scales proportionally, all text is larger and readable
    And verify all page elements remain visible without horizontal scrolling (vertical scrolling is acceptable)
    Then page layout adapts responsively, no content is cut off, horizontal scrolling is not required or is minimal
    And click 'Create New Template' button at 200% zoom
    Then button is clickable, modal opens correctly, all form fields are visible and accessible
    And fill out template creation form at 200% zoom
    Then all form fields are usable, dropdowns open correctly, text input is visible, no overlapping elements
    And verify validation error messages display correctly at 200% zoom
    Then error messages are fully visible, readable, and properly positioned near relevant fields
    And save template and verify success message at 200% zoom
    Then success message displays correctly, is fully readable, and does not overlap other content
    And verify templates list displays correctly at 200% zoom
    Then template list is readable, all columns are visible (may require scrolling), action buttons are accessible
    And all functionality works at 200% zoom
    And content reflows appropriately without loss of information
    And users with low vision can use the feature at increased zoom levels
    And no content is hidden or inaccessible due to zoom

  @high @tc-acce-006
  Scenario: TC-ACCE-006 - Verify ARIA live regions announce dynamic content changes for template creation and deletion
    Given user is logged in as Administrator
    And screen reader (NVDA or JAWS) is active
    And user is on Shift Template Management page
    And at least one template exists in the system
    When create a new template using the form and click Save
    Then screen reader announces 'Shift template created successfully' immediately without requiring navigation, using aria-live='polite' or 'assertive' region
    And verify screen reader announces the updated template count
    Then screen reader announces 'Total templates: X' where X is the new count, using aria-live region
    And attempt to save a template with validation errors
    Then screen reader announces each validation error as it appears: 'Error: Template Name is required' using aria-live='assertive' for immediate announcement
    And delete an existing template
    Then screen reader announces 'Shift template deleted successfully' and updated count 'Total templates: X' using aria-live region
    And edit a template and save changes
    Then screen reader announces 'Shift template updated successfully' using aria-live region
    And trigger a network error during save operation
    Then screen reader announces error message 'Network error: Unable to save template' using aria-live='assertive' for critical errors
    And all dynamic content changes are announced to screen reader users
    And aRIA live regions are properly implemented with appropriate politeness levels
    And users are informed of success, errors, and state changes without manual navigation
    And critical errors use assertive live regions for immediate announcement

  @medium @tc-acce-007
  Scenario: TC-ACCE-007 - Verify mobile accessibility with touch targets meeting minimum size requirements (44x44 CSS pixels)
    Given user is logged in as Administrator on mobile device or browser in mobile emulation mode
    And device viewport is set to mobile size (375x667 iPhone size or similar)
    And user is on Shift Template Management page in mobile view
    When measure the touch target size of 'Create New Template' button using browser developer tools
    Then button has minimum dimensions of 44x44 CSS pixels (or 48x48 for better accessibility), easily tappable with finger
    And measure touch target sizes of Edit and Delete icon buttons in templates list
    Then each icon button has minimum 44x44 pixel touch target, adequate spacing between buttons (at least 8 pixels) to prevent accidental taps
    And open template creation form on mobile and verify form field touch targets
    Then all form fields (Template Name input, Start Time dropdown, End Time dropdown) have touch targets of at least 44x44 pixels
    And test dropdown menus (Start Time, End Time) on mobile device
    Then dropdowns open correctly, time options are easily selectable with finger, each option has adequate touch target size
    And verify Save and Cancel buttons in mobile form have adequate touch targets
    Then both buttons are at least 44x44 pixels, properly spaced apart to prevent accidental taps
    And test mobile gestures: swipe to scroll templates list, pinch to zoom
    Then standard mobile gestures work correctly, page is responsive to touch, no gesture conflicts
    And verify mobile screen reader (VoiceOver on iOS or TalkBack on Android) announces all elements correctly
    Then mobile screen reader announces all buttons, fields, and content with proper labels and roles
    And all interactive elements meet minimum touch target size requirements
    And mobile users can easily tap buttons without errors
    And adequate spacing prevents accidental activation of adjacent controls
    And mobile screen readers provide full accessibility

