@accessibility @a11y @wcag
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify complete keyboard navigation through shift template creation form
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And screen reader is not required for this test (keyboard only)
    And browser supports standard keyboard navigation
    When press Tab key to navigate to 'Create New Template' button
    Then button receives visible focus indicator (outline or highlight) and is clearly distinguishable
    And press Enter key to activate the button
    Then template creation form modal opens and focus moves to first input field (Template Name)
    And type 'Keyboard Test Shift' in Template Name field, then press Tab
    Then focus moves to Start Time field with visible focus indicator
    And use Arrow keys to select '08:00 AM' in Start Time dropdown, then press Tab
    Then time is selected and focus moves to End Time field
    And use Arrow keys to select '04:00 PM' in End Time field, then press Tab
    Then time is selected and focus moves to 'Add Break' button
    And press Enter on 'Add Break' button, then Tab through break time fields
    Then break fields appear and are navigable via Tab key with visible focus
    And press Tab to navigate to 'Save Template' button and press Enter
    Then template is saved, success message appears, and focus returns to main page or 'Create New Template' button
    And press Escape key when form is open
    Then form closes and focus returns to 'Create New Template' button
    And all interactive elements are reachable via keyboard
    And focus order is logical and follows visual layout
    And focus is never trapped in any component
    And escape key closes modal and returns focus appropriately

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader announces all form elements, labels, and validation messages correctly
    Given user is logged in as an Administrator
    And screen reader is active (NVDA, JAWS, or VoiceOver)
    And user is on the shift template management page
    And screen reader is in forms mode
    When navigate to 'Create New Template' button using screen reader
    Then screen reader announces: 'Create New Template, button' with role and state
    And activate button and navigate to Template Name field
    Then screen reader announces: 'Template Name, edit text, required' or similar with label and required state
    And navigate to Start Time field
    Then screen reader announces: 'Start Time, combobox, required' with appropriate role
    And navigate to End Time field
    Then screen reader announces: 'End Time, combobox, required' with appropriate role
    And leave Template Name empty and attempt to save
    Then screen reader announces error message: 'Error: Template Name is required' and focus moves to the field with error
    And successfully save a template
    Then screen reader announces success message: 'Success: Template created successfully' via ARIA live region
    And navigate through the templates list
    Then screen reader announces each template with its details: 'Morning Shift, Start Time 8:00 AM, End Time 5:00 PM, Edit button, Delete button'
    And all form labels are properly associated with inputs
    And required fields are announced as required
    And error and success messages are announced via ARIA live regions
    And all interactive elements have accessible names

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify ARIA labels, roles, and properties are correctly implemented throughout template management
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And browser developer tools are available for inspection
    And accessibility testing extension is installed (e.g., axe DevTools)
    When inspect 'Create New Template' button in browser developer tools
    Then button has appropriate ARIA attributes: role='button' (or is a native button element), aria-label or visible text
    And open template creation form and inspect modal container
    Then modal has role='dialog', aria-labelledby pointing to modal title, aria-modal='true'
    And inspect Template Name input field
    Then input has associated label via <label> element or aria-label, aria-required='true' attribute
    And inspect time picker dropdowns
    Then dropdowns have role='combobox' or use native <select>, aria-label or associated label, aria-required='true'
    And trigger a validation error and inspect error message
    Then error message has role='alert' or is in an aria-live='assertive' region, aria-describedby links input to error message
    And inspect success message after saving template
    Then success message is in aria-live='polite' region for non-intrusive announcement
    And inspect templates list/table
    Then list has appropriate structure: role='table' or semantic <table>, headers have scope attributes, rows have proper markup
    And all ARIA roles are semantically correct
    And aRIA properties accurately reflect component states
    And no ARIA validation errors are present
    And accessibility tree is properly structured

  @high @tc-acce-004
  Scenario: TC-ACCE-004 - Verify sufficient color contrast ratios for all text and interactive elements (WCAG AA compliance)
    Given user is on the shift template management page
    And color contrast analyzer tool is available (e.g., browser extension or online tool)
    And page is displayed at 100% zoom
    When measure color contrast ratio of 'Create New Template' button text against button background
    Then contrast ratio is at least 4.5:1 for normal text or 3:1 for large text (18pt+)
    And measure contrast ratio of form labels (Template Name, Start Time, End Time) against page background
    Then contrast ratio meets WCAG AA standard of 4.5:1 minimum
    And measure contrast ratio of input field text against input background
    Then contrast ratio is at least 4.5:1
    And measure contrast ratio of error messages (red text) against background
    Then contrast ratio is at least 4.5:1, error is not conveyed by color alone (icon or text indicator present)
    And measure contrast ratio of success messages (green text) against background
    Then contrast ratio is at least 4.5:1, success is not conveyed by color alone
    And measure contrast ratio of focus indicators on interactive elements
    Then focus indicator has at least 3:1 contrast ratio against adjacent colors
    And check that information is not conveyed by color alone
    Then required fields have asterisk or 'required' text in addition to any color coding, errors have icons or text in addition to red color
    And all text meets WCAG AA contrast requirements
    And interactive elements are distinguishable
    And information is accessible to users with color blindness
    And focus indicators are clearly visible

  @medium @tc-acce-005
  Scenario: TC-ACCE-005 - Verify page functionality and readability at 200% browser zoom level
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And browser is set to 100% zoom initially
    And browser window is at standard desktop resolution (1920x1080 or similar)
    When set browser zoom to 200% using Ctrl/Cmd + '+' or browser settings
    Then page content scales to 200% without horizontal scrolling required
    And verify 'Create New Template' button is visible and clickable
    Then button is fully visible, text is readable, and button is clickable without overlapping other elements
    And click 'Create New Template' and verify form modal at 200% zoom
    Then modal opens and all form fields are visible, properly sized, and usable without horizontal scrolling within modal
    And verify all form labels and input fields are readable
    Then text is not truncated, fields are properly sized, and layout adapts responsively
    And complete form and save template at 200% zoom
    Then all interactions work correctly, success message is visible and readable
    And verify templates list is readable and functional at 200% zoom
    Then list items are visible, text is readable, Edit and Delete buttons are accessible and clickable
    And all functionality remains available at 200% zoom
    And no content is cut off or hidden
    And layout adapts appropriately to larger text
    And user can complete all tasks without reducing zoom

  @high @tc-acce-006
  Scenario: TC-ACCE-006 - Verify focus management and focus trap behavior in template creation modal dialog
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And keyboard navigation is being used (no mouse)
    When press Tab to navigate to 'Create New Template' button and press Enter
    Then modal opens and focus automatically moves to first focusable element (Template Name field or modal close button)
    And press Tab repeatedly to cycle through all focusable elements in the modal
    Then focus cycles through: Template Name, Start Time, End Time, Add Break button, Save button, Cancel button, Close (X) button
    And continue pressing Tab after reaching the last focusable element
    Then focus wraps back to the first focusable element in the modal (focus is trapped within modal)
    And press Shift+Tab from the first focusable element
    Then focus moves backward to the last focusable element (reverse focus trap works)
    And press Escape key while modal is open
    Then modal closes and focus returns to 'Create New Template' button that originally opened the modal
    And open modal again, fill form, and click Save button
    Then after successful save, modal closes and focus returns to appropriate element (either 'Create New Template' button or newly created template in list)
    And focus is properly trapped within modal when open
    And focus returns to logical location when modal closes
    And no focus is lost or moved to unexpected locations
    And keyboard users can efficiently navigate and exit modal

  @medium @tc-acce-007
  Scenario: TC-ACCE-007 - Verify mobile accessibility including touch target sizes and gesture support
    Given user is logged in as an Administrator on a mobile device or browser in mobile emulation mode
    And screen size is set to mobile dimensions (e.g., 375x667 for iPhone)
    And touch input is available or simulated
    When measure the size of 'Create New Template' button on mobile view
    Then button is at least 44x44 pixels (iOS) or 48x48 pixels (Android) to meet minimum touch target size
    And tap 'Create New Template' button
    Then button responds to touch, modal opens, and form is displayed in mobile-optimized layout
    And verify spacing between interactive elements in the form
    Then all buttons and input fields have adequate spacing (at least 8px) to prevent accidental taps
    And measure Edit and Delete icon buttons in templates list
    Then icon buttons are at least 44x44 pixels or have sufficient padding to meet touch target requirements
    And test time picker dropdowns on mobile
    Then time pickers use native mobile controls (iOS/Android time pickers) or custom controls optimized for touch
    And verify modal can be dismissed by tapping outside modal area or using close button
    Then modal closes appropriately, close button is large enough for easy tapping
    And test form submission on mobile
    Then save button is easily tappable, success message is visible on mobile screen, and layout remains usable
    And all touch targets meet minimum size requirements
    And mobile layout is optimized for touch interaction
    And no elements are too small or too close together
    And mobile users can complete all tasks efficiently

