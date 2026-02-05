@accessibility @a11y @wcag
Feature: As Admin, I want to create shift templates to achieve efficient scheduling. - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify complete keyboard navigation through shift template creation workflow
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And keyboard is the only input device being used (no mouse)
    And screen reader is optionally enabled for testing
    When press Tab key repeatedly to navigate to 'Create New Template' button
    Then focus indicator (visible outline) moves through page elements in logical order, 'Create New Template' button receives focus with clear visual indicator
    And press Enter key to activate 'Create New Template' button
    Then template creation form modal opens, focus automatically moves to first input field (Template Name)
    And type 'Keyboard Test Shift' in Template Name field, then press Tab
    Then text is entered successfully, focus moves to Start Time field with visible focus indicator
    And type '09:00 AM' in Start Time field, press Tab to move to End Time field
    Then start Time accepts input, focus moves to End Time field with clear visual indicator
    And type '05:00 PM' in End Time field, press Tab to move to Role dropdown
    Then end Time accepts input, focus moves to Role dropdown, dropdown can be opened with Enter or Space key
    And press Enter to open Role dropdown, use Arrow Down key to select 'Cashier', press Enter to confirm
    Then dropdown opens, arrow keys navigate options, Enter selects 'Cashier', focus returns to dropdown showing selected value
    And press Tab to move to 'Save Template' button, press Enter to submit
    Then focus moves to 'Save Template' button, Enter key submits form, success message appears and receives focus for screen reader announcement
    And press Escape key to close success message or modal
    Then modal closes, focus returns to 'Create New Template' button or templates list in logical position
    And entire template creation workflow is completable using only keyboard
    And focus order is logical and follows visual layout
    And all interactive elements are reachable and operable via keyboard
    And focus is never trapped, user can always navigate away using Tab or Escape

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader announces all form fields, labels, and validation errors correctly
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And screen reader is enabled (NVDA, JAWS, or VoiceOver)
    And template creation form is open
    When navigate to 'Create New Template' button using screen reader navigation
    Then screen reader announces 'Create New Template, button' with role and accessible name
    And activate button and navigate to Template Name field
    Then screen reader announces 'Template Name, edit text, required' indicating field label, type, and required status
    And navigate to Start Time field
    Then screen reader announces 'Start Time, time picker, required' with appropriate role and instructions
    And navigate to End Time field
    Then screen reader announces 'End Time, time picker, required' with appropriate role
    And leave all fields empty and attempt to submit form
    Then screen reader announces validation errors: 'Error: Template Name is required', 'Error: Start Time is required', 'Error: End Time is required' using ARIA live region
    And enter end time before start time and submit
    Then screen reader announces 'Error: End time must be after start time' with clear error description
    And correct errors and successfully submit form
    Then screen reader announces 'Success: Shift template created successfully' using ARIA live region with polite or assertive priority
    And all form elements have proper ARIA labels and roles
    And required fields are announced as required
    And validation errors are announced immediately and clearly
    And success messages are announced to screen reader users

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify sufficient color contrast ratios for all text and interactive elements
    Given user is on the Shift Template management page
    And color contrast analyzer tool is available (browser extension or standalone tool)
    And wCAG 2.1 Level AA requires 4.5:1 contrast ratio for normal text, 3:1 for large text
    And template creation form is visible
    When use color contrast analyzer to check 'Create New Template' button text against button background
    Then contrast ratio is at least 4.5:1 for normal text or 3:1 for large text (18pt+), meets WCAG AA standards
    And check contrast ratio of form field labels (Template Name, Start Time, End Time) against page background
    Then all labels have contrast ratio of at least 4.5:1, text is clearly readable
    And check contrast ratio of placeholder text in input fields
    Then placeholder text has contrast ratio of at least 4.5:1, visible to users with low vision
    And check contrast ratio of error messages (red text) against background
    Then error message text has contrast ratio of at least 4.5:1, errors are not conveyed by color alone (icon or text indicator present)
    And check contrast ratio of success messages (green text) against background
    Then success message text has contrast ratio of at least 4.5:1, success is not conveyed by color alone
    And check focus indicator contrast against both focused element and page background
    Then focus indicator has contrast ratio of at least 3:1 against adjacent colors, clearly visible when elements receive focus
    And all text meets WCAG 2.1 Level AA contrast requirements
    And interactive elements are distinguishable from non-interactive elements
    And users with low vision or color blindness can read all content
    And information is not conveyed by color alone

  @medium @tc-acce-004
  Scenario: TC-ACCE-004 - Verify form remains functional and readable at 200% browser zoom level
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And browser zoom is set to 100% initially
    And template creation form is open
    When set browser zoom to 200% using Ctrl/Cmd + Plus key or browser zoom controls
    Then page content scales to 200%, all elements remain visible without horizontal scrolling required
    And verify all form fields (Template Name, Start Time, End Time, Role) are visible and accessible
    Then all form fields are visible, labels are not truncated, fields are usable at 200% zoom
    And verify 'Save Template' and 'Cancel' buttons are visible and clickable
    Then buttons remain visible and functional, not cut off or overlapping other elements
    And enter data in all fields: 'Zoom Test Shift', '09:00 AM', '05:00 PM', 'Cashier'
    Then all fields accept input correctly, text is readable at 200% zoom, no layout breaks occur
    And submit form and verify success message is visible and readable at 200% zoom
    Then success message appears and is fully readable, not cut off or requiring horizontal scroll
    And verify templates list displays correctly at 200% zoom
    Then templates list is readable, columns adjust appropriately, no content is hidden or inaccessible
    And all functionality remains available at 200% zoom level
    And no horizontal scrolling is required to access content
    And text remains readable and layout is maintained
    And wCAG 2.1 Level AA reflow requirement is met

  @high @tc-acce-005
  Scenario: TC-ACCE-005 - Verify proper ARIA landmarks and semantic HTML structure for assistive technology navigation
    Given user is on the Shift Template management page
    And screen reader is enabled for testing
    And browser developer tools are available to inspect HTML structure
    And template creation form is open
    When use screen reader landmarks navigation (NVDA: D key, JAWS: ; key) to navigate page regions
    Then screen reader announces landmarks: 'main region', 'navigation region', 'form region' with appropriate ARIA roles or HTML5 semantic elements
    And inspect template creation form modal in developer tools
    Then modal has role='dialog', aria-labelledby pointing to modal title, aria-modal='true' to indicate modal context
    And verify form element has proper semantic structure
    Then form uses <form> element, fields use <label> elements properly associated with inputs via for/id attributes
    And check that required fields have aria-required='true' attribute
    Then all required fields (Template Name, Start Time, End Time) have aria-required='true' or HTML5 required attribute
    And verify error messages are associated with fields using aria-describedby
    Then when validation errors appear, fields have aria-describedby pointing to error message IDs, screen reader announces errors when field receives focus
    And check that success/error messages use ARIA live regions
    Then success and error messages have aria-live='polite' or 'assertive' and role='alert' or 'status' for automatic announcement
    And page structure uses semantic HTML5 elements and ARIA landmarks appropriately
    And screen reader users can efficiently navigate page regions
    And form fields are properly labeled and associated with error messages
    And dynamic content updates are announced to assistive technology users

  @high @tc-acce-006
  Scenario: TC-ACCE-006 - Verify focus is not trapped in modal and can be escaped using keyboard
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And keyboard is the only input device being used
    And template creation form modal is closed initially
    When use keyboard to navigate to and activate 'Create New Template' button
    Then modal opens, focus moves to first focusable element inside modal (Template Name field or Close button)
    And press Tab key repeatedly to cycle through all focusable elements in modal
    Then focus cycles through: Template Name, Start Time, End Time, Role dropdown, Save button, Cancel button, Close (X) button
    And continue pressing Tab after reaching last focusable element
    Then focus wraps back to first focusable element in modal, focus remains trapped within modal (cannot Tab to background page elements)
    And press Shift+Tab to navigate backwards through focusable elements
    Then focus moves backwards through modal elements, wraps from first to last element when continuing backwards
    And press Escape key while focus is anywhere in the modal
    Then modal closes immediately, focus returns to 'Create New Template' button that originally opened the modal
    And reopen modal, click Cancel button using keyboard (Enter key)
    Then modal closes, focus returns to 'Create New Template' button, no data is saved
    And focus management follows ARIA Authoring Practices for modal dialogs
    And users can always escape modal using Escape key or Cancel button
    And focus returns to logical position after modal closes
    And keyboard users are not trapped and can navigate freely

