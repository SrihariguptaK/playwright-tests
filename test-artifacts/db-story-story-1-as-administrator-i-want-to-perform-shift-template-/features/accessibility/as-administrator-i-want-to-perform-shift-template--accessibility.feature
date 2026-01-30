@accessibility @a11y @wcag
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify complete keyboard navigation through shift template creation workflow
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And no mouse or pointing device is used for this test
    And screen reader is not active (pure keyboard test)
    When press Tab key repeatedly to navigate through page elements
    Then focus moves sequentially through all interactive elements: navigation menu, 'Create New Template' button, template list items, edit buttons, delete buttons. Focus indicator is clearly visible with 2px solid border or outline
    And navigate to 'Create New Template' button and press Enter key
    Then template creation form modal opens and focus automatically moves to the first field (Template Name)
    And type 'Keyboard Test Shift' in Template Name field and press Tab
    Then text is entered and focus moves to Start Time field
    And in Start Time field, type '0800' or use arrow keys to select '08:00 AM', then press Tab
    Then start Time is set to '08:00 AM' and focus moves to End Time field
    And in End Time field, type '1700' or use arrow keys to select '05:00 PM', then press Tab
    Then end Time is set to '05:00 PM' and focus moves to 'Add Break' button
    And press Enter on 'Add Break' button, then Tab to break start time, enter '12:00 PM', Tab to break end time, enter '01:00 PM'
    Then break fields are populated correctly, focus moves through break time fields
    And press Tab to navigate to 'Save Template' button and press Enter
    Then template is saved, success message appears, and focus returns to 'Create New Template' button or first template in list
    And press Escape key while form is open
    Then form closes without saving and focus returns to 'Create New Template' button
    And all functionality is accessible via keyboard only
    And focus order is logical and follows visual layout
    And no keyboard traps exist where user cannot escape
    And focus indicators are visible throughout interaction

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader announces all elements and state changes correctly (NVDA/JAWS)
    Given user is logged in as an Administrator
    And nVDA or JAWS screen reader is active
    And user is on the shift template management page
    And screen reader verbosity is set to default level
    When navigate to 'Create New Template' button using screen reader navigation
    Then screen reader announces: 'Create New Template, button' with role and accessible name
    And activate the button and listen to announcement when form opens
    Then screen reader announces: 'Dialog opened, Create Shift Template' or 'Modal dialog, Create Shift Template, Template Name, edit, required'
    And navigate to Template Name field
    Then screen reader announces: 'Template Name, edit, required, blank' with field label, role, required state, and current value
    And navigate to Start Time field
    Then screen reader announces: 'Start Time, time picker, required' or 'Start Time, edit, required' with appropriate role
    And fill in all fields and navigate to 'Save Template' button, then activate it
    Then screen reader announces: 'Save Template, button' then after save: 'Shift template created successfully, alert' or live region announcement
    And navigate to the templates list
    Then screen reader announces: 'Shift Templates, list, 5 items' or 'Shift Templates, table, 5 rows' with structure information
    And navigate to a template item in the list
    Then screen reader announces: 'Morning Shift, Start Time: 08:00 AM, End Time: 05:00 PM, Edit button, Delete button' with all relevant information
    And navigate to Delete button and activate it to trigger confirmation dialog
    Then screen reader announces: 'Alert dialog, Are you sure you want to delete this template? This action cannot be undone. Cancel button, Delete button'
    And all interactive elements have proper ARIA labels and roles
    And state changes are announced via ARIA live regions
    And form validation errors are announced immediately
    And screen reader users can complete all tasks independently

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify focus management and focus trap in modal dialogs
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And keyboard-only navigation is being used
    When press Tab to navigate to 'Create New Template' button and press Enter
    Then modal opens and focus automatically moves to first focusable element (Template Name field)
    And press Shift+Tab repeatedly to move focus backward
    Then focus moves backward through form fields and when reaching the first element, pressing Shift+Tab moves focus to the last focusable element in modal (Save or Cancel button), creating a focus trap within modal
    And press Tab repeatedly to move focus forward from last element
    Then focus wraps around to first element in modal (Template Name field), confirming focus is trapped within modal and cannot escape to background page
    And press Escape key
    Then modal closes and focus returns to 'Create New Template' button that originally opened the modal
    And open modal again, fill in fields, and click 'Save Template' button
    Then modal closes after successful save and focus returns to logical location (either 'Create New Template' button or newly created template in list)
    And navigate to a template's Delete button and activate it to open confirmation dialog
    Then confirmation dialog opens and focus moves to 'Cancel' or 'Delete' button (preferably Cancel as safer default)
    And press Escape key in confirmation dialog
    Then dialog closes without deleting and focus returns to Delete button that triggered the dialog
    And focus is properly trapped within modal dialogs
    And focus returns to triggering element when modal closes
    And escape key closes modals and returns focus appropriately
    And no focus is lost or moved to unexpected locations

  @high @tc-acce-004
  Scenario: TC-ACCE-004 - Verify color contrast ratios meet WCAG 2.1 Level AA standards (4.5:1 for normal text)
    Given user is on the shift template management page
    And color contrast analyzer tool is available (browser extension or standalone tool)
    And page is displayed at 100% zoom
    When use color contrast analyzer to check contrast ratio of page heading 'Shift Template Management' against background
    Then contrast ratio is at least 4.5:1 for normal text or 3:1 for large text (18pt+ or 14pt+ bold)
    And check contrast ratio of 'Create New Template' button text against button background
    Then contrast ratio is at least 4.5:1, button is clearly readable
    And check contrast ratio of form field labels (Template Name, Start Time, End Time) against page background
    Then contrast ratio is at least 4.5:1 for all labels
    And check contrast ratio of placeholder text in input fields against field background
    Then contrast ratio is at least 4.5:1 or placeholder text is not relied upon for critical information
    And check contrast ratio of success message (green) text against background
    Then contrast ratio is at least 4.5:1, message is readable without relying on color alone
    And check contrast ratio of error message (red) text against background
    Then contrast ratio is at least 4.5:1, error is indicated by icon or text in addition to color
    And check contrast ratio of focus indicators (outline/border) against background
    Then focus indicator has at least 3:1 contrast ratio against adjacent colors
    And check contrast of disabled button or field against background
    Then disabled state is indicated by more than just reduced contrast (e.g., cursor change, explicit 'disabled' text)
    And all text meets WCAG 2.1 Level AA contrast requirements
    And information is not conveyed by color alone
    And focus indicators are clearly visible
    And page is readable for users with low vision or color blindness

  @high @tc-acce-005
  Scenario: TC-ACCE-005 - Verify page functionality at 200% browser zoom level
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And browser zoom is set to 100% initially
    When press Ctrl and + (or Cmd and + on Mac) repeatedly to zoom to 200%
    Then page zooms to 200% and all content remains visible without horizontal scrolling (or minimal horizontal scrolling)
    And verify all text is readable and not truncated
    Then all headings, labels, button text, and body text are fully visible and readable at 200% zoom
    And click 'Create New Template' button
    Then modal opens and is fully visible at 200% zoom, all form fields are accessible without excessive scrolling
    And fill in all form fields (Template Name, Start Time, End Time, Break Times)
    Then all fields are accessible and functional, time pickers work correctly at 200% zoom
    And scroll through the form if necessary
    Then scrolling is smooth, no content is hidden or inaccessible, sticky headers/footers (if any) don't obscure content
    And click 'Save Template' button
    Then template saves successfully, success message is fully visible at 200% zoom
    And verify templates list is readable and functional at 200% zoom
    Then list items are readable, Edit and Delete buttons are accessible and properly sized, no layout breaks
    And all functionality works correctly at 200% zoom
    And no content is lost or becomes inaccessible
    And layout adapts responsively without breaking
    And users with low vision can use the feature effectively

  @high @tc-acce-006
  Scenario: TC-ACCE-006 - Verify proper ARIA labels, roles, and landmarks for assistive technology
    Given user is on the shift template management page
    And browser developer tools are open to inspect HTML elements
    And accessibility tree view is available in developer tools
    When inspect the main page structure in accessibility tree
    Then page has proper landmark regions: <header> or role='banner', <main> or role='main', <nav> or role='navigation', <footer> or role='contentinfo'
    And inspect 'Create New Template' button element
    Then button has accessible name (aria-label or visible text), role='button' (implicit or explicit), and no empty or generic labels
    And open template creation modal and inspect modal container
    Then modal has role='dialog' or role='alertdialog', aria-labelledby pointing to modal title, aria-modal='true' to indicate modal state
    And inspect form fields (Template Name, Start Time, End Time)
    Then each field has associated <label> with for attribute matching input id, or aria-label/aria-labelledby, required fields have aria-required='true' or required attribute
    And inspect time picker components
    Then time pickers have appropriate role (combobox, spinbutton, or custom with proper ARIA), aria-label describes purpose, keyboard interaction is documented or intuitive
    And trigger a validation error and inspect error message
    Then error message has role='alert' or is in aria-live='assertive' region, error is associated with field via aria-describedby, field has aria-invalid='true'
    And inspect success message after saving template
    Then success message is in aria-live='polite' or role='status' region so screen readers announce it automatically
    And inspect templates list structure
    Then list has role='list' with child role='listitem', or is a proper <table> with <thead>, <tbody>, <th> scope attributes for data table
    And all interactive elements have proper ARIA roles and labels
    And landmark regions provide clear page structure
    And dynamic content changes are announced to screen readers
    And form validation is accessible to assistive technology

  @medium @tc-acce-007
  Scenario: TC-ACCE-007 - Verify mobile accessibility including touch target sizes and gesture support
    Given user is logged in as an Administrator
    And page is accessed on mobile device or browser in mobile emulation mode (375x667 viewport)
    And touch input is being used (not mouse)
    When measure the size of 'Create New Template' button on mobile viewport
    Then button is at least 44x44 CSS pixels (iOS) or 48x48 CSS pixels (Android) to meet touch target size guidelines
    And tap 'Create New Template' button
    Then button responds to tap immediately, modal opens, no accidental activation of nearby elements
    And verify spacing between interactive elements (Edit and Delete buttons in list)
    Then minimum 8px spacing between touch targets to prevent accidental taps
    And fill in form fields using mobile keyboard
    Then appropriate keyboard types appear: text keyboard for Template Name, time picker or numeric keyboard for time fields
    And test time picker interaction on mobile
    Then time picker is touch-friendly, uses native mobile time picker if available, or custom picker has large touch targets
    And attempt to scroll the templates list on mobile
    Then list scrolls smoothly with touch gestures, no horizontal scrolling required, content fits viewport width
    And test swipe gestures if implemented (e.g., swipe to delete)
    Then swipe gestures work reliably, have visual feedback, and include alternative methods (buttons) for users who cannot perform gestures
    And test with mobile screen reader (TalkBack on Android or VoiceOver on iOS)
    Then all elements are announced correctly, touch exploration works, double-tap to activate functions properly
    And all touch targets meet minimum size requirements
    And mobile interactions are smooth and reliable
    And mobile screen readers can access all functionality
    And no functionality requires precise touch or complex gestures

