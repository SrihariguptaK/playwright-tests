@accessibility @a11y @wcag
Feature: As Merchant Manager, I want to add a new merchant to the system to achieve accurate merchant representation - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify complete keyboard navigation through entire Add Merchant form using Tab and Shift+Tab
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And keyboard is the only input device being used (mouse disconnected or not used)
    And browser is set to show focus indicators
    When press Tab key from page load
    Then focus moves to first interactive element (likely 'Merchant Name' field) with visible blue focus ring/outline of at least 2px thickness
    And continue pressing Tab key through all form fields
    Then focus moves sequentially through: Merchant Name → Address → Email → Phone → Category dropdown → Upload Documents button → Submit button → Cancel button, each showing clear focus indicator
    And press Shift+Tab to navigate backwards
    Then focus moves in reverse order through all interactive elements with visible focus indicators
    And navigate to Category dropdown and press Enter or Space
    Then dropdown opens, focus moves to first option, arrow keys navigate through options
    And press Enter to select an option
    Then option is selected, dropdown closes, focus returns to dropdown trigger
    And fill all fields using keyboard only and press Enter on Submit button
    Then form submits successfully, confirmation message receives focus and is announced
    And all form elements are accessible via keyboard
    And focus order is logical and follows visual layout
    And no keyboard traps exist (user can navigate away from all elements)
    And form can be completed and submitted entirely with keyboard

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader announces all form labels, errors, and success messages correctly (NVDA/JAWS)
    Given user is logged in as Merchant Manager
    And nVDA or JAWS screen reader is active and running
    And user is on the 'Add Merchant' page
    And screen reader is set to verbose mode for testing
    When navigate to 'Merchant Name' field using Tab key
    Then screen reader announces: 'Merchant Name, required, edit text' or similar, indicating field label, required status, and field type
    And navigate through all form fields
    Then each field is announced with: label text, required/optional status, field type (edit, combobox, button), and any help text or descriptions
    And leave 'Merchant Name' field empty and Tab away
    Then screen reader announces error: 'Merchant Name, required, invalid entry, Merchant Name is required' or similar, clearly indicating the error
    And enter valid data in Merchant Name field
    Then screen reader announces: 'Merchant Name, valid' or error message is cleared and not announced
    And fill all fields and submit form successfully
    Then screen reader announces: 'Merchant added successfully' from ARIA live region with assertive politeness, interrupting other announcements
    And navigate to uploaded document
    Then screen reader announces: 'merchant_license.pdf, 2 megabytes, uploaded successfully, button remove' providing file details and available actions
    And all form elements have proper ARIA labels and roles
    And error messages are associated with fields via aria-describedby
    And success messages are announced via aria-live regions
    And screen reader users can complete form independently

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify focus management and focus trap in modal dialogs (unsaved changes warning)
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And some form data has been entered but not saved
    And keyboard is being used for navigation
    When enter 'Test Merchant' in Merchant Name field
    Then data is entered
    And press browser back button or attempt to navigate away
    Then warning modal appears: 'You have unsaved changes. Are you sure you want to leave?', focus automatically moves to first button in modal (likely 'Stay' button)
    And press Tab key repeatedly
    Then focus cycles only within modal between: 'Stay' button → 'Leave' button → Close (X) button → back to 'Stay' button, focus is trapped within modal
    And press Shift+Tab from first element
    Then focus moves to last element in modal (Close button), confirming bidirectional focus trap
    And press Escape key
    Then modal closes, focus returns to the element that triggered the modal (back button or navigation link)
    And trigger modal again and press Enter on 'Stay' button
    Then modal closes, focus returns to form, user remains on Add Merchant page
    And focus is properly trapped within modal when open
    And focus returns to triggering element when modal closes
    And escape key closes modal as expected
    And no focus is lost or moved to unexpected elements

  @high @tc-acce-004
  Scenario: TC-ACCE-004 - Verify color contrast ratios meet WCAG 2.1 AA standards (4.5:1 for normal text, 3:1 for large text)
    Given user is on the 'Add Merchant' page
    And color contrast analyzer tool is available (e.g., browser extension or online tool)
    And page is displayed in default theme/colors
    When use color contrast analyzer to check form field labels (normal text) against background
    Then contrast ratio is at least 4.5:1, labels are clearly readable
    And check error messages (red text) against background
    Then contrast ratio is at least 4.5:1, error text is clearly readable without relying solely on color
    And check success message (green text/background) against its background
    Then contrast ratio is at least 4.5:1, success message is clearly readable
    And check Submit button text against button background color
    Then contrast ratio is at least 4.5:1 for normal text or 3:1 if text is large (18pt+ or 14pt+ bold)
    And check focus indicators (outline/border) against background
    Then contrast ratio is at least 3:1, focus indicators are clearly visible
    And check placeholder text in empty fields
    Then contrast ratio is at least 4.5:1 or placeholder is supplemented with visible label
    And all text meets WCAG 2.1 AA contrast requirements
    And users with low vision can read all content
    And color is not the only means of conveying information
    And focus indicators are visible to all users

  @medium @tc-acce-005
  Scenario: TC-ACCE-005 - Verify form remains functional and readable at 200% browser zoom level
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And browser zoom is set to 100% initially
    And browser window is at standard desktop size (1920x1080)
    When press Ctrl and + (or Cmd and + on Mac) repeatedly to zoom to 200%
    Then page zooms to 200%, all content scales proportionally
    And verify all form fields are visible without horizontal scrolling
    Then form layout adjusts responsively, fields stack vertically if needed, no content is cut off, no horizontal scrollbar appears
    And verify all text is readable and not truncated
    Then labels, help text, error messages, and button text are fully visible and readable at larger size
    And fill out form fields at 200% zoom
    Then all fields are accessible and functional, typing works normally, dropdowns open correctly
    And submit form at 200% zoom
    Then form submits successfully, confirmation message is visible and readable at 200% zoom
    And verify focus indicators are visible at 200% zoom
    Then focus outlines scale appropriately and remain clearly visible
    And form is fully functional at 200% zoom
    And no content is hidden or requires horizontal scrolling
    And text remains readable and properly sized
    And layout adapts responsively to larger text size

  @high @tc-acce-006
  Scenario: TC-ACCE-006 - Verify proper ARIA roles, labels, and live regions are implemented throughout the form
    Given user is on the 'Add Merchant' page
    And browser developer tools are open to inspect HTML
    And aRIA validator or accessibility testing tool is available
    When inspect form element in developer tools
    Then form has role='form' or is a semantic <form> element, has aria-label='Add Merchant Form' or aria-labelledby pointing to form heading
    And inspect required field indicators (asterisks)
    Then required fields have aria-required='true' attribute, asterisk is not the only indicator (label includes 'required' text or aria-label)
    And inspect error messages
    Then error messages have role='alert' or are in container with aria-live='assertive', errors are associated with fields via aria-describedby
    And inspect success confirmation message area
    Then success message container has aria-live='polite' or 'assertive' and role='status' or 'alert', ensuring screen reader announcement
    And inspect Category dropdown
    Then dropdown has role='combobox' or is semantic <select>, has aria-label or associated <label>, aria-expanded state changes when opened/closed
    And inspect Upload Documents button and file list
    Then button has descriptive aria-label='Upload supporting documents', uploaded file list has role='list' with items having role='listitem'
    And all interactive elements have appropriate ARIA roles
    And all form fields have accessible labels
    And dynamic content changes are announced via ARIA live regions
    And form passes automated ARIA validation tools

  @medium @tc-acce-007
  Scenario: TC-ACCE-007 - Verify mobile accessibility with touch targets meeting minimum size requirements (44x44px)
    Given user is accessing the 'Add Merchant' page on mobile device or mobile emulator
    And screen size is set to typical mobile dimensions (375x667px - iPhone SE)
    And user is logged in as Merchant Manager
    And touch is the primary input method
    When inspect Submit button touch target size using developer tools
    Then button is at least 44x44 pixels (iOS) or 48x48 pixels (Android), easily tappable with thumb
    And inspect all form field touch targets
    Then all input fields have touch target height of at least 44px, adequate spacing between fields (at least 8px) to prevent mis-taps
    And tap on Category dropdown
    Then dropdown opens easily on first tap, options are large enough to tap accurately (44px minimum height)
    And tap on Upload Documents button
    Then button is easily tappable, file picker opens, button is at least 44x44px
    And attempt to tap close icon (X) on uploaded file
    Then close icon has touch target of at least 44x44px (may have invisible padding), taps register accurately
    And fill and submit form using only touch input
    Then all interactions work smoothly with touch, no precision tapping required, form submits successfully
    And all interactive elements meet minimum touch target size
    And form is fully usable on mobile devices
    And no accidental taps occur due to small or close targets
    And mobile users can complete form efficiently

