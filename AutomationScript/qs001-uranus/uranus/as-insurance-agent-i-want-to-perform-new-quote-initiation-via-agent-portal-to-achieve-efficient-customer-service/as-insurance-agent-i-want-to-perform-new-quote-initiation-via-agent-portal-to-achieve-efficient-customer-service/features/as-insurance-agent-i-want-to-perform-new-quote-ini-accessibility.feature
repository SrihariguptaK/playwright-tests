@accessibility @a11y @wcag
Feature: As Insurance Agent, I want to perform new quote initiation via agent portal to achieve efficient customer service - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify complete keyboard navigation through quote initiation form
    Given agent is logged into Agent Portal using keyboard only (no mouse)
    And quote initiation form is displayed
    And screen reader is not required for this test (keyboard only)
    And browser supports standard keyboard navigation
    When press Tab key repeatedly from top of page to navigate through all form elements
    Then focus moves sequentially through: Customer Name field, Policy Type dropdown, Coverage Amount field, Effective Date picker, Contact Email field, Phone field, 'Save as Draft' button, 'Submit Quote' button. Focus indicator is clearly visible on each element with blue outline
    And press Shift+Tab to navigate backwards through form
    Then focus moves in reverse order through all interactive elements, no focus traps occur, focus indicator remains visible
    And navigate to Policy Type dropdown and press Space or Enter key to open
    Then dropdown opens showing policy options, focus moves to first option
    And use Arrow Down/Up keys to navigate dropdown options, then press Enter to select
    Then arrow keys move through options with visual highlight, Enter key selects highlighted option and closes dropdown, selected value appears in field
    And navigate to Effective Date field and press Enter or Space to open date picker
    Then date picker calendar opens, focus is on current date, Arrow keys navigate dates, Enter selects date, Escape closes picker
    And fill all mandatory fields using keyboard only, navigate to 'Submit Quote' button and press Enter
    Then form submits successfully, confirmation message appears and receives focus, reference number is announced
    And all form functionality is accessible via keyboard
    And no keyboard traps prevent navigation
    And focus order is logical and predictable
    And visual focus indicators are always visible

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader announces all form elements and validation messages correctly
    Given agent is logged into Agent Portal
    And screen reader is active (NVDA, JAWS, or VoiceOver)
    And quote initiation form is displayed
    And aRIA labels and live regions are implemented
    When navigate to quote initiation form with screen reader active and listen to page announcement
    Then screen reader announces: 'Quote Initiation Form, form landmark, heading level 1' and reads form instructions if present
    And tab to Customer Name field and listen to screen reader announcement
    Then screen reader announces: 'Customer Name, required, edit text' indicating field label, required status, and field type
    And leave Customer Name empty and tab out to trigger validation error
    Then screen reader immediately announces: 'Error: Customer Name is required' via ARIA live region, error is associated with field
    And enter valid data in Customer Name and tab out
    Then screen reader announces: 'Customer Name valid' or similar confirmation message
    And navigate to Policy Type dropdown and activate it
    Then screen reader announces: 'Policy Type, required, combo box collapsed' then 'combo box expanded' when opened, announces each option as focus moves
    And attempt to submit form with missing fields and listen to error announcement
    Then screen reader announces: 'Error: Please complete all mandatory fields. 3 errors found.' Focus moves to first error, each error is announced as user navigates
    And complete form and submit successfully
    Then screen reader announces: 'Success: Quote successfully created. Reference number QT-YYYYMMDD-XXXX' via ARIA live region
    And all form elements have proper ARIA labels
    And required fields are announced as required
    And validation errors are announced immediately
    And success messages are announced to screen reader users

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify color contrast ratios meet WCAG 2.1 AA standards throughout form
    Given agent Portal is accessible in browser
    And color contrast checking tool is available (e.g., browser extension or online tool)
    And quote initiation form is displayed
    And wCAG 2.1 Level AA requires 4.5:1 for normal text, 3:1 for large text
    When use contrast checker tool to measure contrast ratio between form field labels (text) and background
    Then contrast ratio is at least 4.5:1 for normal-sized label text, meets WCAG AA standard
    And measure contrast ratio between input field text and field background
    Then contrast ratio is at least 4.5:1, text is clearly readable
    And measure contrast ratio of error messages (red text) against background
    Then red error text has at least 4.5:1 contrast ratio, errors are not conveyed by color alone (icon or text indicator also present)
    And measure contrast ratio of success indicators (green checkmarks/text) against background
    Then green success indicators have at least 3:1 contrast ratio, success is not conveyed by color alone
    And measure contrast ratio of 'Submit Quote' button text against button background in normal, hover, and focus states
    Then all button states have at least 4.5:1 contrast ratio for text, button remains clearly visible and readable in all states
    And measure contrast ratio of focus indicators (outline/border) against background
    Then focus indicators have at least 3:1 contrast ratio against adjacent colors, focus is always clearly visible
    And all text meets WCAG 2.1 AA contrast requirements
    And form is usable by users with low vision or color blindness
    And information is not conveyed by color alone
    And focus indicators are clearly visible

  @medium @tc-acce-004
  Scenario: TC-ACCE-004 - Verify form remains functional and readable at 200% browser zoom
    Given agent is logged into Agent Portal
    And quote initiation form is displayed at 100% zoom
    And browser supports zoom functionality
    And responsive design is implemented
    When set browser zoom to 200% using Ctrl/Cmd + Plus key or browser zoom menu
    Then page zooms to 200%, all content scales proportionally, no horizontal scrolling is required for form content
    And verify all form field labels are fully visible and readable at 200% zoom
    Then all labels are visible, not truncated, and remain associated with their fields, text is clear and readable
    And verify all form input fields are fully visible and usable at 200% zoom
    Then input fields are appropriately sized, not cut off, cursor is visible when typing, field boundaries are clear
    And verify error messages and validation indicators are visible at 200% zoom
    Then error messages appear in full, are not hidden or truncated, validation icons are visible and appropriately sized
    And navigate through entire form using Tab key at 200% zoom
    Then focus indicator is visible and appropriately sized, focused elements scroll into view automatically, no content is inaccessible
    And fill out and submit form at 200% zoom
    Then all form functionality works correctly, submission succeeds, confirmation message is fully visible and readable
    And form is fully functional at 200% zoom
    And no content is lost or becomes inaccessible
    And layout adapts appropriately to zoom level
    And users with low vision can use form effectively

  @high @tc-acce-005
  Scenario: TC-ACCE-005 - Verify form provides clear focus management and no keyboard traps exist
    Given agent is logged into Agent Portal using keyboard only
    And quote initiation form is displayed
    And modal dialogs or overlays may appear during interaction
    And focus management is implemented for dynamic content
    When navigate to quote form and trigger validation error by submitting empty form using keyboard
    Then after error appears, focus automatically moves to first field with error or to error summary, focus is not lost
    And open Policy Type dropdown using keyboard (Space or Enter), then press Escape key
    Then dropdown closes, focus returns to Policy Type field (not lost), user can continue navigating form
    And open Effective Date picker using keyboard, navigate dates, then press Escape
    Then date picker closes, focus returns to Effective Date field, no keyboard trap occurs
    And fill form and click 'Save as Draft', observe focus after success message appears
    Then success message appears, focus moves to message or remains on 'Save as Draft' button, user can navigate away from message using Tab
    And if confirmation dialog appears after submission, navigate through dialog using Tab
    Then focus is trapped within dialog (cannot tab to background content), can navigate all dialog elements, Escape or 'Close' button exits dialog and returns focus appropriately
    And test that focus never becomes invisible or stuck in any part of the form
    Then focus indicator is always visible, focus never gets trapped in any component, user can always navigate forward and backward through all interactive elements
    And no keyboard traps exist anywhere in form
    And focus is managed logically for all dynamic content
    And focus indicator is always visible
    And users can complete entire workflow using keyboard only

