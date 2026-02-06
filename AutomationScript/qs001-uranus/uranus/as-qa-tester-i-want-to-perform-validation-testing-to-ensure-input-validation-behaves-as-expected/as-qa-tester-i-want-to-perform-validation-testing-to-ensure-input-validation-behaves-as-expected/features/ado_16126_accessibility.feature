Feature: Validation Form Accessibility Testing
  As a QA Tester
  I want to ensure validation features are fully accessible to all users
  So that users with disabilities can successfully interact with forms and receive validation feedback

  Background:
    Given user is on the validation test form page
    And form contains multiple input fields with validation rules

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation through validation form and error messages
    Given mouse is disconnected or not used during test
    And screen reader is turned off to test keyboard-only navigation
    When user presses Tab key from browser address bar
    Then focus should move to first input field
    And visible focus indicator should appear around the field
    When user continues pressing Tab key through all form fields
    Then focus should move sequentially through all interactive elements
    And focus indicator should be clearly visible on each element
    And tab order should follow visual layout
    When user presses Shift+Tab to navigate backwards
    Then focus should move in reverse order through all fields
    And focus indicator should remain visible
    And no focus traps should occur
    When user navigates to a required field and leaves it empty
    And user presses Tab to move to next field
    Then validation error message should appear
    And focus should move to next field
    And error message should be associated with the field
    When user presses Shift+Tab to return to field with validation error
    Then focus should return to the invalid field
    And focus indicator should be visible
    And error message should remain displayed
    When user navigates to submit button using Tab key
    And user presses Enter key
    Then form submission should be triggered
    And focus should move to first invalid field if validation fails
    And all error messages should be displayed
    When user presses Escape key on any form field
    Then modal or dropdown should close if open
    And focus should remain on current element if no modal is open

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader announcements for validation errors and success messages
    Given screen reader is enabled
    And audio output is enabled to hear announcements
    When user navigates to first input field using screen reader commands
    Then screen reader should announce field label
    And screen reader should announce field type
    And screen reader should announce required status
    And screen reader should announce any help text
    When user leaves required field empty and navigates to next field
    Then screen reader should announce "Error: This field is required"
    And error should be associated with the field
    When user enters invalid email format and navigates away
    Then screen reader should announce "Error: Please enter a valid email address"
    And error message should be clear and descriptive
    When user corrects invalid input to valid data and navigates away
    Then screen reader should announce error is cleared or remain silent
    And no error message should be announced
    And field should be marked as valid
    When user fills all fields with valid data
    And user activates submit button
    Then screen reader should announce "Success: Form submitted successfully"
    And announcement should use ARIA live region
    And announcement should be clear and immediate
    When user navigates to error summary section after validation fails
    Then screen reader should announce "Error summary" heading
    And screen reader should list all validation errors with links
    And errors should be numbered or bulleted
    When user activates link in error summary
    Then focus should move to corresponding invalid field
    And screen reader should announce field label and error message

  @accessibility @a11y @priority-high @focus-management
  Scenario: Focus management and focus trap prevention in validation modals
    Given user is on page with validation that triggers modal dialogs
    And keyboard-only navigation is being used
    And screen reader is enabled for testing
    When user triggers validation error that opens modal dialog
    Then modal should open
    And focus should automatically move to first focusable element in modal
    And screen reader should announce modal title and role
    When user presses Tab key repeatedly in modal
    Then focus should cycle only through elements within modal
    And focus should not escape to background page content
    When user presses Shift+Tab from first focusable element in modal
    Then focus should move to last focusable element in modal
    And focus trap should keep focus within modal
    When user presses Escape key while focus is inside modal
    Then modal should close
    And focus should return to element that triggered modal
    And screen reader should announce modal closure
    When user reopens modal and activates close button using Enter key
    Then modal should close
    And focus should return to triggering element
    And no focus should be lost to document body
    When user reopens modal and activates confirmation button
    Then modal should close after action is completed
    And focus should return to appropriate element
    And screen reader should announce the result

  @accessibility @a11y @priority-high @color-contrast
  Scenario: Color contrast and visual indicators for validation states
    Given color contrast analyzer tool is available
    And form displays validation states for default, error, success, and focus
    And browser zoom is set to 100%
    When user checks contrast ratio of error message text against background
    Then error message text should have minimum contrast ratio of "4.5:1" for normal text
    And error message should meet WCAG 2.1 AA standards
    When user checks contrast ratio of error state border color against white background
    Then error border should have minimum contrast ratio of "3:1"
    And error border should meet WCAG 2.1 AA standards for non-text contrast
    When user verifies validation errors are indicated by more than color
    Then error state should include error icon in addition to red color
    And error message text should be present
    And error should not rely solely on color
    When user checks contrast ratio of success message and indicators
    Then success message should have minimum "4.5:1" contrast ratio
    And success icon should be present in addition to green color
    When user focuses on input field and checks focus indicator contrast
    Then focus indicator should have minimum "3:1" contrast ratio against background
    And focus indicator should be at least "2" pixels thick
    When user enables Windows High Contrast Mode
    Then all validation states should remain visible and distinguishable
    And icons and borders should be visible in high contrast mode

  @accessibility @a11y @priority-medium @zoom @responsive
  Scenario: Form validation accessibility at 200% browser zoom and text scaling
    Given browser zoom is initially set to 100%
    And test is performed on desktop browser
    When user sets browser zoom to "200" percent
    Then page should zoom to "200" percent
    And all content should scale proportionally
    And no horizontal scrolling should be required for form content
    When user verifies form elements at "200" percent zoom
    Then all form labels should be visible and readable
    And all input fields should be visible and readable
    And all buttons should be visible and readable
    And no text should be truncated or cut off
    And form layout should adapt responsively
    And no elements should overlap
    When user triggers validation errors at "200" percent zoom
    Then error messages should display completely
    And error text should not be truncated
    And error icons should be visible
    And error messages should be positioned correctly near fields
    When user navigates through form fields using Tab key at "200" percent zoom
    Then focus indicator should be visible and properly sized
    And focused elements should scroll into view automatically if needed
    When user increases browser text size to "200" percent
    Then text should scale to "200" percent
    And layout should adapt without breaking
    And no text should overlap or become unreadable
    And form should remain functional
    When user submits form with valid data at "200" percent zoom
    Then form should submit successfully
    And success message should be fully visible and readable
    And all functionality should work as expected

  @accessibility @a11y @priority-high @aria @semantic-html
  Scenario: ARIA attributes and roles for validation feedback elements
    Given browser developer tools are open to inspect ARIA attributes
    And screen reader is enabled for testing announcements
    When user inspects required input field in browser developer tools
    Then field should have "aria-required" attribute set to "true"
    And field should have associated label with proper for/id relationship
    When user triggers validation error and inspects input field
    Then field should have "aria-invalid" attribute set to "true"
    And field should have "aria-describedby" attribute pointing to error message ID
    And error message element should have appropriate role or be in live region
    When user inspects error message element in developer tools
    Then error message should have unique ID matching "aria-describedby" value
    And error message should have "role" attribute set to "alert" or be within ARIA live region
    When user corrects validation error and inspects field again
    Then "aria-invalid" attribute should be removed or set to "false"
    And "aria-describedby" should no longer reference error message
    And error message should be removed from DOM or hidden with "aria-hidden"
    When user inspects form element in developer tools
    Then form should have appropriate "role" attribute set to "form" or be semantic form element
    And form should have accessible name via "aria-label" or "aria-labelledby" if multiple forms exist
    When user tests with screen reader to verify ARIA attributes
    Then screen reader should announce required status correctly
    And screen reader should announce invalid status correctly
    And screen reader should announce error messages correctly
    And all ARIA relationships should function as intended
    When user inspects success message after successful form submission
    Then success message should be in "aria-live" region set to "polite"
    And success message should be announced by screen reader without requiring focus
    And message should have appropriate role or semantic markup

  @accessibility @a11y @priority-medium @mobile @touch
  Scenario: Mobile accessibility for validation feedback with touch and gesture support
    Given test is performed on mobile device or mobile emulator
    And mobile screen reader is enabled
    And form is responsive and optimized for mobile devices
    When user enables mobile screen reader and swipes right to first field
    Then screen reader should announce field label
    And screen reader should announce field type
    And screen reader should announce required status
    And screen reader should announce any help text
    And focus indicator should be visible on mobile
    When user verifies touch target sizes
    Then all interactive elements should be at least "44" by "44" pixels
    And adequate spacing should exist between touch targets
    When user taps on input field and enters invalid data
    Then error message should appear below field
    And error message should be announced by screen reader
    And error message should be large enough to read on mobile screen
    When user uses screen reader gestures to navigate through error messages
    Then screen reader should navigate to and read all error messages
    And error messages should be in logical reading order
    And swipe gestures should work correctly
    When user double-taps submit button with screen reader active
    Then form should submit
    And validation errors should be announced if present
    And success message should be announced if submission succeeds
    When user tests pinch-to-zoom functionality on form
    Then form should zoom up to "200" percent without loss of functionality
    And validation messages should remain visible and readable when zoomed
    And no content should be cut off
    When user rotates device to landscape orientation
    Then form layout should adapt to landscape orientation
    And all validation messages should remain visible
    And functionality should be preserved in both orientations