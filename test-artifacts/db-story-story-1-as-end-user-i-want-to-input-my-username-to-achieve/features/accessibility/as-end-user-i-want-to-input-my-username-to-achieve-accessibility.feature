@accessibility @a11y @wcag
Feature: As End User, I want to input my username to achieve identification for authentication - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify username input field is fully accessible via keyboard navigation using Tab key
    Given user is on the login page
    And username input field is visible and enabled
    And keyboard is the only input method being used (no mouse)
    And page has fully loaded with all interactive elements
    When press Tab key repeatedly from the top of the page to navigate through interactive elements
    Then focus moves sequentially through page elements in logical order
    And continue pressing Tab until focus reaches the username input field
    Then username input field receives focus with visible focus indicator (blue outline or border)
    And verify the focus indicator is clearly visible with sufficient contrast
    Then focus indicator is visible with at least 3:1 contrast ratio against background, clearly showing field is focused
    And type username 'keyboarduser' using keyboard only
    Then text 'keyboarduser' appears in the field as typed
    And press Tab key to move focus to the next element (password field or submit button)
    Then focus moves to next interactive element in logical tab order, username field retains entered value
    And press Shift+Tab to move focus back to username field
    Then focus returns to username field with visible focus indicator, entered text 'keyboarduser' is still present
    And username field is fully accessible via keyboard Tab navigation
    And focus indicators are visible and meet contrast requirements
    And tab order is logical and predictable
    And entered username value is preserved during navigation

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify username input field has proper ARIA labels and is announced correctly by screen readers
    Given user is on the login page
    And screen reader software is active (NVDA, JAWS, or VoiceOver)
    And username input field is visible
    And user is navigating with screen reader in forms mode
    When use screen reader navigation (Tab key or arrow keys) to move to the username input field
    Then screen reader announces the field with label: 'Username, edit text' or 'Username, text field'
    And verify screen reader announces the placeholder text when field is empty
    Then screen reader announces: 'Enter your username' as placeholder or hint text
    And verify the field has proper ARIA attributes by checking for aria-label or associated label element
    Then field has either aria-label='Username' or is associated with <label> element containing 'Username' text via for/id attributes
    And type username 'screenreadertest' in the field
    Then screen reader announces each character as typed or announces word after completion
    And tab out of the field without entering text to trigger validation error
    Then screen reader announces error message: 'Username is required, error' or similar with error role/aria-live region
    And verify error message is associated with field via aria-describedby or aria-errormessage
    Then screen reader announces error in context of the username field, making clear connection between field and error
    And username field is properly labeled for screen readers
    And all field states (empty, filled, error) are announced correctly
    And aRIA attributes are properly implemented
    And error messages are accessible and associated with the field

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify username field error messages are announced by screen readers via ARIA live regions
    Given user is on the login page
    And screen reader is active (NVDA, JAWS, or VoiceOver)
    And username input field is visible and empty
    And user is in forms mode with screen reader
    When navigate to username input field using screen reader
    Then screen reader announces: 'Username, edit text, Enter your username'
    And tab out of the empty username field without entering any text
    Then validation error is triggered
    And listen for screen reader announcement of error message
    Then screen reader immediately announces: 'Username is required' or 'Error: Username is required' via ARIA live region
    And navigate back to username field using Shift+Tab
    Then screen reader announces field with error state: 'Username, invalid entry, Username is required, edit text'
    And verify error message has aria-live='polite' or 'assertive' attribute for dynamic announcement
    Then error message container has aria-live attribute ensuring screen reader announces changes without user navigation
    And type valid username 'validuser' and tab out
    Then screen reader announces error is cleared (silence or 'valid' announcement), error message disappears
    And error messages are announced dynamically via ARIA live regions
    And screen reader users are immediately informed of validation errors
    And error state is clearly communicated when field is focused
    And error clearing is also announced or indicated to screen reader users

  @high @tc-acce-004
  Scenario: TC-ACCE-004 - Verify username field label has sufficient color contrast ratio for WCAG AA compliance
    Given user is on the login page
    And username input field with label 'Username' is visible
    And color contrast checking tool is available (browser extension or online tool)
    And page is displayed at 100% zoom level
    When locate the 'Username' label text above or adjacent to the input field
    Then label 'Username' is visible and clearly readable
    And use color contrast checker tool to measure contrast ratio between label text color and background color
    Then contrast ratio is measured and displayed by the tool
    And verify the contrast ratio meets WCAG AA standard of at least 4.5:1 for normal text
    Then contrast ratio is 4.5:1 or higher (e.g., 7.2:1, 12:1), meeting WCAG AA compliance
    And check placeholder text 'Enter your username' contrast ratio against field background
    Then placeholder text has at least 4.5:1 contrast ratio or meets WCAG requirements for placeholder text
    And verify error message text color contrast when validation error is displayed
    Then error message 'Username is required' in red has at least 4.5:1 contrast ratio against background
    And all text elements (label, placeholder, error) meet WCAG AA contrast requirements
    And text is readable for users with low vision or color blindness
    And page meets accessibility compliance standards
    And visual design supports accessibility requirements

  @medium @tc-acce-005
  Scenario: TC-ACCE-005 - Verify username field remains functional and readable at 200% browser zoom level
    Given user is on the login page
    And browser is set to 100% zoom level initially
    And username input field is visible
    And page layout is responsive
    When verify username field is visible and functional at 100% zoom
    Then field displays correctly with label 'Username' and placeholder text visible
    And press Ctrl and + (or Cmd and + on Mac) repeatedly to increase zoom to 200%
    Then page zooms to 200%, all elements scale proportionally
    And verify username field label 'Username' is still fully visible and readable
    Then label text is not cut off, truncated, or overlapping other elements; remains fully readable
    And verify username input field is fully visible and functional
    Then input field is not cut off, maintains proper size, and is fully interactive
    And click inside the username field and type 'zoomtest'
    Then text entry works normally, typed text 'zoomtest' is visible and readable at 200% zoom
    And trigger validation error by clearing field and tabbing out
    Then error message 'Username is required' is fully visible and readable at 200% zoom without horizontal scrolling
    And verify no content is lost and horizontal scrolling is not required (or minimal)
    Then all form elements remain accessible, layout adapts to zoom level, no critical content is hidden
    And username field is fully functional at 200% zoom
    And all text remains readable without loss of content
    And layout adapts appropriately to zoom level
    And wCAG 2.1 Level AA zoom requirement (1.4.4) is met

  @high @tc-acce-006
  Scenario: TC-ACCE-006 - Verify username field focus indicator is visible and meets WCAG focus visible requirements
    Given user is on the login page
    And username input field is visible
    And keyboard navigation is being used
    And focus indicator styling is implemented
    When press Tab key to navigate to the username input field
    Then username field receives keyboard focus
    And verify a visible focus indicator appears around the username field
    Then focus indicator is clearly visible: blue outline, border change, or glow effect around the field
    And measure the focus indicator contrast ratio against adjacent colors using contrast checker
    Then focus indicator has at least 3:1 contrast ratio against adjacent colors (WCAG 2.1 Level AA requirement)
    And verify focus indicator is at least 2 CSS pixels thick or has sufficient visual weight
    Then focus indicator border/outline is clearly visible with adequate thickness (2px or more)
    And press Tab to move focus away from username field
    Then focus indicator disappears from username field and appears on next focusable element
    And press Shift+Tab to return focus to username field
    Then focus indicator reappears on username field, clearly showing it has focus again
    And focus indicator is clearly visible when field has focus
    And focus indicator meets WCAG 2.1 contrast requirements (3:1)
    And focus indicator is removed when focus moves away
    And keyboard users can clearly see which element has focus

  @medium @tc-acce-007
  Scenario: TC-ACCE-007 - Verify username field is accessible on mobile devices with proper touch target size
    Given user is accessing login page on mobile device (iOS or Android) or mobile emulator
    And username input field is visible on mobile viewport
    And touch input is available
    And page is responsive and mobile-optimized
    When load login page on mobile device or in mobile emulator (viewport 375x667 or similar)
    Then login page loads and displays correctly in mobile viewport
    And locate the username input field on the mobile screen
    Then username field is visible, properly sized, and not cut off or overlapping
    And measure or verify the touch target size of the username field is at least 44x44 CSS pixels (iOS) or 48x48dp (Android)
    Then username field touch target meets minimum size requirements: at least 44x44 pixels for easy tapping
    And tap on the username input field with finger
    Then field receives focus immediately, mobile keyboard appears, cursor is visible in field
    And type username 'mobileuser' using mobile keyboard
    Then text 'mobileuser' appears in field as typed, mobile keyboard functions properly
    And verify label 'Username' is visible and readable on mobile screen
    Then label text is not too small, maintains readability on mobile device (at least 16px font size recommended)
    And tap outside the field to dismiss keyboard and verify entered text is retained
    Then mobile keyboard dismisses, username 'mobileuser' remains in field, field loses focus
    And username field is easily tappable on mobile devices
    And touch target size meets WCAG 2.1 Level AAA guidelines (2.5.5)
    And mobile keyboard interaction works correctly
    And field is fully functional on mobile devices for users with motor impairments

