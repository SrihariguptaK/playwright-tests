@functional @smoke
Feature: As End User, I want to input my username to achieve identification for authentication - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Verify username input field displays with correct label and placeholder text
    Given user has navigated to the login page URL
    And login page is fully loaded in a supported browser (Chrome, Firefox, Safari, Edge)
    And no previous session is active (user is logged out)
    And page DOM elements are rendered completely
    When navigate to the login page by entering the login URL in the browser
    Then login page loads successfully and displays the login form
    And locate the username input field on the login form
    Then username input field is visible and properly rendered
    And verify the label text above or adjacent to the username input field
    Then label displays exactly 'Username' in clear, readable text
    And click inside the username input field to focus it
    Then input field receives focus and placeholder text 'Enter your username' is visible in light gray color
    And verify the input field is empty and ready for text entry
    Then cursor blinks inside the input field, ready to accept keyboard input
    And username input field remains focused and ready for user input
    And no error messages are displayed
    And login form remains in its initial state
    And page remains on the login screen

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Verify successful username input with valid alphanumeric characters
    Given user is on the login page with username input field visible
    And username input field is empty and enabled
    And keyboard input is functional
    And no validation errors are currently displayed
    When click inside the username input field to focus it
    Then input field receives focus with visible cursor and placeholder text disappears
    And type a valid username 'testuser123' using the keyboard
    Then each character appears in the input field as typed, displaying 'testuser123'
    And verify the entered text is visible and correctly formatted in the input field
    Then username 'testuser123' is displayed clearly in the input field with no formatting issues
    And click outside the username input field or press Tab key to remove focus
    Then input field loses focus, entered username remains visible, no error messages appear
    And verify that the username value is retained in the field
    Then username 'testuser123' remains in the input field and is ready for form submission
    And username 'testuser123' is stored in the input field value
    And no validation errors are displayed
    And form is ready to proceed to password input or submission
    And input field maintains the entered value until cleared or submitted

  @medium @tc-func-003
  Scenario: TC-FUNC-003 - Verify username input field accepts and displays lowercase letters
    Given user is on the login page
    And username input field is visible and enabled
    And no text is currently entered in the username field
    And browser supports standard text input
    When click inside the username input field
    Then input field is focused with blinking cursor
    And type lowercase username 'johnsmith' using keyboard
    Then text 'johnsmith' appears in the input field exactly as typed in lowercase
    And verify the text is displayed without any automatic case conversion
    Then username displays as 'johnsmith' in lowercase without conversion to uppercase or title case
    And tab out of the username field
    Then field loses focus and retains 'johnsmith' as entered, no validation errors appear
    And username 'johnsmith' is stored in lowercase in the input field
    And no error messages are displayed
    And form remains in valid state ready for next input
    And username value is preserved for form submission

  @medium @tc-func-004
  Scenario: TC-FUNC-004 - Verify username input field accepts and displays uppercase letters
    Given user is on the login page
    And username input field is visible and enabled
    And input field is empty
    And caps Lock functionality is available
    When click inside the username input field to focus it
    Then input field receives focus with cursor visible
    And type uppercase username 'ADMINUSER' using keyboard with Caps Lock on or Shift key
    Then text 'ADMINUSER' appears in the input field in uppercase letters
    And verify the text displays in uppercase without automatic conversion
    Then username displays exactly as 'ADMINUSER' in all uppercase letters
    And click outside the username field to blur focus
    Then field loses focus, 'ADMINUSER' remains visible, no validation errors shown
    And username 'ADMINUSER' is stored in uppercase in the input field
    And no validation errors are present
    And form state is valid and ready for submission
    And username value is preserved exactly as entered

  @medium @tc-func-005
  Scenario: TC-FUNC-005 - Verify username input field accepts mixed case alphanumeric characters
    Given user is on the login page
    And username input field is visible and enabled
    And field is empty and ready for input
    And keyboard input is functional
    When click inside the username input field
    Then input field is focused with blinking cursor
    And type mixed case username 'TestUser2024' using keyboard
    Then each character appears as typed: 'TestUser2024' with mixed uppercase, lowercase, and numbers
    And verify all characters (uppercase T, lowercase letters, and numbers) are displayed correctly
    Then username displays exactly as 'TestUser2024' with proper case preservation
    And press Tab key to move focus away from username field
    Then focus moves to next field (password field), username 'TestUser2024' remains visible, no errors shown
    And username 'TestUser2024' is stored with exact case and numbers preserved
    And no validation errors are displayed
    And form is in valid state
    And focus has moved to the next input field in the form

  @medium @tc-func-006
  Scenario: TC-FUNC-006 - Verify username input can be edited and modified after initial entry
    Given user is on the login page
    And username input field is visible
    And username 'oldusername' has been previously entered in the field
    And cursor and keyboard editing functions are available
    When click inside the username input field containing 'oldusername'
    Then input field receives focus, cursor appears at click position within the text
    And use Ctrl+A (or Cmd+A on Mac) to select all text in the field
    Then all text 'oldusername' is highlighted/selected
    And type new username 'newusername' to replace selected text
    Then old text is replaced and 'newusername' appears in the input field
    And verify the new username is displayed correctly
    Then input field displays 'newusername' with no remnants of old text
    And click outside the field to blur focus
    Then field loses focus, 'newusername' is retained, no validation errors appear
    And username field contains 'newusername' as the current value
    And previous value 'oldusername' has been completely replaced
    And no validation errors are present
    And form is ready for submission with updated username

  @high @tc-func-007
  Scenario: TC-FUNC-007 - Verify username input sanitization prevents script injection attempts
    Given user is on the login page
    And username input field is visible and enabled
    And input sanitization security measures are implemented
    And field is empty and ready for input
    When click inside the username input field to focus it
    Then input field receives focus with cursor visible
    And type username containing script tags: '<script>alert("test")</script>'
    Then text is entered into the field (may display as-is in the input field)
    And tab out of the username field or attempt to submit the form
    Then input is sanitized: either special characters are stripped/escaped, or validation error appears stating 'Username contains invalid characters' or similar message
    And verify that no script execution occurs (no alert popup appears)
    Then no JavaScript alert or script execution occurs, input is treated as plain text
    And check that the sanitized or rejected input does not allow form submission with malicious content
    Then form either blocks submission with error message or sanitizes input to safe plain text before processing
    And no script injection has occurred in the application
    And username field either contains sanitized text or displays validation error
    And application security is maintained
    And user is prevented from submitting malicious input

