@negative @error-handling
Feature: As End User, I want to input my username to achieve identification for authentication - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify form submission is prevented when username field is empty
    Given user is on the login page
    And username input field is visible and enabled
    And username field is completely empty (no text entered)
    And submit button or form submission mechanism is available
    When verify the username input field is empty with no text
    Then username field displays placeholder text 'Enter your username' and contains no actual value
    And click the submit button or press Enter key to attempt form submission
    Then form submission is blocked and prevented from processing
    And verify that an inline error message appears near the username field
    Then error message 'Username is required' appears in red text below or adjacent to the username field
    And verify the username input field receives visual error indication
    Then username field border changes to red color or displays error styling to indicate validation failure
    And verify focus is set to the username field
    Then cursor is automatically placed in the username field for user to enter required input
    And form has not been submitted to the server
    And error message 'Username is required' is displayed
    And username field shows error state with red border or error styling
    And user remains on the login page to correct the error

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify form submission is prevented when username contains only whitespace characters
    Given user is on the login page
    And username input field is visible and enabled
    And form validation is active
    And submit button is available
    When click inside the username input field to focus it
    Then input field receives focus with cursor visible
    And press the spacebar key multiple times to enter only spaces (e.g., '     ')
    Then whitespace characters are entered in the field (may appear as blank space)
    And click the submit button or press Enter to attempt form submission
    Then form submission is blocked and prevented
    And verify error message appears indicating username is required
    Then error message 'Username is required' appears below the username field in red text
    And verify the username field displays error styling
    Then username field border turns red and field shows error state
    And form has not been submitted
    And error message is displayed indicating username is required
    And username field shows error state
    And user remains on login page to enter valid username

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Verify username field rejects SQL injection attempts
    Given user is on the login page
    And username input field is visible and enabled
    And input sanitization and validation are implemented
    And security measures are active
    When click inside the username input field
    Then input field receives focus
    And type SQL injection string: "admin' OR '1'='1" in the username field
    Then text is entered into the field
    And tab out of the username field or attempt to submit the form
    Then validation error appears: 'Username contains invalid characters' or similar security-related error message
    And verify the input is either sanitized or rejected
    Then special characters like quotes and SQL keywords are either stripped/escaped, or form submission is blocked with error
    And verify no SQL injection vulnerability is exploited
    Then no unauthorized access occurs, input is treated as plain text, security is maintained
    And sQL injection attempt has been blocked or sanitized
    And error message is displayed or input is sanitized to safe text
    And no security breach has occurred
    And form either shows validation error or sanitized input

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Verify username field rejects XSS attack attempts with event handlers
    Given user is on the login page
    And username input field is visible
    And xSS protection is implemented
    And input sanitization is active
    When click inside the username input field
    Then field receives focus
    And type XSS payload: "<img src=x onerror=alert('XSS')>" in the username field
    Then text is entered into the field
    And tab out of the field or attempt form submission
    Then validation error appears: 'Username contains invalid characters' or input is sanitized
    And verify no JavaScript alert or script execution occurs
    Then no alert popup appears, no script is executed, input is treated as plain text
    And verify the malicious input is either stripped or form submission is blocked
    Then hTML tags and event handlers are removed/escaped, or validation error prevents submission
    And xSS attack has been prevented
    And no script execution has occurred
    And input is sanitized or validation error is shown
    And application security is maintained

  @medium @tc-nega-005
  Scenario: TC-NEGA-005 - Verify error handling when username field loses focus without input
    Given user is on the login page
    And username input field is visible and empty
    And real-time validation on blur is implemented
    And no text has been entered
    When click inside the username input field to focus it
    Then field receives focus, placeholder text disappears, cursor is visible
    And without typing anything, click outside the username field or press Tab key
    Then field loses focus
    And verify that validation error message appears
    Then error message 'Username is required' appears below the username field in red text
    And verify the username field displays error styling
    Then username field border turns red indicating validation error
    And verify placeholder text reappears in the empty field
    Then placeholder text 'Enter your username' is visible again in the empty field
    And error message 'Username is required' is displayed
    And username field shows error state with red border
    And field remains empty with placeholder text visible
    And user is prompted to enter username before proceeding

  @medium @tc-nega-006
  Scenario: TC-NEGA-006 - Verify username field rejects input with null bytes or control characters
    Given user is on the login page
    And username input field is visible
    And input validation for control characters is implemented
    And field is empty
    When click inside the username input field
    Then field receives focus
    And attempt to paste or enter username with null byte: 'admin\x00user' or control characters
    Then input is either rejected, control characters are stripped, or field shows no visible change
    And tab out of the field or attempt form submission
    Then validation error appears: 'Username contains invalid characters' or control characters are automatically removed
    And verify the field either shows sanitized input or validation error
    Then either only valid characters remain (e.g., 'adminuser') or error message is displayed
    And control characters and null bytes are rejected or sanitized
    And username field contains only valid characters or shows error
    And form security is maintained
    And user is prevented from submitting invalid input

  @medium @tc-nega-007
  Scenario: TC-NEGA-007 - Verify username field handles paste operation with invalid content appropriately
    Given user is on the login page
    And username input field is visible and enabled
    And clipboard contains text with special characters: '!@#$%^&*()+=[]{}|\:;"<>?/'
    And paste functionality is available
    When click inside the username input field to focus it
    Then field receives focus with cursor visible
    And press Ctrl+V (or Cmd+V on Mac) to paste clipboard content with special characters
    Then paste operation completes and content appears in field
    And tab out of the username field or attempt form submission
    Then validation error appears: 'Username contains invalid characters' or 'Username must contain only letters and numbers'
    And verify the username field displays error styling
    Then field border turns red and error message is displayed below the field
    And verify form submission is blocked
    Then submit button is disabled or clicking it shows validation error without submitting form
    And invalid pasted content is rejected with error message
    And username field shows error state
    And form submission is prevented
    And user is required to enter valid username format

