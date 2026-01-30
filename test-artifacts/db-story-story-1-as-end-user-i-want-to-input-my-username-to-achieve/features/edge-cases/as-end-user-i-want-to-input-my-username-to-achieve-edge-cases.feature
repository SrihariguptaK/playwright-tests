@edge-cases @boundary
Feature: As End User, I want to input my username to achieve identification for authentication - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-edge-001
  Scenario: TC-EDGE-001 - Verify username field handles maximum character length boundary
    Given user is on the login page
    And username input field is visible and enabled
    And maximum character limit is defined (assume 255 characters if not specified)
    And field is empty
    When click inside the username input field
    Then field receives focus
    And type or paste a username string with exactly 255 characters (e.g., 'a' repeated 255 times)
    Then all 255 characters are accepted and displayed in the field
    And attempt to type one additional character (256th character)
    Then either the character is not accepted (field stops accepting input at 255), or character counter shows limit reached
    And tab out of the field
    Then field loses focus, 255 characters remain in field, no validation error appears
    And verify form can be submitted with 255-character username
    Then form accepts the maximum length username without error
    And username field contains exactly 255 characters
    And no validation errors are displayed
    And form is ready for submission with maximum length username
    And character limit is properly enforced

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Verify username field handles minimum valid length (single character)
    Given user is on the login page
    And username input field is visible and enabled
    And no minimum length restriction is specified (or minimum is 1 character)
    And field is empty
    When click inside the username input field
    Then field receives focus
    And type a single character username: 'a'
    Then single character 'a' appears in the field
    And tab out of the username field
    Then field loses focus, single character 'a' remains visible, no validation error appears
    And verify the form accepts this single-character username
    Then no error message is displayed, form is in valid state
    And attempt to submit the form with single-character username
    Then form submission is allowed (validation passes for single character)
    And username field contains single character 'a'
    And no validation errors are present
    And form is ready for submission
    And minimum length boundary is properly handled

  @medium @tc-edge-003
  Scenario: TC-EDGE-003 - Verify username field handles Unicode characters and international text
    Given user is on the login page
    And username input field is visible and enabled
    And browser supports Unicode input
    And field is empty
    When click inside the username input field
    Then field receives focus
    And type or paste username with Unicode characters: '用户名123' (Chinese characters with numbers)
    Then unicode characters are entered and displayed correctly in the field
    And tab out of the username field
    Then field loses focus, Unicode characters remain visible and properly rendered
    And verify the system's handling: either accepts Unicode (no error) or shows validation error if only ASCII is allowed
    Then either username is accepted with no error, or validation error appears: 'Username must contain only English letters and numbers'
    And verify consistent behavior with other Unicode sets (Arabic: 'مستخدم', Cyrillic: 'пользователь')
    Then system handles all Unicode consistently - either accepts all or rejects all with clear error message
    And unicode handling is consistent and predictable
    And either Unicode is accepted or clear validation error is shown
    And no character rendering issues or corruption occurs
    And system behavior is documented and consistent

  @low @tc-edge-004
  Scenario: TC-EDGE-004 - Verify username field handles rapid consecutive input and deletion
    Given user is on the login page
    And username input field is visible and enabled
    And field is empty
    And keyboard input is responsive
    When click inside the username input field
    Then field receives focus
    And rapidly type username 'testuser' as fast as possible
    Then all characters appear in correct order: 'testuser' with no missing or duplicated characters
    And immediately press and hold Backspace key to rapidly delete all characters
    Then characters are deleted one by one from right to left until field is empty
    And rapidly type another username 'newuser' immediately after deletion
    Then new username 'newuser' appears correctly with all characters in proper order
    And verify field state is stable and no characters are corrupted or duplicated
    Then field displays 'newuser' correctly with no artifacts from previous input
    And username field contains 'newuser' with no corruption
    And field handles rapid input/deletion without errors
    And no performance issues or lag observed
    And field state is consistent and stable

  @medium @tc-edge-005
  Scenario: TC-EDGE-005 - Verify username field behavior with copy-paste operations of very long text
    Given user is on the login page
    And username input field is visible
    And clipboard contains text exceeding 1000 characters
    And maximum field length is enforced (e.g., 255 characters)
    When click inside the username input field
    Then field receives focus
    And press Ctrl+V (or Cmd+V) to paste 1000+ character text from clipboard
    Then paste operation completes
    And verify the field truncates input to maximum allowed length (e.g., 255 characters)
    Then only first 255 characters are displayed in field, remaining characters are discarded
    And verify no error message appears for truncation (or appropriate message if shown)
    Then either no error appears (silent truncation) or informational message: 'Username truncated to maximum length'
    And tab out of field and verify form accepts truncated input
    Then field loses focus, truncated username is accepted, form is in valid state
    And username field contains exactly 255 characters (truncated from 1000+)
    And no validation errors are present
    And form is ready for submission
    And excess characters beyond limit are properly discarded

  @low @tc-edge-006
  Scenario: TC-EDGE-006 - Verify username field handles emoji and special Unicode symbols
    Given user is on the login page
    And username input field is visible
    And browser supports emoji input
    And field is empty
    When click inside the username input field
    Then field receives focus
    And type or paste username with emojis: 'user😀test🎉'
    Then text with emojis is entered into the field
    And tab out of the username field
    Then field loses focus
    And verify system handling: either accepts emojis or shows validation error
    Then either emojis are displayed correctly with no error, or validation error appears: 'Username contains invalid characters'
    And verify consistent behavior and no rendering issues with emoji display
    Then emojis either render properly or are rejected with clear error; no broken characters or display corruption
    And emoji handling is consistent and predictable
    And either emojis are accepted or validation error is shown
    And no character rendering corruption occurs
    And system behavior with special Unicode is documented

  @medium @tc-edge-007
  Scenario: TC-EDGE-007 - Verify username field behavior when browser autofill populates the field
    Given user is on the login page
    And browser has saved username 'saveduser123' from previous login
    And browser autofill feature is enabled
    And username field is empty initially
    When click inside the username input field
    Then field receives focus and browser shows autofill dropdown with saved username 'saveduser123'
    And click on the autofill suggestion 'saveduser123' or press Down arrow and Enter
    Then username field is automatically populated with 'saveduser123'
    And verify the autofilled username is displayed correctly in the field
    Then username 'saveduser123' appears in the field with proper formatting
    And verify no validation errors appear for autofilled content
    Then no error messages are displayed, field shows valid state
    And tab out of the field and verify form accepts autofilled username
    Then field loses focus, autofilled username is retained, form is in valid state ready for submission
    And username field contains autofilled value 'saveduser123'
    And no validation errors are present
    And form is ready for submission with autofilled data
    And autofill integration works correctly with validation

