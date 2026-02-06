Feature: Input Validation Testing
  As a QA Tester
  I want to perform comprehensive validation testing
  So that I can ensure input validation behaves as expected and provides excellent user experience

  Background:
    Given application with input validation is accessible
    And test forms with various validation rules are available

  @undefined @functional @priority-high @usability
  Scenario: Verify real-time validation feedback provides immediate system status
    Given browser developer tools are available for timing measurements
    And user navigates to form with real-time validation enabled
    When user observes the initial state of input fields
    Then input fields should be clearly visible
    And no validation indicators should be shown initially
    When user begins typing "test@" in "Email" field
    Then visual feedback should appear within 500 milliseconds
    And validation indicator should be visible
    When user completes email address with "test@example.com" in "Email" field
    Then positive validation feedback should appear immediately
    And success icon should be displayed for "Email" field
    When user moves focus to another field
    Then validation status indicators should remain visible
    And validation status should be consistent for all fields
    When user submits form with mix of valid and invalid fields
    Then clear visual distinction between validated and non-validated fields should be shown
    And processing indicator should be displayed during submission
    And validation feedback response time should be less than 500 milliseconds

  @undefined @functional @priority-high @usability
  Scenario: Validate error prevention through input constraints and helpful guidance
    Given forms with various input types are available
    And test data sets prepared for boundary conditions
    And form specifications documenting validation rules are accessible
    When user examines input fields for format hints and placeholders
    Then all fields requiring specific formats should display clear examples
    And placeholders showing expected format should be visible
    When user attempts to enter "abc" in numeric-only field
    Then system should prevent entry of invalid characters
    And immediate inline warning should be shown
    When user tests date picker field by attempting manual entry
    Then date picker widget should be provided
    And format validation with helpful correction suggestions should be shown
    When user enters password in "Password" field
    Then password requirements should be visible before entry
    And strength meter should update in real-time
    And specific unmet requirements should be highlighted
    When user attempts to exceed maximum character count in text field
    Then character counter should display remaining characters
    And system should prevent exceeding limit
    And clear indication of maximum allowed should be shown
    When user attempts to submit form with required fields empty
    Then submit button should be disabled
    And indication of incomplete required fields should be shown

  @undefined @functional @priority-high @usability @negative
  Scenario Outline: Evaluate error message clarity and recovery guidance for validation failures
    Given application with server-side and client-side validation is accessible
    And test scenarios prepared for various validation error types
    And validation rules are documented for reference
    When user submits form with "<invalid_input>" in "<field_name>" field
    Then error message should use plain language
    And error message "<error_message>" should be displayed
    And error message should not contain technical jargon
    And error message should be clearly visible
    And error message should appear adjacent to "<field_name>" field
    And visual indicators should draw attention to errors
    And error message should be accessible via screen readers

    Examples:
      | field_name | invalid_input      | error_message                                                                    |
      | Email      | invalid-email      | Please enter a valid email address like name@example.com                         |
      | Password   | weak               | Password must contain at least one uppercase letter and one number               |
      | Username   | duplicate_user     | This username is already taken. Please choose a different username               |
      | Phone      | 123                | Please enter a valid phone number in format (XXX) XXX-XXXX                       |
      | Date       | 13/32/2024         | Please enter a valid date in format MM/DD/YYYY                                   |

  @undefined @functional @priority-high @usability
  Scenario: Verify error message presentation for multiple validation failures
    Given application with server-side and client-side validation is accessible
    And form with multiple required fields is displayed
    When user triggers multiple validation errors simultaneously
    Then all errors should be clearly listed with specific field identification
    And error summary should appear at top of form
    And error summary should contain links to each problematic field
    And each field should show inline error message
    When user corrects one error and resubmits form
    Then corrected field should no longer show error
    And remaining errors should still be clearly displayed
    And user should be able to progressively fix errors without losing context

  @undefined @functional @priority-high @usability @consistency
  Scenario: Verify consistency of validation behavior across multiple forms
    Given multiple forms are available in the application
    And documentation of validation standards and design system guidelines is accessible
    And checklist of consistency criteria is prepared
    When user navigates to 5 different forms in the application
    And user documents validation trigger timing for each form
    Then all forms should use consistent validation trigger pattern
    And validation timing should be identical across all forms
    When user compares error message styling across different forms
    Then error messages should use identical visual styling
    And error color should be consistent across all forms
    And error icon should be consistent across all forms
    And error positioning should be consistent across all forms
    And error typography should be consistent across all forms
    When user tests required field indicators across multiple forms
    Then required fields should be marked consistently
    And required field indicator position should be identical
    When user triggers validation errors on similar field types across different forms
    Then same field types should show identical validation rules
    And error messages should be identical for same field types
    When user tests success state indicators across forms
    Then valid input confirmation should use consistent visual pattern
    And success indicators should be identical across all forms
    When user tests keyboard navigation for validation errors across forms
    Then tab order should be consistent across all forms
    And focus management should be identical
    And ARIA announcements should be consistent

  @undefined @accessibility @priority-high @usability
  Scenario: Verify accessibility of validation feedback elements
    Given application with input validation is accessible
    And screen reader testing tools are available
    When user navigates to form using keyboard only
    Then all validation feedback should be accessible via keyboard
    And focus should move to first error field on form submission
    When validation error occurs
    Then ARIA live regions should announce validation status
    And error messages should be associated with form fields using aria-describedby
    And error fields should have aria-invalid attribute set to true
    When validation succeeds
    Then success status should be announced to screen readers
    And aria-invalid attribute should be removed from valid fields

  @undefined @performance @priority-medium @usability
  Scenario: Test validation performance under load
    Given application with input validation is accessible
    And load testing tools are configured
    When user submits 100 forms simultaneously with validation errors
    Then validation feedback should appear within 500 milliseconds for all submissions
    And system should remain responsive
    And no validation errors should be lost or delayed
    When user performs rapid input changes triggering real-time validation
    Then validation should debounce appropriately
    And system should not lag or freeze
    And validation feedback should remain accurate