Feature: Schedule Change Request Accessibility Compliance
  As an employee with accessibility needs
  I want the schedule change request form to be fully accessible
  So that I can submit schedule changes using keyboard navigation, screen readers, and assistive technologies

  Background:
    Given user is logged in as an authenticated employee
    And user is on "Schedule Change Request" page

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation through schedule change request form
    Given browser is set to show focus indicators
    And screen reader is not active
    When user presses Tab key from page header
    Then focus should move to "Date" field
    And focus indicator with minimum "2" px width should be visible
    When user presses Tab key
    Then focus should move to "Time" field
    And focus indicator should be visible
    When user presses Tab key
    Then focus should move to "Reason" field
    And focus indicator should be visible
    When user presses Tab key
    Then focus should move to "Submit Request" button
    And focus indicator should be visible
    And button should show hover state
    When user presses Shift+Tab key
    Then focus should move backwards to "Reason" field
    When user presses Shift+Tab key
    Then focus should move backwards to "Time" field
    When user presses Shift+Tab key
    Then focus should move backwards to "Date" field
    When user navigates to "Date" field
    And user presses Space key to open date picker
    Then date picker should open
    And focus should be on current date
    And arrow keys should navigate between dates
    And Enter key should select date
    And Escape key should close picker
    When user fills all fields using keyboard only
    And user presses Enter on "Submit Request" button
    Then form should submit successfully
    And success message should receive focus
    And success message should be announced

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader announces form fields with proper labels and attributes
    Given NVDA or JAWS screen reader is active and running
    And screen reader is set to verbose mode
    And form has proper ARIA labels and roles
    When user navigates to "Date" field using Tab key
    Then screen reader should announce "Date, required, edit, date picker. Press Space to open calendar."
    When user navigates to "Time" field using Tab key
    Then screen reader should announce "Time, required, edit, time picker. Enter time in format HH:MM AM/PM."
    When user navigates to "Reason" field using Tab key
    Then screen reader should announce "Reason, required, edit, multi-line. Minimum 10 characters, maximum 500 characters."

  @accessibility @a11y @priority-high @screen-reader @validation
  Scenario: Screen reader announces validation errors correctly
    Given NVDA or JAWS screen reader is active and running
    And screen reader is set to verbose mode
    When user leaves "Date" field empty
    And user tabs out of "Date" field
    Then screen reader should announce "Date is required. Error. Date, required, invalid entry, edit."
    When user attempts to submit form with empty fields
    Then screen reader should announce "Form has 3 errors. Please correct the following: Date is required, Time is required, Reason is required."
    And focus should move to first error field

  @accessibility @a11y @priority-high @screen-reader @success-message
  Scenario: Screen reader announces successful form submission
    Given NVDA or JAWS screen reader is active and running
    And all form fields are filled correctly
    When user submits the form
    Then screen reader should announce "Schedule change request submitted successfully. Request ID: SCR-12350. Status region."

  @accessibility @a11y @priority-high @color-contrast @wcag-aa
  Scenario: Form field labels meet WCAG 2.1 AA contrast ratio standards
    Given color contrast analyzer tool is available
    And page is rendered in default theme
    And all form elements are visible on screen
    When user checks contrast ratio of form field labels against background
    Then contrast ratio should be at least "4.5" to 1 for "Date" label
    And contrast ratio should be at least "4.5" to 1 for "Time" label
    And contrast ratio should be at least "4.5" to 1 for "Reason" label

  @accessibility @a11y @priority-high @color-contrast @wcag-aa
  Scenario Outline: Text elements meet WCAG 2.1 AA contrast ratio requirements
    Given color contrast analyzer tool is available
    And page is rendered in default theme
    When user checks contrast ratio of "<element_type>" against background
    Then contrast ratio should be at least "<minimum_ratio>" to 1

    Examples:
      | element_type                  | minimum_ratio |
      | error message text            | 4.5           |
      | Submit Request button text    | 4.5           |
      | placeholder text              | 4.5           |
      | success message text          | 4.5           |

  @accessibility @a11y @priority-high @color-contrast @wcag-aa
  Scenario: Button maintains adequate contrast in all states
    Given color contrast analyzer tool is available
    When user checks "Submit Request" button text contrast in normal state
    Then contrast ratio should be at least "4.5" to 1
    When user checks "Submit Request" button text contrast in hover state
    Then contrast ratio should be at least "3" to 1
    When user checks "Submit Request" button text contrast in focus state
    Then contrast ratio should be at least "3" to 1

  @accessibility @a11y @priority-high @color-contrast @wcag-aa
  Scenario: Validation status is not conveyed by color alone
    Given form has validation errors
    When user views error state on form field
    Then error state should display red border
    And error state should display error icon
    And error state should display error text
    When user views success state on form field
    Then success state should display green checkmark
    And success state should display border color
    And success state should display success text

  @accessibility @a11y @priority-medium @zoom @responsive
  Scenario: Form remains functional at 200% browser zoom level
    Given browser zoom is set to "100" percent
    And browser window is at standard desktop resolution
    When user increases browser zoom to "200" percent
    Then page content should scale proportionally
    And all text should be larger and readable
    And no horizontal scrolling should be required for form content
    And "Date" field should be fully visible
    And "Time" field should be fully visible
    And "Reason" field should be fully visible
    And field labels should not be truncated
    And fields should be properly aligned vertically

  @accessibility @a11y @priority-medium @zoom @responsive
  Scenario: Submit button remains accessible at 200% zoom
    Given browser zoom is set to "200" percent
    When user views "Submit Request" button
    Then button should be visible without scrolling
    And button text should not be truncated
    And button should remain functional

  @accessibility @a11y @priority-medium @zoom @responsive
  Scenario: Form fields accept input and display errors correctly at 200% zoom
    Given browser zoom is set to "200" percent
    When user fills in all form fields
    Then all fields should accept input normally
    And date picker should open and function correctly
    And time picker should open and function correctly
    And text should be readable in all states
    When user triggers validation errors by leaving fields empty
    Then error messages should be fully visible
    And error messages should not be truncated
    And error messages should be positioned correctly below respective fields

  @accessibility @a11y @priority-medium @zoom @responsive
  Scenario: Form submission succeeds at 200% zoom level
    Given browser zoom is set to "200" percent
    And all form fields are filled correctly
    When user submits the form
    Then form should submit successfully
    And success message should be fully visible
    And success message should be readable at "200" percent zoom

  @accessibility @a11y @priority-high @focus-management @modal
  Scenario: Focus moves correctly when opening date picker modal
    Given "Date" field has accessible date picker component
    And keyboard navigation is being used
    When user tabs to "Date" field
    And user presses Space key
    Then date picker modal should open
    And focus should automatically move to current date in calendar grid

  @accessibility @a11y @priority-high @focus-management @modal @focus-trap
  Scenario: Focus is trapped within date picker modal
    Given date picker modal is open
    When user presses Tab key repeatedly
    Then focus should cycle through month selector
    And focus should cycle through year selector
    And focus should cycle through dates
    And focus should cycle through close button
    And focus should not escape to page content behind modal

  @accessibility @a11y @priority-high @focus-management @modal @keyboard-navigation
  Scenario: Arrow keys navigate between dates in calendar
    Given date picker modal is open
    And focus is on a date in calendar
    When user presses Up arrow key
    Then focus should move to date one week earlier
    When user presses Down arrow key
    Then focus should move to date one week later
    When user presses Left arrow key
    Then focus should move to previous date
    When user presses Right arrow key
    Then focus should move to next date
    And each date should be announced by screen reader with day, date, and month information

  @accessibility @a11y @priority-high @focus-management @modal
  Scenario: Escape key closes date picker and returns focus
    Given date picker modal is open
    When user presses Escape key
    Then date picker should close
    And focus should return to "Date" input field
    And no date should be selected

  @accessibility @a11y @priority-high @focus-management @modal
  Scenario: Selecting date with Enter key closes picker and returns focus
    Given date picker modal is open
    When user navigates to a date using arrow keys
    And user presses Enter key
    Then selected date should be populated in "Date" field
    And date picker should close
    And focus should return to "Date" field
    And "Date" field should display selected value

  @accessibility @a11y @priority-high @focus-management @modal
  Scenario Outline: Focus returns correctly when closing date picker via different methods
    Given date picker modal is open
    When user closes date picker using "<closure_method>"
    Then date picker should close
    And focus should return to "Date" field

    Examples:
      | closure_method          |
      | Escape key              |
      | close button click      |
      | clicking outside picker |