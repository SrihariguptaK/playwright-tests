Feature: Accessible Shift Template Assignment for Employees
  As an Admin user relying on assistive technologies
  I want to assign shift templates to employees using accessible interfaces
  So that I can efficiently manage schedules regardless of my abilities or assistive technology needs

  Background:
    Given admin user is logged in to the system
    And user is on "Employee Schedule" page

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation through shift assignment workflow
    Given employee "Keyboard User" exists in the system
    And shift template "Day Shift (9AM-5PM)" is available
    And mouse is not used for this test
    When user presses Tab key repeatedly from page load
    Then focus should move in logical order through "main navigation, employee search field, employee list items, Assign Shift Template button"
    And visible focus indicator should appear on each focused element
    When user navigates through employee list using Arrow Down key
    And user presses Enter on employee "Keyboard User"
    Then employee "Keyboard User" should be selected
    And employee details panel should open
    And focus should move to details panel
    When user presses Tab to focus "Assign Shift Template" button
    And user presses Enter to activate button
    Then assignment modal should open
    And focus should automatically move to first interactive element in modal
    When user presses Space to open shift template dropdown
    And user navigates through templates using Arrow Down and Arrow Up keys
    And user presses Enter to select "Day Shift (9AM-5PM)"
    Then dropdown should close
    And selected template "Day Shift (9AM-5PM)" should be confirmed
    When user presses Tab to move to date field
    And user types "02/26/2024" using keyboard
    Then date field should display "02/26/2024"
    And visible focus indicator should be present on date field
    When user presses Tab to focus "Confirm Assignment" button
    And user presses Enter to submit
    Then assignment should be submitted successfully
    And success message should appear
    And focus should move to success message or newly assigned shift
    When user opens assignment modal again
    And user presses Escape key while modal is open
    Then modal should close
    And focus should return to "Assign Shift Template" button

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader announces all critical information during shift assignment
    Given screen reader software is active
    And employee "Screen Reader User" exists in the system
    And shift template "Evening Shift (4PM-12AM)" is available
    When user navigates to "Employee Schedule" page
    Then screen reader should announce "Employee Schedule" page information
    And screen reader should announce page title and main heading
    When user navigates to employee list
    And user focuses on employee "Screen Reader User" item
    Then screen reader should announce "Screen Reader User, list item, 1 of 10"
    When user activates employee "Screen Reader User"
    And user navigates to "Assign Shift Template" button
    Then screen reader should announce "Assign Shift Template, button"
    When user activates "Assign Shift Template" button
    Then screen reader should announce "Assign Shift Template dialog opened"
    And focus should move into modal
    And modal title should be announced
    When user navigates to shift template dropdown
    And user opens dropdown
    Then screen reader should announce "Shift template, combo box, collapsed"
    And screen reader should announce "expanded" when opened
    And screen reader should announce number of available options
    When user navigates through template options
    Then screen reader should announce each option as "Evening Shift 4PM to 12AM, option 2 of 5"
    When user selects "Evening Shift (4PM-12AM)"
    Then screen reader should announce "selected"
    When user navigates to date field
    Then screen reader should announce "Date, edit, required"
    When user submits assignment
    Then screen reader should announce "Shift template successfully assigned to Screen Reader User, alert"
    When user triggers a double-scheduling error
    Then screen reader should announce "Error: Cannot assign shift, employee already scheduled during this time, alert" via ARIA live region

  @accessibility @a11y @priority-high @color-contrast
  Scenario: Sufficient color contrast ratios for all text and interactive elements
    Given color contrast analyzer tool is available
    And page displays employee list, calendar, and assignment modal
    And WCAG 2.1 Level AA requires "4.5:1" contrast for normal text
    And WCAG 2.1 Level AA requires "3:1" contrast for large text and UI components
    When user checks employee names in employee list using contrast analyzer
    Then text color against background should have contrast ratio of at least "4.5:1"
    When user checks "Assign Shift Template" button text and background
    Then button text should have "4.5:1" contrast ratio
    And button border should have "3:1" contrast against surrounding background
    When user checks success message banner with green background
    Then white text on green background should have minimum "4.5:1" contrast ratio
    When user checks error message banner with red background
    Then white text on red background should have minimum "4.5:1" contrast ratio
    When user checks shift blocks in calendar view
    Then shift text on colored blocks should have minimum "4.5:1" contrast
    And shift blocks should have "3:1" contrast against calendar background
    When user checks form field labels and input borders in assignment modal
    Then labels should have "4.5:1" contrast
    And input field borders should have "3:1" contrast against background
    When user checks focus indicators on focused elements
    Then focus indicator should have minimum "3:1" contrast ratio against focused element and adjacent background
    When user verifies information conveyed by color
    Then errors should use icons or text in addition to red color
    And shift types should use patterns or labels in addition to color coding

  @accessibility @a11y @priority-medium @zoom @responsive
  Scenario Outline: Page functionality at increased browser zoom levels
    Given browser is set to "100%" zoom level
    And employee list and calendar are visible
    And at least one employee and shift template exist
    When user increases browser zoom to "<zoom_level>"
    Then page content should scale to "<zoom_level>"
    And text should be larger and readable
    And no horizontal scrolling should be required for main content
    When user verifies employee list at "<zoom_level>" zoom
    Then employee list should display properly
    And employee names should not be truncated
    And vertical scrolling should work if needed
    And no elements should overlap
    When user verifies calendar view at "<zoom_level>" zoom
    Then calendar should remain functional
    And shift blocks should be visible and readable
    And dates and times should not be cut off
    When user selects an employee at "<zoom_level>" zoom
    And user clicks "Assign Shift Template" button
    Then button should be fully visible and clickable
    And modal should open properly sized for zoomed viewport
    When user interacts with assignment modal at "<zoom_level>" zoom
    And user selects template and enters date
    Then all form fields should be accessible and usable
    And dropdown options should be readable
    And buttons should not be cut off
    And modal content should scroll vertically if needed
    When user views success or error messages at "<zoom_level>" zoom
    Then messages should be fully visible
    And text should wrap appropriately
    And no content should be hidden or inaccessible

    Examples:
      | zoom_level |
      | 200%       |
      | 400%       |

  @accessibility @a11y @priority-medium @aria @semantic-html
  Scenario: Proper ARIA landmarks and semantic HTML structure for assistive technologies
    Given browser developer tools or accessibility inspector is open
    And screen reader is available for testing
    And page displays employee list, calendar, and controls
    When user inspects page structure using accessibility inspector
    Then page should use semantic HTML5 elements "header, nav, main, section, footer"
    When user verifies ARIA landmarks implementation
    Then main content area should have "main" role or element
    And navigation should have "navigation" role or element
    And proper landmark structure should exist
    When user navigates between landmarks using screen reader
    Then screen reader should announce "Main navigation"
    And screen reader should announce "Main content"
    And screen reader should announce "Employee list region"
    And screen reader should announce "Calendar region"
    When user verifies employee list ARIA attributes
    Then employee list should have "list" role or use list elements
    And each employee should have "listitem" role
    And screen reader should announce "list with X items"
    When user verifies assignment modal ARIA attributes
    Then modal should have "dialog" role
    And modal should have "aria-labelledby" attribute
    And modal should have "aria-modal" set to "true"
    And screen reader should announce modal as "dialog"
    When user verifies form fields have proper labels
    Then all form inputs should have associated label elements or "aria-label"
    And screen reader should announce label when field is focused
    When user verifies success and error messages
    Then success messages should have "aria-live" set to "polite"
    And error messages should have "aria-live" set to "assertive" or "alert" role
    And messages should be announced automatically without focus change
    When user verifies calendar ARIA structure
    Then calendar should use "grid" role or table element with proper headers
    And dates should be navigable and announced with context