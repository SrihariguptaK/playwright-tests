Feature: Schedule Change History Accessibility
  As an employee with accessibility needs
  I want the schedule change history page to be fully accessible
  So that I can track my schedule changes regardless of my abilities or assistive technologies

  Background:
    Given user is logged in as an authenticated employee
    And user has schedule change requests in the system

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation through schedule change history page and filters
    Given user is on "Schedule Change History" page with visible requests and filter controls
    And keyboard is the only input method being used
    When user presses Tab key repeatedly to navigate through all interactive elements
    Then focus should move sequentially through navigation menu, filter controls, request list items, and pagination controls
    And visible focus indicators should be displayed on each focused element
    When user uses Tab to focus on "From Date" filter field
    And user presses Enter key to open date picker
    Then date picker calendar should open
    And focus should move to current date
    And calendar should be navigable with arrow keys
    When user uses arrow keys to navigate to a date in date picker
    And user presses Enter key to select date
    Then selected date should be populated in "From Date" field
    And date picker should close
    And focus should return to date input field
    When user tabs to "Status" dropdown filter
    And user presses Enter key to open dropdown
    Then dropdown menu should open showing status options
    And focus should be on first option
    And arrow keys should navigate through options
    When user uses arrow keys to select "Approved" status
    And user presses Enter key to confirm selection
    Then status "Approved" should be selected
    And dropdown should close
    And focus should return to dropdown control
    When user tabs to "Apply Filter" button
    And user presses Enter key to apply filters
    Then filters should be applied
    And page should update with filtered results
    And focus should move to first result or status message
    When user tabs through filtered request list
    And user presses Enter key on a request to view details
    Then request details should be displayed
    And focus should move to first interactive element in details view
    And user should be able to tab through all details
    When user presses Escape key to close request details
    Then details view should close
    And focus should return to request item in list
    And no keyboard traps should exist on page

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader announces all schedule change history information and filter changes
    Given screen reader software is active
    And user is on "Schedule Change History" page
    And page has proper ARIA labels and semantic HTML
    When user navigates to schedule change history page with screen reader active
    Then screen reader should announce page title "My Schedule Change History"
    And screen reader should announce main heading
    And screen reader should announce page landmark "main content region"
    When user navigates to filter section using screen reader commands
    Then screen reader should announce "Filter section"
    And screen reader should read label "From Date, date picker"
    And screen reader should read label "To Date, date picker"
    And screen reader should read label "Status, dropdown menu, currently All Statuses"
    When user uses screen reader to navigate through request list table
    Then screen reader should announce "Schedule change requests table, 5 rows"
    And screen reader should read each row with request ID, date submitted, status, and comments
    And screen reader should announce column headers during table navigation
    When user applies filter using keyboard and screen reader
    Then screen reader should announce "Filter applied, showing 2 Approved requests" via ARIA live region
    And updated result count should be communicated immediately
    When user navigates to a request and opens details using screen reader
    Then screen reader should announce "Request details dialog opened"
    And screen reader should read all detail fields with labels
    And screen reader should read request ID, submission date, original schedule, requested schedule, status, and manager comments
    When user navigates to pagination controls with screen reader
    Then screen reader should announce "Pagination navigation, Page 1 of 10"
    And screen reader should announce "Next page button"
    And screen reader should announce "Previous page button disabled"

  @accessibility @a11y @priority-high @focus-management
  Scenario: Focus management and focus indicators meet WCAG 2.1 standards
    Given user is on "Schedule Change History" page
    And page is tested in modern browser with focus indicators
    And WCAG 2.1 Level AA compliance is target standard
    When user tabs through all interactive elements on page
    Then every focusable element should display visible focus indicator
    And focus indicator should have minimum "3:1" contrast ratio against background
    And focus indicator should be at least "2" pixels thick
    When user opens request details modal
    Then focus should move to first interactive element in modal
    And tab key should cycle through modal elements only
    And shift tab should move backward within modal
    And focus should not escape to background content
    When user closes modal using Escape key
    Then focus should return to element that triggered modal
    And focus indicator should be visible on returned element
    And user should be able to continue navigation from previous position
    When user applies filter
    And dynamic content updates
    Then focus should remain on "Apply Filter" button or move to status message
    And focus should not be lost or reset to top of page
    When user interacts with elements in different states
    Then focus indicators should be distinct from hover states
    And focus should remain visible when element is activated
    And focus indicators should meet WCAG 2.1 Success Criterion 2.4.7

  @accessibility @a11y @priority-high @color-contrast
  Scenario Outline: Color contrast ratios meet WCAG 2.1 AA standards for all text and interactive elements
    Given user is on "Schedule Change History" page
    And color contrast checking tool is available
    And page displays status badges with colors
    And WCAG 2.1 Level AA requires "4.5:1" for normal text and "3:1" for large text
    When user checks contrast ratio for "<element_type>"
    Then contrast ratio should be at least "<minimum_ratio>"
    And text should be readable against background
    And status information should not be conveyed by color alone
    And status badges should include text labels or icons

    Examples:
      | element_type                          | minimum_ratio |
      | body text on background               | 4.5:1         |
      | large text on background              | 3:1           |
      | Approved badge text on green          | 4.5:1         |
      | Pending badge text on yellow          | 4.5:1         |
      | Rejected badge text on red            | 4.5:1         |
      | button text on button background      | 4.5:1         |
      | link text on background               | 4.5:1         |
      | form field borders                    | 3:1           |

  @accessibility @a11y @priority-medium @zoom-reflow
  Scenario: Page remains functional and readable at 200% zoom level
    Given user is on "Schedule Change History" page with multiple requests visible
    And browser zoom is set to "100" percent
    And WCAG 2.1 SC 1.4.4 requires content readable at 200% zoom
    When user sets browser zoom to "200" percent
    Then page content should scale to "200" percent zoom level
    And text should become larger and more readable
    And all text content should remain visible without horizontal scrolling
    And text should reflow to fit viewport width
    And users should be able to read all text by scrolling vertically only
    When user checks interactive elements at "200" percent zoom
    Then all buttons and interactive elements should be fully visible
    And elements should not be cut off or overlapping
    And elements should remain clickable with adequate target size
    When user navigates through request list and applies filters at "200" percent zoom
    Then filter controls should remain functional
    And dropdown menus should open properly without being cut off
    And date pickers should be accessible
    And filtered results should display correctly
    When user opens request details at "200" percent zoom
    Then request details should display properly
    And all detail fields should be readable
    And no content should be hidden or require horizontal scrolling
    When user views table or list layout at "200" percent zoom
    Then table columns should stack or reflow responsively
    And all data should remain accessible
    And horizontal scrolling should only apply to table container if needed