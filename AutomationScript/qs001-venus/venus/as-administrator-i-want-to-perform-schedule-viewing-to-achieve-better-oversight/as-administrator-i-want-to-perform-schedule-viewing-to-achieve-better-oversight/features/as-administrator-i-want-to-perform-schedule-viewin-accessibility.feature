@accessibility @a11y @wcag
Feature: As Administrator, I want to perform schedule viewing to achieve better oversight. - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify complete keyboard navigation through schedule viewing interface
    Given user is logged in as Administrator
    And schedule viewing page is loaded with calendar displayed
    And at least 10 schedules are visible
    And mouse is disconnected or not used for this test
    When press Tab key repeatedly from page load to navigate through all interactive elements
    Then focus moves sequentially through: main navigation, filter controls, calendar navigation buttons, schedule entries, export button, print button with visible focus indicator (2px solid outline)
    And use Shift+Tab to navigate backwards through elements
    Then focus moves in reverse order through all interactive elements, no focus traps occur
    And navigate to filter dropdown using Tab, press Enter or Space to open
    Then dropdown opens and focus moves to first option, arrow keys navigate through options
    And use arrow keys to navigate through calendar dates and schedule entries
    Then arrow keys move focus between dates and schedules, Enter key opens schedule details
    And navigate to Export button, press Enter to open export menu
    Then export dropdown opens, arrow keys navigate options, Enter selects export format
    And press Escape key while dropdown is open
    Then dropdown closes and focus returns to Export button
    And all interactive elements are accessible via keyboard
    And focus order is logical and follows visual layout
    And no keyboard traps prevent navigation
    And focus indicators are clearly visible throughout

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader compatibility and announcements
    Given user is logged in as Administrator
    And screen reader is active (NVDA, JAWS, or VoiceOver)
    And schedule viewing page is loaded
    And at least 5 schedules are displayed in calendar
    When navigate to schedule viewing page with screen reader active
    Then screen reader announces page title 'Schedule Viewing' and main landmark 'main content region'
    And navigate through calendar interface using screen reader commands
    Then screen reader announces calendar structure: 'Calendar, current month: January 2024', each date cell announces 'January 15, 3 schedules'
    And focus on a schedule entry
    Then screen reader announces complete schedule information: 'Schedule for John Smith, Morning shift, 8:00 AM to 4:00 PM, button'
    And navigate to filter controls
    Then screen reader announces 'Filter by Employee, combobox, collapsed' and 'Filter by Shift Type, combobox, collapsed'
    And apply a filter and wait for results
    Then screen reader announces via ARIA live region: 'Schedules updated, showing 5 results for John Smith'
    And navigate to export button
    Then screen reader announces 'Export schedules, button, has popup menu'
    And all content is accessible to screen reader users
    And dynamic content changes are announced appropriately
    And aRIA labels and roles are properly implemented
    And user can complete all tasks using screen reader alone

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify focus management and focus trap prevention
    Given user is logged in as Administrator
    And schedule viewing page is loaded
    And modal dialogs or popups can be triggered (schedule details, export options)
    And keyboard navigation is being used
    When click on a schedule entry to open details modal using Enter key
    Then modal opens and focus automatically moves to first interactive element in modal (close button or first form field)
    And press Tab repeatedly while modal is open
    Then focus cycles only through elements within the modal, does not escape to background page content
    And press Escape key to close modal
    Then modal closes and focus returns to the schedule entry that opened it
    And open export dropdown menu using keyboard
    Then focus moves to first menu item, Tab and arrow keys navigate within menu only
    And close dropdown by pressing Escape
    Then dropdown closes and focus returns to Export button
    And apply a filter that causes page content to update
    Then focus remains on or near the filter control, does not jump unexpectedly to top of page
    And focus is managed logically throughout all interactions
    And modal dialogs properly trap focus
    And focus returns to triggering element when dialogs close
    And no unexpected focus jumps occur

  @high @tc-acce-004
  Scenario: TC-ACCE-004 - Verify color contrast ratios meet WCAG 2.1 AA standards
    Given user is logged in as Administrator
    And schedule viewing page is fully loaded
    And color contrast analyzer tool is available (e.g., browser extension or WAVE tool)
    And page displays various UI elements: text, buttons, calendar cells, schedule entries
    When use contrast analyzer to check text color against background in calendar cells
    Then normal text (under 18pt) has contrast ratio of at least 4.5:1, large text (18pt+) has at least 3:1
    And check contrast of button text and backgrounds (Export, Print, Filter buttons)
    Then all button text meets 4.5:1 contrast ratio against button background
    And verify focus indicators have sufficient contrast
    Then focus outline has at least 3:1 contrast ratio against both the focused element and the background
    And check schedule entry colors and shift type color coding
    Then if colors are used to distinguish shift types, text labels are also present (not relying on color alone), and colors meet contrast requirements
    And verify error messages and success notifications have adequate contrast
    Then error text (red) and success text (green) both have 4.5:1 contrast against their backgrounds
    And all text meets WCAG 2.1 AA contrast requirements
    And interactive elements are visually distinguishable
    And color is not the only means of conveying information
    And page is usable for users with low vision or color blindness

  @medium @tc-acce-005
  Scenario: TC-ACCE-005 - Verify page functionality at 200% browser zoom
    Given user is logged in as Administrator
    And schedule viewing page is loaded at 100% zoom
    And browser supports zoom functionality (Chrome, Firefox, Safari, Edge)
    And at least 10 schedules are displayed
    When increase browser zoom to 200% using Ctrl/Cmd + plus key
    Then page content scales proportionally, all text remains readable
    And verify calendar layout at 200% zoom
    Then calendar remains functional, may switch to mobile/responsive layout, no horizontal scrolling required for main content, schedule entries are still readable
    And test all interactive elements: filters, buttons, dropdowns
    Then all buttons and controls remain clickable and functional, no overlapping elements, touch targets are at least 44x44 pixels
    And navigate through calendar and view schedule details
    Then all functionality works normally, modals and popups display correctly without content cutoff
    And test export and print functions at 200% zoom
    Then export and print dialogs open correctly, functionality works as expected
    And page remains fully functional at 200% zoom
    And no content is hidden or inaccessible
    And layout adapts responsively without breaking
    And users with low vision can use all features

  @high @tc-acce-006
  Scenario: TC-ACCE-006 - Verify ARIA labels, roles, and live regions are properly implemented
    Given user is logged in as Administrator
    And schedule viewing page is loaded
    And browser developer tools are open to inspect ARIA attributes
    And screen reader is available for testing announcements
    When inspect calendar component in developer tools
    Then calendar has role='application' or role='grid', proper ARIA labels like aria-label='Schedule calendar for January 2024'
    And inspect filter controls for ARIA attributes
    Then dropdowns have aria-label or aria-labelledby, aria-expanded states, aria-controls pointing to dropdown content
    And check for ARIA live regions for dynamic content updates
    Then status messages area has aria-live='polite' or 'assertive', aria-atomic='true' for complete announcements
    And apply a filter and observe ARIA live region updates
    Then screen reader announces filter results: 'Showing 5 schedules for John Smith' via live region
    And inspect buttons for proper ARIA attributes
    Then export button has aria-haspopup='menu', Print button has descriptive aria-label='Print current schedule view'
    And check schedule entries for semantic markup
    Then each schedule has proper role (button or link), aria-label with complete information: 'View schedule for John Smith, Morning shift, January 15, 8 AM to 4 PM'
    And all ARIA attributes are correctly implemented
    And dynamic content changes are announced to screen readers
    And interactive elements have appropriate roles and labels
    And page structure is semantically correct and accessible

