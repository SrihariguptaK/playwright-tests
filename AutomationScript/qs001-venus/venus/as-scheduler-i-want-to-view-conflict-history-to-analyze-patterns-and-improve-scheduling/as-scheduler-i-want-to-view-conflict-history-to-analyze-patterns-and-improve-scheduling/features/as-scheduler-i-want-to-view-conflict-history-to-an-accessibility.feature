@accessibility @a11y @wcag
Feature: As Scheduler, I want to view conflict history to analyze patterns and improve scheduling - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify complete keyboard navigation through conflict history page and all interactive elements
    Given user is logged in as Scheduler on the conflict history page
    And conflict history displays at least 10 records
    And keyboard navigation is enabled in browser
    And no mouse or pointing device is used for this test
    When press Tab key from the page header to move focus to the first interactive element
    Then focus moves to the first filter control (Start Date field) with visible focus indicator (blue outline or highlight)
    And continue pressing Tab to navigate through all filter controls: Start Date, End Date, Conflict Type dropdown, Apply Filter button, Clear Filters button
    Then focus moves sequentially through each control in logical order. Each element shows clear focus indicator. Focus does not skip any interactive elements
    And press Tab to move focus into the conflict history table, then use Arrow keys to navigate between table rows
    Then focus enters the table and highlights the first conflict row. Down Arrow moves to next row, Up Arrow moves to previous row. Focus indicator clearly shows which row is selected
    And press Enter key on a focused conflict row to open the detail modal
    Then conflict detail modal opens and focus automatically moves to the modal's first interactive element (Close button or first focusable content)
    And press Escape key to close the modal
    Then modal closes and focus returns to the conflict row that was previously selected in the table
    And tab to the Export button and press Enter to open export modal
    Then export modal opens and focus moves to the first format option (CSV radio button)
    And use Arrow keys to select different export format options, then Tab to Download button and press Enter
    Then arrow keys change radio button selection. Enter on Download button initiates export. Focus management prevents keyboard trap
    And all interactive elements are reachable via keyboard
    And focus order is logical and predictable
    And no keyboard traps exist in the interface
    And focus indicators are visible throughout navigation

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader announces all conflict history content, labels, and state changes correctly
    Given user is logged in as Scheduler on the conflict history page
    And screen reader software (NVDA, JAWS, or VoiceOver) is active
    And conflict history displays at least 5 records
    And aRIA labels and live regions are implemented
    When navigate to conflict history page and listen to screen reader announcement
    Then screen reader announces: 'Conflict History page. Main region. Showing 10 of 50 conflicts. Use filters to narrow results.'
    And tab to the Start Date filter field and listen to announcement
    Then screen reader announces: 'Start Date, date picker, edit text. Press Enter to open calendar. Format: MM/DD/YYYY'
    And tab to Conflict Type dropdown and listen to announcement
    Then screen reader announces: 'Conflict Type, combo box, All Types selected. Press Alt+Down Arrow to expand options'
    And apply a filter and listen to the announcement when results update
    Then aRIA live region announces: 'Conflict history updated. Now showing 3 of 50 conflicts. Filtered by date range March 1 to March 31, 2024'
    And navigate to the conflict history table and listen to table structure announcement
    Then screen reader announces: 'Conflict history table with 6 columns and 3 rows. Column headers: Conflict ID, Date, Time, Type, Resources Involved, Status'
    And navigate to a table cell and listen to content announcement
    Then screen reader announces cell content with context: 'Row 1, Conflict ID column: CF-2024-001. Date column: March 15, 2024. Type column: Resource Overlap'
    And open a conflict detail modal and listen to announcement
    Then screen reader announces: 'Conflict details dialog. Conflict ID CF-2024-001. Resource Overlap detected on March 15, 2024. Close button available.'
    And initiate an export and listen to progress announcement
    Then aRIA live region announces: 'Export started. Preparing file... Export complete. File conflict_history_2024-03-15.csv downloaded.'
    And all content is accessible to screen reader users
    And dynamic content changes are announced via ARIA live regions
    And form labels and instructions are properly associated
    And table structure and relationships are conveyed correctly

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify color contrast ratios meet WCAG 2.1 AA standards (4.5:1 for normal text, 3:1 for large text)
    Given user is logged in as Scheduler on the conflict history page
    And conflict history page is fully loaded with data
    And color contrast analyzer tool is available (browser extension or standalone tool)
    And page uses standard color scheme without user customization
    When use color contrast analyzer to check the contrast ratio between body text (conflict descriptions) and background
    Then contrast ratio is at least 4.5:1 for normal text (14px or smaller). Example: Black text (#000000) on white background (#FFFFFF) = 21:1, which passes
    And check contrast ratio for filter labels and form field text against their backgrounds
    Then all label text has minimum 4.5:1 contrast ratio. Field borders have minimum 3:1 contrast against adjacent colors
    And check contrast ratio for table header text against header background color
    Then table header text has minimum 4.5:1 contrast ratio. If headers use large text (18px+ or 14px+ bold), minimum 3:1 ratio is acceptable
    And check contrast ratio for button text (Apply Filter, Export, etc.) against button background colors in all states (normal, hover, focus, disabled)
    Then all button states maintain minimum 4.5:1 contrast for text. Focus indicators have minimum 3:1 contrast against background
    And check contrast for status indicators and conflict type badges (colored labels)
    Then status text on colored backgrounds maintains 4.5:1 contrast. If color alone conveys meaning, additional text or icons are present
    And check contrast for error messages and validation text
    Then error messages in red have sufficient contrast (4.5:1 minimum). Error state is indicated by more than color alone (icons, text, borders)
    And verify link text contrast and underline visibility
    Then link text has 4.5:1 contrast and is distinguishable from surrounding text by more than color (underline, icon, or other visual indicator)
    And all text meets WCAG 2.1 AA contrast requirements
    And information is not conveyed by color alone
    And users with color vision deficiencies can use the interface
    And contrast is maintained in all interactive states

  @high @tc-acce-004
  Scenario: TC-ACCE-004 - Verify focus management and focus trap prevention in modal dialogs
    Given user is logged in as Scheduler on the conflict history page
    And conflict history displays at least 3 records
    And keyboard navigation is being used exclusively
    And modal dialogs (conflict detail, export) are functional
    When use keyboard to navigate to a conflict row and press Enter to open the conflict detail modal
    Then modal opens and focus automatically moves to the first focusable element inside the modal (typically the Close button or modal heading)
    And press Tab repeatedly to cycle through all focusable elements within the modal
    Then focus moves through all interactive elements inside the modal: Close button, any links or buttons in content, action buttons. Focus stays trapped within the modal and does not move to background page elements
    And after reaching the last focusable element in the modal, press Tab again
    Then focus cycles back to the first focusable element in the modal (Close button), creating a focus loop within the modal
    And press Shift+Tab from the first focusable element
    Then focus moves backward to the last focusable element in the modal, allowing reverse navigation within the focus trap
    And press Escape key to close the modal
    Then modal closes and focus returns to the exact element that triggered the modal (the conflict row in the table). Focus is not lost or moved to an unexpected location
    And open the Export modal using keyboard, then click the Close button instead of using Escape
    Then modal closes and focus returns to the Export button that opened the modal. Focus restoration works regardless of close method
    And verify that when a modal is open, background content is not accessible via keyboard
    Then tab and Shift+Tab do not move focus to elements behind the modal. Background content has aria-hidden='true' or inert attribute applied
    And focus is properly trapped within modal dialogs
    And focus returns to triggering element when modal closes
    And background content is not accessible when modal is open
    And users cannot accidentally interact with hidden content

  @high @tc-acce-005
  Scenario: TC-ACCE-005 - Verify ARIA roles, labels, and properties are correctly implemented for dynamic content
    Given user is logged in as Scheduler on the conflict history page
    And browser developer tools or accessibility inspector is available
    And conflict history page has dynamic content (filters, loading states, results)
    And aRIA attributes are implemented in the codebase
    When inspect the main conflict history table using accessibility inspector
    Then table has role='table' or uses semantic <table> element. Column headers have role='columnheader' or use <th> elements. Rows have role='row' or use <tr> elements
    And inspect the filter section for proper ARIA labels
    Then filter controls have aria-label or associated <label> elements. Dropdown has aria-haspopup='listbox' and aria-expanded state. Date pickers have aria-label describing their purpose
    And apply a filter and inspect the results update area
    Then results container has aria-live='polite' or aria-live='assertive' for announcing updates. Loading state has aria-busy='true' while loading, then aria-busy='false' when complete
    And inspect the conflict count badge or summary text
    Then count display has aria-live='polite' so updates are announced. Text like 'Showing 3 of 50 conflicts' is programmatically associated with the table via aria-describedby
    And inspect modal dialogs for proper ARIA attributes
    Then modal has role='dialog' and aria-modal='true'. Modal has aria-labelledby pointing to modal title. Background content has aria-hidden='true' when modal is open
    And inspect buttons for proper ARIA labels, especially icon-only buttons
    Then icon-only buttons (Export, Close, etc.) have aria-label providing text description. Example: Export button has aria-label='Export conflict history'
    And inspect error messages and validation feedback
    Then error messages have role='alert' or aria-live='assertive' for immediate announcement. Form fields with errors have aria-invalid='true' and aria-describedby pointing to error message
    And verify sortable table columns have appropriate ARIA attributes
    Then sortable column headers have aria-sort='ascending', aria-sort='descending', or aria-sort='none' to indicate current sort state
    And all interactive elements have appropriate ARIA roles
    And dynamic content changes are announced to assistive technologies
    And form validation and errors are properly communicated
    And table structure and sorting states are conveyed accessibly

  @medium @tc-acce-006
  Scenario: TC-ACCE-006 - Verify date picker accessibility with keyboard navigation and screen reader support
    Given user is logged in as Scheduler on the conflict history page
    And date range filter with calendar date pickers is visible
    And keyboard navigation is being used exclusively
    And screen reader is active for testing announcements
    When tab to the Start Date field and press Enter or Space to open the calendar picker
    Then calendar picker opens and focus moves to the currently selected date or today's date. Screen reader announces: 'Calendar dialog opened. Use arrow keys to navigate dates. Enter to select. Escape to close.'
    And use Arrow keys (Up, Down, Left, Right) to navigate between dates in the calendar
    Then arrow keys move focus between dates. Left/Right move by day, Up/Down move by week. Focus indicator clearly shows which date is selected. Screen reader announces each date as focus moves: 'March 15, 2024, Friday'
    And press Page Up and Page Down keys to navigate between months
    Then page Up moves to previous month, Page Down moves to next month. Screen reader announces: 'February 2024' or 'April 2024' when month changes
    And press Home key to jump to the first day of the current month, End key to jump to the last day
    Then home key moves focus to the 1st of the month, End key moves to the last day (28th, 30th, or 31st). Screen reader announces the new date
    And press Enter to select the focused date
    Then calendar closes, selected date populates the Start Date field, and focus returns to the date input field. Screen reader announces: 'March 15, 2024 selected'
    And open the calendar again and press Escape to close without selecting
    Then calendar closes without changing the date value. Focus returns to the date input field. Previous date selection is maintained
    And verify the calendar has proper ARIA labels for month/year navigation buttons
    Then previous/Next month buttons have aria-label='Previous month' and aria-label='Next month'. Month/year display has appropriate role and label
    And date picker is fully operable via keyboard
    And all date picker interactions are announced by screen reader
    And focus management works correctly when opening/closing calendar
    And users can efficiently navigate and select dates without a mouse

