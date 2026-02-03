@accessibility @a11y @wcag
Feature: As Administrator, I want to perform employee schedule management to achieve optimal staffing. - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify complete keyboard navigation through schedule management interface
    Given user is logged in as Administrator
    And schedule management page is loaded with calendar view and employee list visible
    And at least 5 employees are available for assignment
    And keyboard focus indicators are enabled in browser
    And no mouse or pointing device is used during test
    When press Tab key repeatedly to navigate through all interactive elements on the page starting from the top
    Then focus moves in logical order: main navigation → page heading → template dropdown → employee list → calendar grid → save button. Focus indicator is clearly visible (2px solid outline) on each element
    And navigate to the shift template dropdown using Tab, then press Enter or Space to open dropdown, use Arrow keys to select a template, press Enter to confirm
    Then dropdown opens on Enter/Space, Arrow Up/Down navigate through template options, selected template is highlighted, Enter confirms selection and closes dropdown, focus returns to dropdown trigger
    And tab to employee list, use Arrow keys to navigate through employee names, press Enter on an employee to select for assignment
    Then arrow keys move focus through employee list items, selected employee is highlighted with visual indicator, Enter key selects employee and opens assignment modal or activates assignment mode
    And navigate to calendar grid using Tab, use Arrow keys to move between time slots, press Enter to assign selected employee to focused slot
    Then calendar grid is keyboard accessible, Arrow keys navigate between days and time slots, focused slot has clear visual indicator, Enter key assigns employee to slot, confirmation message is announced
    And press Tab to navigate to 'Save Schedule' button and press Enter to save
    Then focus moves to Save button with visible indicator, Enter key triggers save operation, success message appears and receives focus for screen reader announcement
    And press Shift+Tab to navigate backwards through the interface
    Then focus moves in reverse order through all interactive elements, no focus traps encountered, user can navigate back to any previous element
    And all functionality is accessible via keyboard without requiring mouse
    And focus order is logical and follows visual layout
    And no keyboard traps prevent user from navigating away from any element
    And schedule assignment is successfully saved using only keyboard input

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader compatibility and ARIA announcements for schedule management
    Given user is logged in as Administrator
    And screen reader is active (NVDA, JAWS, or VoiceOver)
    And schedule management page is loaded
    And at least 3 employees are assigned to shifts
    And aRIA live regions are implemented for dynamic content updates
    When navigate to schedule management page and listen to screen reader announcement of page title and main content
    Then screen reader announces: 'Employee Schedule Management, main region. Calendar view showing week of [date]. 3 employees assigned.' Page structure with landmarks (navigation, main, complementary) is announced
    And navigate to shift template dropdown and activate it, listen to screen reader announcements
    Then screen reader announces: 'Shift template, combo box, collapsed' then 'Shift template, expanded, 5 options available. Morning Shift 8AM-4PM, 1 of 5' as user navigates through options
    And navigate through employee list and listen to how each employee is announced
    Then screen reader announces each employee with relevant info: 'John Smith, available, button' or 'Jane Doe, assigned to Morning Shift Monday, button'. Status and assignment info is included in announcement
    And assign an employee to a shift and listen for dynamic update announcement
    Then aRIA live region announces: 'John Smith assigned to Monday Morning Shift 8AM-4PM. Unsaved changes.' User is informed of action result without focus change
    And navigate to calendar grid and listen to how time slots and assignments are announced
    Then screen reader announces: 'Monday, 8AM to 4PM, Morning Shift, assigned to John Smith, button' for filled slots, and 'Tuesday, 8AM to 4PM, Morning Shift, empty, button' for empty slots
    And save schedule and listen to success message announcement
    Then aRIA live region announces: 'Success: Schedule saved successfully. 3 employees assigned.' Message is announced immediately without requiring focus change
    And trigger a validation error (attempt double-booking) and listen to error announcement
    Then aRIA live region announces: 'Error: Cannot assign John Smith. Employee has overlapping shift from 8AM to 4PM.' Error is announced assertively with clear description
    And all interactive elements have appropriate ARIA labels and roles
    And dynamic content updates are announced via ARIA live regions
    And screen reader users can understand page structure and complete all tasks
    And error messages and success confirmations are announced clearly

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify focus management and focus trap handling in assignment modals
    Given user is logged in as Administrator
    And schedule management page is loaded
    And assignment modal functionality is available (triggered by clicking assign button)
    And keyboard navigation is being used exclusively
    When use keyboard to navigate to an empty shift slot and press Enter to open assignment modal
    Then modal opens and focus automatically moves to first interactive element in modal (employee search field or first employee in list), background content is inert (not focusable)
    And press Tab repeatedly to cycle through all interactive elements within the modal
    Then focus cycles through: search field → employee list items → assign button → cancel button → back to search field. Focus remains trapped within modal, cannot Tab to background content
    And press Escape key while modal is open
    Then modal closes immediately, focus returns to the shift slot button that triggered the modal, user can continue navigating from that point
    And reopen modal, select an employee, and press Enter on 'Assign' button
    Then assignment is completed, modal closes, focus returns to the shift slot (now showing assigned employee), success message is announced via ARIA live region
    And open modal again and press Tab until reaching 'Cancel' button, press Enter
    Then modal closes without making changes, focus returns to original trigger element (shift slot button), no assignment is made
    And focus is properly managed when modal opens and closes
    And focus trap prevents keyboard users from accessing background content while modal is open
    And escape key provides consistent way to close modal
    And focus returns to logical element after modal closes, maintaining user's place in navigation

  @high @tc-acce-004
  Scenario: TC-ACCE-004 - Verify color contrast ratios meet WCAG 2.1 AA standards throughout schedule interface
    Given user is logged in as Administrator
    And schedule management page is fully loaded with calendar and assignments visible
    And color contrast checking tool is available (browser extension or DevTools)
    And page includes various UI states: default, hover, focus, active, disabled, error
    When use color contrast checker to measure contrast ratio of primary text (employee names, shift times) against background
    Then all body text (14px and above) has minimum contrast ratio of 4.5:1, large text (18px+ or 14px+ bold) has minimum 3:1 ratio, meets WCAG AA standards
    And check contrast of interactive elements: buttons, links, form controls in their default state
    Then button text and borders have 4.5:1 contrast against background, link text has 4.5:1 contrast, form control borders have 3:1 contrast minimum
    And check contrast of focus indicators on all interactive elements
    Then focus indicators (outlines, borders) have minimum 3:1 contrast ratio against adjacent colors, focus state is clearly distinguishable from non-focused state
    And check contrast of status indicators: success messages (green), error messages (red), warning messages (yellow/orange)
    Then all status message text has 4.5:1 contrast against background, status is not conveyed by color alone (icons or text labels accompany color coding)
    And check contrast of calendar grid lines, shift boundaries, and assignment cards
    Then grid lines and borders have 3:1 contrast minimum, assigned shift cards have sufficient contrast for text and background, visual distinctions are clear
    And check contrast in disabled state for buttons and form controls
    Then disabled elements are visually distinguishable but may have lower contrast (WCAG allows exemption), disabled state is indicated by more than just color (opacity, cursor change)
    And all text content meets WCAG 2.1 AA contrast requirements (4.5:1 for normal text, 3:1 for large text)
    And interactive elements and focus indicators have sufficient contrast
    And information is not conveyed by color alone
    And users with low vision or color blindness can perceive all content and controls

  @medium @tc-acce-005
  Scenario: TC-ACCE-005 - Verify page functionality at 200% browser zoom level
    Given user is logged in as Administrator
    And schedule management page is loaded at default 100% zoom
    And browser supports zoom functionality (Chrome, Firefox, Safari, Edge)
    And page has responsive design that adapts to zoom levels
    When set browser zoom to 200% using Ctrl/Cmd + Plus key or browser zoom controls
    Then page content scales to 200%, layout adapts responsively, no horizontal scrolling is required for main content, text remains readable
    And navigate through the schedule management interface at 200% zoom using keyboard and mouse
    Then all interactive elements remain accessible and clickable, buttons and links are not cut off or overlapping, calendar grid adapts to larger size (may switch to mobile view)
    And attempt to assign an employee to a shift at 200% zoom
    Then assignment functionality works correctly, modals and dropdowns display properly at zoomed level, all text in modals is readable without horizontal scrolling
    And verify that form controls (dropdowns, buttons, input fields) are fully visible and functional at 200% zoom
    Then all form controls are accessible, dropdown options are readable, buttons are not cut off, input fields show full content without overflow
    And check that success and error messages are fully visible at 200% zoom
    Then notification banners and messages display completely, text wraps appropriately, no content is hidden or requires horizontal scrolling to read
    And all functionality remains accessible at 200% zoom level per WCAG 2.1 AA requirement
    And no loss of content or functionality occurs due to zoom
    And layout adapts responsively without breaking or requiring horizontal scrolling
    And users with low vision can effectively use the interface at increased zoom levels

  @high @tc-acce-006
  Scenario: TC-ACCE-006 - Verify proper ARIA roles, labels, and states for complex calendar widget
    Given user is logged in as Administrator
    And schedule management page with calendar widget is loaded
    And browser developer tools are open to inspect ARIA attributes
    And screen reader is available for testing announcements
    When inspect the calendar container element and verify ARIA role and label
    Then calendar container has role='grid' or role='table', aria-label='Employee schedule calendar for week of [date]' provides context, aria-describedby references instructions if present
    And inspect individual calendar cells (time slots) and verify ARIA attributes
    Then each cell has role='gridcell' or role='cell', aria-label describes the slot: 'Monday 8AM to 4PM Morning Shift, assigned to John Smith' or 'Tuesday 8AM to 4PM, empty', aria-selected='true/false' indicates selection state
    And inspect employee assignment cards within calendar and verify ARIA attributes
    Then assignment cards have role='button' or role='link', aria-label='John Smith assigned to Morning Shift, click to edit or remove', aria-pressed or aria-expanded if applicable for interactive states
    And trigger a validation error (double-booking) and inspect error message ARIA attributes
    Then error message container has role='alert' or aria-live='assertive', aria-atomic='true' ensures full message is read, error is associated with relevant form control via aria-describedby
    And inspect the save button and verify ARIA states during save operation
    Then save button has aria-label='Save schedule', during save operation aria-busy='true' is set, aria-disabled='true' when save is in progress, states update appropriately when operation completes
    And inspect dynamic content update regions (assignment confirmations, notifications) for ARIA live region attributes
    Then notification areas have aria-live='polite' for non-critical updates or aria-live='assertive' for errors, aria-atomic='true' for complete message reading, updates are announced by screen reader without focus change
    And all interactive elements have appropriate ARIA roles that match their function
    And aRIA labels provide clear, descriptive text for screen reader users
    And aRIA states (selected, expanded, pressed, busy) accurately reflect current UI state
    And dynamic content updates are properly announced via ARIA live regions

