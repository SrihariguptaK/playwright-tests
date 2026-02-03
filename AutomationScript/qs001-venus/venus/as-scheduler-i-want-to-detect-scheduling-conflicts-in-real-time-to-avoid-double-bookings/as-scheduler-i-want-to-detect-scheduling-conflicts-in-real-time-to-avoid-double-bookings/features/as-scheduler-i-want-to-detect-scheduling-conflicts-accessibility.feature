@accessibility @a11y @wcag
Feature: As Scheduler, I want to detect scheduling conflicts in real-time to avoid double bookings - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify complete keyboard navigation through scheduling form and conflict detection workflow
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling dashboard page
    And keyboard navigation is enabled
    And no mouse or pointing device is used during test
    When press Tab key repeatedly to navigate through page elements starting from the top
    Then focus moves sequentially through all interactive elements: navigation menu, 'Create New Schedule' button, calendar controls, etc. Visible focus indicator (blue outline) appears on each element
    And when focus reaches 'Create New Schedule' button, press Enter key
    Then scheduling form modal opens and focus automatically moves to the first form field (Resource dropdown)
    And press Space bar or Enter to open Resource dropdown, use Arrow Down/Up keys to navigate options, press Enter to select 'Conference Room A'
    Then dropdown opens with keyboard, options are navigable with arrow keys, selected option is confirmed with Enter, and focus moves to Start Time field
    And type '10:00 AM' in Start Time field, press Tab to move to End Time field, type '11:00 AM'
    Then time values are entered successfully, Tab key moves focus between fields in logical order
    And press Tab to reach 'Check Availability' button and press Enter
    Then conflict detection is triggered, and if conflict exists, focus moves to the conflict alert message which is announced by screen readers
    And press Escape key while modal is open
    Then modal closes and focus returns to 'Create New Schedule' button that originally opened the modal
    And all interactive elements are accessible via keyboard
    And focus order is logical and follows visual layout
    And focus is never trapped in any component
    And escape key properly closes modals and returns focus appropriately

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader announces conflict detection results and all critical information
    Given user is logged in with Scheduler role permissions
    And screen reader software (NVDA, JAWS, or VoiceOver) is active
    And user is on the scheduling form page
    And existing schedule: 'Meeting Room 5' booked from 2:00 PM to 3:00 PM
    When navigate to scheduling form using screen reader and verify page title is announced
    Then screen reader announces 'Create New Schedule - Scheduling Dashboard' and describes the page purpose
    And navigate to Resource dropdown field using screen reader
    Then screen reader announces 'Resource, combo box, required' with instructions 'Use arrow keys to navigate options'
    And select 'Meeting Room 5', enter Start Time '2:15 PM' and End Time '3:15 PM', navigate to 'Check Availability' button
    Then screen reader announces each field label, current value, and field type. Button is announced as 'Check Availability, button'
    And activate 'Check Availability' button and wait for conflict detection
    Then screen reader announces 'Checking for conflicts, please wait' followed by 'Alert: Conflict Detected. Meeting Room 5 is already booked from 2:00 PM to 3:00 PM. Your requested time overlaps by 45 minutes.' ARIA live region updates are announced immediately
    And navigate to the conflict alert message using screen reader
    Then screen reader announces full conflict details including resource name, conflicting times, overlap duration, and available actions like 'View Details' or 'Suggest Alternatives'
    And navigate to 'Conflict Log' link and verify announcement
    Then screen reader announces 'Conflict Log, link, navigate to view all detected conflicts' with proper context
    And all form labels are properly associated with inputs and announced
    And aRIA live regions announce dynamic content changes
    And error and success messages are announced immediately when they appear
    And all interactive elements have descriptive accessible names

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify focus management and focus indicators throughout conflict detection workflow
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling dashboard
    And browser zoom is set to 100%
    And high contrast mode is disabled initially
    When tab through the page and observe focus indicators on all interactive elements
    Then every focusable element displays a visible focus indicator with minimum 3:1 contrast ratio against background. Focus indicator is at least 2px thick and clearly visible
    And open scheduling form modal and verify focus is automatically moved to the first input field
    Then when modal opens, focus automatically moves to Resource dropdown field. Focus is not left on the background page or the button that opened the modal
    And trigger a conflict alert by entering conflicting schedule details and clicking 'Check Availability'
    Then when conflict alert appears, focus automatically moves to the alert container or the first actionable element within the alert. Alert has role='alert' or aria-live='assertive'
    And enable Windows High Contrast Mode or browser high contrast extension and verify focus indicators
    Then focus indicators remain visible in high contrast mode. All UI elements maintain sufficient contrast and remain distinguishable
    And tab through conflict alert actions ('View Details', 'Suggest Alternatives', 'Modify Request') and verify focus order
    Then focus moves through alert actions in logical order matching visual layout. Focus never gets trapped within the alert
    And focus indicators meet WCAG 2.1 Level AA requirements (3:1 contrast)
    And focus is managed programmatically for dynamic content
    And focus order is logical and predictable
    And high contrast mode does not break focus visibility

  @high @tc-acce-004
  Scenario: TC-ACCE-004 - Verify ARIA labels, roles, and properties are correctly implemented for conflict detection components
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling form page
    And browser developer tools are available for inspecting ARIA attributes
    And accessibility testing extension (axe DevTools or similar) is installed
    When inspect the scheduling form modal using browser developer tools
    Then modal has role='dialog', aria-labelledby pointing to modal title, and aria-modal='true'. Modal title has unique ID matching aria-labelledby
    And inspect Resource dropdown field for ARIA attributes
    Then dropdown has role='combobox', aria-required='true', aria-expanded='false' (when closed) or 'true' (when open), and aria-label or associated label element
    And trigger a conflict alert and inspect the alert container
    Then alert container has role='alert' or aria-live='assertive', aria-atomic='true'. Alert message is contained within this region for immediate screen reader announcement
    And inspect the 'Check Availability' button during loading state
    Then button has aria-busy='true' while processing, aria-disabled='true' if disabled, and aria-label describes the action clearly: 'Check availability for selected resource and time'
    And run automated accessibility scan using axe DevTools on the scheduling page
    Then no critical or serious ARIA-related violations are reported. All interactive elements have accessible names. All ARIA attributes are used correctly according to WAI-ARIA specifications
    And inspect the Conflict Log table for proper ARIA table semantics
    Then table has role='table' or uses semantic <table> element, column headers have role='columnheader' or <th> elements, and aria-label describes the table purpose: 'Conflict history log'
    And all ARIA roles are used correctly and appropriately
    And aRIA properties accurately reflect component states
    And no ARIA violations are present in automated scans
    And screen readers can properly interpret all ARIA markup

  @medium @tc-acce-005
  Scenario: TC-ACCE-005 - Verify color contrast ratios meet WCAG 2.1 Level AA standards for all conflict detection UI elements
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling dashboard and form pages
    And color contrast analyzer tool is available (browser extension or standalone)
    And all UI states are testable (default, hover, focus, error, success)
    When use color contrast analyzer to check normal text (form labels, body text) against background
    Then all normal text (under 18pt or 14pt bold) has minimum 4.5:1 contrast ratio against background. Examples: form labels, descriptions, table text
    And check large text (headings, button text) contrast ratios
    Then all large text (18pt and larger, or 14pt bold and larger) has minimum 3:1 contrast ratio. Examples: page headings, button labels, modal titles
    And trigger a conflict alert (red error state) and measure contrast of error text and icons
    Then red error text has minimum 4.5:1 contrast against background. Error icons have 3:1 contrast. Error state is not conveyed by color alone - icons or text patterns are also used
    And trigger a success message (green success state) and measure contrast
    Then green success text has minimum 4.5:1 contrast against background. Success icons have 3:1 contrast. Success state uses icons or text in addition to color
    And check focus indicators on all interactive elements (buttons, links, form fields)
    Then focus indicators have minimum 3:1 contrast ratio against adjacent colors. Focus indicator is clearly visible on all elements
    And verify that information is not conveyed by color alone in conflict visualization
    Then conflict status uses icons, text labels, or patterns in addition to color coding. Users with color blindness can distinguish between conflict states
    And all text meets WCAG 2.1 Level AA contrast requirements
    And uI components and graphical objects meet 3:1 contrast requirement
    And information is not conveyed by color alone
    And interface is usable for users with color vision deficiencies

  @medium @tc-acce-006
  Scenario: TC-ACCE-006 - Verify scheduling interface remains functional and readable at 200% browser zoom
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling dashboard page
    And browser zoom is initially set to 100%
    And responsive design is implemented
    When set browser zoom to 200% using Ctrl/Cmd + Plus key or browser zoom controls
    Then page content scales to 200% zoom. All text remains readable without horizontal scrolling on a 1280px wide viewport
    And navigate through the scheduling dashboard at 200% zoom
    Then all navigation elements, buttons, and interactive components remain accessible and clickable. No content is cut off or hidden. Layout adapts responsively
    And open the scheduling form modal at 200% zoom
    Then modal displays completely within viewport. All form fields are visible and accessible. Vertical scrolling within modal is available if needed, but horizontal scrolling is not required
    And fill out the scheduling form and trigger conflict detection at 200% zoom
    Then all form fields are usable. Conflict alert message is fully visible and readable. Action buttons remain accessible and properly sized for interaction
    And navigate to Conflict Log page at 200% zoom
    Then conflict log table adapts to zoom level. Table may switch to card layout or allow horizontal scrolling, but all data remains accessible and readable
    And test all interactive elements (buttons, dropdowns, links) at 200% zoom
    Then all interactive elements have sufficient size (minimum 44x44 CSS pixels) and spacing for easy interaction. Touch targets do not overlap
    And interface meets WCAG 2.1 Success Criterion 1.4.4 Resize text
    And all functionality remains available at 200% zoom
    And no loss of content or functionality occurs
    And layout adapts appropriately to increased text size

