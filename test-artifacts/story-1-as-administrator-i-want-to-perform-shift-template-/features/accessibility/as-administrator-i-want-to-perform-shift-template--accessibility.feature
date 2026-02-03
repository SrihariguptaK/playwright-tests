@accessibility @a11y @wcag
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-acce-001
  Scenario: TC-ACCE-001 - Verify complete keyboard navigation through shift template creation form
    Given user is logged in as Administrator
    And user is on shift template management page
    And screen reader is not active (testing keyboard only)
    And browser is Chrome, Firefox, or Edge
    When press Tab key to navigate to 'Create New Template' button and verify visible focus indicator (blue outline)
    Then button receives focus with clearly visible 2px blue outline, focus indicator has 3:1 contrast ratio against background
    And press Enter key to activate 'Create New Template' button
    Then template creation form opens, focus automatically moves to Template Name field
    And type 'Keyboard Test Shift' in Template Name field, then press Tab to move to Start Time field
    Then focus moves to Start Time dropdown, visible focus indicator appears around field
    And press Space or Enter to open Start Time dropdown, use Arrow Down key to select '08:00 AM', press Enter to confirm
    Then dropdown opens, arrow keys navigate through time options, Enter selects time and closes dropdown
    And press Tab to move to End Time field, repeat time selection using keyboard only
    Then end Time field receives focus, keyboard selection works identically to Start Time
    And press Tab to navigate to 'Add Break' button, press Enter to add break, then use Tab and keyboard to enter break times
    Then break fields are added, all break time inputs are keyboard accessible with same interaction pattern
    And press Tab to navigate to 'Save Template' button, press Enter to submit form
    Then form submits successfully, success message receives focus and is announced
    And press Escape key while form is open to test cancel/close functionality
    Then form closes or cancel confirmation appears, focus returns to 'Create New Template' button
    And all form interactions are completable using keyboard only
    And focus order is logical and follows visual layout
    And no keyboard traps exist in the form
    And focus indicators are visible throughout entire workflow

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader announces all form elements and validation errors correctly
    Given user is logged in as Administrator
    And nVDA or JAWS screen reader is active and running
    And user is on shift template management page
    And screen reader verbosity is set to default level
    When navigate to 'Create New Template' button using screen reader navigation (Tab or virtual cursor)
    Then screen reader announces 'Create New Template, button' with role and accessible name
    And activate button and navigate to Template Name field
    Then screen reader announces 'Template Name, edit, required' indicating field type and required status
    And navigate to Start Time field without entering value
    Then screen reader announces 'Start Time, combobox, required, collapsed' with current state
    And attempt to submit form with empty required fields
    Then screen reader announces 'Error: Template name is required' and 'Error: Start time is required' for each validation error, focus moves to first error field
    And navigate to error messages using screen reader
    Then each error message is announced with role 'alert' or is in aria-live region, errors are associated with fields via aria-describedby
    And fill form correctly and submit, listen for success message announcement
    Then screen reader announces 'Success: Shift template created successfully' from aria-live region without moving focus
    And navigate to templates list and verify each template is announced with complete information
    Then screen reader announces 'Morning Shift, Start Time 8:00 AM, End Time 5:00 PM, Edit button, Delete button' for each template row
    And all interactive elements have proper ARIA labels and roles
    And validation errors are programmatically associated with form fields
    And success and error messages are announced via aria-live regions
    And screen reader users can complete entire workflow independently

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify form maintains proper focus management during dynamic content changes
    Given user is logged in as Administrator
    And user is on shift template creation form
    And keyboard navigation is being used
    When navigate to 'Add Break' button using Tab key and press Enter to add first break
    Then break fields are added to form, focus automatically moves to first break Start Time field
    And enter break times, then click 'Add Break' again to add second break
    Then second break fields appear, focus moves to new break's Start Time field, focus is not lost
    And navigate to 'Remove Break' button (if exists) next to first break and press Enter
    Then break is removed, focus moves to logical next element (next break or 'Add Break' button), focus is not lost to body
    And submit form with validation errors, observe focus behavior
    Then focus automatically moves to first field with error, error message is announced
    And successfully submit form and observe focus after success message
    Then focus moves to success message or remains on form with clear indication of success, user can continue navigation logically
    And focus is never lost during dynamic content updates
    And focus movement is predictable and logical
    And users always know where focus is located
    And no focus traps are created by dynamic content

  @high @tc-acce-004
  Scenario: TC-ACCE-004 - Verify color contrast ratios meet WCAG 2.1 AA standards throughout template management interface
    Given user is on shift template management page
    And color contrast analyzer tool is available (browser extension or standalone)
    And page is displayed at 100% zoom in standard lighting conditions
    When use color contrast analyzer to measure contrast ratio of 'Create New Template' button text against button background
    Then contrast ratio is at least 4.5:1 for normal text or 3:1 for large text (18pt+), meeting WCAG AA standards
    And measure contrast ratio of form field labels (Template Name, Start Time, End Time) against page background
    Then all labels have minimum 4.5:1 contrast ratio against background
    And measure contrast ratio of error messages (red text) against background
    Then error text has at least 4.5:1 contrast ratio, errors are not conveyed by color alone (icon or text indicator present)
    And measure contrast ratio of success message (green banner) text against banner background
    Then success message text has minimum 4.5:1 contrast ratio
    And check focus indicators on all interactive elements for contrast against background
    Then focus indicators have at least 3:1 contrast ratio against adjacent colors per WCAG 2.1 AA
    And verify that information is not conveyed by color alone (e.g., required fields, validation states)
    Then required fields have asterisk or 'required' text, errors have icons, success has icon, not just color coding
    And all text meets WCAG 2.1 AA contrast requirements (4.5:1 for normal, 3:1 for large)
    And focus indicators meet 3:1 contrast requirement
    And information is conveyed through multiple means, not color alone
    And interface is usable for users with color vision deficiencies

  @medium @tc-acce-005
  Scenario: TC-ACCE-005 - Verify interface remains functional and readable at 200% browser zoom
    Given user is logged in as Administrator
    And user is on shift template management page
    And browser zoom is set to 100% initially
    And browser window is at standard desktop resolution (1920x1080)
    When increase browser zoom to 200% using Ctrl/Cmd + Plus key or browser zoom controls
    Then page content scales proportionally, no horizontal scrolling is required, layout remains intact
    And verify 'Create New Template' button is fully visible and clickable without scrolling
    Then button is visible, text is not truncated, button remains functional
    And open template creation form and verify all form fields are visible and usable
    Then form fields stack vertically if needed, all labels are visible, no content is cut off or overlapping
    And verify dropdown menus (Start Time, End Time) open correctly and display all options
    Then dropdowns function normally, options are readable, no layout breaks occur
    And submit form and verify success message is fully visible at 200% zoom
    Then success banner displays completely, text is readable, no content overflow
    And verify templates list displays correctly with all columns readable
    Then table or list layout adapts to zoom level, all data is accessible, horizontal scrolling is minimal or absent
    And all functionality remains available at 200% zoom
    And no content is lost or becomes inaccessible
    And layout adapts responsively to increased text size
    And users with low vision can use interface effectively

  @medium @tc-acce-006
  Scenario: TC-ACCE-006 - Verify proper ARIA landmarks and semantic HTML structure for assistive technology navigation
    Given user is on shift template management page
    And screen reader is active (NVDA or JAWS)
    And browser developer tools are available for inspecting HTML
    When use screen reader landmarks navigation (NVDA: D key, JAWS: ; key) to navigate through page regions
    Then screen reader announces distinct landmarks: 'banner' or 'header', 'navigation', 'main', 'contentinfo' or 'footer'
    And verify template creation form is within a <form> element or has role='form' with accessible name
    Then screen reader announces 'form, Create Shift Template' or similar when entering form region
    And use screen reader headings navigation (H key) to navigate through page structure
    Then headings are properly nested (h1 for page title, h2 for sections, h3 for subsections), no heading levels are skipped
    And inspect form fields to verify proper label associations using <label> elements or aria-labelledby
    Then all form inputs have programmatically associated labels, clicking label focuses corresponding input
    And verify buttons use <button> elements (not <div> or <span> with click handlers)
    Then all interactive buttons are semantic <button> elements with proper type attribute (button, submit)
    And check that templates list uses semantic table (<table>) or list (<ul>/<ol>) markup
    Then data is structured semantically, screen reader announces 'table with X rows' or 'list with X items'
    And page structure is semantically correct and navigable by landmarks
    And all interactive elements use appropriate HTML elements
    And screen reader users can efficiently navigate page structure
    And form relationships are programmatically determinable

