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
    And user is on the shift template management page
    And screen reader is not active (testing keyboard only)
    And browser is set to show focus indicators
    When press Tab key to navigate to 'Create New Template' button
    Then button receives visible focus indicator (outline or highlight) and can be identified as focused element
    And press Enter key to activate 'Create New Template' button
    Then template creation form opens and focus moves to first form field (Template Name)
    And type 'Keyboard Test Shift' in Template Name field, then press Tab
    Then focus moves to Start Time field with visible focus indicator
    And use Arrow keys to select '09:00 AM' in Start Time dropdown, then press Tab
    Then time is selected and focus moves to End Time field
    And use Arrow keys to select '05:00 PM' in End Time field, then press Tab
    Then time is selected and focus moves to 'Add Break' button
    And press Enter on 'Add Break' button, then Tab through break time fields
    Then break fields are added and keyboard focus moves through break start and end time fields sequentially
    And press Tab to reach 'Save Template' button and press Enter
    Then form is submitted, template is created, and focus returns to template list or success message
    And press Escape key while form is open
    Then form closes and focus returns to 'Create New Template' button on main page
    And all interactive elements are reachable via keyboard
    And focus order is logical and follows visual layout
    And no keyboard traps exist in the form
    And focus indicators are visible throughout navigation

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Verify screen reader announces all form labels, errors, and success messages correctly
    Given user is logged in as Administrator
    And nVDA or JAWS screen reader is active and running
    And user is on the shift template management page
    And screen reader verbosity is set to default level
    When navigate to 'Create New Template' button using screen reader commands
    Then screen reader announces: 'Create New Template, button' with role and accessible name
    And activate button and navigate to Template Name field
    Then screen reader announces: 'Template Name, edit, required' indicating field label, type, and required status
    And navigate to Start Time field
    Then screen reader announces: 'Start Time, combobox, required' or 'Start Time, time picker, required'
    And leave Template Name empty and attempt to save, then navigate to validation error
    Then screen reader announces: 'Error: Template Name is required' and error is associated with the field via aria-describedby
    And fill all required fields correctly and save template
    Then screen reader announces success message: 'Success: Shift template created successfully' via ARIA live region
    And navigate through the template list
    Then screen reader announces each template with format: 'Morning Shift, Start Time: 08:00 AM, End Time: 05:00 PM, Edit button, Delete button'
    And all form controls have proper labels associated via label element or aria-label
    And error messages are announced immediately and associated with fields
    And success/failure messages use ARIA live regions for announcements
    And dynamic content changes are communicated to screen reader users

  @high @tc-acce-003
  Scenario: TC-ACCE-003 - Verify sufficient color contrast ratios for all text and interactive elements (WCAG 2.1 AA)
    Given user is on the shift template management page
    And color contrast analyzer tool is available (e.g., browser extension or WAVE tool)
    And page is displayed at 100% zoom in standard lighting conditions
    And all templates and form elements are visible
    When use color contrast analyzer to check Template Name label text against background
    Then contrast ratio is at least 4.5:1 for normal text (or 3:1 for large text 18pt+)
    And check contrast of 'Create New Template' button text against button background
    Then contrast ratio meets 4.5:1 minimum for button text
    And check contrast of validation error messages (red text) against background
    Then error text has minimum 4.5:1 contrast ratio and does not rely solely on color to convey error state (includes icon or text indicator)
    And check contrast of success message (green banner) text against banner background
    Then success message text meets 4.5:1 contrast ratio
    And check focus indicators on all interactive elements
    Then focus indicators have at least 3:1 contrast ratio against adjacent colors
    And verify disabled button states have sufficient contrast or are clearly indicated
    Then disabled buttons are distinguishable and meet minimum contrast requirements or use additional indicators beyond color
    And all text meets WCAG 2.1 Level AA contrast requirements
    And interactive elements are distinguishable from non-interactive content
    And error and success states do not rely on color alone
    And page is usable for users with color vision deficiencies

  @medium @tc-acce-004
  Scenario: TC-ACCE-004 - Verify form remains functional and readable at 200% browser zoom level
    Given user is logged in as Administrator
    And user is on the shift template creation page
    And browser zoom is set to 100% initially
    And browser window is at standard desktop resolution (1920x1080)
    When open shift template creation form at 100% zoom and note layout
    Then form displays normally with all fields visible
    And increase browser zoom to 200% using Ctrl/Cmd + '+' or browser settings
    Then page content scales proportionally to 200% size
    And verify all form fields are still visible without horizontal scrolling
    Then form fields reflow and remain accessible, vertical scrolling may be present but horizontal scrolling is not required
    And attempt to fill out Template Name, Start Time, and End Time fields at 200% zoom
    Then all fields are functional, text is readable, and dropdowns/pickers work correctly
    And click 'Save Template' button at 200% zoom
    Then button is clickable, form submits successfully, and success message is visible and readable
    And verify template list displays correctly at 200% zoom
    Then template list is readable with proper text wrapping, no content is cut off or overlapping
    And all functionality remains available at 200% zoom
    And no loss of content or functionality occurs
    And text remains readable without horizontal scrolling
    And interactive elements remain clickable and properly sized

  @high @tc-acce-005
  Scenario: TC-ACCE-005 - Verify proper ARIA roles, labels, and states for dynamic form elements
    Given user is logged in as Administrator
    And user is on shift template creation page
    And browser developer tools are open to inspect ARIA attributes
    And screen reader testing mode is available
    When inspect 'Create New Template' button in developer tools
    Then button has role='button' (implicit or explicit) and accessible name via text content or aria-label
    And inspect Template Name input field
    Then field has associated label via <label for='id'> or aria-labelledby, and aria-required='true' attribute
    And trigger validation error on Template Name field and inspect error message
    Then error message has role='alert' or is in aria-live='polite' region, and field has aria-invalid='true' and aria-describedby pointing to error message ID
    And inspect time picker/dropdown components
    Then components have appropriate roles (combobox, listbox) and aria-expanded state changes when opened/closed
    And click 'Add Break' button and inspect newly added break fields
    Then new fields are properly labeled, have unique IDs, and are announced to screen readers via ARIA live region
    And inspect success message banner after template creation
    Then success message has role='status' or aria-live='polite' to announce to screen readers without interrupting
    And all interactive elements have appropriate ARIA roles
    And form validation states are communicated via ARIA attributes
    And dynamic content changes are announced to assistive technologies
    And aRIA attributes are used correctly without conflicts

  @high @tc-acce-006
  Scenario: TC-ACCE-006 - Verify focus management when opening and closing modal dialogs (delete confirmation)
    Given user is logged in as Administrator
    And at least one shift template exists in the list
    And user is on shift template management page
    And keyboard navigation is being used
    When use Tab key to navigate to 'Delete' button for a template and press Enter
    Then delete confirmation modal opens and focus automatically moves to the first focusable element in modal (typically 'Cancel' or 'Confirm' button)
    And press Tab key repeatedly while modal is open
    Then focus cycles only through elements within the modal (focus trap is active), cannot tab to background content
    And press Shift+Tab to navigate backwards through modal elements
    Then focus moves backwards through modal elements and wraps from first to last element
    And press Escape key while modal is open
    Then modal closes and focus returns to the 'Delete' button that originally opened the modal
    And open modal again and click 'Confirm' button using keyboard (Enter key)
    Then modal closes, delete action executes, and focus moves to logical location (success message or next template in list)
    And verify modal has proper ARIA attributes: role='dialog' or role='alertdialog', aria-modal='true', aria-labelledby pointing to modal title
    Then modal is properly identified to screen readers with all required ARIA attributes present
    And focus is never lost or trapped in inaccessible location
    And modal implements proper focus management pattern
    And background content is inert while modal is open (aria-hidden='true' or inert attribute)
    And keyboard users can operate modal completely without mouse

