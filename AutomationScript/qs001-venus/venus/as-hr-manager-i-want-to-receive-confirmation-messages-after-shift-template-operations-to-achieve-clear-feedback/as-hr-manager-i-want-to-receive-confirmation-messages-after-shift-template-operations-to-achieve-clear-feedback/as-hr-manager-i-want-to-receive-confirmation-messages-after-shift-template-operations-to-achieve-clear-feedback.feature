Feature: As HR Manager, I want to receive confirmation messages after shift template operations to achieve clear feedback

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Verify success message displays after shift template creation
    Given User is logged in as HR Manager
    Given User has permissions to create shift templates
    Given User is on the shift template management page
    Given All required fields for shift template creation are available
    When Navigate to the shift template creation page
    Then Shift template creation form is displayed with all required fields
    And Fill in all required fields (template name, shift hours, break times, etc.)
    Then All fields accept valid input and display entered data correctly
    And Click the 'Create' or 'Save' button to submit the shift template
    Then System processes the request and submits the data
    And Observe the notification area for confirmation message
    Then A clear success message is displayed (e.g., 'Shift template created successfully') within 2 seconds
    And Verify the message content and visibility
    Then Message is clearly visible, uses appropriate color coding (green for success), and contains specific details about the created template

  Scenario: Verify success message displays after shift template update
    Given User is logged in as HR Manager
    Given User has permissions to edit shift templates
    Given At least one shift template exists in the system
    Given User is on the shift template management page
    When Select an existing shift template from the list
    Then Shift template details are displayed
    And Click the 'Edit' button or icon
    Then Shift template edit form opens with current values populated
    And Modify one or more fields (e.g., change shift hours, update template name)
    Then Modified fields accept the new input and display changes
    And Click the 'Update' or 'Save Changes' button
    Then System processes the update request
    And Observe the notification area for confirmation message
    Then A clear success message is displayed (e.g., 'Shift template updated successfully') within 2 seconds
    And Verify the updated template reflects the changes
    Then Template list shows the updated information

  Scenario: Verify success message displays after shift template deletion
    Given User is logged in as HR Manager
    Given User has permissions to delete shift templates
    Given At least one shift template exists that can be deleted
    Given User is on the shift template management page
    When Locate a shift template to delete from the list
    Then Shift template is visible in the list with delete option available
    And Click the 'Delete' button or icon for the selected template
    Then Confirmation dialog appears asking to confirm deletion
    And Click 'Confirm' or 'Yes' in the confirmation dialog
    Then System processes the deletion request
    And Observe the notification area for confirmation message
    Then A clear success message is displayed (e.g., 'Shift template deleted successfully') within 2 seconds
    And Verify the template is removed from the list
    Then Deleted template no longer appears in the shift template list

  Scenario: Verify confirmation messages are accessible and comply with WCAG standards
    Given User is logged in as HR Manager
    Given Screen reader software is available for testing
    Given User has permissions to perform shift template operations
    Given Accessibility testing tools are configured
    When Enable screen reader software (e.g., NVDA, JAWS)
    Then Screen reader is active and functioning
    And Perform a shift template creation operation
    Then Template is created successfully
    And Listen to the screen reader announcement of the success message
    Then Screen reader announces the success message clearly and completely with appropriate ARIA labels
    And Verify the message has proper ARIA attributes (role='alert' or role='status')
    Then Message container has appropriate ARIA attributes for accessibility
    And Check color contrast ratio of the message using accessibility tools
    Then Message text has sufficient contrast ratio (minimum 4.5:1 for normal text) meeting WCAG AA standards
    And Navigate to the message using keyboard only (Tab key)
    Then Message is keyboard accessible and can be focused if interactive
    And Verify message remains visible for adequate time or can be dismissed
    Then Message stays visible long enough to be read (minimum 5 seconds) or has a dismiss button

  Scenario: Verify notifications are displayed promptly after shift template creation
    Given User is logged in as HR Manager
    Given User has permissions to create shift templates
    Given User is on the shift template creation page
    Given System performance is normal
    When Note the current time or start a timer
    Then Timer is ready to measure response time
    And Fill in all required fields for shift template creation
    Then All fields are populated with valid data
    And Click the 'Create' or 'Save' button
    Then System begins processing the request
    And Measure the time until the success notification appears
    Then Success notification is displayed within 2 seconds of clicking the submit button
    And Verify the notification appears without requiring page refresh
    Then Notification appears dynamically without full page reload

  Scenario: Verify notifications are displayed promptly after shift template update
    Given User is logged in as HR Manager
    Given User has permissions to edit shift templates
    Given At least one shift template exists in the system
    Given User is on the shift template edit page
    When Open an existing shift template for editing
    Then Edit form is displayed with current values
    And Make changes to one or more fields
    Then Changes are entered successfully
    And Start a timer and click the 'Update' or 'Save Changes' button
    Then System begins processing the update
    And Measure the time until the success notification appears
    Then Success notification is displayed within 2 seconds of clicking the update button
    And Verify the notification appears immediately without delay
    Then Notification is displayed promptly and dynamically

  Scenario: Verify notifications are displayed promptly after shift template deletion
    Given User is logged in as HR Manager
    Given User has permissions to delete shift templates
    Given At least one deletable shift template exists
    Given User is on the shift template management page
    When Select a shift template to delete
    Then Template is selected and delete option is available
    And Click the 'Delete' button
    Then Confirmation dialog appears
    And Start a timer and confirm the deletion
    Then System begins processing the deletion
    And Measure the time until the success notification appears
    Then Success notification is displayed within 2 seconds of confirming deletion
    And Verify the notification appears immediately and the template is removed from the list
    Then Notification is displayed promptly and template list is updated in real-time

  Scenario: Verify notification messages comply with UI design standards and consistency
    Given User is logged in as HR Manager
    Given User has permissions to perform shift template operations
    Given UI design standards documentation is available
    Given User is on the shift template management page
    When Perform a shift template creation and observe the success notification
    Then Success notification appears with consistent styling (color, font, size, position)
    And Verify the notification uses the standard success color (typically green) and icon
    Then Notification uses consistent success indicators matching UI standards
    And Perform a shift template update and observe the success notification
    Then Update notification has the same styling, position, and format as creation notification
    And Trigger an error condition and observe the error notification
    Then Error notification uses consistent error styling (typically red) with appropriate icon
    And Verify notification positioning is consistent across all operations
    Then All notifications appear in the same location (e.g., top-right corner, top of page)
    And Check that notification text follows consistent formatting and tone
    Then All messages use consistent language style, capitalization, and punctuation
    And Verify notification dismiss behavior is consistent (auto-dismiss or manual close)
    Then All notifications have the same dismiss mechanism and timing

  Scenario: Verify notification messages use modal dialogs appropriately for critical operations
    Given User is logged in as HR Manager
    Given User has permissions to perform shift template operations
    Given User is on the shift template management page
    When Initiate a shift template deletion operation
    Then Delete button is clicked
    And Observe if a modal dialog appears for confirmation
    Then Modal dialog appears asking for deletion confirmation, blocking other interactions
    And Verify the modal contains clear messaging about the action consequences
    Then Modal displays warning message explaining that deletion is permanent or has specific consequences
    And Confirm the deletion in the modal
    Then Modal closes and success notification appears
    And Perform a non-critical operation like template creation
    Then Success notification appears as inline notification or toast, not as modal
    And Verify that modal dialogs are used only for operations requiring explicit confirmation
    Then Modal dialogs are reserved for critical actions (delete, bulk operations), while inline notifications are used for standard operations

  Scenario: Verify notification messages use inline notifications appropriately for standard operations
    Given User is logged in as HR Manager
    Given User has permissions to perform shift template operations
    Given User is on the shift template management page
    When Create a new shift template
    Then Template creation form is submitted successfully
    And Observe the type of notification displayed
    Then An inline notification or toast message appears (not a modal dialog) showing success message
    And Verify the inline notification does not block user interaction with the page
    Then User can continue interacting with the page while notification is visible
    And Update an existing shift template
    Then Template update is submitted successfully
    And Observe the notification type for update operation
    Then Inline notification appears with update success message, allowing continued page interaction
    And Verify the notification auto-dismisses after appropriate time or has a close button
    Then Notification either disappears automatically after 5-10 seconds or provides a close/dismiss button
    And Check that inline notifications appear in a consistent location
    Then All inline notifications appear in the same designated area (e.g., top-right corner, banner area)

  # Negative Test Scenarios
  Scenario: Verify descriptive error message displays when shift template creation fails due to missing required fields
    Given User is logged in as HR Manager
    Given User has permissions to create shift templates
    Given User is on the shift template creation page
    When Navigate to the shift template creation form
    Then Creation form is displayed with all fields
    And Leave one or more required fields empty (e.g., template name)
    Then Fields remain empty
    And Click the 'Create' or 'Save' button
    Then System validates the form
    And Observe the notification area and form validation
    Then A descriptive error message is displayed (e.g., 'Template name is required') with clear indication of which fields are missing
    And Verify the error message provides actionable guidance
    Then Error message uses appropriate color coding (red), specifies the exact issue, and guides user on how to fix it

  Scenario: Verify descriptive error message displays when shift template update fails due to validation errors
    Given User is logged in as HR Manager
    Given User has permissions to edit shift templates
    Given At least one shift template exists in the system
    Given User is on the shift template edit page
    When Open an existing shift template for editing
    Then Edit form is displayed with current values
    And Enter invalid data in one or more fields (e.g., negative shift hours, invalid time format)
    Then Invalid data is entered in the field
    And Click the 'Update' or 'Save Changes' button
    Then System validates the input
    And Observe the notification area for error message
    Then A descriptive error message is displayed (e.g., 'Shift hours must be a positive number') clearly indicating the validation issue
    And Verify the error message provides specific details
    Then Error message specifies which field has the issue and what the valid format or range should be

  Scenario: Verify descriptive error message displays when shift template deletion fails due to dependencies
    Given User is logged in as HR Manager
    Given User has permissions to delete shift templates
    Given A shift template exists that is currently in use or has dependencies
    Given User is on the shift template management page
    When Locate a shift template that has active dependencies (e.g., assigned to employees or schedules)
    Then Template is visible in the list
    And Click the 'Delete' button for the template
    Then Confirmation dialog appears
    And Confirm the deletion action
    Then System attempts to process the deletion
    And Observe the notification area for error message
    Then A descriptive error message is displayed (e.g., 'Cannot delete template: currently assigned to 5 employees') explaining why deletion failed
    And Verify the error message provides actionable guidance
    Then Error message suggests next steps (e.g., 'Remove assignments before deleting') and uses appropriate error styling

  Scenario: Verify error message displays when network or server error occurs during shift template operation
    Given User is logged in as HR Manager
    Given User has permissions to perform shift template operations
    Given Network connectivity issues or server error condition can be simulated
    Given User is on the shift template management page
    When Initiate any shift template operation (create, update, or delete)
    Then Operation form or confirmation is displayed
    And Simulate network disconnection or server error (e.g., disconnect network, simulate 500 error)
    Then Network or server becomes unavailable
    And Submit the operation
    Then System attempts to process the request
    And Observe the notification area for error message
    Then A descriptive error message is displayed (e.g., 'Unable to connect to server. Please check your connection and try again') within a reasonable timeout period
    And Verify the error message provides helpful guidance
    Then Error message explains the issue clearly and suggests troubleshooting steps

  Scenario: Verify error messages are accessible and comply with WCAG standards
    Given User is logged in as HR Manager
    Given Screen reader software is available for testing
    Given User has permissions to perform shift template operations
    Given Accessibility testing tools are configured
    When Enable screen reader software
    Then Screen reader is active
    And Trigger an error condition (e.g., submit form with missing required fields)
    Then Error condition is triggered
    And Listen to the screen reader announcement of the error message
    Then Screen reader announces the error message with appropriate urgency and clarity, including ARIA live region announcements
    And Verify error message has proper ARIA attributes (role='alert', aria-live='assertive')
    Then Error message container has appropriate ARIA attributes for immediate announcement
    And Check color contrast of error message text and icons
    Then Error message meets WCAG contrast requirements (4.5:1 minimum) and does not rely solely on color to convey meaning
    And Verify error message is associated with the relevant form field using aria-describedby
    Then Error message is programmatically linked to the field that caused the error
    And Navigate to error message and associated fields using keyboard only
    Then All error elements are keyboard accessible and focus is managed appropriately

  # Accessibility Test Scenarios
  Scenario: Keyboard Navigation
    When the user navigates using keyboard only
    Then all interactive elements should be accessible via keyboard
    And focus indicators should be clearly visible

  Scenario: Screen Reader Compatibility
    When the user accesses the page with a screen reader
    Then all content should be properly announced
    And ARIA labels should be present for all interactive elements

  Scenario: Color Contrast
    Then all text should meet WCAG AA color contrast standards
    And important information should not rely solely on color

