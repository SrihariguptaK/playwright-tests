Feature: As HR Manager, I want to create shift templates to achieve standardized shift definitions

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: System allows creation of shift templates with all required fields and saves successfully
    Given User is logged in with HR Manager role
    Given User has access to shift template management page
    Given ShiftTemplates database table is accessible
    Given No existing templates with conflicting times exist
    When Navigate to the shift template management page
    Then Shift template management page loads successfully with 'Create New Template' button visible
    And Click on 'Create New Template' button
    Then New template creation form opens with empty fields for shift start time, end time, break duration, and shift type
    And Enter shift start time as '09:00 AM'
    Then Start time field accepts the input and displays '09:00 AM'
    And Enter shift end time as '05:00 PM'
    Then End time field accepts the input and displays '05:00 PM'
    And Enter break duration as '60' minutes
    Then Break duration field accepts the input and displays '60'
    And Select shift type as 'Day Shift' from dropdown
    Then Shift type dropdown displays 'Day Shift' as selected value
    And Click 'Save' button
    Then System validates all inputs, processes the request within 2 seconds, and displays success confirmation message 'Shift template created successfully'
    And Verify the new template appears in the template list
    Then Newly created template is visible in the shift template list with all entered details displayed correctly

  Scenario: System supports editing existing templates and maintains version history
    Given User is logged in with HR Manager role
    Given At least one shift template exists in the system (e.g., 'Day Shift' 09:00 AM - 05:00 PM)
    Given Version history tracking is enabled
    Given User has edit permissions for shift templates
    When Navigate to the shift template management page
    Then Page loads displaying list of existing shift templates
    And Locate the 'Day Shift' template and click 'Edit' button
    Then Edit template form opens pre-populated with current values: Start time '09:00 AM', End time '05:00 PM', Break '60 mins', Type 'Day Shift'
    And Modify the end time from '05:00 PM' to '06:00 PM'
    Then End time field updates to display '06:00 PM'
    And Modify break duration from '60' to '45' minutes
    Then Break duration field updates to display '45'
    And Click 'Save' button
    Then System validates changes, processes within 2 seconds, and displays confirmation message 'Shift template updated successfully'
    And Navigate to version history for the edited template
    Then Version history displays at least 2 versions: Original version (09:00 AM - 05:00 PM, 60 min break) and Current version (09:00 AM - 06:00 PM, 45 min break) with timestamps and editor information
    And Verify audit trail entry exists
    Then Audit log shows entry with timestamp, HR Manager username, action 'Template Updated', and details of changes made

  Scenario: System displays confirmation messages upon successful operations
    Given User is logged in with HR Manager role
    Given User has access to shift template management page
    Given At least one shift template exists for testing edit and delete operations
    Given System notification/messaging component is functional
    When Navigate to shift template management page and click 'Create New Template'
    Then Template creation form opens successfully
    And Fill in all required fields: Start time '06:00 AM', End time '02:00 PM', Break '30 mins', Type 'Morning Shift'
    Then All fields accept input and display entered values
    And Click 'Save' button
    Then System displays success confirmation message 'Shift template created successfully' in a visible notification banner or dialog
    And Verify the confirmation message is clearly visible and styled appropriately (e.g., green color, success icon)
    Then Confirmation message appears with success styling, is easily readable, and auto-dismisses after 3-5 seconds or has a close button
    And Select an existing template and click 'Edit', modify the break duration, and save
    Then System displays confirmation message 'Shift template updated successfully' with appropriate success styling
    And Select a template that is not assigned to any schedules and click 'Delete'
    Then System displays confirmation message 'Shift template deleted successfully' with appropriate success styling
    And Attempt an invalid operation (e.g., create template with end time before start time)
    Then System displays error message with appropriate error styling (e.g., red color, error icon) describing the validation failure

  # Negative Test Scenarios
  Scenario: System validates and rejects overlapping shift times with descriptive error messages
    Given User is logged in with HR Manager role
    Given User has access to shift template management page
    Given An existing shift template exists with time range 09:00 AM to 05:00 PM
    Given ShiftTemplates database contains at least one active template
    When Navigate to the shift template management page
    Then Shift template management page loads with existing templates displayed
    And Click on 'Create New Template' button
    Then New template creation form opens with empty input fields
    And Enter shift start time as '08:00 AM'
    Then Start time field accepts and displays '08:00 AM'
    And Enter shift end time as '10:00 AM' (overlapping with existing 09:00 AM - 05:00 PM template)
    Then End time field accepts and displays '10:00 AM'
    And Enter break duration as '30' minutes
    Then Break duration field accepts and displays '30'
    And Select shift type as 'Morning Shift'
    Then Shift type dropdown displays 'Morning Shift' as selected
    And Click 'Save' button
    Then System performs validation and displays descriptive error message: 'Cannot create template. Shift times overlap with existing template: Day Shift (09:00 AM - 05:00 PM)'
    And Verify template is not saved
    Then Template list does not contain the attempted new template, and form remains open with entered data

  Scenario: System prevents deletion of templates assigned to active schedules and shows warning
    Given User is logged in with HR Manager role
    Given A shift template named 'Evening Shift' exists in the system
    Given The 'Evening Shift' template is assigned to at least one active employee schedule
    Given User has delete permissions for shift templates
    When Navigate to the shift template management page
    Then Page loads displaying all shift templates including 'Evening Shift'
    And Locate the 'Evening Shift' template that is assigned to active schedules
    Then 'Evening Shift' template is visible with a delete button or option available
    And Click the 'Delete' button for the 'Evening Shift' template
    Then System displays warning message: 'Cannot delete template. This template is currently assigned to active schedules. Please reassign or remove schedules before deletion.'
    And Verify the warning dialog includes details about active assignments
    Then Warning message shows number of active schedules using this template (e.g., 'Used in 5 active schedules')
    And Click 'OK' or 'Close' on the warning dialog
    Then Warning dialog closes and user returns to template management page
    And Verify the template still exists in the list
    Then 'Evening Shift' template remains in the template list unchanged

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

