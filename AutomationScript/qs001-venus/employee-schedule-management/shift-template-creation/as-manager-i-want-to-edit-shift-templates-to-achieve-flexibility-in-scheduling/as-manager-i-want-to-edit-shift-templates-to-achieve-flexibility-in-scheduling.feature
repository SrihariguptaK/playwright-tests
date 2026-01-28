Feature: Shift Template Creation

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Validate successful editing of shift template
    Given User is logged in with Manager role credentials
    Given At least one shift template exists in the system
    Given User has permission to edit shift templates
    Given ShiftTemplates table is accessible in the database
    Given PUT /api/shift-templates/{id} endpoint is available
    When Navigate to the shift template section from the main dashboard
    Then Shift template list is displayed showing all existing templates with their details (name, start time, end time, break duration, assigned roles)
    And Select an existing template from the list by clicking on it
    Then Template details are loaded and the editing interface is displayed with all current template information populated in editable fields
    And Modify shift start time by changing it to a new valid time
    Then New start time is accepted and displayed in the input field
    And Modify shift end time by changing it to a new valid time that does not overlap with other shifts
    Then New end time is accepted and displayed in the input field
    And Update break duration to a new valid duration
    Then New break duration is accepted and displayed in the input field
    And Change the role assigned to the shift by selecting a different role from the dropdown
    Then New role is selected and displayed in the role field
    And Click the 'Save' or 'Update' button to save the changes
    Then System validates the changes, sends PUT request to /api/shift-templates/{id}, and displays a success message confirming 'Template updated successfully'
    And Navigate back to the shift template list
    Then Updated template is displayed in the list with all modified details reflected correctly

  # Negative Test Scenarios
  Scenario: Ensure overlapping shift templates cannot be edited
    Given User is logged in with Manager role credentials
    Given Multiple shift templates exist in the system
    Given At least one shift template exists that could potentially overlap with another if edited
    Given User has permission to edit shift templates
    Given Validation rules for overlapping shifts are configured in the system
    Given PUT /api/shift-templates/{id} endpoint is available with overlap validation
    When Navigate to the shift template section from the main dashboard
    Then Shift template list is displayed showing all existing templates with their current time slots and details
    And Identify a template that can be edited to create an overlap with another existing template
    Then Template is identified and available for selection
    And Select the identified template by clicking on it
    Then Template details are loaded and the editing interface is displayed with all current template information populated in editable fields
    And Modify the shift start time to a time that would cause an overlap with another existing shift template
    Then New start time is entered and displayed in the input field
    And Modify the shift end time to a time that would create an overlapping time range with another existing shift template
    Then New end time is entered and displayed in the input field
    And Click the 'Save' or 'Update' button to attempt to save the changes
    Then System validates the changes, detects the overlap conflict, and displays an error message such as 'Cannot update template: The specified time range overlaps with an existing shift template' or 'Overlapping shifts are not allowed'
    And Verify that the template remains in edit mode with the invalid changes still visible
    Then Editing interface remains open with the attempted changes displayed, allowing the manager to correct the values
    And Navigate back to the shift template list without saving
    Then Original template is displayed in the list with unchanged details, confirming no update was applied

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

