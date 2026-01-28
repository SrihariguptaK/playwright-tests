Feature: As HR Manager, I want to prevent deletion of shift templates assigned to active schedules to achieve data integrity

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Verify system blocks deletion of shift template assigned to active schedules
    Given User is logged in as HR Manager with delete permissions
    Given At least one shift template exists in the system
    Given The shift template is assigned to one or more active schedules
    Given User is on the Shift Templates management page
    When Navigate to the Shift Templates management page
    Then Shift Templates page loads successfully displaying list of all shift templates
    And Identify a shift template that is assigned to active schedules
    Then Shift template is visible in the list with assignment indicator
    And Click on the delete button/icon for the selected shift template
    Then System initiates deletion process and checks for active schedule assignments
    And Observe the system response
    Then System displays a warning message stating 'This shift template cannot be deleted as it is assigned to active schedules' or similar clear message
    And Verify the deletion is blocked
    Then Delete operation is prevented and the shift template remains in the system
    And Click OK or Close on the warning message
    Then Warning dialog closes and user returns to Shift Templates page with template still present

  Scenario: Verify system allows deletion of shift template not assigned to any schedules
    Given User is logged in as HR Manager with delete permissions
    Given At least one shift template exists that is NOT assigned to any schedules
    Given User is on the Shift Templates management page
    When Navigate to the Shift Templates management page
    Then Shift Templates page loads successfully displaying list of all shift templates
    And Identify a shift template that is not assigned to any schedules
    Then Shift template is visible in the list without any assignment indicator
    And Click on the delete button/icon for the unassigned shift template
    Then System initiates deletion process and checks for active schedule assignments
    And Observe the system response
    Then System displays a confirmation dialog asking 'Are you sure you want to delete this shift template?'
    And Click 'Confirm' or 'Yes' on the confirmation dialog
    Then System processes the deletion request via DELETE /api/shifttemplates/{id} endpoint
    And Observe the deletion result
    Then System displays success message 'Shift template deleted successfully' and removes the template from the list
    And Verify the template is no longer in the list
    Then Deleted shift template is not visible in the Shift Templates list

  Scenario: Verify system logs deletion attempts for templates assigned to active schedules
    Given User is logged in as HR Manager with delete permissions
    Given At least one shift template exists that is assigned to active schedules
    Given User has access to audit logs or system logs
    Given User is on the Shift Templates management page
    When Navigate to the Shift Templates management page
    Then Shift Templates page loads successfully
    And Note the current timestamp and the shift template ID to be deleted
    Then Template ID and timestamp are recorded for audit verification
    And Attempt to delete a shift template that is assigned to active schedules
    Then System blocks deletion and displays warning message
    And Close the warning message
    Then User returns to Shift Templates page
    And Navigate to the audit logs or system logs section
    Then Audit logs page loads successfully
    And Search for the deletion attempt using the template ID and timestamp
    Then Log entry is found for the deletion attempt
    And Verify the log entry contains: timestamp, user ID, template ID, action attempted (DELETE), outcome (BLOCKED), and reason
    Then Log entry shows all required information including 'BLOCKED - Template assigned to active schedules'

  Scenario: Verify system logs successful deletion of unassigned templates
    Given User is logged in as HR Manager with delete permissions
    Given At least one shift template exists that is NOT assigned to any schedules
    Given User has access to audit logs or system logs
    Given User is on the Shift Templates management page
    When Navigate to the Shift Templates management page
    Then Shift Templates page loads successfully
    And Note the current timestamp and the shift template ID to be deleted
    Then Template ID and timestamp are recorded for audit verification
    And Delete a shift template that is not assigned to any schedules
    Then System allows deletion and displays success message
    And Navigate to the audit logs or system logs section
    Then Audit logs page loads successfully
    And Search for the deletion event using the template ID and timestamp
    Then Log entry is found for the deletion event
    And Verify the log entry contains: timestamp, user ID, template ID, action performed (DELETE), and outcome (SUCCESS)
    Then Log entry shows all required information including 'SUCCESS - Template deleted'

  Scenario: Verify warning message clarity when attempting to delete assigned template
    Given User is logged in as HR Manager with delete permissions
    Given At least one shift template exists that is assigned to active schedules
    Given User is on the Shift Templates management page
    When Navigate to the Shift Templates management page
    Then Shift Templates page loads successfully
    And Attempt to delete a shift template assigned to active schedules
    Then System displays a warning dialog
    And Read and verify the warning message content
    Then Warning message clearly states: 1) Template cannot be deleted, 2) Reason is assignment to active schedules, 3) Suggests alternative actions if applicable
    And Verify the warning dialog has appropriate buttons (OK, Close, or Cancel)
    Then Dialog has clear dismissal option without proceeding with deletion
    And Check if the warning message includes the number of active schedules using the template
    Then Message optionally displays count of affected schedules for user awareness

  Scenario: Verify real-time usage check performance when deleting template
    Given User is logged in as HR Manager with delete permissions
    Given Multiple shift templates exist in the system
    Given Some templates are assigned to active schedules, some are not
    Given User is on the Shift Templates management page
    When Navigate to the Shift Templates management page
    Then Shift Templates page loads successfully
    And Note the current time and click delete on a shift template assigned to active schedules
    Then System initiates real-time usage check
    And Measure the time taken for the system to display the warning message
    Then Warning message appears within 2-3 seconds indicating real-time performance
    And Close the warning dialog
    Then Dialog closes and user returns to template list
    And Note the current time and click delete on an unassigned shift template
    Then System initiates real-time usage check
    And Measure the time taken for the system to display the confirmation dialog
    Then Confirmation dialog appears within 2-3 seconds indicating real-time performance

  Scenario: Verify API endpoint returns success when deleting unassigned template
    Given User has valid authentication token with HR Manager role
    Given At least one shift template exists that is NOT assigned to any schedules
    Given API endpoint DELETE /api/shifttemplates/{id} is accessible
    Given User has API testing tool (Postman, curl, etc.)
    When Identify the ID of a shift template not assigned to any schedules
    Then Template ID is obtained from the system
    And Send DELETE request to /api/shifttemplates/{id} with valid authentication token
    Then API receives the request and processes it
    And Verify the HTTP response status code
    Then API returns 200 OK or 204 No Content status code
    And Verify the response body contains success confirmation
    Then Response includes success message or empty body for 204 status
    And Send GET request to retrieve the deleted template
    Then API returns 404 Not Found confirming template no longer exists
    And Verify the template is removed from the database
    Then Template cannot be found in the system

  # Negative Test Scenarios
  Scenario: Verify role-based access control for template deletion
    Given User is logged in with a role other than HR Manager (e.g., Employee, Supervisor)
    Given Shift templates exist in the system
    Given User navigates to Shift Templates page or attempts to access deletion functionality
    When Login with a user account that does not have HR Manager role
    Then User successfully logs into the system
    And Attempt to navigate to the Shift Templates management page
    Then Either page is not accessible or delete functionality is not visible/enabled
    And If page is accessible, verify that delete buttons/icons are not present or are disabled
    Then Delete functionality is not available to unauthorized users
    And If attempting direct API call, send DELETE request to /api/shifttemplates/{id}
    Then System returns 403 Forbidden or 401 Unauthorized error
    And Verify error message indicates insufficient permissions
    Then Clear error message states 'You do not have permission to delete shift templates' or similar

  Scenario: Verify API endpoint returns correct error code when deleting assigned template
    Given User has valid authentication token with HR Manager role
    Given At least one shift template exists that is assigned to active schedules
    Given API endpoint DELETE /api/shifttemplates/{id} is accessible
    Given User has API testing tool (Postman, curl, etc.)
    When Identify the ID of a shift template assigned to active schedules
    Then Template ID is obtained from the system
    And Send DELETE request to /api/shifttemplates/{id} with valid authentication token
    Then API receives the request and processes it
    And Verify the HTTP response status code
    Then API returns 409 Conflict or 400 Bad Request status code
    And Verify the response body contains error details
    Then Response includes error message explaining template is assigned to active schedules
    And Verify the response includes appropriate error code or identifier
    Then Response contains structured error information (e.g., errorCode: 'TEMPLATE_IN_USE')
    And Verify the template still exists in the database
    Then Template is not deleted and remains in the system

  # Edge Case Test Scenarios
  Scenario: Verify system behavior when template becomes assigned between check and deletion
    Given User is logged in as HR Manager with delete permissions
    Given At least one shift template exists that is currently unassigned
    Given Another HR Manager or system process can assign templates to schedules
    Given User is on the Shift Templates management page
    When Navigate to the Shift Templates management page
    Then Shift Templates page loads successfully
    And Identify an unassigned shift template and initiate deletion
    Then System displays confirmation dialog for deletion
    And Before confirming deletion, have another user assign this template to an active schedule
    Then Template is now assigned to an active schedule in the database
    And Click 'Confirm' on the deletion dialog
    Then System performs final usage check before executing deletion
    And Observe the system response
    Then System detects the template is now assigned and blocks deletion with appropriate warning message
    And Verify the template remains in the system
    Then Template is not deleted and remains assigned to the active schedule

  Scenario: Verify system behavior when attempting to delete multiple templates simultaneously
    Given User is logged in as HR Manager with delete permissions
    Given Multiple shift templates exist in the system
    Given Some templates are assigned to active schedules, some are not
    Given System supports bulk deletion or multiple selection
    Given User is on the Shift Templates management page
    When Navigate to the Shift Templates management page
    Then Shift Templates page loads successfully
    And Select multiple shift templates including both assigned and unassigned templates
    Then Multiple templates are selected as indicated by checkboxes or highlighting
    And Click the bulk delete button or delete action
    Then System initiates usage check for all selected templates
    And Observe the system response
    Then System displays a message indicating which templates can be deleted and which cannot, with reasons
    And Verify the message lists assigned templates that will be skipped
    Then Clear list shows templates blocked from deletion due to active schedule assignments
    And Confirm the bulk deletion
    Then System deletes only the unassigned templates and preserves assigned ones
    And Verify the results in the template list
    Then Unassigned templates are removed, assigned templates remain in the list

  Scenario: Verify system behavior when template is assigned to inactive schedules
    Given User is logged in as HR Manager with delete permissions
    Given At least one shift template exists that is assigned only to inactive/past schedules
    Given No active schedules are using this template
    Given User is on the Shift Templates management page
    When Navigate to the Shift Templates management page
    Then Shift Templates page loads successfully
    And Identify a shift template that is assigned only to inactive or past schedules
    Then Template is visible in the list
    And Click on the delete button for this template
    Then System checks for active schedule assignments only
    And Observe the system response
    Then System allows deletion since template is not assigned to any ACTIVE schedules and displays confirmation dialog
    And Confirm the deletion
    Then System successfully deletes the template and displays success message
    And Verify the template is removed from the list
    Then Template no longer appears in the Shift Templates list

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

