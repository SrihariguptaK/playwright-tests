# Manual Test Cases

## Story: As Scheduling Manager, I want to create shift templates to achieve consistent shift definitions
**Story ID:** story-1

### Test Case: Validate successful shift template creation with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with template creation permissions
- Shift template creation page is accessible
- Database connection is active and ShiftTemplates table is available
- No existing template with the same name exists

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page by clicking on 'Shift Templates' menu and selecting 'Create New Template' | Shift template form is displayed with empty fields for template name, start time, end time, breaks, and roles. All form controls are enabled and ready for input |
| 2 | Enter template name as 'Morning Shift', start time as '08:00 AM', end time as '04:00 PM' | All time inputs accept the data without validation errors. Fields display the entered values correctly |
| 3 | Add break period by clicking 'Add Break' button and enter break start time as '12:00 PM' and break end time as '12:30 PM' | Break period is added to the form. Break times are displayed correctly and fall within the shift duration. No validation errors appear |
| 4 | Select roles from the available roles dropdown by checking 'Cashier' and 'Sales Associate' | Selected roles are displayed in the roles section. Multiple role selection is allowed and roles are highlighted as selected |
| 5 | Click the 'Save Template' button to submit the form | Form is submitted successfully. A confirmation message 'Shift template created successfully' is displayed. The template is saved to the ShiftTemplates table with all entered details |
| 6 | Verify the API response shows status code 201 and returns the created template with a unique template ID | API POST request to /api/shifttemplates returns status 201 with JSON response containing template ID, name, start time, end time, breaks, and assigned roles |

**Postconditions:**
- New shift template 'Morning Shift' exists in the database
- Template is visible in the template management list view
- Template can be selected for future schedule creation
- User remains on the confirmation page or is redirected to template list

---

### Test Case: Reject shift template creation with invalid time data
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with template creation permissions
- Shift template creation page is accessible
- Form validation rules are active and configured correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page by clicking on 'Shift Templates' menu and selecting 'Create New Template' | Shift template form is displayed with empty fields for template name, start time, end time, breaks, and roles. Form is ready for input |
| 2 | Enter template name as 'Invalid Shift', start time as '04:00 PM', and end time as '08:00 AM' (end time earlier than start time) | Validation error message is displayed near the end time field stating 'End time must be after start time' or similar error message. Error is highlighted in red |
| 3 | Attempt to click the 'Save Template' button to submit the form | Form submission is blocked. The 'Save Template' button either remains disabled or clicking it triggers validation errors. Error message persists indicating 'Please correct the errors before submitting' or similar message |
| 4 | Verify that no API call is made to POST /api/shifttemplates endpoint | No network request is sent to the backend. Browser console or network tab shows no POST request to /api/shifttemplates |
| 5 | Correct the end time to '08:00 PM' (valid time after start time) | Validation error message disappears. End time field shows valid state with no error highlighting. 'Save Template' button becomes enabled |

**Postconditions:**
- No invalid template is created in the database
- User remains on the template creation form with error messages cleared after correction
- Form data is retained for user to correct errors
- System maintains data integrity by preventing invalid entries

---

### Test Case: List existing shift templates
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as a Scheduling Manager
- At least 3 shift templates exist in the database with different names and roles
- Templates include: 'Morning Shift' (Cashier role), 'Evening Shift' (Sales Associate role), 'Night Shift' (Security role)
- Template management page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template management page by clicking on 'Shift Templates' menu and selecting 'Manage Templates' | Template management page loads successfully. A list of all existing shift templates is displayed in a table or card format showing template name, start time, end time, and assigned roles. At least 3 templates are visible |
| 2 | Verify the API GET request to /api/shifttemplates returns all templates with response time under 2 seconds | API responds with status 200 and returns JSON array of all templates. Response time is less than 2 seconds. All template data includes ID, name, times, breaks, and roles |
| 3 | Enter 'Morning' in the search box to search for a template by name | Filtered list updates dynamically showing only templates matching 'Morning' in the name. 'Morning Shift' template is displayed while other templates are hidden from view |
| 4 | Clear the search box and enter 'Cashier' to search by role | Filtered list updates to show only templates assigned to the 'Cashier' role. Templates with Cashier role are displayed. Search works across role assignments |
| 5 | Click on the 'Morning Shift' template from the filtered list | Template details view opens showing complete information: template name 'Morning Shift', start time '08:00 AM', end time '04:00 PM', break period '12:00 PM - 12:30 PM', and assigned roles 'Cashier, Sales Associate'. Details are displayed in a readable format |
| 6 | Verify all template fields are displayed correctly with proper formatting | All fields show accurate data matching the created template. Times are formatted consistently. Roles are listed clearly. No data is missing or corrupted |

**Postconditions:**
- User can view the complete list of shift templates
- Search functionality works for both name and role filters
- Template details are accessible and accurate
- User remains on the template management page ready for further actions

---

## Story: As Scheduling Manager, I want to edit existing shift templates to update shift details
**Story ID:** story-2

### Test Case: Edit shift template with valid updated data
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with template editing permissions
- At least one shift template named 'Morning Shift' exists with start time '08:00 AM', end time '04:00 PM', and break '12:00 PM - 12:30 PM'
- Template management page is accessible
- Database connection is active and ShiftTemplates table is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template management page by clicking on 'Shift Templates' menu and selecting 'Manage Templates' | Template management page loads successfully displaying a list of all existing shift templates in a table or grid format. 'Morning Shift' template is visible in the list |
| 2 | Locate the 'Morning Shift' template in the list and click on the 'Edit' button or icon next to it | Template edit form opens with all current template details pre-populated: name 'Morning Shift', start time '08:00 AM', end time '04:00 PM', break '12:00 PM - 12:30 PM'. All fields are editable |
| 3 | Modify the start time from '08:00 AM' to '07:00 AM' by clicking on the start time field and selecting the new time | Start time field updates to show '07:00 AM'. No validation errors appear. Field accepts the change without issues |
| 4 | Modify the end time from '04:00 PM' to '05:00 PM' by clicking on the end time field and selecting the new time | End time field updates to show '05:00 PM'. No validation errors appear. Time range remains valid with end time after start time |
| 5 | Update the break period from '12:00 PM - 12:30 PM' to '01:00 PM - 01:30 PM' | Break period fields update to show new times '01:00 PM - 01:30 PM'. Break times fall within the new shift duration (07:00 AM - 05:00 PM). No validation errors appear |
| 6 | Click the 'Save Changes' or 'Update Template' button to submit the updated form | Form is submitted successfully. A confirmation message 'Shift template updated successfully' is displayed. The template changes are saved to the database |
| 7 | Verify the API PUT request to /api/shifttemplates/{id} returns status 200 and completes within 2 seconds | API responds with status 200 and returns the updated template JSON with new start time '07:00 AM', end time '05:00 PM', and break '01:00 PM - 01:30 PM'. Response time is under 2 seconds |
| 8 | Navigate back to the template list and verify the 'Morning Shift' template shows updated times | Template list displays 'Morning Shift' with updated start time '07:00 AM' and end time '05:00 PM'. Changes are persisted and visible in the list view |

**Postconditions:**
- Shift template 'Morning Shift' is updated in the database with new times
- Template list reflects the updated information
- No data corruption or loss occurred during the update
- Template remains available for schedule creation with new details
- User is redirected to template list or remains on confirmation page

---

### Test Case: Reject update with invalid break times
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with template editing permissions
- A shift template named 'Evening Shift' exists with start time '02:00 PM', end time '10:00 PM', and one break '05:00 PM - 05:30 PM'
- Template edit form validation rules are active
- Template management page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template management page and locate the 'Evening Shift' template | Template management page displays the list of templates. 'Evening Shift' template is visible with current details |
| 2 | Click the 'Edit' button next to the 'Evening Shift' template | Template edit form opens with pre-populated fields showing 'Evening Shift' details: start time '02:00 PM', end time '10:00 PM', break '05:00 PM - 05:30 PM'. Form is ready for editing |
| 3 | Click 'Add Break' button to add a second break period | A new break period input section appears with empty start and end time fields. Form now shows two break period sections |
| 4 | Enter the second break period as '05:15 PM - 05:45 PM' creating an overlap with the existing break '05:00 PM - 05:30 PM' | Validation error message is displayed indicating 'Break periods cannot overlap' or similar error message. Error is highlighted near the break fields in red or with an error icon |
| 5 | Attempt to click the 'Save Changes' button to save the template with overlapping breaks | Form submission is blocked. The 'Save Changes' button either remains disabled or clicking it triggers validation errors. Error message persists stating 'Please correct the errors before saving' or similar message. Form does not submit |
| 6 | Verify that no API call is made to PUT /api/shifttemplates/{id} endpoint | No network request is sent to the backend. Browser network tab shows no PUT request to /api/shifttemplates. Database remains unchanged |
| 7 | Correct the second break period to '06:00 PM - 06:30 PM' eliminating the overlap | Validation error message disappears. Break fields show valid state with no error highlighting. Both breaks are now non-overlapping: '05:00 PM - 05:30 PM' and '06:00 PM - 06:30 PM'. 'Save Changes' button becomes enabled |

**Postconditions:**
- No invalid template update is saved to the database
- Original template data remains unchanged and intact
- User remains on the edit form with error messages cleared after correction
- Form retains entered data allowing user to correct errors without re-entering all information
- System maintains data integrity by preventing overlapping breaks

---

## Story: As Scheduling Manager, I want to delete shift templates to remove obsolete shifts
**Story ID:** story-3

### Test Case: Delete unused shift template successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager with delete permissions
- At least one shift template exists in the system that is not assigned to any schedules
- User has access to the shift template management interface
- Database contains ShiftTemplates table with test data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list page from the main menu | Shift template list page loads successfully and displays all available templates in a table or grid format |
| 2 | Locate an unused shift template in the list (template with no schedule assignments) | Unused template is visible in the list with template name, details, and action buttons displayed |
| 3 | Click the delete button/icon associated with the unused template | A confirmation dialog appears asking to confirm the deletion action with 'Confirm' and 'Cancel' options |
| 4 | Click the 'Confirm' button in the deletion confirmation dialog | System processes the deletion request within 2 seconds, displays a success message, and the template is removed from the list |
| 5 | Verify the deleted template no longer appears in the template list by scrolling through the list or using search functionality | The deleted template is completely absent from the list and cannot be found using search |
| 6 | Refresh the page to confirm persistence of deletion | Page reloads and the deleted template remains absent from the list, confirming successful deletion from database |

**Postconditions:**
- The unused shift template is permanently deleted from the ShiftTemplates table
- Template list is updated and no longer shows the deleted template
- No orphaned records exist in the database
- System logs record the deletion action with timestamp and user information

---

### Test Case: Prevent deletion of shift template assigned to schedules
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager with delete permissions
- At least one shift template exists that is currently assigned to one or more schedules
- ScheduleAssignments table contains records linking the template to active schedules
- User has access to the shift template management interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list page from the main menu | Shift template list page loads successfully and displays all available templates |
| 2 | Select a shift template that is currently assigned to one or more schedules by clicking on it | Template details are displayed showing template information and available actions including delete option |
| 3 | Click the delete button/icon for the assigned template | System checks for dependencies in ScheduleAssignments table and detects existing assignments |
| 4 | Observe the system response after attempting deletion | System displays a clear error message indicating that the template cannot be deleted because it is currently assigned to schedules, with details about the dependency |
| 5 | Close the error message dialog by clicking 'OK' or 'Close' button | Error dialog closes and user returns to the template list view |
| 6 | Verify the template still appears in the template list | The template remains in the list with all its original details intact and unchanged |
| 7 | Refresh the page to confirm the template was not deleted | Page reloads and the template is still present in the list, confirming deletion was successfully prevented |

**Postconditions:**
- The shift template remains in the ShiftTemplates table unchanged
- All schedule assignments remain intact in ScheduleAssignments table
- Template continues to appear in the template list
- No orphaned schedule records are created
- System logs record the failed deletion attempt with reason

---

