# Manual Test Cases

## Story: As Scheduling Manager, I want to create shift templates to achieve standardized shift definitions
**Story ID:** story-1

### Test Case: Validate successful creation of shift template with valid times
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with appropriate permissions
- Shift template management page is accessible
- Database is available and responsive
- No existing shift templates with conflicting times exist

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page by clicking 'Create New Template' button | Shift template form is displayed with empty fields for start time, end time, and break duration. All form controls are enabled and ready for input |
| 2 | Enter valid start time (e.g., 09:00 AM), valid end time (e.g., 05:00 PM), and break duration (e.g., 60 minutes) in respective fields | All entered values are accepted without validation errors. Fields display the entered data correctly. No error messages are shown on the form |
| 3 | Click the 'Submit' or 'Save' button to create the shift template | Shift template is successfully created and saved to the database. A confirmation message is displayed indicating successful creation. The user is redirected to the shift template list page showing the newly created template with all entered details |

**Postconditions:**
- New shift template exists in the ShiftTemplates table
- Shift template appears in the searchable list of templates
- System response time was under 2 seconds
- User remains on shift template management interface

---

### Test Case: Reject creation of shift template with overlapping times
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with appropriate permissions
- At least one existing shift template exists in the system (e.g., 09:00 AM - 05:00 PM)
- Shift template creation page is accessible
- Database contains existing shift template data for overlap validation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page by clicking 'Create New Template' button | Shift template form is displayed with empty fields for start time, end time, and break duration. Form is ready for data entry |
| 2 | Enter start time and end time that overlap with an existing template (e.g., start time 08:00 AM, end time 10:00 AM when existing template is 09:00 AM - 05:00 PM) | System detects the overlap and displays a clear validation error message indicating that the entered times conflict with an existing shift template. Error message specifies which template is causing the conflict |
| 3 | Attempt to submit the form by clicking the 'Submit' or 'Save' button without correcting the overlapping times | Form submission is blocked and prevented. Error message remains visible highlighting the overlapping time conflict. No new shift template is created. User remains on the creation form to correct the input |

**Postconditions:**
- No new shift template is created in the database
- Existing shift templates remain unchanged
- User remains on the shift template creation page with error messages visible
- Form retains the invalid data entered for correction

---

### Test Case: Edit existing shift template successfully
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with appropriate permissions
- At least one shift template exists in the system that can be edited
- Shift template list page is accessible
- Database is available and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list page from the main menu or dashboard | List of all existing shift templates is displayed with columns showing template name, start time, end time, break duration, and action buttons. Templates are clearly visible and selectable |
| 2 | Select a specific shift template from the list by clicking the 'Edit' button or icon associated with that template | Edit form is displayed and populated with the current values of the selected template including start time, end time, and break duration. All fields are editable and form controls are enabled |
| 3 | Modify the start time, end time, or break duration with valid non-overlapping values and click the 'Submit' or 'Update' button | Template is successfully updated in the database. A confirmation message is displayed indicating successful update. The user is redirected to the shift template list page showing the updated template with the new values reflected accurately |

**Postconditions:**
- Shift template is updated in the ShiftTemplates table with new values
- Updated template appears in the list with modified details
- System response time was under 2 seconds
- Original template data is replaced with new data
- User is returned to the shift template list view

---

## Story: As Scheduling Manager, I want to edit shift templates to maintain accurate shift definitions
**Story ID:** story-2

### Test Case: Edit shift template with valid data successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with edit permissions
- At least one shift template exists in the system available for editing
- Shift template list page is accessible
- Audit logging functionality is enabled and operational
- Database is available and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list page from the navigation menu | Complete list of shift templates is displayed with all template details including start time, end time, break duration, and edit options. List is properly formatted and all templates are visible |
| 2 | Locate a specific shift template in the list and click the 'Edit' button or action to open the edit form. Modify the start time and/or end time fields with valid values that do not overlap with other templates | Edit form is displayed and pre-populated with the current template values. Modified values are accepted without validation errors. Form shows the updated data correctly in the input fields |
| 3 | Click the 'Submit' or 'Save Changes' button to save the modifications | Template update is successfully saved to the database. A confirmation message is displayed confirming the successful update. An audit log entry is automatically created recording the modification with timestamp, user, and changed values. The updated template appears in the list with new values |

**Postconditions:**
- Shift template is updated in the ShiftTemplates table with modified values
- Audit log entry exists in the audit table documenting the change
- Updated template is visible in the shift template list with correct data
- System response time was under 2 seconds
- User is returned to the shift template list view with confirmation message

---

### Test Case: Prevent editing shift template with overlapping times
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with edit permissions
- Multiple shift templates exist in the system
- At least two templates exist where one could potentially overlap with another if edited
- Shift template list and edit functionality are accessible
- Validation rules for overlap detection are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list and select a specific template to edit by clicking the 'Edit' button | Edit form is displayed with current template values pre-populated in all fields. Form is ready for modification with all controls enabled |
| 2 | Modify the start time and/or end time fields to values that would overlap with another existing shift template in the system | System detects the time overlap conflict and displays a clear validation error message. Error message indicates which existing template would be affected by the overlap and provides specific details about the conflicting times |
| 3 | Attempt to save the changes by clicking the 'Submit' or 'Save Changes' button without correcting the overlapping times | Save operation is blocked and prevented from executing. The validation error message remains prominently displayed. No changes are committed to the database. User remains on the edit form with the invalid data visible for correction. Original template values remain unchanged in the system |

**Postconditions:**
- No changes are saved to the ShiftTemplates table
- Original shift template data remains unchanged
- No audit log entry is created for the failed update attempt
- User remains on the edit form with error messages displayed
- All existing shift templates maintain their original values without conflicts

---

## Story: As Scheduling Manager, I want to delete shift templates to remove obsolete shift definitions
**Story ID:** story-3

### Test Case: Delete unassigned shift template successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as Scheduling Manager with delete permissions
- At least one shift template exists in the system that is not assigned to any schedule
- User has access to the shift template management page
- ShiftTemplates table is accessible and contains test data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list page | Shift template list page is displayed with all available templates shown in a table or grid format |
| 2 | Identify and select an unassigned shift template from the list | The selected template is highlighted or marked as selected |
| 3 | Click the delete button or icon for the selected template | A confirmation dialog appears asking 'Are you sure you want to delete this shift template?' with Cancel and Confirm buttons |
| 4 | Click the Confirm button in the confirmation dialog | The confirmation dialog closes, a success message is displayed (e.g., 'Shift template deleted successfully'), and the template is removed from the list within 2 seconds |
| 5 | Verify the template list has been updated | The deleted template no longer appears in the shift template list and the total count is reduced by one |

**Postconditions:**
- The shift template is permanently removed from the ShiftTemplates table
- The template list displays updated data without the deleted template
- No orphaned data remains in the database
- User remains on the shift template list page

---

### Test Case: Prevent deletion of assigned shift template
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as Scheduling Manager with delete permissions
- At least one shift template exists that is currently assigned to one or more schedules
- User has access to the shift template management page
- Foreign key relationships are properly configured in the database

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list page | Shift template list page is displayed with all available templates |
| 2 | Identify and select a shift template that is currently assigned to active schedules | The template is selected and either the delete button is disabled/grayed out or a warning indicator is shown next to the template |
| 3 | Attempt to click the delete button for the assigned template | An informative error message is displayed stating 'This shift template cannot be deleted because it is currently assigned to one or more schedules. Please remove all assignments before deleting.' or the delete action is prevented entirely |
| 4 | Verify the template still exists in the list | The shift template remains in the list unchanged and no deletion has occurred |
| 5 | Close the error message or dialog | The error message closes and the user returns to the shift template list with no changes made |

**Postconditions:**
- The assigned shift template remains in the ShiftTemplates table
- No data integrity issues occur
- All schedule assignments remain intact
- User remains on the shift template list page with the template still visible

---

