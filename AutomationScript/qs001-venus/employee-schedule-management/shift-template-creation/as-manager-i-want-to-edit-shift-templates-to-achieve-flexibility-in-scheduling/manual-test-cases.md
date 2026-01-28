# Manual Test Cases

## Story: As Manager, I want to edit shift templates to achieve flexibility in scheduling.
**Story ID:** story-2

### Test Case: Validate successful editing of shift template
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role credentials
- At least one shift template exists in the system
- User has permission to edit shift templates
- ShiftTemplates table is accessible in the database
- PUT /api/shift-templates/{id} endpoint is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template section from the main dashboard | Shift template list is displayed showing all existing templates with their details (name, start time, end time, break duration, assigned roles) |
| 2 | Select an existing template from the list by clicking on it | Template details are loaded and the editing interface is displayed with all current template information populated in editable fields |
| 3 | Modify shift start time by changing it to a new valid time | New start time is accepted and displayed in the input field |
| 4 | Modify shift end time by changing it to a new valid time that does not overlap with other shifts | New end time is accepted and displayed in the input field |
| 5 | Update break duration to a new valid duration | New break duration is accepted and displayed in the input field |
| 6 | Change the role assigned to the shift by selecting a different role from the dropdown | New role is selected and displayed in the role field |
| 7 | Click the 'Save' or 'Update' button to save the changes | System validates the changes, sends PUT request to /api/shift-templates/{id}, and displays a success message confirming 'Template updated successfully' |
| 8 | Navigate back to the shift template list | Updated template is displayed in the list with all modified details reflected correctly |

**Postconditions:**
- Shift template is updated in the ShiftTemplates table with new values
- Success message is displayed to the manager
- Updated template appears in the shift template list with modified details
- No overlapping shifts exist in the system
- Audit log records the template modification with timestamp and user details

---

### Test Case: Ensure overlapping shift templates cannot be edited
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Multiple shift templates exist in the system
- At least one shift template exists that could potentially overlap with another if edited
- User has permission to edit shift templates
- Validation rules for overlapping shifts are configured in the system
- PUT /api/shift-templates/{id} endpoint is available with overlap validation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template section from the main dashboard | Shift template list is displayed showing all existing templates with their current time slots and details |
| 2 | Identify a template that can be edited to create an overlap with another existing template | Template is identified and available for selection |
| 3 | Select the identified template by clicking on it | Template details are loaded and the editing interface is displayed with all current template information populated in editable fields |
| 4 | Modify the shift start time to a time that would cause an overlap with another existing shift template | New start time is entered and displayed in the input field |
| 5 | Modify the shift end time to a time that would create an overlapping time range with another existing shift template | New end time is entered and displayed in the input field |
| 6 | Click the 'Save' or 'Update' button to attempt to save the changes | System validates the changes, detects the overlap conflict, and displays an error message such as 'Cannot update template: The specified time range overlaps with an existing shift template' or 'Overlapping shifts are not allowed' |
| 7 | Verify that the template remains in edit mode with the invalid changes still visible | Editing interface remains open with the attempted changes displayed, allowing the manager to correct the values |
| 8 | Navigate back to the shift template list without saving | Original template is displayed in the list with unchanged details, confirming no update was applied |

**Postconditions:**
- Shift template is NOT updated in the ShiftTemplates table
- Error message is displayed to the manager indicating overlap conflict
- Original template data remains unchanged in the database
- No overlapping shifts exist in the system
- Template list shows the original, unmodified template details
- System maintains data integrity by preventing invalid edits

---

