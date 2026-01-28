# Manual Test Cases

## Story: As HR Manager, I want to create shift templates to achieve standardized shift definitions
**Story ID:** db-story-story-1

### Test Case: System allows creation of shift templates with all required fields and saves successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with HR Manager role
- User has access to shift template management page
- ShiftTemplates database table is accessible
- No existing templates with conflicting times exist

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template management page | Shift template management page loads successfully with 'Create New Template' button visible |
| 2 | Click on 'Create New Template' button | New template creation form opens with empty fields for shift start time, end time, break duration, and shift type |
| 3 | Enter shift start time as '09:00 AM' | Start time field accepts the input and displays '09:00 AM' |
| 4 | Enter shift end time as '05:00 PM' | End time field accepts the input and displays '05:00 PM' |
| 5 | Enter break duration as '60' minutes | Break duration field accepts the input and displays '60' |
| 6 | Select shift type as 'Day Shift' from dropdown | Shift type dropdown displays 'Day Shift' as selected value |
| 7 | Click 'Save' button | System validates all inputs, processes the request within 2 seconds, and displays success confirmation message 'Shift template created successfully' |
| 8 | Verify the new template appears in the template list | Newly created template is visible in the shift template list with all entered details displayed correctly |

**Postconditions:**
- New shift template is saved in ShiftTemplates database table
- Audit log entry is created for template creation action
- Template is available for future scheduling operations
- User remains on shift template management page

---

### Test Case: System validates and rejects overlapping shift times with descriptive error messages
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with HR Manager role
- User has access to shift template management page
- An existing shift template exists with time range 09:00 AM to 05:00 PM
- ShiftTemplates database contains at least one active template

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template management page | Shift template management page loads with existing templates displayed |
| 2 | Click on 'Create New Template' button | New template creation form opens with empty input fields |
| 3 | Enter shift start time as '08:00 AM' | Start time field accepts and displays '08:00 AM' |
| 4 | Enter shift end time as '10:00 AM' (overlapping with existing 09:00 AM - 05:00 PM template) | End time field accepts and displays '10:00 AM' |
| 5 | Enter break duration as '30' minutes | Break duration field accepts and displays '30' |
| 6 | Select shift type as 'Morning Shift' | Shift type dropdown displays 'Morning Shift' as selected |
| 7 | Click 'Save' button | System performs validation and displays descriptive error message: 'Cannot create template. Shift times overlap with existing template: Day Shift (09:00 AM - 05:00 PM)' |
| 8 | Verify template is not saved | Template list does not contain the attempted new template, and form remains open with entered data |

**Postconditions:**
- No new template is created in the database
- Existing templates remain unchanged
- User remains on the template creation form to correct the error
- Error message is logged in system logs

---

### Test Case: System supports editing existing templates and maintains version history
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with HR Manager role
- At least one shift template exists in the system (e.g., 'Day Shift' 09:00 AM - 05:00 PM)
- Version history tracking is enabled
- User has edit permissions for shift templates

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template management page | Page loads displaying list of existing shift templates |
| 2 | Locate the 'Day Shift' template and click 'Edit' button | Edit template form opens pre-populated with current values: Start time '09:00 AM', End time '05:00 PM', Break '60 mins', Type 'Day Shift' |
| 3 | Modify the end time from '05:00 PM' to '06:00 PM' | End time field updates to display '06:00 PM' |
| 4 | Modify break duration from '60' to '45' minutes | Break duration field updates to display '45' |
| 5 | Click 'Save' button | System validates changes, processes within 2 seconds, and displays confirmation message 'Shift template updated successfully' |
| 6 | Navigate to version history for the edited template | Version history displays at least 2 versions: Original version (09:00 AM - 05:00 PM, 60 min break) and Current version (09:00 AM - 06:00 PM, 45 min break) with timestamps and editor information |
| 7 | Verify audit trail entry exists | Audit log shows entry with timestamp, HR Manager username, action 'Template Updated', and details of changes made |

**Postconditions:**
- Template is updated in ShiftTemplates database with new values
- Previous version is preserved in version history
- Audit trail contains complete record of the modification
- Updated template is immediately available for scheduling
- Version counter is incremented

---

### Test Case: System prevents deletion of templates assigned to active schedules and shows warning
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with HR Manager role
- A shift template named 'Evening Shift' exists in the system
- The 'Evening Shift' template is assigned to at least one active employee schedule
- User has delete permissions for shift templates

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template management page | Page loads displaying all shift templates including 'Evening Shift' |
| 2 | Locate the 'Evening Shift' template that is assigned to active schedules | 'Evening Shift' template is visible with a delete button or option available |
| 3 | Click the 'Delete' button for the 'Evening Shift' template | System displays warning message: 'Cannot delete template. This template is currently assigned to active schedules. Please reassign or remove schedules before deletion.' |
| 4 | Verify the warning dialog includes details about active assignments | Warning message shows number of active schedules using this template (e.g., 'Used in 5 active schedules') |
| 5 | Click 'OK' or 'Close' on the warning dialog | Warning dialog closes and user returns to template management page |
| 6 | Verify the template still exists in the list | 'Evening Shift' template remains in the template list unchanged |

**Postconditions:**
- Template is not deleted from the database
- All active schedules using the template remain intact
- Warning action is logged in audit trail
- User remains on shift template management page
- Template status remains unchanged

---

### Test Case: System displays confirmation messages upon successful operations
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with HR Manager role
- User has access to shift template management page
- At least one shift template exists for testing edit and delete operations
- System notification/messaging component is functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template management page and click 'Create New Template' | Template creation form opens successfully |
| 2 | Fill in all required fields: Start time '06:00 AM', End time '02:00 PM', Break '30 mins', Type 'Morning Shift' | All fields accept input and display entered values |
| 3 | Click 'Save' button | System displays success confirmation message 'Shift template created successfully' in a visible notification banner or dialog |
| 4 | Verify the confirmation message is clearly visible and styled appropriately (e.g., green color, success icon) | Confirmation message appears with success styling, is easily readable, and auto-dismisses after 3-5 seconds or has a close button |
| 5 | Select an existing template and click 'Edit', modify the break duration, and save | System displays confirmation message 'Shift template updated successfully' with appropriate success styling |
| 6 | Select a template that is not assigned to any schedules and click 'Delete' | System displays confirmation message 'Shift template deleted successfully' with appropriate success styling |
| 7 | Attempt an invalid operation (e.g., create template with end time before start time) | System displays error message with appropriate error styling (e.g., red color, error icon) describing the validation failure |

**Postconditions:**
- All successful operations show appropriate confirmation messages
- Error operations show descriptive error messages
- Messages are logged appropriately
- User has clear feedback for every action performed
- UI returns to stable state after message dismissal

---

