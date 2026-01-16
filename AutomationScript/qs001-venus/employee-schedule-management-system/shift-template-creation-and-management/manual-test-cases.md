# Manual Test Cases

## Story: As HR Manager, I want to create shift templates to achieve standardized shift definitions
**Story ID:** story-1

### Test Case: Validate successful creation of a shift template with valid times
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager
- User has appropriate role-based permissions to create shift templates
- Shift template management page is accessible
- Database connection is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page | Shift template form is displayed with fields for shift name, start time, end time, and break periods |
| 2 | Enter valid start time (e.g., 09:00 AM), end time (e.g., 05:00 PM), and break periods (e.g., 12:00 PM - 01:00 PM) | Form accepts inputs without validation errors, all fields display entered values correctly |
| 3 | Submit the form by clicking the 'Save' or 'Create' button | Shift template is created successfully, confirmation message is displayed, and the new template appears in the shift templates list |

**Postconditions:**
- New shift template is saved in ShiftTemplates table
- Shift template appears in the searchable list
- User remains on shift template management page or is redirected to the list view

---

### Test Case: Prevent creation of overlapping shift templates
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager
- At least one shift template already exists (e.g., 09:00 AM - 05:00 PM)
- User has appropriate role-based permissions to create shift templates
- Shift template creation page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to create a shift template with times overlapping an existing template (e.g., start time 08:00 AM, end time 10:00 AM when 09:00 AM - 05:00 PM exists) | System displays error message indicating overlap with existing template and prevents creation |
| 2 | Adjust times to non-overlapping values (e.g., start time 06:00 AM, end time 08:00 AM) | Form accepts inputs without errors, validation error message is cleared |
| 3 | Submit the form by clicking the 'Save' or 'Create' button | Shift template is created successfully and confirmation message is displayed |

**Postconditions:**
- Non-overlapping shift template is saved in ShiftTemplates table
- Original overlapping template remains unchanged
- New template appears in the shift templates list

---

### Test Case: Edit and delete existing shift templates
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager
- At least one shift template exists in the system
- User has appropriate role-based permissions to edit and delete shift templates
- Shift template list page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select an existing shift template from the list by clicking on it or clicking an 'Edit' button | Template details are displayed in an editable form showing current start time, end time, and break periods |
| 2 | Modify template details (e.g., change end time from 05:00 PM to 06:00 PM) and click 'Save' button | Changes are saved successfully, confirmation message is displayed, and updated template appears in the list with modified values |
| 3 | Click 'Delete' button for the shift template | System displays a confirmation prompt asking to confirm deletion |
| 4 | Confirm deletion by clicking 'Yes' or 'Confirm' in the confirmation dialog | Template is deleted from the system, confirmation message is displayed, and template is removed from the list |

**Postconditions:**
- Edited template changes are persisted in ShiftTemplates table
- Deleted template is removed from ShiftTemplates table
- Shift template list reflects the deletion
- User remains on shift template management page

---

## Story: As Scheduler, I want to search and filter shift templates to achieve efficient template management
**Story ID:** story-5

### Test Case: Search shift templates by name
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as Scheduler
- User has appropriate role-based permissions to view shift templates
- Multiple shift templates exist in the system with different names
- Shift template list page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list page | List of all shift templates is displayed with columns showing template name, start time, end time, and other attributes |
| 2 | Enter a keyword in the search box (e.g., 'Morning' to find morning shift templates) | List updates dynamically to show only templates matching the search keyword, non-matching templates are filtered out |
| 3 | Clear search box by deleting the text or clicking a 'Clear' button | Full list of all shift templates is restored and displayed |

**Postconditions:**
- Search functionality returns to default state
- All shift templates are visible in the list
- No filters are applied

---

### Test Case: Filter shift templates by start time
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Scheduler
- User has appropriate role-based permissions to view shift templates
- Multiple shift templates exist with varying start times
- Shift template list page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select a start time filter criterion (e.g., start time = 09:00 AM) from the filter dropdown or input field | List updates to show only templates with the specified start time, other templates are filtered out |
| 2 | Combine with search keywords by entering text in the search box (e.g., 'Shift A') while filter is active | List shows only templates matching both the start time filter and the search keyword criteria |
| 3 | Remove filters by clearing the filter selection and search box | Full list of all shift templates is displayed again without any filtering applied |

**Postconditions:**
- All filters are cleared
- Complete list of shift templates is visible
- System is ready for new search or filter operations

---

### Test Case: Sort shift templates by duration
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 2 mins

**Preconditions:**
- User is logged in as Scheduler
- User has appropriate role-based permissions to view shift templates
- Multiple shift templates exist with different durations
- Shift template list page is accessible with sortable columns

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Click on the duration column header in the shift templates list | Templates are sorted in ascending order by duration (shortest to longest), with a visual indicator (arrow) showing ascending sort |
| 2 | Click again on the duration column header | Templates are sorted in descending order by duration (longest to shortest), with visual indicator changing to show descending sort |

**Postconditions:**
- Shift templates remain sorted by duration in descending order
- Sort state is maintained until user changes it
- All templates remain visible in the sorted list

---

## Story: As HR Manager, I want to validate shift template data to achieve data integrity
**Story ID:** story-7

### Test Case: Validate time format and logical order
- **ID:** tc-001
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permission to create shift templates
- Shift template creation form is accessible
- System validation rules are active on frontend and backend

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page | Shift template creation form is displayed with all required fields (shift name, start time, end time, break times) |
| 2 | Enter invalid time format in start time field (e.g., '25:00', 'abc', '13:75') | Inline error message is displayed immediately below the start time field indicating 'Invalid time format. Please use HH:mm format (00:00 - 23:59)' |
| 3 | Clear the start time field and enter a valid start time (e.g., '09:00') | Error message disappears and field is marked as valid |
| 4 | Enter end time earlier than start time (e.g., start time: '09:00', end time: '08:00') | Validation error message is displayed stating 'End time must be after start time' |
| 5 | Attempt to submit the form with the invalid end time | Form submission is prevented, error message remains visible, and focus returns to the end time field |
| 6 | Correct the end time to a valid time after start time (e.g., '17:00') | Validation error disappears and field is marked as valid |
| 7 | Complete all remaining required fields with valid data and submit the form | No validation errors are displayed, form is successfully submitted, and confirmation message appears indicating shift template was created |

**Postconditions:**
- Valid shift template is saved in the system
- Shift template appears in the list of available templates
- No invalid data is persisted in the database
- User remains on shift template management page or is redirected to template list

---

### Test Case: Prevent overlapping shift templates
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permission to create shift templates
- At least one existing shift template is already created (e.g., 'Morning Shift' from 08:00 to 16:00)
- Shift template creation form is accessible
- Overlap validation is enabled on both frontend and backend

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page | Shift template creation form is displayed with all required fields |
| 2 | Enter shift template name (e.g., 'Mid-Day Shift') | Shift name is accepted and field shows valid state |
| 3 | Attempt to create a shift template with times that overlap an existing template (e.g., start time: '10:00', end time: '18:00' when existing shift is 08:00-16:00) | Validation error message is displayed stating 'Shift template overlaps with existing template: Morning Shift (08:00 - 16:00). Please adjust the times.' |
| 4 | Attempt to submit the form with overlapping times | Form submission is blocked, error message remains visible, and no data is sent to the backend |
| 5 | Adjust the start time to a non-overlapping value (e.g., start time: '16:00', end time: '23:00') | Validation error disappears and fields are marked as valid |
| 6 | Complete all remaining required fields and submit the form | Form is successfully submitted without errors, confirmation message is displayed, and new shift template is created |
| 7 | Verify the newly created shift template appears in the shift template list | New shift template 'Mid-Day Shift' (16:00 - 23:00) is visible in the list alongside existing templates without any overlap conflicts |

**Postconditions:**
- Non-overlapping shift template is successfully saved in the system
- No overlapping shift templates exist in the database
- Both shift templates are available for schedule assignment
- System maintains data integrity with no conflicting time ranges

---

