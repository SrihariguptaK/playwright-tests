# Manual Test Cases

## Story: As HR Manager, I want to create shift templates to achieve standardized shift definitions
**Story ID:** story-1

### Test Case: Validate successful creation of shift template with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has role-based access to shift template management
- Shift template management page is accessible
- No existing shift templates with conflicting time ranges exist

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page by clicking on 'Shift Templates' menu and selecting 'Create New Template' | Shift template form is displayed with fields for template name, start time, end time, and break details. All fields are empty and enabled for input |
| 2 | Enter valid shift template name (e.g., 'Morning Shift'), start time (e.g., '08:00 AM'), end time (e.g., '04:00 PM'), and break details (e.g., '30 minutes at 12:00 PM') | All input fields accept the data without any validation errors. Data is displayed correctly in the respective fields with proper formatting |
| 3 | Click the 'Save' or 'Submit' button to create the shift template | System validates the input, processes the request, displays a success confirmation message (e.g., 'Shift template created successfully'), and redirects to the shift template list page showing the newly created template |

**Postconditions:**
- New shift template is saved in the ShiftTemplates table
- Shift template appears in the template list with all entered details
- Template is available for future use and editing
- System response time is under 2 seconds

---

### Test Case: Verify rejection of overlapping shift template creation
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- At least one shift template already exists in the system (e.g., 'Morning Shift' from 08:00 AM to 04:00 PM)
- User has access to shift template creation page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page by clicking on 'Shift Templates' menu and selecting 'Create New Template' | Shift template form is displayed with all input fields empty and ready for data entry |
| 2 | Enter shift template name (e.g., 'Overlapping Shift'), start time that overlaps with existing template (e.g., '10:00 AM'), and end time (e.g., '06:00 PM') that creates an overlap with the existing 08:00 AM - 04:00 PM template | System detects the overlap and displays a validation error message (e.g., 'This shift template overlaps with existing template: Morning Shift'). Error message is clearly visible near the conflicting fields or at the top of the form |
| 3 | Attempt to submit the form by clicking the 'Save' or 'Submit' button | Form submission is blocked. System displays an error notification preventing the creation (e.g., 'Cannot create overlapping shift templates. Please adjust the time range'). The form remains on the screen with entered data intact |

**Postconditions:**
- No new shift template is created in the database
- Existing shift templates remain unchanged
- User remains on the creation form to correct the input
- Error message is clearly communicated to the user

---

### Test Case: Validate editing and deletion of existing shift templates
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- At least two shift templates exist in the system for testing edit and delete operations
- Templates are not currently assigned to any employee schedules
- User has access to shift template management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list page by clicking on 'Shift Templates' menu | Complete list of existing shift templates is displayed in a table or grid format showing template names, start times, end times, break details, and action buttons (Edit, Delete) |
| 2 | Select a template from the list (e.g., 'Morning Shift') and click the 'Edit' button or icon | Edit form is displayed with all current template data pre-populated in the respective fields (template name, start time, end time, break details). All fields are editable |
| 3 | Modify one or more fields (e.g., change end time from '04:00 PM' to '05:00 PM') and click 'Save' or 'Update' button | System validates the changes, updates the template in the database, displays a success confirmation message (e.g., 'Shift template updated successfully'), and redirects to the template list showing the updated information |
| 4 | Select a different template from the list and click the 'Delete' button or icon | System displays a confirmation prompt dialog with message (e.g., 'Are you sure you want to delete this shift template? This action cannot be undone') with 'Confirm' and 'Cancel' options |
| 5 | Click 'Confirm' button in the confirmation dialog | Template is removed from the database, confirmation message is displayed (e.g., 'Shift template deleted successfully'), and the template list is automatically refreshed showing the updated list without the deleted template |

**Postconditions:**
- Edited template is updated in the ShiftTemplates table with new values
- Deleted template is removed from the ShiftTemplates table
- Template list reflects all changes immediately
- No orphaned data remains in the system
- All operations complete within 2 seconds

---

## Story: As HR Manager, I want to delete obsolete shift templates to maintain template accuracy
**Story ID:** story-5

### Test Case: Validate successful deletion of unassigned shift template
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- At least one shift template exists that is not assigned to any employee schedule
- User has role-based access to delete shift templates
- Shift template list page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list page by clicking on 'Shift Templates' menu option | Template list is displayed showing all existing shift templates with columns for template name, start time, end time, assignment status, and action buttons. Unassigned templates are clearly identifiable |
| 2 | Identify an unassigned template (e.g., 'Obsolete Evening Shift') and click the 'Delete' button or icon associated with that template | System displays a confirmation dialog with message (e.g., 'Are you sure you want to delete the shift template: Obsolete Evening Shift? This action cannot be undone') with 'Confirm' and 'Cancel' buttons |
| 3 | Click the 'Confirm' button in the confirmation dialog | System processes the deletion request, removes the template from the ShiftTemplates table, displays a success message (e.g., 'Shift template deleted successfully'), and automatically refreshes the template list showing the updated list without the deleted template |

**Postconditions:**
- Selected shift template is permanently removed from the database
- Template list is updated and no longer shows the deleted template
- No references to the deleted template remain in the system
- Deletion operation completes in under 2 seconds
- Success confirmation is displayed to the user

---

### Test Case: Verify prevention of deletion for assigned shift template
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- At least one shift template exists that is currently assigned to one or more employee schedules
- User has access to shift template management page
- System has validation logic to check template assignments before deletion

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list and identify a template that is assigned to schedules (e.g., 'Day Shift' assigned to 5 employees) | Template list displays the assigned template with an indicator showing it is in use. Delete option/button is visible and available for selection |
| 2 | Click the 'Delete' button or icon for the assigned template | System checks the template assignment status in the EmployeeSchedules table and displays an error message (e.g., 'Cannot delete this shift template. It is currently assigned to 5 employee schedules. Please reassign or remove schedules before deleting') preventing the deletion. No confirmation dialog appears |
| 3 | Click 'OK' or 'Close' button on the error message dialog to dismiss it | Error dialog closes and user returns to the template list. The assigned template remains in the list unchanged with all its data intact |

**Postconditions:**
- Assigned shift template remains in the ShiftTemplates table
- All employee schedule assignments remain intact
- Template list shows the template with its assignment status unchanged
- User is informed why deletion was prevented
- No data integrity issues occur

---

## Story: As HR Manager, I want to search and filter shift templates to quickly find relevant templates
**Story ID:** story-8

### Test Case: Validate search by shift template name
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager
- User has role-based access to shift template management
- Multiple shift templates exist in the system with varying names
- Shift template list page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list page by clicking on 'Shift Templates' menu option | Template list page is displayed showing all available shift templates with search bar visible at the top |
| 2 | Enter a search keyword in the search field that matches an existing template name (e.g., 'Morning') | Filtered list is displayed showing only templates with names containing 'Morning', search results appear within 2 seconds |
| 3 | Verify the filtered results display only matching templates | All displayed templates contain the search keyword in their name or description, non-matching templates are hidden |
| 4 | Clear the search field by clicking the clear button or deleting the text | Search field is empty and the full list of all templates is restored and displayed |
| 5 | Verify all templates are visible after clearing search | Complete list of shift templates is displayed without any filters applied |

**Postconditions:**
- Search field is cleared
- Full template list is displayed
- No filters are active
- System is ready for next operation

---

### Test Case: Verify filtering by shift type
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as HR Manager
- User has role-based access to shift template management
- Multiple shift templates exist with different shift types (e.g., Day, Night, Evening)
- Shift template list page is accessible
- Filter controls are visible on the page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list page | Template list page is displayed with all templates and filter dropdown visible |
| 2 | Click on the shift type filter dropdown and select a specific shift type (e.g., 'Day Shift') | List updates within 2 seconds to show only templates with the selected 'Day Shift' type, other shift types are filtered out |
| 3 | Verify filtered results show only the selected shift type | All displayed templates are of 'Day Shift' type, count of results is updated accordingly |
| 4 | Enter a search keyword in the search field while the shift type filter is active | List shows only templates that match both the selected shift type AND the search keyword, results display within 2 seconds |
| 5 | Verify combined filter results are accurate | Displayed templates meet both criteria: correct shift type and contain search keyword |
| 6 | Clear the search field and remove the shift type filter by selecting 'All Types' or clicking clear filters button | All filters are removed and the complete list of all templates is displayed |
| 7 | Verify full list is restored | All shift templates are visible regardless of type or name |

**Postconditions:**
- All filters are cleared
- Search field is empty
- Full template list is displayed
- Filter controls are reset to default state

---

### Test Case: Validate sorting and pagination of templates
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as HR Manager
- User has role-based access to shift template management
- More than 10 shift templates exist in the system to enable pagination
- Templates have different creation dates and names
- Shift template list page is accessible
- Pagination is configured to display a specific number of items per page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list page | Template list page is displayed with default sorting, pagination controls visible at the bottom |
| 2 | Click on the 'Creation Date' column header or select 'Sort by Creation Date - Ascending' from sort dropdown | Templates are reordered with oldest templates first, sorting completes within 2 seconds, sort indicator shows ascending order |
| 3 | Verify the templates are sorted correctly by creation date in ascending order | Templates are displayed in chronological order from oldest to newest based on creation date |
| 4 | Click the 'Next' button or page number '2' in the pagination controls | Next set of templates is displayed (e.g., items 11-20), page indicator updates to show page 2, navigation completes within 2 seconds |
| 5 | Verify pagination navigation is successful | Different set of templates is displayed, page number indicator shows current page as 2, previous page button becomes enabled |
| 6 | Click on the 'Name' column header or select 'Sort by Name - Descending' from sort dropdown | Templates on current page reorder alphabetically in descending order (Z to A), sorting completes within 2 seconds, sort indicator shows descending order |
| 7 | Verify templates are sorted by name in descending order | Templates are displayed in reverse alphabetical order by name, sorting is maintained across the current page |
| 8 | Navigate back to page 1 using pagination controls | First page of templates is displayed with the descending name sort order maintained |

**Postconditions:**
- Templates remain sorted by the last selected sort option
- Pagination controls are functional
- User can continue navigating and sorting as needed
- System maintains sort preference during session

---

