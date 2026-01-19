# Manual Test Cases

## Story: As HR Manager, I want to create shift templates to achieve standardized shift definitions
**Story ID:** story-1

### Test Case: Validate successful shift template creation with valid input
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has authorization to create shift templates
- Shift template management system is accessible
- Database connection is active and ShiftTemplates table is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page by clicking on 'Shift Templates' menu and selecting 'Create New Template' | Shift template form is displayed with fields for start time, end time, break periods, shift type, and category. All fields are empty and ready for input |
| 2 | Enter valid start time (e.g., 09:00 AM) in the start time field | Start time field accepts the input and displays the entered time in correct format without validation errors |
| 3 | Enter valid end time (e.g., 05:00 PM) in the end time field | End time field accepts the input and displays the entered time in correct format without validation errors |
| 4 | Enter break period details (e.g., 12:00 PM - 01:00 PM, 60 minutes lunch break) | Break period fields accept the input and display the break time within the shift duration without validation errors |
| 5 | Select shift type from dropdown (e.g., 'Morning Shift') | Shift type dropdown displays available options and selected value is highlighted |
| 6 | Select or enter shift category (e.g., 'Standard Office Hours') | Category field accepts the input and displays the entered category |
| 7 | Click 'Save' or 'Submit' button to create the shift template | System processes the request, creates the shift template in ShiftTemplates table, and displays a success confirmation message (e.g., 'Shift template created successfully'). Template appears in the template list with version 1.0 |

**Postconditions:**
- New shift template is saved in the database with unique ID
- Template is assigned version 1.0
- Template appears in the shift template list
- Template is available for use in schedule creation
- Success message is displayed to the user
- User remains on template management page or is redirected to template list

---

### Test Case: Reject shift template creation with invalid time ranges
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has authorization to create shift templates
- Shift template management system is accessible
- Validation rules are configured to check time range validity

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page by clicking on 'Shift Templates' menu and selecting 'Create New Template' | Shift template form is displayed with all required fields empty and ready for input |
| 2 | Enter start time as 05:00 PM in the start time field | Start time field accepts and displays 05:00 PM |
| 3 | Enter end time as 09:00 AM (earlier than start time) in the end time field | System detects invalid time range and displays validation error message (e.g., 'End time must be after start time' or 'Invalid time range detected'). Error message appears near the end time field or at the top of the form |
| 4 | Attempt to click 'Save' or 'Submit' button without correcting the error | Form submission is blocked. Save button may be disabled or clicking it triggers validation error display again. System does not create the template and error message remains visible |
| 5 | Correct the end time to a valid time after start time (e.g., 11:00 PM) | Validation error message disappears and Save button becomes enabled or clickable |

**Postconditions:**
- No shift template is created in the database with invalid time ranges
- User remains on the template creation form
- Error messages are cleared once valid data is entered
- Form data is retained for correction

---

### Test Case: Ensure unauthorized users cannot create shift templates
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Test user account exists with non-HR role (e.g., Employee, Manager, or other role without HR privileges)
- Role-based access control is configured and active
- Shift template creation is restricted to HR Manager role only
- Application security settings are properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the application using non-HR user credentials (e.g., username: 'employee01', role: 'Employee') | User successfully logs in and is redirected to their role-appropriate dashboard without HR management options |
| 2 | Attempt to navigate to shift template creation page by entering the URL directly or searching for the menu option | Access to shift template creation page is denied. System displays 'Access Denied', '403 Forbidden', or 'You do not have permission to access this page' message. User is redirected to unauthorized access page or remains on current page |
| 3 | Using API testing tool (e.g., Postman, cURL), attempt to send POST request to /api/shifttemplates endpoint with valid shift template data and non-HR user authentication token | API returns authorization error with HTTP status code 403 (Forbidden) or 401 (Unauthorized). Response body contains error message such as 'Insufficient permissions' or 'Access denied for this resource'. No shift template is created in the database |
| 4 | Verify in the database that no new shift template record was created from the unauthorized attempt | Database query confirms no new records were added to ShiftTemplates table from the unauthorized user's attempts |

**Postconditions:**
- No shift template is created by unauthorized user
- Security logs record the unauthorized access attempt
- User remains restricted from accessing shift template creation functionality
- System security integrity is maintained

---

## Story: As HR Manager, I want to edit existing shift templates to maintain accurate shift definitions
**Story ID:** story-2

### Test Case: Validate successful shift template edit with versioning
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has authorization to edit shift templates
- At least one existing shift template is available in the system (e.g., Template ID: 101, Version: 1.0)
- Selected template is not assigned to any active schedules
- Database versioning mechanism is functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list page by clicking on 'Shift Templates' menu and selecting 'View Templates' | List of existing shift templates is displayed in a table or grid format showing template names, shift times, types, and current versions. Templates are sortable and searchable |
| 2 | Locate and select a specific shift template (e.g., 'Morning Shift - Standard') by clicking on it or clicking an 'Edit' button/icon | Template edit form opens displaying current template details including start time, end time, break periods, shift type, and category. All fields are populated with existing values and are editable |
| 3 | Modify the start time from current value (e.g., 09:00 AM) to new value (e.g., 08:30 AM) | Start time field accepts the change and displays the new time (08:30 AM) without validation errors |
| 4 | Modify the end time from current value (e.g., 05:00 PM) to new value (e.g., 05:30 PM) | End time field accepts the change and displays the new time (05:30 PM) without validation errors |
| 5 | Click 'Save Changes' or 'Update' button to save the modifications | System processes the update request, creates a new version of the template (e.g., Version 2.0), saves it to the database, and displays success confirmation message (e.g., 'Shift template updated successfully. New version 2.0 created') |
| 6 | Click on 'View Version History' or 'History' link/button for the updated template | Version history panel or page displays showing all versions of the template including Version 1.0 (original) and Version 2.0 (current) with timestamps, modified by user, and changes made |

**Postconditions:**
- New version of shift template is saved in the database (Version 2.0)
- Previous version (Version 1.0) is retained in version history
- Updated template reflects new start and end times
- Version history is accessible and displays all versions
- Template list shows the updated version as current
- Audit trail records the modification with timestamp and user details

---

### Test Case: Prevent editing of templates assigned to active schedules
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- At least one shift template exists that is currently assigned to active schedules
- Active schedules are defined as schedules with status 'Active' or 'In Progress' or with dates including current date or future dates
- System has logic to check template usage before allowing edits

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list page | List of shift templates is displayed with indicators showing which templates are in use by active schedules (e.g., badge, icon, or status column) |
| 2 | Select a shift template that is assigned to one or more active schedules by clicking on it or clicking 'Edit' button | System detects that the template is in active use and displays a warning message (e.g., 'This template is currently assigned to active schedules and cannot be edited' or 'Template in use - editing disabled'). Edit form either does not open, opens in read-only mode, or displays with all input fields disabled/grayed out |
| 3 | Verify that input fields are disabled and cannot be modified | All input fields (start time, end time, break periods, shift type, category) are disabled or read-only. Clicking on fields does not allow data entry |
| 4 | Verify that 'Save' or 'Update' button is either hidden, disabled, or non-functional | Save button is either not visible, grayed out/disabled, or if clicked, displays error message preventing the save operation |
| 5 | Check if system provides information about which schedules are using this template | System displays list or count of active schedules using this template, helping HR Manager understand the dependency |

**Postconditions:**
- Template assigned to active schedules remains unchanged
- No new version is created
- Warning message is displayed to user
- User is prevented from making changes to the template
- Active schedules continue to use the original template without disruption

---

### Test Case: Reject edits with invalid shift parameters
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- At least one existing shift template is available for editing
- Selected template is not assigned to active schedules
- Validation rules are configured to check time range validity and data integrity

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list and select a template to edit | Template edit form opens with current template details populated in all fields |
| 2 | Modify the start time to 06:00 PM | Start time field accepts and displays 06:00 PM |
| 3 | Modify the end time to 02:00 PM (earlier than the new start time, creating invalid time range) | System detects invalid time range and displays validation error message (e.g., 'End time must be after start time' or 'Invalid shift duration'). Error message appears inline near the field or at the top of the form with red highlighting on the invalid field |
| 4 | Attempt to click 'Save Changes' or 'Update' button without correcting the validation error | Save operation is blocked. System prevents form submission and keeps the validation error message visible. No new version is created. User may see additional message like 'Please correct errors before saving' or the Save button remains disabled |
| 5 | Correct the end time to a valid time after start time (e.g., 10:00 PM) | Validation error message disappears, error highlighting is removed, and Save button becomes enabled or clickable |
| 6 | Test another invalid scenario: Enter break period outside shift duration (e.g., break from 11:00 PM to 12:00 AM when shift ends at 10:00 PM) | System displays validation error message (e.g., 'Break period must be within shift duration' or 'Invalid break time'). Save operation is blocked |

**Postconditions:**
- No new version of the template is created with invalid data
- Original template data remains unchanged in the database
- User remains on the edit form with error messages displayed
- Form retains entered data for correction
- System maintains data integrity by preventing invalid updates

---

## Story: As HR Manager, I want to categorize shift templates to organize and filter them efficiently
**Story ID:** story-8

### Test Case: Validate creation and editing of shift template categories
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager with category management permissions
- System is accessible and responsive
- Database is available and contains existing shift template categories

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to category management page from the main menu or dashboard | Category management page loads successfully and displays a list of existing categories with options to create, edit, and delete |
| 2 | Click on 'Create New Category' button and enter category name (e.g., 'Morning Shifts') and optional description | Category creation form accepts input and displays validation feedback |
| 3 | Click 'Save' button to create the new category | New category 'Morning Shifts' is added to the category list, success message is displayed, and category appears in the list with correct details |
| 4 | Locate the newly created category in the list and click 'Edit' button | Edit category form opens with pre-populated fields showing current category name and description |
| 5 | Modify the category name to 'Early Morning Shifts' and update the description | Form accepts the modified input and displays updated values |
| 6 | Click 'Save' button to save the changes | Changes are saved successfully, success message is displayed, and the category list reflects the updated category name 'Early Morning Shifts' and description |

**Postconditions:**
- New category 'Early Morning Shifts' exists in the system
- Category is available for assignment to shift templates
- Changes are persisted in the database
- Category list displays the updated information

---

### Test Case: Verify filtering of shift templates by category
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as HR Manager
- At least two categories exist in the system (e.g., 'Morning Shifts', 'Evening Shifts')
- Multiple shift templates exist in the system
- Shift template list page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template management page | Shift template list page loads displaying all available shift templates with their details |
| 2 | Select a shift template (e.g., 'Early Morning 6AM-2PM') and click 'Edit' or 'Assign Category' | Template edit form opens with category assignment option visible |
| 3 | Assign 'Morning Shifts' category to the selected template and save | Category is successfully assigned and template displays 'Morning Shifts' category label in the list view |
| 4 | Select another shift template (e.g., 'Evening 2PM-10PM') and assign 'Evening Shifts' category, then save | Category is successfully assigned and template displays 'Evening Shifts' category label in the list view |
| 5 | Locate the category filter dropdown or filter panel on the shift template list page | Category filter control is visible and displays all available categories including 'Morning Shifts' and 'Evening Shifts' |
| 6 | Select 'Morning Shifts' from the category filter dropdown | Template list refreshes within 2 seconds and displays only shift templates assigned to 'Morning Shifts' category (e.g., 'Early Morning 6AM-2PM'). Templates from other categories are hidden |
| 7 | Change filter selection to 'Evening Shifts' | Template list refreshes within 2 seconds and displays only shift templates assigned to 'Evening Shifts' category (e.g., 'Evening 2PM-10PM'). Previously displayed morning shift templates are now hidden |
| 8 | Clear the category filter or select 'All Categories' | Template list refreshes and displays all shift templates regardless of category assignment |

**Postconditions:**
- Shift templates retain their category assignments
- Filter state can be cleared to show all templates
- System performance meets the 2-second response time requirement
- Category information is visible on each template in the list

---

### Test Case: Ensure unauthorized users cannot manage categories
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Test user account exists with non-HR role (e.g., Employee, Supervisor)
- Category management page URL is known
- System has role-based access control configured
- User is logged out or not authenticated

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page and enter credentials for a non-HR user (e.g., regular employee account) | User is successfully authenticated and logged into the system with non-HR role |
| 2 | Attempt to navigate to the category management page via menu, direct URL, or navigation | Access is denied with appropriate error message (e.g., 'Access Denied: Insufficient Permissions' or '403 Forbidden'). User is redirected to home page or shown an error page |
| 3 | Verify that category management menu options or buttons are not visible in the user interface | Category management links, buttons, or menu items are hidden or disabled for non-HR users |
| 4 | Attempt to access category management API endpoint directly (if applicable) using browser developer tools or API client | API returns 401 Unauthorized or 403 Forbidden status code with appropriate error message |

**Postconditions:**
- Non-HR user remains unable to access category management functionality
- No categories are created, modified, or deleted by unauthorized user
- Security audit log records the unauthorized access attempt
- System security remains intact

---

## Story: As HR Manager, I want to delete shift templates to remove obsolete or incorrect shift definitions
**Story ID:** story-10

### Test Case: Validate successful shift template deletion with confirmation
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager with deletion permissions
- At least one shift template exists that is not assigned to any active schedules
- Shift template list page is accessible
- Database is available and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list page from the main menu or dashboard | Shift template list page loads successfully displaying all available shift templates with details including template name, time range, and status |
| 2 | Locate a shift template that is not in use (e.g., 'Obsolete Night Shift 10PM-6AM') and click the checkbox or select button to mark it for deletion | Template is visually marked as selected with checkbox checked or highlighted row, and delete button becomes enabled |
| 3 | Click the 'Delete' button to initiate deletion process | Confirmation dialog appears with message asking 'Are you sure you want to delete the selected shift template(s)?' with options to 'Confirm' or 'Cancel' |
| 4 | Review the confirmation message and click 'Confirm' button to proceed with deletion | System processes the deletion request within 2 seconds, removes the template from the list, and displays success confirmation message (e.g., 'Shift template successfully deleted') |
| 5 | Verify the deleted template is no longer visible in the shift template list | The deleted template 'Obsolete Night Shift 10PM-6AM' is removed from the list and is no longer available for selection or assignment |
| 6 | Refresh the page or navigate away and return to the shift template list | Deleted template remains absent from the list, confirming permanent deletion from the database |

**Postconditions:**
- Shift template is permanently deleted from the database
- Template is no longer available for assignment to schedules
- Deletion is logged in system audit trail
- Template count is updated in the system
- Success confirmation message is displayed to the user

---

### Test Case: Prevent deletion of templates assigned to active schedules
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager with deletion permissions
- At least one shift template exists that is assigned to one or more active employee schedules
- Active schedules are present in the system using the template
- Shift template list page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template list page | Shift template list page loads successfully displaying all shift templates including those assigned to active schedules |
| 2 | Identify and select a shift template that is currently assigned to active schedules (e.g., 'Standard Day Shift 9AM-5PM' used by 15 employees) | Template is marked as selected and delete button becomes enabled |
| 3 | Click the 'Delete' button to attempt deletion of the in-use template | System validates template usage and displays a warning dialog with message such as 'Cannot delete template: This template is currently assigned to 15 active schedule(s). Please remove all assignments before deletion.' with only a 'Close' or 'OK' button (no confirm option) |
| 4 | Verify that the warning message clearly indicates the number of active schedules using the template | Warning message displays specific count of affected schedules and provides clear explanation why deletion is blocked |
| 5 | Click 'Close' or 'OK' to dismiss the warning dialog | Warning dialog closes and user returns to the shift template list with the template still present and unchanged |
| 6 | Verify the template remains in the list and is still assigned to active schedules | Template 'Standard Day Shift 9AM-5PM' remains in the list, is still functional, and continues to be assigned to the same active schedules without any data loss |

**Postconditions:**
- Shift template remains in the system unchanged
- Active schedule assignments are preserved
- No data loss occurs
- Warning is logged in system audit trail
- User is informed of the reason for deletion prevention

---

### Test Case: Ensure unauthorized users cannot delete shift templates
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Test user account exists with non-HR role (e.g., Employee, Supervisor, Manager without HR permissions)
- Shift templates exist in the system
- System has role-based access control configured for deletion operations
- User is logged out or not authenticated

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page and authenticate using credentials for a non-HR user account | User is successfully logged into the system with non-HR role and appropriate permissions for their role |
| 2 | Attempt to navigate to the shift template list page or management area | If accessible, page loads but deletion functionality (delete buttons, checkboxes for selection) is hidden, disabled, or not present in the interface |
| 3 | If delete controls are visible, attempt to select a template and click delete button | Access is denied with error message such as 'Access Denied: You do not have permission to delete shift templates' or action is blocked at the UI level |
| 4 | Attempt to access the delete API endpoint directly using browser developer tools, API client, or direct URL manipulation (e.g., DELETE /api/shifttemplates/{id}) | API returns 401 Unauthorized or 403 Forbidden status code with appropriate error message indicating insufficient permissions |
| 5 | Verify that no shift templates have been deleted from the system | All shift templates remain intact in the database and template list shows no changes |

**Postconditions:**
- Non-HR user remains unable to delete shift templates
- All shift templates remain unchanged in the system
- Unauthorized access attempt is logged in security audit trail
- System security and data integrity are maintained
- No templates are accidentally or maliciously deleted

---

