# Manual Test Cases

## Story: As HR Manager, I want to create shift templates to achieve standardized scheduling
**Story ID:** story-1

### Test Case: Validate successful shift template creation with valid input
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has role-based access permissions to create shift templates
- Shift template management module is accessible
- Database connection to ShiftTemplates table is active
- No existing template with the same name exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page from the main dashboard or menu | Shift template form is displayed with all required fields: template name, category, start time, end time, breaks section, and roles assignment section |
| 2 | Enter template name as 'Morning Shift - Weekday' | Template name field accepts the input and displays the entered text |
| 3 | Select category as 'Standard Shifts' from the dropdown | Category dropdown displays selected value 'Standard Shifts' |
| 4 | Enter valid start time as '09:00 AM' | Start time field accepts the input without validation errors |
| 5 | Enter valid end time as '05:00 PM' | End time field accepts the input and validates that end time is after start time |
| 6 | Add first break period: Start time '12:00 PM', End time '12:30 PM', Break type 'Lunch' | Break is added to the breaks list with no validation errors |
| 7 | Add second break period: Start time '03:00 PM', End time '03:15 PM', Break type 'Rest' | Second break is added to the breaks list with no overlap validation errors |
| 8 | Assign roles 'Customer Service Representative' and 'Team Lead' from the roles dropdown | Selected roles are displayed in the assigned roles section |
| 9 | Click the 'Save Template' button | System validates all inputs, processes the request within 2 seconds, and displays success confirmation message 'Shift template created successfully' |
| 10 | Verify the newly created template appears in the shift templates list | Template 'Morning Shift - Weekday' is visible in the templates list with all entered details |

**Postconditions:**
- Shift template is saved in ShiftTemplates table with unique ID
- Template is available for future retrieval and use
- Audit trail entry is created with HR Manager username and timestamp
- User remains on the shift template management page or is redirected to templates list
- System is ready to accept new template creation requests

---

### Test Case: Reject shift template creation with overlapping breaks
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has role-based access permissions to create shift templates
- Shift template creation page is accessible
- Validation rules for overlapping breaks are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page from the main dashboard | Shift template form is displayed with all required input fields |
| 2 | Enter template name as 'Test Overlapping Breaks' | Template name field accepts the input |
| 3 | Enter valid start time as '08:00 AM' and end time as '04:00 PM' | Time fields accept the input without errors |
| 4 | Add first break period: Start time '11:00 AM', End time '11:30 AM' | First break is added successfully to the breaks list |
| 5 | Add second break period with overlapping time: Start time '11:15 AM', End time '11:45 AM' | Validation error message is displayed: 'Break periods cannot overlap. Please adjust the break times.' The overlapping break is highlighted in red |
| 6 | Add third break period with complete overlap: Start time '11:00 AM', End time '11:30 AM' | Validation error message is displayed: 'This break period overlaps with an existing break.' Error indicator appears next to the break field |
| 7 | Assign role 'Supervisor' from the roles dropdown | Role is assigned successfully despite break validation errors |
| 8 | Attempt to submit the form by clicking 'Save Template' button | Form submission is blocked. Error summary is displayed at the top: 'Cannot save template. Please correct the following errors: Overlapping break periods detected.' Save button remains disabled or shows error state |
| 9 | Verify that no API call is made to POST /api/shifttemplates | No network request is sent to the backend. Client-side validation prevents submission |

**Postconditions:**
- No shift template is created in the database
- User remains on the shift template creation page with error messages visible
- All entered data (except invalid breaks) is retained in the form
- No audit trail entry is created
- System is ready to accept corrected input

---

### Test Case: Ensure audit trail records template creation
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as HR Manager with username 'hr.manager@company.com'
- User has permissions to create shift templates
- Audit logging system is enabled and functioning
- User has access to query audit trail logs or audit trail viewing interface
- System timestamp is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page | Shift template creation form is displayed |
| 2 | Enter template name as 'Evening Shift - Audit Test' | Template name is accepted |
| 3 | Enter start time '02:00 PM' and end time '10:00 PM' | Time fields accept valid input |
| 4 | Add break period: Start time '05:00 PM', End time '05:30 PM' | Break is added without validation errors |
| 5 | Assign role 'Sales Associate' | Role is assigned successfully |
| 6 | Select category as 'Evening Shifts' | Category is selected |
| 7 | Note the current system timestamp before submission | Current timestamp is recorded for verification (e.g., 2024-01-15 14:30:00) |
| 8 | Click 'Save Template' button | Template is saved successfully and confirmation message 'Shift template created successfully' is displayed. Note the template ID from the confirmation or URL |
| 9 | Navigate to audit trail logs interface or query the audit database for recent entries | Audit trail interface is accessible and displays recent audit entries |
| 10 | Filter audit logs by action type 'Template Creation' or entity type 'ShiftTemplate' for the noted timestamp range | Audit log entries are filtered and displayed |
| 11 | Locate the audit entry for template 'Evening Shift - Audit Test' | Audit entry exists with the following details: Action: 'CREATE', Entity: 'ShiftTemplate', Entity ID: [template ID], User: 'hr.manager@company.com', Timestamp: [within 1 second of noted time], Details: Template name and key attributes |
| 12 | Verify audit entry contains complete information including user identity and accurate timestamp | Audit entry shows complete trail with username 'hr.manager@company.com', accurate timestamp matching creation time, and all relevant template details |

**Postconditions:**
- Shift template 'Evening Shift - Audit Test' exists in the database
- Audit trail entry is permanently recorded in audit logs
- Audit entry is retrievable for compliance and tracking purposes
- System maintains data integrity between template and audit records
- User can view audit history for the created template

---

## Story: As Scheduler, I want to edit existing shift templates to maintain accurate scheduling standards
**Story ID:** story-2

### Test Case: Validate successful shift template editing with versioning
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Scheduler with valid credentials
- User has role-based permissions to edit shift templates
- At least one existing shift template 'Morning Shift - Standard' exists in the system with version 1.0
- Existing template has: Start time '08:00 AM', End time '04:00 PM', Break '12:00 PM - 12:30 PM', Role 'Agent'
- Version control system is enabled for shift templates
- Database connection to ShiftTemplates table with versioning is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list page from the main menu | List of existing shift templates is displayed in a table or grid format showing template names, categories, current version, and last modified date |
| 2 | Locate the template 'Morning Shift - Standard' in the list | Template 'Morning Shift - Standard' is visible with current version displayed as 'v1.0' |
| 3 | Click on the 'Edit' button or icon next to the template | Template edit form opens with all current values pre-populated: Start time '08:00 AM', End time '04:00 PM', Break '12:00 PM - 12:30 PM', Role 'Agent' |
| 4 | Modify the start time from '08:00 AM' to '09:00 AM' | Start time field updates to show '09:00 AM' without validation errors |
| 5 | Modify the end time from '04:00 PM' to '05:00 PM' | End time field updates to show '05:00 PM' and validates that end time is after start time |
| 6 | Edit the existing break period from '12:00 PM - 12:30 PM' to '12:30 PM - 01:00 PM' | Break period is updated successfully with no overlap validation errors |
| 7 | Add an additional role 'Senior Agent' to the existing role assignment | Role 'Senior Agent' is added to the roles list alongside existing 'Agent' role |
| 8 | Enter version notes or change description as 'Updated shift timing and added senior agent role' | Version notes field accepts the input |
| 9 | Click 'Save Changes' button | System validates all inputs, processes the update request, and displays confirmation message 'Shift template updated successfully. New version v2.0 created.' |
| 10 | Navigate back to the shift template list | Template 'Morning Shift - Standard' now shows version 'v2.0' with updated last modified date |
| 11 | Click on 'View Version History' or similar option for the template | Version history displays both v1.0 and v2.0 with timestamps, user who made changes, and change descriptions. v1.0 shows original values and v2.0 shows updated values |
| 12 | Verify that previous version v1.0 is still accessible and preserved | Version v1.0 can be viewed with all original values intact: Start '08:00 AM', End '04:00 PM', Break '12:00 PM - 12:30 PM', Role 'Agent' |

**Postconditions:**
- New version v2.0 of the shift template is saved in the database
- Previous version v1.0 is preserved and accessible in version history
- Template list displays the latest version v2.0 as the active version
- Audit trail entry is created for the edit action with Scheduler username and timestamp
- Updated template is available for scheduling operations
- Version history is complete and accurate for compliance tracking

---

### Test Case: Reject edits with invalid break overlaps
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Scheduler with edit permissions
- Existing shift template 'Afternoon Shift' exists with: Start '01:00 PM', End '09:00 PM', Break '04:00 PM - 04:30 PM'
- Template is at version v1.0
- Validation rules for overlapping breaks are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list page | List of shift templates is displayed including 'Afternoon Shift' |
| 2 | Select template 'Afternoon Shift' and click 'Edit' | Edit form opens with pre-populated values: Start '01:00 PM', End '09:00 PM', existing break '04:00 PM - 04:30 PM' |
| 3 | Click 'Add Break' to add a second break period | New break input fields are displayed for start and end time |
| 4 | Enter second break with overlapping time: Start '04:15 PM', End '04:45 PM' | Validation error message appears: 'Break periods cannot overlap. The new break overlaps with existing break (04:00 PM - 04:30 PM).' Error is highlighted in red next to the break field |
| 5 | Verify that error indicator shows which breaks are conflicting | Both the existing break '04:00 PM - 04:30 PM' and new break '04:15 PM - 04:45 PM' are highlighted or marked with error indicators showing the overlap conflict |
| 6 | Attempt to add another break with complete overlap: Start '04:00 PM', End '04:30 PM' | Validation error displays: 'This break period exactly matches an existing break. Please use different times.' Duplicate break is marked with error |
| 7 | Modify shift end time to '10:00 PM' while overlapping breaks still exist | End time is updated but break overlap errors remain visible |
| 8 | Click 'Save Changes' button while validation errors are present | Form submission is blocked. Error summary appears at top of form: 'Cannot save changes. Please resolve the following errors: Break periods overlap detected.' Save button is disabled or shows error state |
| 9 | Verify no API call is made to PUT /api/shifttemplates/{id} | No network request is sent to backend. Client-side validation prevents submission |
| 10 | Correct the overlapping break by changing second break to '05:00 PM - 05:30 PM' | Validation error clears. Break fields show no error indicators. Save button becomes enabled |
| 11 | Click 'Save Changes' after correcting errors | Template is saved successfully with new version created. Confirmation message displays: 'Shift template updated successfully' |

**Postconditions:**
- No invalid template version is created during error state
- After correction, new valid version is saved with non-overlapping breaks
- Original version remains unchanged until valid edits are saved
- Audit trail shows only the successful save operation, not the blocked attempts
- User remains on edit page during error state, redirected to list after successful save

---

### Test Case: Verify audit trail records template edits
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduler with username 'scheduler@company.com'
- User has permissions to edit shift templates and view audit logs
- Existing shift template 'Night Shift - Audit Test' exists at version v1.0
- Existing template details: Start '10:00 PM', End '06:00 AM', Break '02:00 AM - 02:30 AM', Role 'Night Supervisor'
- Audit logging system is enabled and functioning
- System timestamp is accurate and synchronized

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list page | Shift templates list is displayed showing 'Night Shift - Audit Test' at version v1.0 |
| 2 | Note the current system timestamp before making edits | Current timestamp is recorded for audit verification (e.g., 2024-01-15 16:45:00) |
| 3 | Select 'Night Shift - Audit Test' and click 'Edit' | Edit form opens with current values pre-populated |
| 4 | Change the break period from '02:00 AM - 02:30 AM' to '01:30 AM - 02:00 AM' | Break time is updated without validation errors |
| 5 | Add additional role 'Security Officer' to the template | Role 'Security Officer' is added alongside 'Night Supervisor' |
| 6 | Enter version notes as 'Adjusted break time and added security officer role' | Version notes are accepted |
| 7 | Click 'Save Changes' button | Edit is saved successfully. Confirmation message displays: 'Shift template updated successfully. New version v2.0 created.' Note the template ID and new version number |
| 8 | Navigate to audit trail logs interface or access audit log query tool | Audit trail interface is accessible and displays recent audit entries |
| 9 | Filter audit logs by action type 'Template Edit' or 'UPDATE' for entity type 'ShiftTemplate' within the timestamp range | Filtered audit entries are displayed for template modifications |
| 10 | Locate the audit entry for 'Night Shift - Audit Test' edit operation | Audit entry exists with following details: Action: 'UPDATE', Entity: 'ShiftTemplate', Entity ID: [template ID], User: 'scheduler@company.com', Timestamp: [within 1 second of save time], Previous Version: 'v1.0', New Version: 'v2.0' |
| 11 | Verify audit entry contains detailed change information | Audit entry shows: Changed fields: 'break_period' (from '02:00 AM - 02:30 AM' to '01:30 AM - 02:00 AM'), 'roles' (added 'Security Officer'), Version notes: 'Adjusted break time and added security officer role' |
| 12 | Verify audit entry includes complete user identification and timestamp accuracy | Audit record displays: User: 'scheduler@company.com', User role: 'Scheduler', Timestamp matches save operation time, IP address or session ID is logged for security tracking |
| 13 | Check that audit entry is immutable and permanently stored | Audit entry cannot be edited or deleted. Entry is marked as permanent record for compliance purposes |

**Postconditions:**
- Shift template 'Night Shift - Audit Test' exists at version v2.0 with updated values
- Version v1.0 is preserved in version history
- Audit trail entry is permanently recorded with complete edit details
- Audit log is retrievable for compliance, security, and tracking purposes
- System maintains referential integrity between template versions and audit records
- Complete change history is available for the template showing who changed what and when

---

## Story: As HR Manager, I want to categorize shift templates by department to improve template organization
**Story ID:** story-6

### Test Case: Create and assign categories to shift templates
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager with appropriate permissions
- Shift template management interface is accessible
- At least one shift template exists in the system
- Categories table is accessible and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template management section | Shift template management page loads successfully with list of existing templates |
| 2 | Click on 'Manage Categories' or 'Create Category' button | Category creation form or modal opens |
| 3 | Enter a unique category name (e.g., 'Sales Department') in the category name field | Category name is accepted and displayed in the input field |
| 4 | Click 'Save' or 'Create' button to save the new category | Category is saved successfully, success message is displayed, and category appears in the categories list |
| 5 | Select an existing shift template from the template list | Template details page or edit form opens |
| 6 | Locate the category assignment section in the template form | Category selection dropdown or multi-select field is visible with available categories including the newly created 'Sales Department' |
| 7 | Select 'Sales Department' category from the available options | Category is selected and displayed as assigned to the template |
| 8 | Click 'Save' button to save the template with assigned category | Template is saved successfully with the assigned category, confirmation message is displayed, and category is visible in template details |

**Postconditions:**
- New category 'Sales Department' exists in the system
- Selected shift template has 'Sales Department' category assigned
- Category is visible in template list view
- Changes are persisted in the database

---

### Test Case: Filter shift templates by category
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager with appropriate permissions
- Multiple shift templates exist in the system
- At least two different categories exist (e.g., 'Sales Department', 'IT Department')
- Templates are assigned to different categories
- At least 2 templates are assigned to 'Sales Department' category

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template management page | Template management page loads with all available templates displayed in the list |
| 2 | Locate the category filter dropdown or filter section in the UI | Category filter control is visible and displays all available categories |
| 3 | Click on the category filter dropdown | Dropdown expands showing list of all categories including 'Sales Department' and 'IT Department' |
| 4 | Select 'Sales Department' from the category filter options | Filter is applied immediately, template list updates to show only templates assigned to 'Sales Department' category, templates from other categories are hidden |
| 5 | Verify the filtered results by checking each displayed template | All displayed templates show 'Sales Department' as their assigned category, template count reflects only filtered results |
| 6 | Clear the filter or select 'All Categories' option | Filter is removed and all templates are displayed again in the list |

**Postconditions:**
- Template list can be filtered and unfiltered without errors
- Filter state can be cleared to show all templates
- No data is modified during filtering operation

---

### Test Case: Prevent duplicate category names
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager with appropriate permissions
- Category management interface is accessible
- A category named 'Sales Department' already exists in the system
- Category validation rules are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template management section | Shift template management page loads successfully |
| 2 | Click on 'Manage Categories' or 'Create Category' button | Category creation form or modal opens |
| 3 | Enter an existing category name 'Sales Department' in the category name field | Category name is entered in the input field |
| 4 | Click 'Save' or 'Create' button to attempt saving the duplicate category | Validation error message is displayed indicating 'Category name already exists' or similar message, category is not saved, form remains open with entered data |
| 5 | Verify that the duplicate category was not created by checking the categories list | Only one instance of 'Sales Department' exists in the categories list, no duplicate entry is present |
| 6 | Modify the category name to a unique value (e.g., 'Sales Department - East Region') | New unique category name is accepted in the input field |
| 7 | Click 'Save' or 'Create' button | Category is saved successfully with the unique name, success message is displayed |

**Postconditions:**
- No duplicate category names exist in the system
- Original 'Sales Department' category remains unchanged
- New unique category 'Sales Department - East Region' is created successfully
- Data integrity is maintained

---

