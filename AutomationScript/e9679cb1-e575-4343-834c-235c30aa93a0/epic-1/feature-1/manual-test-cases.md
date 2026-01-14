# Manual Test Cases

## Story: As HR Manager, I want to create shift templates to achieve standardized shift definitions
**Story ID:** story-1

### Test Case: Validate successful creation of valid shift template
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to create shift templates
- ShiftTemplates table is accessible
- System is operational and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page | Shift template form is displayed with fields for shift name, start time, end time, and break periods |
| 2 | Enter valid start time (e.g., 09:00 AM), end time (e.g., 05:00 PM), and break periods (e.g., 30 minutes lunch break at 12:00 PM) | All input fields accept the data without validation errors, fields display entered values correctly |
| 3 | Submit the form by clicking the Save button | Shift template is saved to the database, confirmation message is displayed (e.g., 'Shift template created successfully'), and response time is under 2 seconds |

**Postconditions:**
- New shift template is stored in ShiftTemplates table
- Template appears in the list of available templates
- Template is available for future use
- Audit log records the creation with timestamp and user

---

### Test Case: Reject shift template with invalid duration
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to create shift templates
- Shift template creation page is accessible
- Validation rules are configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page | Shift template form is displayed with all required input fields |
| 2 | Enter end time (e.g., 09:00 AM) that is earlier than start time (e.g., 05:00 PM) | Validation error message is displayed indicating 'End time must be after start time' or similar error message, error is highlighted near the relevant field |
| 3 | Attempt to submit the form by clicking the Save button | Form submission is blocked, error message remains visible, no data is saved to the database, user remains on the form page |

**Postconditions:**
- No shift template is created in the database
- User remains on the creation page to correct errors
- Form retains entered data for correction
- No audit log entry is created for failed submission

---

### Test Case: Prevent deletion of assigned shift template
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager
- At least one shift template exists that is assigned to active schedules
- At least one shift template exists that is not assigned to any schedules
- User has permissions to delete shift templates

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list and attempt to delete a shift template that is assigned to schedules by clicking the Delete button | System displays a warning message such as 'This template is assigned to active schedules and cannot be deleted' and prevents the deletion action |
| 2 | Navigate to shift template list and attempt to delete a shift template that is not assigned to any schedules by clicking the Delete button | System prompts for confirmation, upon confirmation the template is deleted successfully, confirmation message is displayed (e.g., 'Template deleted successfully') |

**Postconditions:**
- Assigned shift template remains in the database and is still available
- Unassigned shift template is removed from the database
- Deleted template no longer appears in the template list
- Audit log records the deletion attempt and successful deletion with timestamp and user

---

## Story: As HR Manager, I want to manage user roles and permissions to achieve secure access control
**Story ID:** story-9

### Test Case: Create and assign user roles successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager with admin privileges
- User has access to role management features
- Users, Roles, and Permissions tables are accessible
- At least one user exists in the system to assign roles to

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | HR Manager navigates to role management page from the main menu or admin dashboard | Role management UI is displayed showing existing roles, permissions list, and options to create new roles |
| 2 | Create a new role by entering role name (e.g., 'Scheduler'), selecting specific permissions (e.g., 'View Schedules', 'Edit Schedules'), and clicking Save Role button | New role is created and saved to the Roles table, confirmation message is displayed (e.g., 'Role created successfully'), role appears in the roles list |
| 3 | Assign the newly created role to a user by selecting the user from the user list, choosing the role from dropdown, and clicking Assign button | Role is successfully assigned to the user, confirmation message is displayed (e.g., 'Role assigned to user successfully'), user-role assignment is saved, audit log records the assignment with timestamp and HR Manager username |

**Postconditions:**
- New role exists in the Roles table with defined permissions
- User has the assigned role and associated permissions
- Audit log contains entries for role creation and assignment
- User can access features according to new role permissions

---

### Test Case: Restrict access to role management
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 2 mins

**Preconditions:**
- A non-HR user account exists in the system (e.g., Employee or Scheduler role)
- Non-HR user is logged into the system
- Role management features are protected by role-based access control
- Access control rules are properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Non-HR user attempts to access role management page by navigating directly via URL or menu (if visible) | Access is denied, appropriate error message is displayed (e.g., 'Access Denied: You do not have permission to access this page' or 'Unauthorized Access'), user is redirected to their home page or previous page, no role management UI is displayed |

**Postconditions:**
- Non-HR user remains without access to role management features
- No unauthorized changes are made to roles or permissions
- Access attempt is logged in audit trail with timestamp and user details
- System security remains intact

---

