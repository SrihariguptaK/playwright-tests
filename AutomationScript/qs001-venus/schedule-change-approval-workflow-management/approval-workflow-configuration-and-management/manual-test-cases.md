# Manual Test Cases

## Story: As Manager, I want to configure approval workflows to achieve compliant and flexible schedule change approvals
**Story ID:** story-14

### Test Case: Validate creation of multi-level approval workflow
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager user account exists with workflow configuration permissions
- Manager is logged into the admin portal
- ApprovalWorkflows and WorkflowRules tables are accessible
- At least two potential approvers exist in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to workflow configuration page from the admin portal menu | Workflow configuration UI is displayed with options to create new workflow, view existing workflows, and configure workflow settings |
| 2 | Manager clicks 'Create New Workflow' button | Workflow creation form is displayed with fields for workflow name, description, and approval levels |
| 3 | Manager enters workflow name 'Schedule Change Approval - Level 2' and description 'Two-level approval for schedule changes' | Workflow name and description are accepted and displayed in the form fields |
| 4 | Manager adds first approval level by selecting 'Add Level' and assigns 'Team Lead' as Level 1 approver | Level 1 approval is created and displayed with 'Team Lead' assigned as approver |
| 5 | Manager adds second approval level by selecting 'Add Level' and assigns 'Department Manager' as Level 2 approver | Level 2 approval is created and displayed with 'Department Manager' assigned as approver, showing hierarchy: Level 1 → Level 2 |
| 6 | Manager clicks 'Save' button to save the workflow configuration | Success message is displayed confirming 'Workflow saved successfully' and workflow appears in the workflow list with status 'Active' |
| 7 | Manager navigates to the audit log section and filters by workflow configuration changes | Audit log entry is displayed showing workflow creation with workflow name, creation timestamp, manager username, and action type 'CREATE' |

**Postconditions:**
- New multi-level workflow is saved in ApprovalWorkflows table
- Workflow is visible in the workflow list
- Audit log contains complete record of workflow creation
- Workflow is available for assignment to schedule change types

---

### Test Case: Verify rejection of invalid workflow configuration
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Manager user account exists with workflow configuration permissions
- Manager is logged into the admin portal
- Workflow configuration page is accessible
- System validation rules are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to workflow configuration page and clicks 'Create New Workflow' | Workflow creation form is displayed |
| 2 | Manager enters workflow name 'Invalid Circular Workflow' and creates Level 1 approver as 'Manager A' | Level 1 is created with 'Manager A' as approver |
| 3 | Manager creates Level 2 approver as 'Manager B' with escalation back to 'Manager A' | Level 2 is created with 'Manager B' as approver and escalation path configured |
| 4 | Manager creates Level 3 approver as 'Manager A', creating a circular hierarchy (Manager A → Manager B → Manager A) | Level 3 is created with 'Manager A' selected |
| 5 | Manager clicks 'Save' button to attempt saving the workflow | Validation error message is displayed: 'Invalid workflow configuration: Circular approval hierarchy detected. Approver cannot appear multiple times in the approval chain.' Save operation is prevented and workflow is not saved |
| 6 | Manager removes Level 3 from the workflow configuration | Level 3 is removed and workflow now shows only Level 1 (Manager A) → Level 2 (Manager B) |
| 7 | Manager clicks 'Save' button again to save the corrected workflow | Success message is displayed: 'Workflow saved successfully' and workflow appears in the workflow list with valid configuration |

**Postconditions:**
- Invalid workflow with circular hierarchy is not saved in the database
- Corrected workflow is successfully saved in ApprovalWorkflows table
- System validation rules prevented data corruption
- Audit log shows attempted save and successful save of corrected workflow

---

### Test Case: Test role-based access control for workflow configuration
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Two user accounts exist: one unauthorized user (Employee role) and one authorized manager (Manager role)
- Role-based access control is configured and active
- Workflow configuration page requires Manager role or higher
- Both users have valid login credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Unauthorized user (Employee role) logs into the system with valid credentials | User is successfully logged in and redirected to employee dashboard |
| 2 | Unauthorized user attempts to navigate to workflow configuration page by entering the URL directly or clicking menu option (if visible) | Access is denied with error message: 'Access Denied: You do not have permission to access workflow configuration. Please contact your administrator.' User is redirected to their dashboard or error page |
| 3 | Unauthorized user logs out of the system | User is successfully logged out and redirected to login page |
| 4 | Authorized manager logs into the admin portal with valid manager credentials | Manager is successfully logged in and redirected to admin dashboard |
| 5 | Authorized manager navigates to workflow configuration page from the admin menu | Access is granted and workflow configuration UI is displayed with full functionality including create, edit, and delete options |
| 6 | Manager verifies all workflow configuration features are accessible (create, edit, view, delete) | All workflow configuration features are available and functional for the authorized manager |

**Postconditions:**
- Unauthorized user access attempt is logged in security audit log
- Authorized manager has full access to workflow configuration
- Role-based access control is functioning correctly
- No unauthorized changes were made to workflow configurations

---

## Story: As System Administrator, I want to manage user roles and permissions for schedule change approval workflows to ensure secure access
**Story ID:** story-20

### Test Case: Create and assign user roles successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System Administrator account exists with full role management permissions
- Administrator is logged into the admin portal
- UserRoles and Permissions tables are accessible
- At least one user account exists for role assignment
- Audit logging system is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to user management section from the admin portal main menu | User management dashboard is displayed showing options for role management, user management, and permissions |
| 2 | Administrator clicks on 'Role Management' tab or menu option | Role management interface is displayed showing existing roles list and 'Create New Role' button |
| 3 | Administrator clicks 'Create New Role' button | Role creation form is displayed with fields for role name, description, and permissions checkboxes |
| 4 | Administrator enters role name 'Schedule Approver' and description 'Can approve schedule change requests' | Role name and description are accepted and displayed in the form fields |
| 5 | Administrator selects specific permissions: 'View Schedule Requests', 'Approve Schedule Requests', and 'Reject Schedule Requests' from the permissions list | Selected permissions are checked and highlighted in the permissions list |
| 6 | Administrator clicks 'Save Role' button | Success message is displayed: 'Role created successfully' and the new role 'Schedule Approver' appears in the role list with assigned permissions visible |
| 7 | Administrator navigates to 'User Management' section and selects a user 'John Doe' from the user list | User details page is displayed showing current roles and option to assign new roles |
| 8 | Administrator clicks 'Assign Role' button and selects 'Schedule Approver' role from the dropdown | Role selection dropdown displays available roles including the newly created 'Schedule Approver' role |
| 9 | Administrator confirms the role assignment by clicking 'Assign' button | Success message is displayed: 'Role assigned successfully' and 'Schedule Approver' role appears in user's assigned roles list with immediate effect indicator |
| 10 | Administrator verifies the role is effective by checking user permissions or having user test access | User 'John Doe' immediately has access to schedule approval functions without requiring re-login |
| 11 | Administrator navigates to audit log section and filters by role management activities | Audit log displays two entries: 1) Role creation for 'Schedule Approver' with timestamp, administrator username, and action details, 2) Role assignment to 'John Doe' with timestamp, administrator username, role name, and user details |

**Postconditions:**
- New role 'Schedule Approver' is saved in UserRoles table
- Role permissions are stored in Permissions table
- User 'John Doe' has 'Schedule Approver' role assigned
- Role assignment is effective immediately
- Complete audit trail exists for both role creation and assignment
- User can perform actions according to assigned permissions

---

### Test Case: Prevent unauthorized access to role management
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Non-administrator user account exists (e.g., Employee or Manager role without admin privileges)
- User has valid login credentials
- Role management access is restricted to Administrator role only
- Authentication and authorization systems are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Non-administrator user logs into the system with valid credentials | User is successfully authenticated and redirected to their appropriate dashboard based on their role |
| 2 | Non-administrator user attempts to access role management UI by entering the direct URL '/admin/role-management' in the browser | Access is denied and error page is displayed with message: 'Access Denied: You do not have sufficient privileges to access role management. This function is restricted to System Administrators only.' |
| 3 | Non-administrator user checks their navigation menu for role management options | Role management menu option is not visible in the user's navigation menu |
| 4 | Non-administrator user attempts to access role management via API endpoint using browser developer tools or API client | API returns 403 Forbidden status code with error message: 'Unauthorized access. Administrator privileges required.' |
| 5 | System logs the unauthorized access attempt | Security audit log records the unauthorized access attempt with user details, timestamp, attempted resource, and denial reason |

**Postconditions:**
- No unauthorized access to role management was granted
- User roles and permissions remain unchanged
- Security audit log contains record of access denial
- System security integrity is maintained
- No sensitive role or permission data was exposed

---

### Test Case: Validate role and permission consistency
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- System Administrator is logged into the admin portal
- Role management interface is accessible
- Permission validation rules are configured and active
- System has predefined conflicting permission rules (e.g., 'Submit Request' conflicts with 'Final Approval')

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to role management section and clicks 'Create New Role' | Role creation form is displayed with permissions list |
| 2 | Administrator enters role name 'Conflicting Role Test' and description 'Testing permission conflict validation' | Role name and description are accepted in the form |
| 3 | Administrator selects permission 'Submit Schedule Change Request' from the permissions list | Permission 'Submit Schedule Change Request' is checked and highlighted |
| 4 | Administrator attempts to also select conflicting permission 'Final Approval Authority' which conflicts with submission permission based on separation of duties principle | Warning message is displayed: 'Permission conflict detected: Users with submission rights cannot have final approval authority due to separation of duties policy.' The conflicting permission is either not selectable or highlighted in red |
| 5 | Administrator ignores warning (if allowed) and clicks 'Save Role' button with both conflicting permissions selected | Validation error is displayed: 'Cannot save role: Conflicting permissions detected. Please review and remove conflicting permissions: Submit Schedule Change Request and Final Approval Authority cannot be assigned to the same role.' Save operation is prevented and role is not created |
| 6 | Administrator deselects 'Final Approval Authority' permission, leaving only 'Submit Schedule Change Request' selected | Conflict warning disappears and form shows valid state |
| 7 | Administrator clicks 'Save Role' button with valid permission set | Success message is displayed: 'Role created successfully' and role appears in the role list with only the valid, non-conflicting permissions |

**Postconditions:**
- Role with conflicting permissions was not saved to database
- Role with valid permissions was successfully created
- Permission consistency rules are enforced
- Audit log shows validation failure and successful creation attempts
- Data integrity is maintained in UserRoles and Permissions tables

---

## Story: As System Administrator, I want to audit all schedule change approval workflow activities to ensure compliance and traceability
**Story ID:** story-22

### Test Case: Verify logging of schedule change workflow activities
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- System Administrator is logged in with valid credentials
- Administrator has audit log access permissions
- AuditLogs table is accessible and operational
- At least one schedule change workflow exists in the system
- Audit logging service is enabled and running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request submission page | Schedule change request form is displayed |
| 2 | Submit a new schedule change request with all required details (schedule ID, change description, reason) | Schedule change request is submitted successfully and confirmation message is displayed |
| 3 | Navigate to the approval workflow and approve the submitted schedule change request | Schedule change request is approved successfully and status is updated |
| 4 | Navigate to the audit logs portal via secure access point | Audit logs dashboard is displayed with search and filter options |
| 5 | Query audit logs without any filters to view all recent activities | All workflow activities are displayed including the submission and approval actions performed in previous steps with user identity, timestamps, and action details |
| 6 | Verify that the schedule change request submission log entry contains: user ID, timestamp, action type (submission), request ID, and change details | Log entry displays all required fields with correct and complete information |
| 7 | Verify that the schedule change approval log entry contains: approver user ID, timestamp, action type (approval), request ID, and approval details | Log entry displays all required fields with correct and complete information |
| 8 | Apply filters to audit logs: filter by user (select the user who submitted the request), action type (submission), and date range (today's date) | Filtered results are returned within 5 seconds showing only the submission activity by the selected user |
| 9 | Clear filters and apply new filters: filter by action type (approval) and date range (today's date) | Filtered results are returned within 5 seconds showing only approval activities for today |
| 10 | Measure and record the query response time for the filtered results | Query response time is 5 seconds or less |
| 11 | Select the export option and choose CSV format for audit logs | Export dialog is displayed with CSV format selected |
| 12 | Confirm the export and download the audit log file | CSV file is downloaded successfully to the local system |
| 13 | Open the exported CSV file and verify its contents | CSV file contains all filtered audit log entries with correct columns: user ID, timestamp, action type, request ID, and details. Data matches the displayed logs in the portal |
| 14 | Select the export option again and choose JSON format for audit logs | Export dialog is displayed with JSON format selected |
| 15 | Confirm the export and download the audit log file in JSON format | JSON file is downloaded successfully and contains properly formatted audit log data matching the portal display |

**Postconditions:**
- All schedule change workflow activities are logged in AuditLogs table
- Audit logs contain complete and accurate information for all performed actions
- Exported audit log files are saved locally and contain correct data
- System remains in stable state with audit logging continuing to function
- No data integrity issues in audit logs

---

### Test Case: Ensure audit log access is restricted
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Audit logging system is operational
- Role-based access control (RBAC) is configured and enabled
- Test user account exists without audit log access permissions
- Audit logs contain data from previous workflow activities
- Security policies are enforced at application level

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log out from any existing administrator session | User is successfully logged out and redirected to login page |
| 2 | Log in with an unauthorized user account (user without administrator or audit access role) | User is successfully authenticated and logged into the system with limited permissions |
| 3 | Attempt to navigate to the audit logs portal URL directly by entering the URL in the browser | Access is denied and error message is displayed: 'Access Denied - You do not have permission to view audit logs' or similar message with HTTP 403 Forbidden status |
| 4 | Check if audit logs menu option is visible in the navigation menu for the unauthorized user | Audit logs menu option is not visible or is disabled in the navigation menu |
| 5 | Attempt to access audit logs via API endpoint GET /api/audit-logs using the unauthorized user's authentication token | API request is rejected with HTTP 403 Forbidden status and error response: 'Insufficient permissions to access audit logs' |
| 6 | Verify that no audit log data is returned in the API response | Response body contains error message only, no audit log data is exposed |
| 7 | Log out from the unauthorized user account | User is successfully logged out |
| 8 | Log in with a System Administrator account that has audit log access permissions | Administrator is successfully authenticated and logged in |
| 9 | Navigate to the audit logs portal | Audit logs dashboard is displayed successfully with full access to all audit log features |
| 10 | Verify that the previous unauthorized access attempts are logged in the audit logs | Audit logs contain entries showing the unauthorized access attempts with user ID, timestamp, action type (access denied), and resource (audit logs) |

**Postconditions:**
- Unauthorized users remain unable to access audit logs
- Security policies continue to be enforced
- All access attempts (authorized and unauthorized) are logged
- System security integrity is maintained
- Administrator can verify all access attempts through audit logs

---

