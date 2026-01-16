# Manual Test Cases

## Story: As Administrator, I want to configure approval workflows to manage schedule change approvals
**Story ID:** story-2

### Test Case: Validate creation of multi-stage approval workflow
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Administrator is logged into the admin portal with valid credentials
- Administrator has admin role permissions
- ApprovalWorkflows and Approvers tables are accessible
- At least one role and department exist in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page | Page displays existing workflows and creation options with 'Create New Workflow' button visible |
| 2 | Administrator clicks 'Create New Workflow' button | New workflow creation form is displayed with fields for workflow name, description, and stage configuration |
| 3 | Administrator enters workflow name and description | Workflow name and description are accepted and displayed in the form |
| 4 | Administrator adds first approval stage and assigns approvers by role | First stage is created with selected role displayed as approver |
| 5 | Administrator adds second approval stage and assigns approvers by department | Second stage is created with selected department displayed as approver |
| 6 | Administrator adds third approval stage and assigns specific approvers | Third stage is created with all assigned approvers displayed correctly in the workflow stages list |
| 7 | Administrator reviews the complete multi-stage workflow configuration | All workflow stages and approvers are displayed correctly in sequential order |
| 8 | Administrator clicks 'Save' button to save the workflow | System processes the save request within 3 seconds, displays success message, and workflow appears in the workflows list |
| 9 | Administrator navigates to workflow version history | Version history shows new entry with creation timestamp, administrator username, and version 1.0 |

**Postconditions:**
- New multi-stage approval workflow is saved in ApprovalWorkflows table
- Workflow is active and available for use
- Version history entry is created with initial version
- Configuration changes are logged in audit trail

---

### Test Case: Verify validation prevents circular dependencies
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Administrator is logged into the admin portal with valid credentials
- Administrator has admin role permissions
- Workflow configuration page is accessible
- System validation rules for circular dependencies are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page and clicks 'Create New Workflow' | New workflow creation form is displayed |
| 2 | Administrator enters workflow name 'Test Circular Workflow' | Workflow name is accepted and displayed |
| 3 | Administrator creates Stage A with approver from Role 1 | Stage A is created and displayed in workflow |
| 4 | Administrator creates Stage B with approver from Role 2 and sets Stage A as next stage | Stage B is created with Stage A configured as next stage |
| 5 | Administrator attempts to configure Stage A to route back to Stage B, creating a circular dependency | System detects circular dependency configuration |
| 6 | Administrator clicks 'Save' button to save the workflow | System displays validation error message: 'Circular dependency detected. Stage A cannot route to Stage B as it would create an infinite loop.' Save operation is prevented |
| 7 | Administrator removes the circular routing from Stage A | Circular dependency is removed and workflow structure is corrected |
| 8 | Administrator configures Stage A to route to Stage C (new final stage) | Stage A is now correctly configured to route to Stage C without circular dependency |
| 9 | Administrator clicks 'Save' button again | Validation passes, workflow is saved successfully within 3 seconds, and success message is displayed |

**Postconditions:**
- Workflow is saved without circular dependencies
- Validation error was properly displayed and prevented invalid save
- Corrected workflow is active in the system
- Version history reflects the successful save

---

### Test Case: Test escalation rule configuration
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Administrator is logged into the admin portal with valid credentials
- Administrator has admin role permissions
- At least one approval workflow exists in the system
- Escalation approvers and roles are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page and selects existing workflow to edit | Workflow details page is displayed with current configuration |
| 2 | Administrator clicks on 'Escalation Rules' tab or section | Escalation rules configuration interface is displayed |
| 3 | Administrator clicks 'Add Escalation Rule' button for Stage 1 | Escalation rule form is displayed with fields for timeout duration and escalation approver |
| 4 | Administrator sets escalation timeout to 24 hours for Stage 1 | Timeout value of 24 hours is accepted and displayed |
| 5 | Administrator selects escalation approver as 'Department Manager' role | Department Manager role is selected and displayed as escalation approver |
| 6 | Administrator adds second escalation rule for Stage 1 with 48 hours timeout escalating to 'Director' role | Second escalation rule is added and both rules are displayed in correct sequence |
| 7 | Administrator reviews escalation rules configuration | All escalation rules are displayed correctly in workflow details showing timeout periods and escalation approvers for each stage |
| 8 | Administrator clicks 'Save' button to save the workflow with escalation rules | System processes save request within 3 seconds and displays success message 'Workflow with escalation rules saved successfully' |
| 9 | Administrator refreshes the workflow details page | Workflow displays with all escalation rules persisted correctly showing Stage 1: 24h → Department Manager, 48h → Director |
| 10 | Administrator checks version history | Version history shows new entry indicating escalation rules were added with timestamp and administrator username |

**Postconditions:**
- Escalation rules are saved and associated with the workflow
- Workflow with escalation rules is persisted in ApprovalWorkflows table
- Escalation rules are active and will trigger based on configured timeouts
- Version history is updated with escalation rule changes

---

## Story: As Administrator, I want to audit approval workflows and actions to ensure compliance and traceability
**Story ID:** story-6

### Test Case: Validate audit logging of workflow configuration changes
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Administrator is logged into the admin portal with valid credentials
- Administrator has admin role permissions
- AuditLogs table is accessible and functioning
- At least one approval workflow exists in the system
- Audit logging service is active and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page | Workflow configuration page is displayed with list of existing workflows |
| 2 | Administrator selects an existing workflow to modify | Workflow details page is displayed with current configuration |
| 3 | Administrator modifies workflow name from 'Schedule Approval' to 'Schedule Change Approval' | Workflow name is updated in the form |
| 4 | Administrator adds a new approval stage to the workflow | New approval stage is added and displayed in workflow configuration |
| 5 | Administrator clicks 'Save' button to save the modified workflow | Workflow is saved successfully within 3 seconds and success message is displayed |
| 6 | Administrator navigates to audit logs section from the admin portal menu | Audit logs page is displayed with search and filter options |
| 7 | Administrator searches audit logs for workflow configuration changes using workflow name 'Schedule Change Approval' | Search executes within 5 seconds and returns audit log entries related to the workflow |
| 8 | Administrator reviews the most recent audit log entry | Audit log entry is displayed showing: Action Type: 'Workflow Modified', User: current administrator username, Timestamp: current date/time, Details: 'Workflow name changed from Schedule Approval to Schedule Change Approval, Stage added' |
| 9 | Administrator clicks on the audit log entry to view detailed metadata | Detailed audit entry displays complete information including before/after values, IP address, session ID, and all modified fields |
| 10 | Administrator filters audit logs by action type 'Workflow Modified' and date range of today | Filtered results display only workflow modification entries from today, showing all relevant entries accurately within 5 seconds |

**Postconditions:**
- Audit log entry is created and stored in AuditLogs table
- Audit entry contains complete metadata including user, timestamp, and change details
- Audit log is immutable and cannot be modified
- Search functionality returns accurate results

---

### Test Case: Verify audit log immutability
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Administrator is logged into the admin portal with valid credentials
- Administrator has admin role permissions
- AuditLogs table contains existing audit entries
- Audit log immutability protection is enabled
- System security controls are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to audit logs section | Audit logs page is displayed with existing audit entries |
| 2 | Administrator selects an existing audit log entry | Audit log entry details are displayed in read-only view |
| 3 | Administrator attempts to access edit functionality for the audit log entry | No edit button or edit functionality is available; entry is displayed in read-only mode only |
| 4 | Administrator attempts to use browser developer tools or direct API call to modify the audit log entry | System prevents modification and returns error response: 'Audit log entries are immutable and cannot be modified' |
| 5 | System logs the unauthorized modification attempt | New audit log entry is created documenting the attempted modification with Action Type: 'Unauthorized Audit Modification Attempt', User: administrator username, Timestamp: current date/time |
| 6 | Administrator attempts to delete an audit log entry through the UI | No delete button or delete functionality is available for audit log entries |
| 7 | Administrator attempts to use direct API call to delete the audit log entry | System prevents deletion and returns error response: 'Audit log entries cannot be deleted', HTTP status 403 Forbidden |
| 8 | System logs the unauthorized deletion attempt | New audit log entry is created documenting the attempted deletion with Action Type: 'Unauthorized Audit Deletion Attempt', User: administrator username, Timestamp: current date/time |
| 9 | Administrator searches audit logs for unauthorized access attempts | Both unauthorized modification and deletion attempts are displayed in audit logs with complete details |

**Postconditions:**
- Original audit log entry remains unchanged and intact
- All unauthorized access attempts are logged in audit trail
- System security controls prevented tampering
- Audit log integrity is maintained

---

### Test Case: Test audit log export functionality
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- Administrator is logged into the admin portal with valid credentials
- Administrator has admin role permissions
- AuditLogs table contains multiple audit entries
- Export functionality is enabled and operational
- Administrator has appropriate file download permissions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to audit logs section | Audit logs page is displayed with existing audit entries and export options |
| 2 | Administrator applies filters to select specific audit logs (e.g., date range: last 7 days, action type: Workflow Modified) | Filtered audit log entries are displayed matching the selected criteria within 5 seconds |
| 3 | Administrator clicks 'Export' button and selects 'CSV' format | Export dialog appears confirming CSV format selection with estimated record count |
| 4 | Administrator confirms CSV export | System processes export request and CSV file begins downloading within 5 seconds |
| 5 | Administrator opens the downloaded CSV file | CSV file opens successfully and contains all filtered audit log entries with columns: Timestamp, User, Action Type, Details, IP Address, Session ID. Data matches the displayed audit logs exactly |
| 6 | Administrator verifies data integrity in CSV by comparing sample entries with UI display | All data in CSV matches corresponding entries in the audit logs UI with correct formatting and no data loss |
| 7 | Administrator returns to audit logs page and clicks 'Export' button, then selects 'PDF' format | Export dialog appears confirming PDF format selection with estimated record count |
| 8 | Administrator confirms PDF export | System processes export request and PDF file begins downloading within 5 seconds |
| 9 | Administrator opens the downloaded PDF file | PDF file opens successfully and displays formatted audit log entries with proper headers, company branding, page numbers, and export timestamp |
| 10 | Administrator verifies data completeness in PDF by reviewing entries and comparing with UI display | PDF contains all filtered audit log entries with proper formatting, readable text, and organized layout. Data matches the audit logs UI exactly |
| 11 | Administrator checks audit logs for export actions | New audit log entries are created documenting both export actions with Action Type: 'Audit Log Exported', Format: CSV/PDF, User: administrator username, Record Count, Timestamp |

**Postconditions:**
- CSV file is successfully downloaded with correct audit data
- PDF file is successfully downloaded with formatted audit data
- Both export actions are logged in audit trail
- Exported data matches source audit logs exactly
- Files are available in administrator's download folder

---

## Story: As Administrator, I want to manage user roles and permissions for schedule change approval workflows to ensure secure access
**Story ID:** story-9

### Test Case: Validate creation and assignment of user roles
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Administrator is logged into the user management portal
- Administrator has valid authentication credentials with admin privileges
- UserRoles and Permissions tables are accessible
- At least one user account exists in the system for role assignment

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the user management portal and access the roles management section | Roles management interface is displayed with options to create, edit, and delete roles |
| 2 | Click on 'Create New Role' button | Role creation form is displayed with fields for role name and permissions selection |
| 3 | Enter role name 'Scheduler' in the role name field | Role name is accepted and displayed in the input field |
| 4 | Select specific permissions: 'Submit Schedule Changes' and 'View Schedule History' from the permissions list | Selected permissions are highlighted and marked as assigned to the role |
| 5 | Click 'Save Role' button | Role 'Scheduler' is created successfully, confirmation message is displayed, and role appears in the roles list with assigned permissions within 3 seconds |
| 6 | Navigate to the user assignment section for the newly created 'Scheduler' role | User assignment interface is displayed showing available users and currently assigned users |
| 7 | Select a user from the available users list and click 'Assign to Role' button | User is successfully assigned to the 'Scheduler' role and appears in the assigned users list |
| 8 | Log out as administrator and log in as the newly assigned user | User successfully logs in and can access schedule change submission features according to assigned permissions |
| 9 | Verify the user can submit schedule changes but cannot approve them | User can access and use the schedule change submission feature but approval features are not visible or accessible |

**Postconditions:**
- New 'Scheduler' role exists in the system with defined permissions
- User is assigned to the 'Scheduler' role
- User can access features according to role permissions
- Role creation is logged in the audit trail

---

### Test Case: Verify audit logging of role changes
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Administrator is logged into the user management portal
- At least one user role exists in the system (e.g., 'Approver' role)
- Audit logging system is enabled and functioning
- Administrator has permissions to view audit logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the roles management section and select an existing role 'Approver' | Role details are displayed showing current permissions and assigned users |
| 2 | Click 'Edit Role' button for the 'Approver' role | Role editing form is displayed with current permissions pre-selected |
| 3 | Add a new permission 'Configure Approval Workflows' to the existing permissions | New permission is selected and highlighted in the permissions list |
| 4 | Click 'Save Changes' button | Role permissions are updated successfully, confirmation message is displayed within 3 seconds |
| 5 | Navigate to the audit logs section of the user management portal | Audit logs interface is displayed with search and filter options |
| 6 | Filter audit logs by 'Role Changes' and search for the 'Approver' role modification | Audit log entry is displayed showing the role modification event |
| 7 | Verify the audit log entry contains the administrator username who made the change | Audit log displays the correct administrator username |
| 8 | Verify the audit log entry contains the accurate timestamp of the change | Audit log displays the timestamp matching the time when the change was saved |
| 9 | Verify the audit log entry contains details of the permission added | Audit log shows 'Configure Approval Workflows' permission was added to 'Approver' role |

**Postconditions:**
- Role permissions are updated in the system
- Audit log entry exists with 100% accuracy including user, timestamp, and change details
- Audit trail maintains data integrity

---

### Test Case: Test enforcement of role-based access control
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Multiple user roles exist in the system (e.g., 'Scheduler', 'Approver', 'Administrator')
- A test user account exists with 'Scheduler' role assigned (no approval permissions)
- Schedule change approval features are configured and accessible to authorized roles
- Role-based access control is enabled system-wide

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as a user with 'Scheduler' role (no approval permissions) | User successfully logs in and is authenticated |
| 2 | Navigate to the schedule management section | Schedule management interface is displayed with features available to the 'Scheduler' role |
| 3 | Attempt to access the 'Approve Schedule Changes' feature by clicking on the approval menu or directly navigating to the approval URL | Access is denied and an error message is displayed: 'Access Denied: You do not have permission to access this feature' |
| 4 | Verify that approval-related buttons and menu items are not visible in the user interface | Approval features are hidden from the navigation menu and interface for users without approval permissions |
| 5 | Attempt to access the approval feature using direct API endpoint call (POST /api/schedule-approvals) | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 6 | Log out and log in as a user with 'Approver' role | User with 'Approver' role successfully logs in |
| 7 | Navigate to the 'Approve Schedule Changes' feature | Approval feature is accessible and displays pending schedule changes for approval |
| 8 | Verify the access attempt by the 'Scheduler' role user is logged in the security audit trail | Security log contains entry showing unauthorized access attempt with user details and timestamp |

**Postconditions:**
- Unauthorized access is prevented and logged
- Role-based access control is enforced across all schedule change approval features
- No security breach or unauthorized data access occurred
- Users can only access features appropriate to their assigned roles

---

