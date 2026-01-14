# Manual Test Cases

## Story: As Administrator, I want to configure approval workflows to achieve flexible schedule change approvals
**Story ID:** story-2

### Test Case: Validate creation of multi-level approval workflow
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Administrator account with valid credentials exists
- Administrator has role-based access to workflow configuration
- System is accessible and operational
- ApprovalWorkflows and Approvers tables are available
- At least one role and department exist in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator logs into the system using valid credentials | Administrator is successfully authenticated and redirected to the dashboard |
| 2 | Administrator navigates to workflow configuration page from the main menu | Configuration UI is displayed with options to create, edit, and view workflows |
| 3 | Administrator clicks on 'Create New Workflow' button | New workflow creation form is displayed with fields for workflow name, description, and approval levels |
| 4 | Administrator enters workflow name as 'Schedule Change Approval - Level 3' and description | Workflow name and description are accepted and displayed in the form |
| 5 | Administrator adds first approval level by clicking 'Add Level' and sets level name as 'Team Lead Approval' | First approval level is created and displayed in the workflow hierarchy |
| 6 | Administrator adds second approval level with name 'Department Manager Approval' | Second approval level is created and displayed below the first level in the hierarchy |
| 7 | Administrator adds third approval level with name 'HR Director Approval' | Third approval level is created and displayed below the second level, forming a multi-level workflow |
| 8 | Administrator assigns approvers to first level by selecting role 'Team Lead' from dropdown | Team Lead role is assigned to first approval level and displayed in the approvers list |
| 9 | Administrator assigns approvers to second level by selecting role 'Department Manager' | Department Manager role is assigned to second approval level and displayed in the approvers list |
| 10 | Administrator assigns approvers to third level by selecting role 'HR Director' | HR Director role is assigned to third approval level and all approvers are validated and displayed |
| 11 | Administrator clicks 'Save Workflow' button | System validates the workflow configuration and displays success message 'Workflow created successfully' |
| 12 | Administrator verifies the workflow appears in the workflow list | Newly created multi-level workflow is displayed in the workflow list with all configured levels and approvers |

**Postconditions:**
- Multi-level approval workflow is saved in ApprovalWorkflows table
- Approver assignments are stored in Approvers table
- Workflow is active and available for schedule change requests
- Configuration change is logged in audit trail with administrator details and timestamp

---

### Test Case: Verify prevention of circular references in workflow configuration
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Administrator is logged into the system
- Administrator has access to workflow configuration page
- System validation rules for circular references are active
- At least one existing workflow or approval level exists for reference

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page | Workflow configuration page is displayed with existing workflows and create/edit options |
| 2 | Administrator clicks 'Create New Workflow' button | New workflow creation form is displayed |
| 3 | Administrator enters workflow name as 'Circular Test Workflow' | Workflow name is accepted and displayed |
| 4 | Administrator creates first approval level 'Level A' and assigns it to route to 'Level B' | Level A is created with routing to Level B configured |
| 5 | Administrator creates second approval level 'Level B' and assigns it to route to 'Level C' | Level B is created with routing to Level C configured |
| 6 | Administrator creates third approval level 'Level C' and attempts to route it back to 'Level A' | System detects circular reference in the routing configuration |
| 7 | Administrator clicks 'Save Workflow' button | System displays validation error message 'Circular reference detected: Level C cannot route back to Level A. Please correct the workflow routing.' and prevents save operation |
| 8 | Administrator reviews the error message and modifies Level C routing to 'End Workflow' instead of Level A | Level C routing is updated to end the workflow without circular reference |
| 9 | Administrator clicks 'Save Workflow' button again | System validates the corrected workflow successfully and displays success message 'Workflow saved successfully' |
| 10 | Administrator verifies the workflow is saved and appears in the workflow list | Corrected workflow is displayed in the workflow list without circular references |

**Postconditions:**
- Workflow with corrected routing is saved in the database
- No circular references exist in the workflow configuration
- Validation error and correction are logged in audit trail
- Workflow is ready for use in schedule change approvals

---

### Test Case: Ensure workflow changes apply without downtime
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Administrator is logged into the system
- At least one active approval workflow exists and is in use
- Multiple users are actively submitting schedule change requests
- System is under normal operational load
- Performance monitoring tools are available to verify no downtime

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page | Workflow configuration page is displayed with list of existing workflows |
| 2 | Administrator selects an existing active workflow 'Standard Schedule Change Approval' from the list | Workflow details are displayed with current configuration including approval levels and approvers |
| 3 | Administrator clicks 'Edit Workflow' button | Workflow editing interface is displayed with all current settings editable |
| 4 | Administrator modifies the workflow by adding a new approval level 'Senior Manager Review' between existing levels | New approval level is inserted in the workflow hierarchy at the specified position |
| 5 | Administrator assigns 'Senior Manager' role to the new approval level | Senior Manager role is assigned and displayed in the approvers list for the new level |
| 6 | Administrator clicks 'Save Changes' button | System displays confirmation message 'Workflow changes are being applied' and processes the update |
| 7 | System applies the workflow changes dynamically | Changes are accepted and applied within 5 seconds, confirmation message 'Workflow updated successfully' is displayed |
| 8 | Verify that users continue to submit schedule change requests during the workflow modification | Users can submit schedule change requests without interruption or error messages |
| 9 | Monitor system for any downtime indicators or error logs during the workflow update | No downtime occurs, no error messages are logged, and system remains fully operational |
| 10 | Verify that new schedule change requests submitted after the update use the modified workflow | New requests are routed through the updated workflow including the new Senior Manager Review level |
| 11 | Verify that in-progress requests continue processing with their original workflow configuration | Existing in-progress requests complete using the workflow version they started with, ensuring no disruption |

**Postconditions:**
- Modified workflow is active and applied to new schedule change requests
- Zero downtime occurred during workflow modification
- All user submissions during update were processed successfully
- Workflow change is logged in audit trail with timestamp
- System performance remains within acceptable parameters

---

## Story: As System Administrator, I want to manage user roles and permissions for schedule change approval workflows to ensure secure access
**Story ID:** story-8

### Test Case: Validate role assignment and permission enforcement
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- System Administrator account with valid credentials exists
- System Administrator has access to user management section
- Test user account exists in the system without Approver role
- Approver role is defined with specific permissions for approval actions
- UserRoles and Permissions tables are accessible
- At least one schedule change request is available for approval testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | System Administrator logs into the admin portal using valid credentials | Administrator is successfully authenticated and redirected to the admin dashboard |
| 2 | System Administrator navigates to user management section from the admin menu | User management interface is displayed with list of users and role management options |
| 3 | System Administrator searches for the test user by username or email | Test user profile is displayed with current role assignments and permissions |
| 4 | System Administrator clicks 'Edit Roles' button for the test user | Role assignment interface is displayed showing available roles including Employee, Approver, Manager, and Administrator |
| 5 | System Administrator selects 'Approver' role from the available roles list | Approver role is highlighted and selected for assignment |
| 6 | System Administrator clicks 'Save Changes' button | System processes the role assignment and displays success message 'Role assigned successfully' |
| 7 | System Administrator verifies the Approver role appears in the user's role list | Approver role is displayed in the user's assigned roles with associated permissions listed |
| 8 | Verify that role change takes effect within 1 minute by checking system timestamp | Role assignment timestamp confirms changes are applied immediately and within the 1-minute SLA |
| 9 | Test user logs into the system with their credentials | Test user is successfully authenticated and can access the system |
| 10 | Test user navigates to schedule change approval queue | Approval queue is displayed with pending schedule change requests available for review |
| 11 | Test user selects a pending schedule change request from the queue | Request details are displayed with approval action buttons (Approve/Reject) enabled |
| 12 | Test user attempts to approve the schedule change request by clicking 'Approve' button | Approval action is allowed and processed successfully based on assigned Approver permissions |
| 13 | Test user verifies the request status changes to 'Approved' | Request status is updated to 'Approved' and user receives confirmation message 'Schedule change approved successfully' |

**Postconditions:**
- Test user has Approver role assigned in UserRoles table
- Approver permissions are enforced for the test user
- Test user can perform approval actions on schedule change requests
- Role assignment is logged in audit trail with administrator details and timestamp
- Schedule change request status is updated based on approval action

---

### Test Case: Verify audit logging of role changes
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- System Administrator is logged into the admin portal
- Audit logging functionality is enabled and operational
- Test user account exists in the system
- Administrator has access to audit log retrieval interface
- System clock is synchronized for accurate timestamp recording

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | System Administrator navigates to user management section | User management interface is displayed with list of users |
| 2 | System Administrator selects the test user from the user list | Test user profile is displayed with current role assignments |
| 3 | System Administrator notes the current roles assigned to the test user (e.g., 'Employee') | Current role 'Employee' is visible in the user's role list |
| 4 | System Administrator clicks 'Edit Roles' button | Role assignment interface is displayed with available roles |
| 5 | System Administrator adds 'Manager' role to the test user's existing roles | Manager role is selected and added to the user's role assignment |
| 6 | System Administrator clicks 'Save Changes' button and notes the exact timestamp | Role modification is saved successfully with confirmation message and timestamp displayed |
| 7 | System logs the role change event with user identifier, administrator identifier, timestamp, old role, and new role | Change is logged automatically in the audit log system with all required details |
| 8 | System Administrator navigates to audit log section from the admin menu | Audit log interface is displayed with search and filter options |
| 9 | System Administrator filters audit logs by user identifier for the test user and event type 'Role Change' | Filtered audit log entries are displayed showing role change events for the test user |
| 10 | System Administrator retrieves the most recent audit log entry for the role change | Audit log entry is displayed with complete details of the role modification |
| 11 | System Administrator verifies the audit log entry contains user identifier (test user) | Entry contains accurate user identifier matching the test user |
| 12 | System Administrator verifies the audit log entry contains administrator identifier (performing admin) | Entry contains accurate administrator identifier matching the logged-in administrator |
| 13 | System Administrator verifies the audit log entry contains accurate timestamp matching the save time | Entry contains timestamp matching the time when role change was saved |
| 14 | System Administrator verifies the audit log entry contains old role value ('Employee') and new role value ('Employee, Manager') | Entry contains accurate details showing role change from 'Employee' to 'Employee, Manager' |

**Postconditions:**
- Role change is successfully applied to the test user
- Audit log entry is created and stored in the audit database
- Audit log contains complete and accurate details of the role modification
- Audit trail is available for compliance and security review
- No data integrity issues in audit logging system

---

### Test Case: Ensure unauthorized users cannot access role management
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Test user account exists with non-administrator role (e.g., Employee or Approver)
- Role-based access control is enabled and enforced
- User role management UI requires Administrator role for access
- Authentication and authorization mechanisms are operational
- Test user has valid login credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Non-administrator test user logs into the system using valid credentials | Test user is successfully authenticated and redirected to the standard user dashboard |
| 2 | Test user attempts to navigate to user role management UI by entering the direct URL in the browser | System detects unauthorized access attempt and blocks navigation to the role management page |
| 3 | System performs authorization check against the user's assigned roles | Authorization check fails as user does not have Administrator role |
| 4 | System denies access and displays appropriate error message | Access is denied and error message 'Access Denied: You do not have permission to access user role management. Administrator privileges required.' is displayed |
| 5 | Test user is redirected to the previous page or dashboard | User is redirected to their standard dashboard without accessing role management functionality |
| 6 | Test user checks the main navigation menu for role management options | User role management option is not visible in the navigation menu for non-administrator users |
| 7 | Test user attempts to access role management via API endpoint directly using browser developer tools or API client | API request is intercepted by authorization middleware |
| 8 | System validates API request authorization and checks user permissions | Authorization validation fails and API returns HTTP 403 Forbidden status code |
| 9 | System logs the unauthorized access attempt with user identifier, timestamp, and attempted resource | Unauthorized access attempt is logged in security audit trail with all relevant details |
| 10 | Verify that no role management data or functionality is exposed to the unauthorized user | No sensitive role or permission data is returned or displayed to the non-administrator user |

**Postconditions:**
- Non-administrator user remains unable to access role management functionality
- No unauthorized changes are made to user roles or permissions
- Unauthorized access attempt is logged in security audit trail
- System security and access control integrity is maintained
- User session remains active but restricted to authorized functions only

---

