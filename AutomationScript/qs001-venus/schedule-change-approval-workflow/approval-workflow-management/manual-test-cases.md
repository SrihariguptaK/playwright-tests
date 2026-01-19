# Manual Test Cases

## Story: As Approver, I want to review schedule change requests to achieve informed decision-making
**Story ID:** story-24

### Test Case: Verify approver can view and act on pending schedule change requests
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User account with approver role exists in the system
- At least one pending schedule change request is assigned to the approver
- Request contains complete details and at least one attachment
- System is accessible and all services are running
- Database contains valid test data in ScheduleChangeRequests table

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid approver credentials | User is successfully authenticated and redirected to the home page |
| 2 | Click on 'Pending Approvals' menu item or navigate to the pending approvals dashboard | Pending approvals dashboard loads within 3 seconds and displays all assigned pending requests with request ID, requester name, request date, and status |
| 3 | Select a specific pending schedule change request from the list by clicking on it | Request details page opens showing complete information including requester details, requested changes, reason, submission date, and all attached documents |
| 4 | Click on attachment links to verify accessibility | Attachments open or download successfully without errors |
| 5 | Click the 'Approve' button to initiate approval action | Comment dialog box appears prompting for optional comments |
| 6 | Enter comment 'Approved as requested - meets all policy requirements' in the comment field | Comment text is accepted and displayed in the input field |
| 7 | Click 'Submit' or 'Confirm' button to finalize the approval | Success message is displayed confirming approval action, request status updates to 'Approved', action is logged in ApprovalActions table with timestamp and approver details, and request is removed from pending list |

**Postconditions:**
- Request status is updated to 'Approved' in the database
- Approval action is logged with timestamp, approver ID, and comments in ApprovalActions table
- Request no longer appears in the approver's pending list
- Audit trail is complete and traceable
- Requester can view the updated status

---

### Test Case: Ensure unauthorized users cannot approve requests
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User account without approver role exists in the system
- At least one pending schedule change request exists
- Role-based access control is configured and active
- API endpoints are protected with authorization checks

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter credentials for a user without approver role (e.g., regular employee) | User is successfully authenticated and redirected to the home page |
| 2 | Attempt to navigate to 'Pending Approvals' dashboard via URL or menu | Access is denied with error message 'You do not have permission to access this page' or 'Pending Approvals' menu item is not visible |
| 3 | Attempt to directly access a specific approval request URL if known | System redirects to error page or displays 'Access Denied' message with HTTP 403 status |
| 4 | Using API testing tool (e.g., Postman), attempt to call GET /api/approvals/pending with non-approver user token | API returns HTTP 403 Forbidden status with error message indicating insufficient permissions |
| 5 | Using API testing tool, attempt to call POST /api/approvals/decisions with non-approver user token and valid request payload | API returns HTTP 403 Forbidden or 401 Unauthorized status with authorization error message, and no changes are made to the request status |

**Postconditions:**
- No approval actions are recorded in the system
- Request status remains unchanged
- Security violation attempt is logged in audit trail
- No unauthorized access is granted to approval functionality

---

### Test Case: Validate rejection and request for additional information flows
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User account with approver role exists and is logged in
- At least two pending schedule change requests are assigned to the approver
- System is accessible and all services are running
- Database is in consistent state

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the pending approvals dashboard, select the first pending schedule change request | Request details page opens displaying complete request information including all fields and attachments |
| 2 | Click the 'Reject' button to initiate rejection action | Comment dialog box appears with mandatory comment field indicated |
| 3 | Enter rejection comment 'Request does not comply with company policy section 4.2 - insufficient justification provided' | Comment text is accepted and displayed in the input field |
| 4 | Click 'Submit' or 'Confirm' button to finalize the rejection | Success message is displayed, request status updates to 'Rejected', rejection action is logged in ApprovalActions table with timestamp, approver ID, and comments, and request is removed from pending list |
| 5 | Navigate back to pending approvals dashboard and select a second pending request | Second request details page opens displaying complete information |
| 6 | Click the 'Request Additional Information' button | Comment dialog box appears prompting for details about what additional information is needed |
| 7 | Enter comment 'Please provide supporting documentation from your manager and clarify the business justification for the schedule change' | Comment text is accepted and displayed in the input field |
| 8 | Click 'Submit' or 'Confirm' button to send the request for additional information | Success message is displayed, request status updates to 'Additional Information Required' or 'Pending Requester', action is logged in ApprovalActions table with timestamp, approver ID, and comments, and request is removed from approver's pending list |
| 9 | Verify the audit trail by accessing request history for both requests | Complete history is displayed showing all actions with timestamps, approver names, status changes, and comments for both rejected and information-requested actions |

**Postconditions:**
- First request status is 'Rejected' with rejection comments logged
- Second request status is 'Additional Information Required' with comments logged
- Both actions are recorded in ApprovalActions table with complete audit information
- Requesters can view updated statuses and comments
- Both requests are removed from approver's pending list
- Audit trail shows 100% completeness for all actions

---

## Story: As System Administrator, I want to configure approval workflow rules to achieve flexible and compliant routing
**Story ID:** story-25

### Test Case: Validate creation and activation of approval workflow rules
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User account with system administrator role exists in the system
- Admin console is accessible
- At least two approver users exist in the system with assigned roles
- WorkflowConfig tables are accessible and in consistent state
- No conflicting workflow rules exist for the test scenario

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the admin console login page and enter valid system administrator credentials | Administrator is successfully authenticated and redirected to the admin console home page |
| 2 | Click on 'Approval Workflow Configuration' menu item or navigate to workflow configuration section | Workflow configuration UI is displayed showing existing workflows and a 'Create New Workflow' button |
| 3 | Click 'Create New Workflow' or 'Add Workflow Rule' button | Workflow creation form is displayed with fields for workflow name, description, conditions, and approver assignment |
| 4 | Enter workflow name 'Schedule Change - Manager Approval', description 'Requires manager approval for schedule changes up to 5 days' | Workflow name and description are accepted and displayed in the form fields |
| 5 | Configure condition: Set 'Request Type' equals 'Schedule Change' AND 'Duration' less than or equal to '5 days' | Conditional rules are added and displayed in the conditions section with proper logical operators |
| 6 | In the approver section, select 'Direct Manager' as Level 1 approver from the dropdown | Direct Manager is assigned as Level 1 approver and displayed in the workflow chain |
| 7 | Click 'Validate' button to check workflow configuration | System validates the workflow and displays success message 'Workflow configuration is valid - no errors detected' |
| 8 | Click 'Save' button to save the workflow rule | Workflow rule is saved to WorkflowConfig table, success message is displayed, and workflow appears in the list with 'Inactive' status |
| 9 | Select the newly created workflow from the list and click 'Activate' button | Confirmation dialog appears asking to confirm activation |
| 10 | Click 'Confirm' to activate the workflow | Workflow status changes to 'Active', success message confirms activation, and workflow becomes effective immediately |
| 11 | Create a test schedule change request matching the workflow conditions (schedule change for 3 days) | Request is automatically routed to Direct Manager for approval based on the newly activated workflow rule, confirming the rule is applied to new requests |

**Postconditions:**
- New workflow rule is saved in WorkflowConfig table with active status
- Workflow configuration is validated without errors
- Workflow is active and applies to new matching requests
- Changes propagate within 1 minute
- Audit log records workflow creation and activation with administrator details and timestamps

---

### Test Case: Ensure validation prevents circular routing in workflow rules
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User account with system administrator role is logged into admin console
- Workflow configuration UI is accessible
- At least three approver roles exist in the system (e.g., Manager, Director, VP)
- Validation rules for circular dependency detection are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to 'Approval Workflow Configuration' section in admin console | Workflow configuration UI is displayed with option to create new workflow |
| 2 | Click 'Create New Workflow' button to start creating a new workflow rule | Workflow creation form is displayed with all configuration fields |
| 3 | Enter workflow name 'Circular Test Workflow' and description 'Testing circular routing validation' | Workflow name and description are accepted |
| 4 | Configure multi-level approval chain: Set Level 1 approver as 'Manager', Level 2 as 'Director', Level 3 as 'VP' | Three-level approval chain is configured and displayed |
| 5 | Attempt to add Level 4 approver and select 'Manager' (same as Level 1), creating a circular reference | Approver is added to the configuration temporarily |
| 6 | Click 'Validate' or 'Save' button to validate the workflow configuration | System detects circular routing and displays validation error message 'Error: Circular routing detected - Manager appears multiple times in the approval chain' or similar, preventing save operation |
| 7 | Attempt to configure escalation rule where escalation routes back to a previous level approver | Configuration is temporarily accepted in the UI |
| 8 | Click 'Validate' or 'Save' button | System detects circular escalation path and displays validation error 'Error: Circular escalation detected - escalation path creates an infinite loop', preventing save operation |
| 9 | Verify that the workflow is not saved by checking the workflow list | Invalid workflow does not appear in the saved workflows list, confirming save was prevented |

**Postconditions:**
- No workflow with circular routing is saved to the database
- Validation error messages are clearly displayed to the administrator
- WorkflowConfig table remains in consistent state without invalid rules
- System integrity is maintained
- Error is logged in system logs for audit purposes

---

### Test Case: Verify access restriction to workflow configuration
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User account without administrator role exists (e.g., regular employee or approver role only)
- Workflow configuration section exists and is protected by role-based access control
- Admin console is accessible
- Security policies are properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter credentials for a non-administrator user (e.g., regular employee) | User is successfully authenticated and redirected to appropriate home page based on their role |
| 2 | Attempt to access admin console by clicking admin menu or navigating to admin URL | Admin console menu is not visible or access is denied with error message 'Access Denied: Administrator privileges required' |
| 3 | Attempt to directly navigate to workflow configuration URL (e.g., /admin/workflow-config) by typing in browser address bar | System redirects to error page or displays 'Access Denied' message with HTTP 403 Forbidden status, preventing access to workflow configuration |
| 4 | Using API testing tool (e.g., Postman), attempt to call GET /api/workflow-config with non-admin user authentication token | API returns HTTP 403 Forbidden status with error message 'Insufficient permissions - Administrator role required' |
| 5 | Using API testing tool, attempt to call POST /api/workflow-config with non-admin user token and valid workflow configuration payload | API returns HTTP 403 Forbidden or 401 Unauthorized status with appropriate error message, and no workflow configuration changes are made to the database |
| 6 | Verify audit logs for unauthorized access attempts | All unauthorized access attempts are logged in security audit trail with user ID, timestamp, attempted action, and denial reason |

**Postconditions:**
- No workflow configuration changes are made by non-admin user
- WorkflowConfig table remains unchanged
- All unauthorized access attempts are logged in security audit trail
- System security is maintained
- User receives clear error messages indicating lack of permissions

---

