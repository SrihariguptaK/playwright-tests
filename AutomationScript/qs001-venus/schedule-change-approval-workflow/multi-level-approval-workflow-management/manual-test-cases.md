# Manual Test Cases

## Story: As Manager, I want to review and approve schedule change requests to maintain operational continuity
**Story ID:** story-2

### Test Case: Validate manager can view and approve pending requests
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Manager user account exists with valid credentials and approval permissions
- At least one pending schedule change request is assigned to the manager
- System is accessible and operational
- Manager has active session or can authenticate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid manager credentials (username and password), then click Login button | Manager is successfully authenticated and redirected to the approval dashboard showing a list of pending schedule change requests with request ID, employee name, requested change details, and submission date |
| 2 | Select a pending request from the list by clicking on the request row or view details button | Request details page opens displaying complete information including employee details, current schedule, requested schedule, reason for change, submission timestamp, and request history with all previous actions |
| 3 | Review the request details, enter an approval comment in the comment field (e.g., 'Approved - adequate coverage available'), and click the Approve button | System processes the approval, request status updates to 'Approved', confirmation message is displayed (e.g., 'Request approved successfully'), approval action is logged with timestamp and manager details, and the request is removed from pending list or marked as approved |

**Postconditions:**
- Request status is updated to 'Approved' in the database
- Approval action is logged in audit trail with timestamp and manager ID
- Requester receives notification of approval
- Request no longer appears in pending approvals list
- Schedule change is ready for implementation

---

### Test Case: Verify rejection with mandatory comment enforcement
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Manager user is logged into the system with valid approval permissions
- At least one pending schedule change request exists and is assigned to the manager
- Approval dashboard is accessible
- Mandatory comment validation is enabled in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the approval dashboard, select a pending schedule change request by clicking on it | Request details page opens displaying all request information including employee name, current schedule, requested changes, reason for request, and submission details |
| 2 | Without entering any text in the comment field, click the Reject button | System prevents the rejection action, displays a validation error message (e.g., 'Comment is required to reject a request'), the comment field is highlighted in red or marked as required, and the request status remains unchanged as 'Pending' |
| 3 | Enter a meaningful rejection comment in the comment field (e.g., 'Rejected - insufficient coverage during requested period') and click the Reject button | System accepts the rejection, request status updates to 'Rejected', confirmation message is displayed (e.g., 'Request rejected successfully'), rejection action is logged with timestamp and comment, notification is sent to the requester with rejection reason, and request is removed from pending list or marked as rejected |

**Postconditions:**
- Request status is updated to 'Rejected' in the database
- Rejection comment is saved and associated with the request
- Rejection action is logged in audit trail with timestamp, manager ID, and comment
- Requester receives notification with rejection reason
- Request no longer appears in pending approvals list
- Original schedule remains unchanged

---

### Test Case: Ensure escalation triggers after SLA breach
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Escalation workflow is configured with defined SLA time threshold
- Next level approver is configured in the escalation chain
- A pending schedule change request exists that has exceeded the SLA time threshold
- Notification system is operational
- Test environment allows time simulation or actual SLA breach scenario exists

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate or wait for a pending approval request to exceed the configured SLA time threshold (e.g., 24 hours) without any action from the assigned manager | System automatically detects the SLA breach, triggers escalation workflow, generates escalation notification to the next level approver (e.g., senior manager or department head), and logs the escalation event with timestamp in the audit trail |
| 2 | Log in as the next level approver and navigate to the approval dashboard or check notification inbox (email/system notification) | Escalation notification is successfully received by the next approver, notification clearly indicates the request has been escalated due to SLA breach, notification includes request details and original submission time, and the escalated request appears in the next approver's pending list marked as 'Escalated' |
| 3 | As the next level approver, select the escalated request, review details, enter a comment (e.g., 'Approved after escalation - coverage confirmed'), and click Approve or Reject button | System processes the approval/rejection action, request status updates accordingly to 'Approved' or 'Rejected', escalation is marked as resolved, confirmation message is displayed, action is logged with escalation context in audit trail, and notifications are sent to both the original requester and the original assigned manager |

**Postconditions:**
- Escalation event is logged in the system with complete audit trail
- Request status is updated based on next approver's action
- All relevant parties are notified of the final decision
- Escalation metrics are updated for reporting
- SLA breach is recorded for performance tracking
- Request is removed from pending lists

---

## Story: As System Administrator, I want to configure approval workflows to tailor schedule change processes to organizational needs
**Story ID:** story-3

### Test Case: Validate creation of new approval workflow
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- System Administrator account exists with valid credentials and workflow configuration permissions
- Admin portal is accessible and operational
- At least one user role and individual user exist in the system for approver assignment
- Database has capacity to store new workflow configurations

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the admin portal using administrator credentials and navigate to the workflow configuration page by selecting 'Approval Workflows' from the admin menu | Workflow configuration page loads successfully displaying a list of existing workflows (if any) with columns showing workflow name, number of steps, status, and last modified date, and a 'Create New Workflow' button is visible and enabled |
| 2 | Click the 'Create New Workflow' button, enter workflow name (e.g., 'Department Schedule Change Workflow'), add multiple approval steps (e.g., Step 1: Direct Manager, Step 2: Department Head, Step 3: HR Manager), assign approvers to each step by selecting roles or individual users from dropdown menus, and configure step properties (sequential/parallel, required/optional) | Workflow creation form accepts all inputs, approval steps are added in the specified order, approvers are successfully assigned to each step with their names/roles displayed, workflow configuration is saved to the database, success message is displayed (e.g., 'Workflow created successfully'), and the new workflow appears in the workflow list with status 'Active' and correct details including name, number of steps, and assigned approvers |
| 3 | Select the newly created workflow from the list and click 'Validate Configuration' button or trigger automatic validation | System performs validation checks on the workflow configuration, confirms no validation errors exist (no circular dependencies, all steps have assigned approvers, no incomplete configurations), displays validation success message (e.g., 'Workflow configuration is valid'), workflow status remains 'Active', and workflow is ready to be applied to schedule change requests |

**Postconditions:**
- New workflow is saved in ApprovalWorkflows table with all configuration details
- Workflow is marked as active and available for assignment to request types
- All approval steps and approver assignments are stored correctly
- Workflow appears in the list of available workflows for selection
- Audit log records workflow creation with administrator ID and timestamp
- Workflow can be applied to new schedule change requests

---

### Test Case: Verify prevention of circular workflow configurations
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- System Administrator is logged into the admin portal with workflow configuration permissions
- Workflow configuration page is accessible
- Circular dependency validation logic is implemented and active
- System has validation rules to detect workflow loops

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to workflow configuration page, click 'Create New Workflow' or edit an existing workflow, and attempt to create a circular approval chain by configuring steps where Step 1 escalates to Step 2, Step 2 escalates to Step 3, and Step 3 escalates back to Step 1, then click Save or Validate button | System detects the circular dependency during validation, prevents the workflow from being saved, displays a clear and descriptive error message (e.g., 'Circular dependency detected: Step 3 cannot escalate to Step 1 as it creates a loop. Please review your workflow configuration.'), highlights the problematic steps in the configuration interface, and workflow status remains 'Draft' or 'Invalid' |
| 2 | Modify the workflow configuration to remove the circular dependency by changing Step 3 escalation to a different approver or removing the escalation back to Step 1, ensuring a linear or valid branching approval path, then click Save or Validate button | System validates the modified workflow configuration, confirms no circular dependencies exist, accepts and saves the configuration successfully, displays success message (e.g., 'Workflow saved successfully'), workflow status updates to 'Active', and the workflow is now available for use with schedule change requests |

**Postconditions:**
- Invalid circular workflow configuration is not saved in the database
- Valid workflow configuration is saved and marked as active
- Validation error is logged for audit purposes
- Administrator is informed of the issue and resolution
- System maintains data integrity by preventing invalid workflows
- Only valid workflow is available for assignment to requests

---

### Test Case: Ensure escalation rules are configurable and saved
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System Administrator is logged into the admin portal with workflow configuration permissions
- At least one approval workflow exists or can be created
- Escalation configuration interface is available
- Time threshold configuration options are implemented
- Escalation engine is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to workflow configuration page, select an existing workflow or create a new one, access the escalation rules section, configure escalation time thresholds for each approval step (e.g., Step 1: escalate after 24 hours, Step 2: escalate after 48 hours), specify escalation targets (next level approver or specific role), and click Save button | System accepts the escalation rule configurations, time thresholds are saved with correct values for each step, escalation targets are properly assigned, success message is displayed (e.g., 'Escalation rules saved successfully'), escalation rules are stored in the database associated with the workflow, and the workflow configuration page displays the saved escalation rules with correct time thresholds and targets |
| 2 | Create or use an existing schedule change request that uses the configured workflow, allow the request to remain pending without action from the assigned approver until the configured escalation time threshold is reached (simulate time passage or wait for actual threshold), and monitor the system for escalation trigger | System automatically monitors pending approval time, detects when the configured time threshold is exceeded, triggers the escalation process as per the saved rules, escalation notification is sent to the designated next level approver or escalation target, escalation event is logged in the audit trail with timestamp and reason, request status is updated to show 'Escalated', and the escalated request appears in the escalation target's approval queue with escalation indicator |

**Postconditions:**
- Escalation rules are permanently saved in the workflow configuration
- Escalation thresholds are actively monitored for all requests using the workflow
- Escalation triggers function according to configured time thresholds
- All escalation events are logged in audit trail
- Escalation notifications are delivered to correct approvers
- Workflow configuration includes complete escalation rule details
- System demonstrates that configured escalation rules are operational and effective

---

