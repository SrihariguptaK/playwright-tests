# Manual Test Cases

## Story: As Approver, I want to review schedule change requests to achieve timely and accurate approval decisions
**Story ID:** story-2

### Test Case: Validate viewing and decision making on pending approvals
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Approver user account exists with valid credentials
- Approver has been assigned appropriate role and permissions
- At least one pending schedule change request is assigned to the approver
- System is accessible and all services are running
- Database contains valid test data in ScheduleChangeRequests table

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid approver credentials (username and password) | Approver is successfully authenticated and redirected to the dashboard/home page |
| 2 | Click on 'Pending Approvals' menu item or navigate to the pending approvals dashboard | Pending approvals page loads successfully displaying a list of all schedule change requests assigned to the logged-in approver with columns showing request ID, requester name, date submitted, and current status |
| 3 | Select a specific schedule change request from the list by clicking on it | Request details page opens showing comprehensive information including requester details, original schedule, proposed schedule, reason for change, supporting documentation, and submission timestamp |
| 4 | Review all displayed information and click on 'Approve' button | Approval dialog box appears with a text field for optional comments |
| 5 | Enter approval comments in the comments field (e.g., 'Approved as requested - no conflicts identified') | Comments are entered successfully in the text field |
| 6 | Click 'Submit' button to confirm the approval decision | System processes the approval, request status updates to 'Approved', timestamp is recorded, and a confirmation message is displayed stating 'Request has been successfully approved' |
| 7 | Verify the request no longer appears in the pending approvals list | The approved request is removed from the pending list and the list refreshes to show only remaining pending requests |

**Postconditions:**
- Request status is updated to 'Approved' in ScheduleChangeRequests table
- Approval decision is recorded in ApprovalActions table with timestamp and approver ID
- Approved request is removed from approver's pending queue
- Requester can view the approved status of their request

---

### Test Case: Validate rejection of schedule change requests
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Approver is logged into the system with valid credentials
- Approver has appropriate permissions to reject requests
- At least one pending schedule change request exists in the system
- Approver is on the pending approvals dashboard
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the pending approvals list, click on a schedule change request to view its details | Request details page opens displaying all relevant information including requester name, original schedule, proposed changes, reason for change, and submission date |
| 2 | Review the request details and click on the 'Reject' button | Rejection dialog box appears with a text field for mandatory or optional comments explaining the rejection reason |
| 3 | Enter rejection comments in the comments field (e.g., 'Rejected due to insufficient staffing coverage during proposed time') | Comments are successfully entered and visible in the text field |
| 4 | Click 'Submit' button to confirm the rejection decision | System processes the rejection, request status updates to 'Rejected', timestamp is recorded, and a confirmation message is displayed stating 'Request has been rejected successfully' |
| 5 | Navigate back to the pending approvals list | The rejected request no longer appears in the pending approvals list |
| 6 | Verify the rejection is recorded by checking the request history or audit trail | Request shows status as 'Rejected' with the approver's comments, timestamp, and approver identification visible |

**Postconditions:**
- Request status is updated to 'Rejected' in ScheduleChangeRequests table
- Rejection decision with comments is recorded in ApprovalActions table
- Timestamp and approver information are logged
- Rejected request is removed from pending queue
- Requester is able to view rejection status and comments

---

### Test Case: Validate audit logging of approval decisions
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Approver is logged into the system with valid credentials
- At least one schedule change request is available for approval/rejection
- Audit logging functionality is enabled in the system
- User has permissions to view audit logs (if testing log retrieval)
- ApprovalActions table is accessible and configured for logging

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to pending approvals and select a schedule change request | Request details are displayed with approval and rejection options available |
| 2 | Click 'Approve' button, enter comments 'Test approval for audit logging', and click 'Submit' | Approval is processed successfully and confirmation message is displayed |
| 3 | Access the database or audit log interface to query ApprovalActions table for the submitted request ID | Audit log entry is created containing: request ID, approver user ID, decision type (Approved), timestamp of decision, and comments entered |
| 4 | Verify the timestamp recorded in the audit log matches the time of submission (within acceptable system time variance) | Timestamp is accurate and reflects the actual time the approval decision was submitted |
| 5 | Verify the approver information logged includes correct user ID and username | Audit log shows correct approver identification matching the logged-in user who made the decision |
| 6 | Select another pending request, reject it with comments 'Test rejection for audit logging', and submit | Rejection is processed and confirmation is displayed |
| 7 | Retrieve audit logs for the rejected request from ApprovalActions table | New audit log entry exists showing: request ID, approver user ID, decision type (Rejected), accurate timestamp, and rejection comments |
| 8 | Verify audit trail shows complete and accurate history of all approval actions for both requests | Audit logs display chronological history of all decisions with complete information including user, timestamp, decision type, and comments for each action |

**Postconditions:**
- All approval and rejection decisions are logged in ApprovalActions table
- Audit logs contain complete information: timestamp, user ID, decision type, and comments
- Audit trail is retrievable and displays accurate historical data
- No data integrity issues exist in audit logs
- Logs are immutable and cannot be altered post-creation

---

## Story: As System Administrator, I want to configure approval workflow rules to achieve flexible and compliant schedule change processes
**Story ID:** story-4

### Test Case: Validate creation and editing of approval workflow rules
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- System Administrator account exists with valid credentials
- Administrator has full permissions to access workflow configuration
- System is operational and workflow configuration module is accessible
- WorkflowRules table exists and is accessible in the database
- At least one existing workflow rule is present in the system for editing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid administrator credentials | Administrator is successfully authenticated and redirected to the admin dashboard |
| 2 | Click on 'Workflow Configuration' or 'Approval Workflow Settings' menu item | Workflow rule configuration page loads successfully displaying a list of all existing approval workflow rules with columns showing rule name, conditions, approver levels, and status |
| 3 | Click on 'Create New Rule' or 'Add Rule' button | New rule creation form opens with fields for rule name, description, routing conditions, approver roles/levels, and priority |
| 4 | Enter rule details: Rule Name 'High Priority Schedule Changes', Condition 'Request Type = Urgent', Approver Level '2-Level Approval', Approver Roles 'Manager, Director' | All fields accept input correctly and display entered information |
| 5 | Click 'Save' button to save the new workflow rule | System validates the rule configuration, saves it to WorkflowRules table, and displays confirmation message 'Workflow rule created successfully' |
| 6 | Verify the newly created rule appears in the workflow rules list | New rule 'High Priority Schedule Changes' is visible in the rules list with all configured details displayed correctly |
| 7 | Select an existing workflow rule from the list by clicking the 'Edit' button or clicking on the rule name | Rule editing form opens pre-populated with the current rule configuration including all conditions, approver levels, and settings |
| 8 | Modify the rule by changing the Approver Level from '2-Level Approval' to '3-Level Approval' and adding 'VP' to Approver Roles | Changes are accepted and displayed in the form fields |
| 9 | Click 'Save Changes' button to update the workflow rule | System validates the updated configuration, saves changes to WorkflowRules table, and displays confirmation message 'Workflow rule updated successfully' |
| 10 | Verify the edited rule reflects the changes in the workflow rules list | Updated rule shows modified approver level as '3-Level Approval' and includes 'VP' in the approver roles |
| 11 | Create a test schedule change request that matches the new rule conditions | New schedule change request is created and the system applies the newly configured workflow rule, routing it according to the defined approval levels |

**Postconditions:**
- New workflow rule is saved in WorkflowRules table with all configurations
- Existing rule modifications are persisted in the database
- Updated rules are immediately applied to new schedule change requests
- Rule changes are logged in AuditLogs table with timestamp and administrator info
- No existing pending requests are affected by the rule changes

---

### Test Case: Validate rule conflict detection
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Administrator is logged into the system with valid credentials
- Administrator has access to workflow configuration page
- At least one existing workflow rule is configured in the system
- Rule validation engine is operational
- System has conflict detection logic implemented

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the workflow rule configuration page | Configuration page loads displaying existing workflow rules |
| 2 | Click 'Create New Rule' button to start creating a new workflow rule | New rule creation form is displayed with all required fields |
| 3 | Enter rule details that create a conflict with an existing rule: Same conditions but different approver routing (e.g., Rule Name 'Conflicting Rule', Condition 'Request Type = Urgent', Approver Level '1-Level' when existing rule has '2-Level' for same condition) | Form accepts the input and displays the entered information |
| 4 | Click 'Save' button to attempt saving the conflicting rule | System validation detects the conflict and displays error message 'Conflict detected: A rule with the same conditions already exists. Please modify the conditions or update the existing rule.' Save operation is prevented |
| 5 | Verify the conflicting rule is not saved to the database | Conflicting rule does not appear in the workflow rules list and WorkflowRules table remains unchanged |
| 6 | Attempt to create a circular dependency rule: Rule A routes to Approver Group 1, which routes back to Rule A's trigger condition | Form accepts the input initially |
| 7 | Click 'Save' button to attempt saving the circular rule | System validation detects circular dependency and displays error message 'Circular dependency detected: This rule configuration creates an infinite loop. Please revise the routing logic.' Save operation is blocked |
| 8 | Verify no circular rule is created in the system | Rule is not saved and does not appear in the workflow rules list |
| 9 | Create a valid rule without conflicts or circular dependencies with unique conditions | Rule is validated successfully, saved to the database, and confirmation message 'Workflow rule created successfully' is displayed |

**Postconditions:**
- No conflicting rules exist in WorkflowRules table
- No circular dependencies are present in the workflow configuration
- System maintains data integrity with only valid rules saved
- Error messages are logged for troubleshooting purposes
- Valid rules are successfully saved and operational

---

### Test Case: Validate access control for workflow configuration
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- System has role-based access control implemented
- Non-administrator user account exists (e.g., Approver or Requester role)
- Administrator account exists with workflow configuration permissions
- Workflow configuration page URL is known
- Authorization middleware is active and functioning

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using non-administrator credentials (e.g., Approver role user) | User is successfully authenticated and redirected to their role-appropriate dashboard |
| 2 | Verify that 'Workflow Configuration' menu item is not visible in the navigation menu | Workflow Configuration option is hidden or not displayed in the user's menu, showing only options appropriate for their role |
| 3 | Attempt to directly access the workflow configuration page by entering the URL in the browser (e.g., /admin/workflow-rules or /workflow-configuration) | System denies access and displays error message 'Access Denied: You do not have permission to access this page' or 'Error 403: Forbidden' and redirects to unauthorized access page or user's home page |
| 4 | Verify the user remains on an error page or is redirected away from workflow configuration | User cannot access workflow configuration page and no workflow rules are visible |
| 5 | Attempt to access workflow configuration API endpoint directly using API testing tool or browser console (e.g., GET /workflow-rules) | API returns 403 Forbidden status code with error message 'Unauthorized: Administrator privileges required' |
| 6 | Log out the non-administrator user and log in with valid administrator credentials | Administrator is successfully authenticated and redirected to admin dashboard |
| 7 | Verify 'Workflow Configuration' menu item is visible and accessible in the administrator's navigation menu | Workflow Configuration option is displayed in the menu |
| 8 | Click on 'Workflow Configuration' menu item | Workflow configuration page loads successfully displaying all existing workflow rules with full access to create, edit, and delete functionality |
| 9 | Verify administrator can perform all workflow configuration operations | Administrator has full access to view, create, edit, and manage workflow rules without any access restrictions |

**Postconditions:**
- Non-administrator users cannot access workflow configuration functionality
- Access control is enforced at both UI and API levels
- Unauthorized access attempts are logged in security audit logs
- Administrator access remains functional and unrestricted
- System security integrity is maintained

---

## Story: As Approver, I want to escalate pending schedule change requests to higher authority to ensure timely decision making
**Story ID:** story-5

### Test Case: Validate manual escalation by approver
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Approver role and valid permissions
- At least one pending schedule change request exists in the system
- Higher-level approver is configured and available in the system
- Escalation rules are properly configured
- Notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the pending schedule change requests dashboard | Dashboard displays list of all pending schedule change requests with their details |
| 2 | Select a specific pending schedule change request from the list | Request details are displayed with available actions including escalation option |
| 3 | Click on the 'Escalate' button or option for the selected request | Escalation dialog or form appears prompting for escalation reason and higher-level approver selection |
| 4 | Enter escalation reason and confirm the escalation action | System processes the escalation request and displays confirmation message indicating successful escalation |
| 5 | Verify the request status has been updated to 'Escalated' | Request status shows as 'Escalated' and is routed to the designated higher-level approver |
| 6 | Log in as the escalated higher-level approver and check notifications | Escalated approver receives notification containing complete request details, escalation reason, and original approver information |
| 7 | Verify the escalated request appears in the higher-level approver's pending queue | Request is visible in the higher-level approver's dashboard with escalation indicator |

**Postconditions:**
- Schedule change request is successfully escalated to higher-level approver
- Escalation action is logged in the system with timestamp and user details
- Notification is sent to escalated approver
- Request status reflects escalation state
- Original approver can view escalation status

---

### Test Case: Validate automatic escalation of overdue requests
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System has automatic escalation feature enabled
- SLA thresholds are configured in the system (e.g., 24 hours)
- At least one pending schedule change request exists that can exceed SLA
- Higher-level approvers are configured for automatic escalation
- Escalation rules and routing logic are properly set up
- System scheduler/cron job for checking SLA is running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create or identify a pending schedule change request in the system | Pending request is created with timestamp and assigned to an approver |
| 2 | Simulate or wait for the request to exceed the configured SLA threshold (e.g., modify system time or wait for actual threshold) | Request remains pending beyond the configured SLA time limit |
| 3 | Trigger the automatic escalation process (either wait for scheduled job or manually trigger if test environment allows) | System detects the overdue request and initiates automatic escalation process |
| 4 | Verify the request has been automatically escalated to the designated higher-level approver | Request status changes to 'Escalated' and is routed to higher-level approver without manual intervention |
| 5 | Check the escalation logs in the system audit trail | Escalation action is logged with timestamp, reason (SLA exceeded), original approver, escalated approver, and system-generated escalation indicator |
| 6 | Verify notifications were sent to the escalated approver | Higher-level approver receives notification containing request details, SLA breach information, and escalation timestamp |
| 7 | Log in as the escalated approver and verify the request appears in their queue | Escalated request is visible in higher-level approver's dashboard with automatic escalation indicator and SLA breach details |
| 8 | Verify the original approver is notified about the automatic escalation | Original approver receives notification that the request has been escalated due to SLA breach |

**Postconditions:**
- Overdue request is automatically escalated to higher-level approver
- Complete escalation history is logged with all relevant details
- Notifications are sent to both escalated approver and original approver
- Request status reflects automatic escalation
- SLA breach is documented in the system
- Escalation processing completed within 1 minute of SLA threshold breach

---

## Story: As Approver, I want to add comments to schedule change requests during approval to provide context for decisions
**Story ID:** story-8

### Test Case: Validate adding and saving comments during approval
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Approver role and valid permissions
- At least one pending schedule change request exists and is assigned to the logged-in approver
- Database connection is active and ApprovalActions table is accessible
- Comment input field is configured with maximum length of 500 characters

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the pending schedule change requests dashboard | Dashboard displays list of pending schedule change requests assigned to the approver |
| 2 | Select and open a specific schedule change request for review | Request details page opens displaying all request information including employee details, schedule changes, and approval options |
| 3 | Verify the comment input field is visible on the approval form | Comment input field is clearly visible and accessible with appropriate label (e.g., 'Add Comment' or 'Decision Rationale') |
| 4 | Enter a valid comment in the comment field (e.g., 'Approved due to valid business justification and adequate coverage') | Comment text is entered successfully in the input field without errors |
| 5 | Click the 'Approve' button to submit the approval decision with the comment | System processes the approval, displays success confirmation message, and indicates that approval with comment has been saved |
| 6 | Navigate to the schedule change request history or details page | Request history page displays the complete timeline of actions taken on the request |
| 7 | Locate the approval action entry in the request history | Approval action is displayed with timestamp, approver name, decision (Approved), and the comment text entered in step 4 |
| 8 | Verify the comment is properly linked to the approval action in the database | Comment is stored in ApprovalActions table with correct foreign key relationship to the approval record |

**Postconditions:**
- Schedule change request is approved successfully
- Comment is saved and linked to the approval action
- Comment is visible in request history with proper attribution
- Approval action with comment is logged with timestamp
- Request status is updated to 'Approved'
- Requester is notified of approval decision with comment

---

### Test Case: Validate comment length validation
- **ID:** tc-004
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Approver role and valid permissions
- At least one pending schedule change request exists and is assigned to the logged-in approver
- Comment field validation is configured with maximum length of 500 characters
- Input validation rules are active in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the pending schedule change requests dashboard | Dashboard displays list of pending schedule change requests |
| 2 | Select and open a schedule change request for approval | Request details page opens with comment input field visible |
| 3 | Generate and enter a comment text that exceeds 500 characters (e.g., 501 characters or more) | Comment text is entered in the input field |
| 4 | Attempt to submit the approval or rejection decision with the oversized comment | System displays validation error message indicating that comment exceeds maximum allowed length of 500 characters |
| 5 | Verify that the approval/rejection submission is blocked | Form submission is prevented and user remains on the approval page with error message visible |
| 6 | Verify the error message clearly indicates the character limit and current character count | Error message displays specific information such as 'Comment must not exceed 500 characters' with character counter if available |
| 7 | Reduce the comment text to exactly 500 characters or less | Validation error clears and comment field shows valid state |
| 8 | Submit the approval decision with the valid-length comment | Approval is processed successfully and confirmation message is displayed |

**Postconditions:**
- Comment length validation is enforced correctly
- Oversized comments are rejected with clear error message
- Valid-length comments are accepted and saved
- No approval action is saved when validation fails
- User is able to correct and resubmit with valid comment

---

## Story: As Approver, I want to filter and sort schedule change requests in my queue to prioritize my workload effectively
**Story ID:** story-10

### Test Case: Validate filtering by status and date range
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Approver role
- Approver has access to pending requests dashboard
- Multiple schedule change requests exist with varying statuses (Pending, Approved, Rejected)
- Requests exist across different date ranges
- At least 5 requests are assigned to the logged-in approver

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the pending requests dashboard | Dashboard loads successfully displaying all assigned schedule change requests |
| 2 | Locate and click on the status filter dropdown | Status filter dropdown opens showing available status options (Pending, Approved, Rejected, All) |
| 3 | Select 'Pending' status from the dropdown | Status filter is set to 'Pending' and dropdown closes |
| 4 | Locate the date range filter and click on the 'From Date' field | Date picker calendar opens for 'From Date' selection |
| 5 | Select a specific start date (e.g., first day of current month) | Selected date is populated in the 'From Date' field |
| 6 | Click on the 'To Date' field | Date picker calendar opens for 'To Date' selection |
| 7 | Select a specific end date (e.g., last day of current month) | Selected date is populated in the 'To Date' field |
| 8 | Click 'Apply Filter' button | Request list updates within 2 seconds to show only requests with 'Pending' status submitted within the selected date range. Request count is updated to reflect filtered results |
| 9 | Verify each displayed request has 'Pending' status | All displayed requests show 'Pending' status in the status column |
| 10 | Verify each displayed request falls within the selected date range | All displayed requests have submission dates between the selected 'From Date' and 'To Date' |

**Postconditions:**
- Request list displays only filtered results matching the applied criteria
- Filter settings remain active until cleared or modified
- Total request count reflects filtered results
- Page performance remains within 2 seconds response time

---

### Test Case: Validate sorting by priority and submission date
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Approver role
- Approver has access to pending requests dashboard
- At least 10 schedule change requests are assigned to the approver
- Requests have varying priority levels (High, Medium, Low)
- Requests have different submission dates spanning multiple days
- No filters are currently applied

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the pending requests dashboard | Dashboard loads successfully displaying all assigned schedule change requests in default order |
| 2 | Locate the 'Priority' column header and click on it to sort | Sort icon appears next to 'Priority' column header indicating descending order |
| 3 | Observe the order of requests in the list | Requests are ordered with highest priority first (High priority at top, followed by Medium, then Low priority). Request list updates within 2 seconds |
| 4 | Verify the first 3 requests displayed have 'High' priority | First 3 requests in the list show 'High' in the priority column |
| 5 | Scroll down and verify requests with 'Low' priority appear at the bottom | Requests with 'Low' priority are displayed at the bottom of the list |
| 6 | Locate the 'Submission Date' column header and click on it | Sort icon appears next to 'Submission Date' column header indicating ascending order. Previous priority sort is cleared |
| 7 | Observe the order of requests in the list | Requests are ordered from oldest to newest submission date. Request list updates within 2 seconds |
| 8 | Verify the first request has the oldest submission date | First request in the list displays the earliest submission date among all requests |
| 9 | Scroll to the bottom and verify the last request has the most recent submission date | Last request in the list displays the most recent submission date |
| 10 | Click on 'Submission Date' column header again | Sort order reverses to descending (newest to oldest). Sort icon updates to indicate descending order |

**Postconditions:**
- Request list is sorted according to the last applied sort criteria
- Sort indicator is visible on the active column header
- All requests remain visible with no data loss
- Sort operation completes within 2 seconds

---

### Test Case: Validate saving and applying filter presets
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Approver role
- Approver has access to pending requests dashboard
- Multiple schedule change requests exist with varying statuses and dates
- At least 15 requests are assigned to the approver
- No saved filter presets exist for the current user

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the pending requests dashboard | Dashboard loads successfully displaying all assigned schedule change requests |
| 2 | Apply filter for 'Pending' status | Request list updates to show only pending requests |
| 3 | Apply date range filter for current month | Request list further filters to show only pending requests from current month |
| 4 | Sort the filtered results by priority descending | Filtered requests are sorted with highest priority first |
| 5 | Locate and click on 'Save Filter Preset' button or icon | Save preset dialog or modal opens prompting for preset name |
| 6 | Enter preset name 'Current Month High Priority' in the name field | Preset name is entered in the input field |
| 7 | Click 'Save' button in the preset dialog | Preset is saved successfully. Success message displays 'Filter preset saved successfully'. Dialog closes and returns to dashboard |
| 8 | Clear all current filters by clicking 'Clear Filters' or 'Reset' button | All filters and sorting are removed. Request list displays all assigned requests in default order |
| 9 | Verify the request list shows all requests without any filters | Request list displays all assigned requests including different statuses and dates |
| 10 | Locate and click on 'Saved Presets' dropdown or button | Dropdown menu opens displaying saved presets including 'Current Month High Priority' |
| 11 | Select 'Current Month High Priority' preset from the list | Preset is applied. Request list updates within 2 seconds to show pending requests from current month sorted by priority descending |
| 12 | Verify filter indicators show 'Pending' status and current month date range | Status filter displays 'Pending' and date range filter shows current month dates |
| 13 | Verify sort indicator shows priority descending | Priority column header shows descending sort indicator |
| 14 | Verify the request list matches the previously saved filter criteria | Request list displays the same filtered and sorted results as when the preset was saved |

**Postconditions:**
- Filter preset 'Current Month High Priority' is saved in the system
- Preset is available for future use
- Request list displays results according to the applied preset
- Filter and sort settings match the saved preset configuration
- Preset can be reapplied at any time

---

