# Manual Test Cases

## Story: As Approver, I want to review schedule change requests to achieve informed decision making
**Story ID:** story-2

### Test Case: Validate display of pending schedule change requests
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has valid Approver role credentials
- At least 5 pending schedule change requests exist in the system
- Schedule change requests have various dates and requesters
- Test environment is accessible and database is populated
- Browser is supported (Chrome, Firefox, Safari, Edge)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid Approver credentials (username and password), then click Login button | System authenticates successfully and displays the Approver dashboard with a list of pending schedule change requests visible on the main panel |
| 2 | Locate the filter section and select a specific date range from the date picker, then select a specific requester name from the requester dropdown filter | The pending requests list automatically refreshes and displays only the schedule change requests that match the selected date range and requester criteria. Request count updates to reflect filtered results |
| 3 | Click on one of the filtered schedule change requests from the list to open the detailed view | System navigates to the detailed view page showing complete request information including requester name, requested dates, reason for change, current schedule, proposed schedule, submission date, priority level, and all attached documents with download links |

**Postconditions:**
- User remains logged in as Approver
- Detailed view of selected request is displayed
- All filters remain applied to the request list
- No data has been modified in the system

---

### Test Case: Verify adding comments to schedule change requests
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with valid Approver credentials
- At least one pending schedule change request exists in the system
- User has permission to add comments to requests
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the pending requests list on the dashboard, click on a specific schedule change request to open its detail view | Request detail page loads successfully displaying all request information, attachments, and a comments section with a text input field and Submit button |
| 2 | Scroll to the comments section, click in the comment text field, type a test comment 'Please provide additional justification for this schedule change', and click the Submit button | System displays a success message confirming comment submission. The new comment appears in the request history section with the approver's name, timestamp, and comment text. Comment text field is cleared and ready for new input |
| 3 | Click the browser refresh button or navigate away from the request and then reopen the same schedule change request detail view | The request detail page reloads and the previously added comment 'Please provide additional justification for this schedule change' is still visible in the request history with correct approver name and timestamp |

**Postconditions:**
- Comment is permanently saved in the database
- Request history shows the new comment entry
- Request status remains unchanged
- Audit log contains entry for comment addition

---

### Test Case: Ensure request list loads within performance requirements
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User has valid Approver credentials
- System has at least 50 pending schedule change requests for realistic load testing
- Test environment is under normal load conditions
- Browser developer tools or performance monitoring tool is available
- Network latency is within normal parameters

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab to monitor load times. Navigate to the application login page, enter valid Approver credentials, and click Login | System successfully authenticates and displays the Approver dashboard with the pending requests list fully loaded and visible |
| 2 | In the browser developer tools Network tab, locate the API call for loading pending requests (GET /api/schedule-changes/pending) and check the response time from request initiation to complete page render | The pending requests list loads completely within 3 seconds. All request entries are visible with basic information (requester, date, status). Network tab shows API response time is under 3 seconds |
| 3 | Apply multiple filters by selecting a date range, choosing a specific requester, and selecting 'Pending' status. Monitor the Network tab for the filtered API call response time | The filtered request list updates and displays only matching results within 3 seconds. Network tab confirms the filtered API call completes within the 3-second performance requirement. UI remains responsive during filtering |

**Postconditions:**
- Dashboard displays filtered results
- System performance meets SLA requirements
- No performance degradation observed
- All requests are accurately displayed

---

## Story: As Approver, I want to approve or reject schedule change requests to ensure proper authorization
**Story ID:** story-3

### Test Case: Validate approval of schedule change request
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with valid Approver role credentials
- At least one pending schedule change request exists in the system
- User has approval permissions for the selected request
- Audit logging system is enabled and functioning
- Database connection is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the Approver dashboard, locate a pending schedule change request in the list and click on it to open the detailed view | Request detail page opens displaying all request information including requester details, schedule change details, attachments, and action buttons (Approve, Reject, Request More Info) are visible and enabled |
| 2 | Review the request details, then click the 'Approve' button. If a confirmation dialog appears, click 'Confirm' to proceed with the approval | System processes the approval action and displays a success confirmation message 'Schedule change request has been approved successfully'. The request status indicator changes from 'Pending' to 'Approved'. Action buttons become disabled or hidden |
| 3 | Navigate to the audit log section or admin panel, search for audit entries related to this specific request ID, and verify the approval action is logged | Audit log displays a new entry showing the approval action with complete details: approver username, exact timestamp of approval, action type 'APPROVED', request ID, and any comments entered. Log entry is immutable and properly formatted |

**Postconditions:**
- Request status is permanently changed to 'Approved'
- Audit log contains complete approval record
- Requester receives notification of approval (out of scope to verify)
- Request is removed from pending list
- Schedule change is authorized for implementation

---

### Test Case: Verify rejection requires comments
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with valid Approver credentials
- At least one pending schedule change request exists
- User has rejection permissions
- Form validation is enabled on the rejection workflow

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the Approver dashboard, click on a pending schedule change request to open its detailed view | Request detail page loads successfully showing all request information and action buttons including 'Approve', 'Reject', and 'Request More Info' buttons are visible and enabled |
| 2 | Click the 'Reject' button without entering any text in the comments field. Attempt to submit the rejection | System prevents the submission and displays a validation error message 'Comments are required when rejecting a request' or similar. The comment field is highlighted in red or with an error indicator. Request status remains 'Pending' and no changes are saved |
| 3 | In the comments field, enter a detailed rejection reason 'This schedule change conflicts with project deadlines and resource availability', then click the 'Reject' button and confirm if prompted | System accepts the rejection with comments and displays success message 'Schedule change request has been rejected'. Request status updates to 'Rejected'. Audit log is created with rejection action, approver details, timestamp, and the entered comments. The rejection reason is visible in the request history |

**Postconditions:**
- Request status is changed to 'Rejected'
- Rejection comments are permanently stored
- Audit log contains complete rejection record with comments
- Request is removed from pending list
- Requester receives rejection notification with comments

---

### Test Case: Ensure unauthorized users cannot approve requests
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Test user account exists without Approver role permissions
- At least one pending schedule change request exists in the system
- Role-based access control is properly configured
- API security middleware is active
- Audit logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the application using credentials for a user account that does not have Approver role permissions (e.g., regular employee or requester role) | System authenticates the user successfully but displays a dashboard appropriate for their role. Approval-related menu items, buttons, or sections are not visible. If the user navigates to schedule changes, they can only view their own requests without any approval action buttons |
| 2 | Using an API testing tool (Postman, cURL, or browser console), attempt to directly call the approval API endpoint POST /api/schedule-changes/{valid-request-id}/approval with the unauthorized user's authentication token and approval action payload | API returns HTTP 403 Forbidden or 401 Unauthorized error response with message 'Access denied: Insufficient permissions to perform approval actions' or similar. No changes are made to the request status in the database |
| 3 | Log in as an administrator or user with audit log access, navigate to the audit log section, and search for any approval action entries associated with the unauthorized user account for the time period of the attempted access | Audit log shows no approval action entries for the unauthorized user. Optionally, security log may contain an entry for the unauthorized access attempt showing the user, timestamp, attempted action, and denial reason. No successful approval actions are recorded for this user |

**Postconditions:**
- Request status remains unchanged
- No unauthorized approval actions are logged
- System security integrity is maintained
- Unauthorized user remains unable to access approval functions
- Security logs may contain access denial records

---

## Story: As System Administrator, I want to configure approval routing rules to achieve flexible workflow management
**Story ID:** story-4

### Test Case: Validate creation and saving of routing rules
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has System Administrator role and valid credentials
- ApprovalRoutingRules table is accessible and operational
- Routing rules management interface is deployed and functional
- At least one department and approver exist in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid System Administrator credentials | System authenticates successfully and redirects to administrator dashboard |
| 2 | Click on 'Routing Rules Management' menu option from the navigation panel | Routing rules management page loads displaying existing rules list and 'Create New Rule' button |
| 3 | Click 'Create New Rule' button to open the rule creation form | Rule creation form displays with fields for rule name, conditions, and approver assignments |
| 4 | Enter rule name 'Engineering Department Routing', select condition 'Department equals Engineering', and assign approver 'John Smith' | All fields accept input without errors and display entered values correctly |
| 5 | Click 'Save' button to submit the new routing rule | System validates the rule, saves it to ApprovalRoutingRules table, and displays success confirmation message 'Routing rule created successfully' |
| 6 | Navigate to the active rules list view | New rule 'Engineering Department Routing' appears in the active rules list with status 'Active' and correct configuration details |
| 7 | Verify the rule details by clicking on the rule name | Rule details page displays showing all configured conditions and assigned approvers matching the created rule |

**Postconditions:**
- New routing rule is saved in ApprovalRoutingRules table
- Rule is active and available for routing schedule change requests
- Rule appears in the active rules list for all administrators
- System audit log contains entry for rule creation

---

### Test Case: Verify validation prevents conflicting routing rules
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as System Administrator
- At least one active routing rule exists for 'Department equals Engineering' with approver 'John Smith'
- Routing rules management page is accessible
- Rule conflict validation logic is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Routing Rules Management page and click 'Create New Rule' button | Rule creation form opens with empty fields ready for input |
| 2 | Enter rule name 'Duplicate Engineering Rule' and configure condition 'Department equals Engineering' with approver 'Jane Doe' | Form accepts the input and displays all entered values |
| 3 | Click 'Save' button to attempt saving the conflicting rule | System detects conflict with existing rule and displays error message 'Conflict detected: A routing rule already exists for Department equals Engineering. Please modify conditions or deactivate the existing rule.' |
| 4 | Verify the rule was not saved by checking the active rules list | The conflicting rule 'Duplicate Engineering Rule' does not appear in the active rules list |
| 5 | Modify the rule condition to 'Department equals Engineering AND Request Type equals Shift Swap' to resolve the conflict | Form updates with the new condition and no validation errors are displayed |
| 6 | Click 'Save' button to save the modified rule | System validates successfully, saves the rule, and displays confirmation message 'Routing rule created successfully' |
| 7 | Verify the modified rule appears in the active rules list | Rule 'Duplicate Engineering Rule' is listed as active with the updated conditions showing no conflicts |

**Postconditions:**
- No conflicting routing rules exist in the system
- Modified rule is saved and active in ApprovalRoutingRules table
- System maintains data integrity with conflict-free routing rules
- Validation error is logged in system logs

---

### Test Case: Ensure routing rules apply correctly to sample requests
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as System Administrator
- At least two active routing rules exist with different conditions
- Test feature for routing rules is available and functional
- Sample schedule change request templates are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Routing Rules Management page and locate the 'Test Routing Rules' section | Test section displays with option to input sample request parameters |
| 2 | Click 'Create Sample Request' button to open the test request form | Sample request form opens with fields for Department, Request Type, Schedule Type, and Request Size |
| 3 | Enter sample request parameters: Department='Engineering', Request Type='Shift Swap', Schedule Type='Full-time', Request Size='Single' | All fields accept input and display the entered values correctly |
| 4 | Click 'Test Routing' button to apply routing rules to the sample request | System processes the request within 1 second and displays results showing matched routing rule and assigned approvers list |
| 5 | Verify the displayed approvers match the expected routing rule configuration | Approvers displayed are 'John Smith' and 'Jane Doe' as configured in the matching rule for Engineering Shift Swap requests |
| 6 | Modify sample request parameters to Department='Sales', Request Type='Time Off', keeping other fields the same | Form updates with new parameter values |
| 7 | Click 'Test Routing' button again to retest with modified parameters | System processes the updated request and displays different routing results showing new matched rule and different approvers list |
| 8 | Verify the routing results updated correctly based on the modified parameters | Approvers displayed are 'Sarah Johnson' matching the Sales department routing rule, confirming rules apply dynamically based on request parameters |

**Postconditions:**
- Test results are displayed accurately without affecting production data
- No actual approval requests are created during testing
- System performance meets the 1-second rule evaluation requirement
- Test activity is logged for audit purposes

---

## Story: As Approver, I want to escalate pending schedule change approvals to achieve timely decision making
**Story ID:** story-7

### Test Case: Validate automatic escalation of pending approvals
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 125 mins

**Preconditions:**
- Escalation rules are configured with time threshold set to 2 hours
- At least one backup approver is designated in the system
- Escalation service is running and operational
- User has permissions to create schedule change requests
- Email notification service is configured and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as a regular employee and navigate to Schedule Change Request page | Schedule Change Request form loads successfully |
| 2 | Create a new schedule change request with valid details: Request Type='Shift Swap', Date='Next Monday', Reason='Personal appointment' | Request is submitted successfully and routed to primary approver 'Manager A' with status 'Pending Approval' |
| 3 | Verify the request appears in the primary approver's pending queue without taking any action | Request is visible in Manager A's approval queue with timestamp showing submission time and status 'Pending' |
| 4 | Wait for the configured escalation threshold time (2 hours) to elapse without approval action | Request remains in 'Pending Approval' status throughout the waiting period with no status changes |
| 5 | Monitor the system for escalation processing after threshold time has passed | Escalation service detects the pending request exceeding threshold and triggers automatic escalation within 1 minute |
| 6 | Check the request status in the system after escalation processing | Request status updates to 'Escalated' and backup approver 'Manager B' is now assigned as additional approver |
| 7 | Log in as the backup approver and check the notification inbox | Escalation notification is received with subject 'Escalated Approval Required' containing request details and escalation reason |
| 8 | Verify the escalated request appears in backup approver's pending queue | Request is visible in Manager B's approval queue with escalation indicator and original submission timestamp |

**Postconditions:**
- Request status is updated to 'Escalated' in ApprovalActions table
- Backup approver has access to approve the escalated request
- Escalation notification is delivered successfully
- Original approver still retains ability to approve the request
- Escalation event is logged with timestamp

---

### Test Case: Verify escalation logging and status tracking
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in with administrator or approver role
- At least one schedule change request exists that is eligible for escalation
- Escalation monitoring UI is accessible
- EscalationRules table contains active escalation configuration
- System logging is enabled and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create or identify a schedule change request that has exceeded the escalation threshold | Request is in pending status beyond the configured threshold time |
| 2 | Allow the escalation service to process and trigger escalation for the pending request | Escalation is triggered automatically and request status changes to 'Escalated' |
| 3 | Navigate to System Logs or Escalation Logs section in the admin panel | Escalation logs page loads displaying list of escalation events |
| 4 | Search for the escalation log entry corresponding to the triggered escalation using request ID | Log entry is found showing escalation action with timestamp, original approver 'Manager A', backup approver 'Manager B', and escalation reason 'Threshold exceeded: 2 hours' |
| 5 | Verify all required details are captured in the log entry | Log contains Request ID, Original Approver ID, Backup Approver ID, Escalation Timestamp (accurate to the minute), Threshold Value, and System User ID who configured the rule |
| 6 | Navigate to Escalation Monitoring UI from the main dashboard | Escalation monitoring dashboard loads displaying active and historical escalations |
| 7 | Locate the escalated request in the monitoring interface | Request appears in the escalations list with status 'Escalated - Pending Backup Approval' |
| 8 | Click on the escalated request to view detailed escalation status | Detailed view displays showing escalation timeline, original submission time, escalation trigger time, current status, assigned backup approver, and notification delivery status |
| 9 | Verify the escalation status accuracy by comparing with system logs | All information in monitoring UI matches the logged escalation data including timestamps and user details |

**Postconditions:**
- Escalation action is permanently logged in system audit trail
- Escalation status is accurately reflected in monitoring UI
- Log entries are immutable and timestamped correctly
- Authorized users can access escalation history for reporting
- Data integrity is maintained across ApprovalActions and EscalationRules tables

---

### Test Case: Ensure escalation processing meets performance requirements
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Performance testing environment is configured
- Multiple schedule change requests can be created simultaneously
- Escalation threshold is set to a testable value (e.g., 5 minutes for testing)
- System monitoring tools are available to measure processing time
- Notification service has capacity for multiple simultaneous notifications
- At least 10 backup approvers are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create 10 schedule change requests simultaneously from different users, all requiring approval | All 10 requests are submitted successfully and routed to their respective primary approvers with status 'Pending Approval' |
| 2 | Record the exact timestamp when each request was submitted | Submission timestamps are captured accurately for all 10 requests |
| 3 | Wait for the escalation threshold time to elapse without any approval actions on the requests | All 10 requests remain in 'Pending Approval' status throughout the threshold period |
| 4 | Monitor the escalation service processing using system monitoring tools as threshold is breached | Escalation service detects all 10 pending requests that exceeded threshold |
| 5 | Measure the time taken from threshold breach to escalation completion for each request | All 10 requests are escalated within 1 minute of their respective threshold breach times, meeting the performance requirement |
| 6 | Verify escalation status updates in the database for all 10 requests | All requests show status 'Escalated' in ApprovalActions table with accurate escalation timestamps |
| 7 | Check notification delivery logs to verify when escalation notifications were sent | All 10 escalation notifications were queued for delivery within the 1-minute processing window |
| 8 | Log in as each of the 10 backup approvers and verify notification receipt | All backup approvers received their respective escalation notifications within the defined SLA (95% within 2 minutes) |
| 9 | Verify system performance metrics during escalation processing | System CPU and memory usage remained within acceptable limits, no performance degradation observed, and all escalations processed concurrently without delays |
| 10 | Review escalation logs to confirm all processing times meet the 1-minute requirement | Log analysis shows 100% of escalations (10 out of 10) were processed within 1 minute of threshold breach, confirming performance requirement compliance |

**Postconditions:**
- All 10 requests are in 'Escalated' status
- Performance metrics confirm 1-minute processing requirement is met
- All escalation notifications are delivered within SLA
- System performance remains stable under concurrent escalation load
- Escalation logs contain accurate timing data for all requests
- No escalation processing errors or timeouts occurred

---

## Story: As Approver, I want to request additional information on schedule change requests to achieve informed approvals
**Story ID:** story-10

### Test Case: Validate approver can request additional information
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Approver role
- At least one pending schedule change request exists in the system
- Approver has permission to access schedule change requests
- Notification system is configured and operational
- Requester user account is active and has valid contact information

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change requests dashboard | Dashboard displays with list of pending schedule change requests |
| 2 | Select and open a pending schedule change request | Request details page opens displaying all request information including requester name, schedule details, reason for change, and current status |
| 3 | Locate and click the 'Request More Info' button | A comment entry dialog or form appears with a mandatory text field for entering comments |
| 4 | Enter detailed comments explaining what additional information is needed (e.g., 'Please provide justification for the extended hours and manager approval') | Comments are entered successfully in the text field with character count visible if applicable |
| 5 | Click 'Submit' or 'Send Request' button | System displays a confirmation message indicating the information request has been submitted successfully |
| 6 | Verify the request status has changed to 'Info Requested' or similar status | Request status is updated and displayed on the request details page |
| 7 | Check the notification system or requester's notification inbox | Notification is sent to the requester containing the approver's comments and a link to respond to the information request |
| 8 | Verify the info request appears in the request history or activity log | Info request action is visible with timestamp, approver name, and comments entered |

**Postconditions:**
- Schedule change request status is updated to 'Info Requested'
- Requester has received notification about the information request
- Info request is logged in the system audit trail
- Approver can view the pending info request status
- Request remains in approver's pending queue until additional information is provided

---

### Test Case: Verify requester can submit additional information
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Schedule Coordinator (Requester) role
- An information request has been submitted by an Approver for one of the requester's schedule change requests
- Notification has been sent to the requester about the info request
- Requester has access to the schedule change request system
- Additional information or documentation is prepared for submission

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as Schedule Coordinator | User successfully logs in and is directed to the dashboard |
| 2 | Check the notifications panel or inbox | Notification about the information request is visible, showing the approver's name, request ID, and comments |
| 3 | Click on the notification to open the associated schedule change request | Request details page opens showing the original request details and the approver's information request with comments |
| 4 | Locate the 'Respond to Info Request' or 'Submit Additional Information' section | A response form or text area is displayed for entering additional information |
| 5 | Enter the additional information requested by the approver (e.g., 'Manager approval attached. Extended hours needed due to project deadline on March 15th') | Information is entered successfully in the response field |
| 6 | Attach any supporting documents if applicable | Documents are uploaded and attached to the response |
| 7 | Click 'Submit' or 'Send Response' button | System displays confirmation message that additional information has been submitted successfully |
| 8 | Verify the request status changes to 'Pending Approval' or 'Under Review' | Request status is updated indicating the additional information has been provided |
| 9 | Log in as the Approver who requested the information | Approver successfully logs in to the system |
| 10 | Navigate to the schedule change request that had the info request | Request details page opens |
| 11 | Review the request details and locate the additional information section | Additional information submitted by the requester is visible and clearly linked to the original info request, including any attached documents |
| 12 | Verify timestamp and requester name are displayed with the additional information | Submission details show when the information was provided and by whom |

**Postconditions:**
- Additional information is saved and linked to the original schedule change request
- Request status is updated to reflect that information has been provided
- Approver can view the additional information and proceed with approval decision
- Response action is logged in the audit trail
- Notification may be sent to approver about the response (system dependent)

---

### Test Case: Ensure all info request actions are logged
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User has Approver role access to request additional information
- User has Requester role access to submit additional information
- At least one pending schedule change request exists
- Audit logging system is enabled and functioning
- User has permission to view audit logs or activity history

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Approver | Approver successfully logs in to the system |
| 2 | Open a pending schedule change request | Request details page is displayed |
| 3 | Click 'Request More Info' button and enter comments 'Need clarification on shift timing' | Comment entry form is displayed and comments are entered |
| 4 | Submit the information request | System confirms the info request has been submitted |
| 5 | Navigate to the audit log or activity history section of the request | Audit log page or section is displayed |
| 6 | Locate the most recent entry for the information request action | Log entry exists showing: Action type 'Information Requested', Approver username, Timestamp (date and time), Comments entered, Request ID |
| 7 | Verify all required fields are captured in the log entry | Log entry contains complete information including user ID, action type, timestamp, and associated comments |
| 8 | Log out and log in as Schedule Coordinator (Requester) | Requester successfully logs in to the system |
| 9 | Open the schedule change request with the info request | Request details page displays with the information request visible |
| 10 | Submit additional information in response to the info request (e.g., 'Shift timing is 2 PM to 10 PM as per department needs') | Additional information is submitted successfully with confirmation message |
| 11 | Navigate to the audit log or activity history section | Audit log page or section is displayed |
| 12 | Locate the log entry for the additional information submission | Log entry exists showing: Action type 'Additional Information Submitted', Requester username, Timestamp (date and time), Response content or reference, Request ID |
| 13 | Verify the chronological order of log entries | Audit trail shows both actions in correct sequence: first the info request, then the response submission |
| 14 | Verify log entries are immutable and cannot be edited or deleted | No edit or delete options are available for audit log entries, ensuring data integrity |

**Postconditions:**
- All information request actions are permanently logged in the audit trail
- Log entries include complete details: user, timestamp, action type, and content
- Audit trail maintains chronological order of all actions
- Logs are accessible for compliance and review purposes
- System maintains data integrity of audit records

---

