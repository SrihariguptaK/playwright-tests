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
- Requests have different dates and requesters for filtering
- At least one request has attachments uploaded
- System is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid Approver credentials (username and password), then click Login button | User is successfully authenticated and redirected to the Approver dashboard displaying a list of pending schedule change requests with columns for request ID, requester name, date submitted, and status |
| 2 | Locate the filter section and select a specific date range from the date picker, then select a specific requester from the requester dropdown | The pending requests list automatically refreshes and displays only the requests matching the selected date range and requester criteria. Request count updates to reflect filtered results |
| 3 | Click on one of the filtered schedule change requests from the list to open the detailed view | Detailed view page opens showing complete request information including: request ID, requester details, submission date, requested schedule changes, reason for change, current status, request history, comments section, and all attached documents with download links |

**Postconditions:**
- User remains logged in as Approver
- Detailed request view is displayed
- No data has been modified
- Filters remain applied to the list view

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
- Request detail view is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the pending requests list, click on a specific schedule change request to open its detail view | Request detail page loads successfully displaying all request information, attachments, existing comments history, and a comment input field at the bottom of the page |
| 2 | Scroll to the comments section, enter text 'Please provide additional justification for this schedule change' in the comment input field, then click the Submit or Add Comment button | Comment is successfully saved and immediately appears in the request history section with the approver's name, timestamp, and comment text. A success confirmation message is displayed. The comment input field is cleared |
| 3 | Click the browser refresh button or navigate away from the request and return to the same request detail view | The request detail page reloads and the previously added comment 'Please provide additional justification for this schedule change' is still visible in the request history with correct timestamp and approver name |

**Postconditions:**
- Comment is permanently saved in the database
- Request history is updated with the new comment
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
- Network connection is stable with normal bandwidth
- System is under normal load conditions (not peak hours)
- Browser performance monitoring tools or stopwatch available for timing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page, enter valid Approver credentials, and click Login button while starting a timer | User is authenticated and the Approver dashboard with pending requests list is fully loaded and displayed. All request entries are visible with complete data |
| 2 | Start a timer and click on the pending requests section or refresh the pending requests list | The complete list of pending schedule change requests loads and displays within 3 seconds. All columns (request ID, requester, date, status) are populated with data. Stop timer and verify load time is ≤ 3 seconds |
| 3 | Start a timer, apply multiple filters (select a date range and a specific requester), then measure the time until the filtered results are fully displayed | The filtered list of schedule change requests loads and displays within 3 seconds. Only requests matching the filter criteria are shown. Request count updates correctly. Stop timer and verify response time is ≤ 3 seconds |

**Postconditions:**
- All performance measurements are documented
- System remains responsive
- No performance degradation observed
- Filters remain applied and functional

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
- User has approval permissions for the request
- Audit logging system is operational
- Database connection is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the pending schedule change requests list and click on a specific pending request to open its detail view | Request detail page opens displaying complete request information including: request ID, requester details, requested changes, current status showing 'Pending', and action buttons (Approve, Reject, Request More Info) |
| 2 | Review the request details, optionally enter approval comments in the comments field, then click the Approve button and confirm the action if prompted | System processes the approval action and displays a success confirmation message. The request status immediately updates from 'Pending' to 'Approved'. The Approve button becomes disabled or changes to show 'Approved' state. Timestamp of approval is displayed |
| 3 | Navigate to the audit log section or admin panel and search for the audit entry corresponding to this request ID and approval action | Audit log displays a new entry containing: the approver's username, exact timestamp of approval action, action type 'Approved', request ID, and any comments entered. All audit fields are populated correctly and match the approval action performed |

**Postconditions:**
- Request status is permanently changed to 'Approved'
- Audit log entry is created and stored
- Request is removed from pending list
- Notification is queued for requester (if in scope)
- Request cannot be modified further without proper workflow

---

### Test Case: Verify rejection requires comments
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with valid Approver role credentials
- At least one pending schedule change request exists in the system
- User has rejection permissions for the request
- Comment validation is enabled in the system
- Audit logging system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the pending requests list, click on a specific pending schedule change request to open its detail view | Request detail page loads successfully displaying all request information, current status as 'Pending', and action buttons including Reject button. Comments field is visible and empty |
| 2 | Without entering any text in the comments field, click the Reject button | System prevents the rejection submission and displays a validation error message such as 'Comments are required when rejecting a request' or 'Please provide a reason for rejection'. The request status remains 'Pending'. The Reject action is not processed |
| 3 | Enter rejection comments in the comments field (e.g., 'Insufficient justification provided for schedule change'), then click the Reject button and confirm if prompted | System successfully processes the rejection. Request status updates from 'Pending' to 'Rejected'. Success confirmation message is displayed. The rejection comments are saved and visible in the request history. Audit log entry is created containing: approver username, timestamp, action type 'Rejected', request ID, and the rejection comments entered |

**Postconditions:**
- Request status is changed to 'Rejected'
- Rejection comments are permanently saved
- Audit log entry is created with all required details
- Request is removed from pending list
- Validation rules for comments are confirmed working

---

### Test Case: Ensure unauthorized users cannot approve requests
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User account exists without Approver role permissions (e.g., regular employee or requester role)
- At least one pending schedule change request exists in the system
- Role-based access control is configured and active
- API endpoint security is properly configured
- Audit logging system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system using credentials of a user without approval permissions (e.g., regular employee role), then navigate to the dashboard or attempt to access the schedule change requests section | User successfully logs in but the approval-related features are not visible. Approval action buttons (Approve, Reject, Request More Info) are either hidden or disabled. The pending requests list may not be accessible at all, or if visible, shows no action buttons |
| 2 | Using API testing tools (e.g., Postman, curl) or browser developer console, attempt to directly call the approval API endpoint POST /api/schedule-changes/{id}/approval with a valid request ID and approval action payload | API returns an authorization error response with HTTP status code 401 (Unauthorized) or 403 (Forbidden). Error message indicates 'Access denied' or 'Insufficient permissions to perform this action'. No changes are made to the request status in the database |
| 3 | Navigate to the audit log section (if accessible) or have an administrator check the audit logs for any entries related to the unauthorized access attempts made in previous steps | Audit log shows no approval action entries for the unauthorized user. If security logging is enabled, there may be entries for failed authorization attempts showing the username, timestamp, attempted action, and 'Access Denied' result. No approval actions are recorded as successful |

**Postconditions:**
- No schedule change requests have been modified
- System security remains intact
- No unauthorized audit entries exist
- Role-based access control is confirmed working
- User remains logged in with limited permissions

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
| 6 | Navigate to the active rules list view | Active rules list displays the newly created rule 'Engineering Department Routing' with status 'Active' and correct configuration details |

**Postconditions:**
- New routing rule is persisted in ApprovalRoutingRules table
- Rule is active and available for routing schedule change requests
- Rule appears in the active rules list with correct details
- System audit log contains rule creation entry

---

### Test Case: Verify validation prevents conflicting routing rules
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as System Administrator
- At least one active routing rule exists: 'Department equals Engineering assigns to John Smith'
- Routing rules management page is accessible
- Rule conflict validation logic is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to routing rules management page and click 'Create New Rule' button | Rule creation form opens with empty fields ready for input |
| 2 | Enter rule name 'Conflicting Engineering Rule', select condition 'Department equals Engineering', and assign different approver 'Jane Doe' | Form accepts all input values and displays them correctly |
| 3 | Click 'Save' button to attempt saving the conflicting rule | System detects conflict with existing rule and displays error message: 'Conflict detected: A rule with identical conditions already exists for Engineering department. Please modify conditions or deactivate the existing rule.' |
| 4 | Verify the rule is not saved and form remains open with entered data | Rule is not added to the database, form retains entered values, and save operation is blocked |
| 5 | Modify the condition to 'Department equals Engineering AND Request Type equals Shift Swap' to resolve the conflict | Updated condition is displayed in the form with additional criteria added |
| 6 | Click 'Save' button again with the modified rule | System validates successfully, saves the rule, and displays confirmation message 'Routing rule created successfully' |
| 7 | Verify the new rule appears in the active rules list without conflicts | Both rules are listed as active with distinct conditions and no conflict warnings displayed |

**Postconditions:**
- Conflicting rule was prevented from being saved initially
- Modified rule is successfully saved and active
- No conflicting rules exist in the system
- Validation error was logged in system logs

---

### Test Case: Ensure routing rules apply correctly to sample requests
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as System Administrator
- At least two active routing rules exist with different conditions
- Test feature is enabled in routing rules management interface
- Sample schedule change request templates are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to routing rules management page and locate the 'Test Routing Rules' section | Test section displays with options to input sample request parameters |
| 2 | Click 'Create Sample Request' button to open the test request form | Sample request form opens with fields for Department, Request Type, Schedule Type, and Request Size |
| 3 | Enter sample request parameters: Department='Engineering', Request Type='Shift Swap', Schedule Type='Full-time', Request Size='Single' | All parameters are entered and displayed correctly in the form |
| 4 | Click 'Test Routing' button to apply routing rules to the sample request | System evaluates active routing rules against sample request parameters and displays results within 1 second |
| 5 | Review the routing results displayed on screen | System displays matched routing rule name, applied conditions, and assigned approvers list showing 'John Smith' based on the matching rule |
| 6 | Modify sample request parameters to Department='Marketing', keeping other parameters the same | Updated parameter is reflected in the test form |
| 7 | Click 'Test Routing' button again with modified parameters | System re-evaluates routing rules and displays updated results showing different approver 'Sarah Johnson' assigned based on Marketing department rule |
| 8 | Verify routing results update reflects the parameter change accurately | Routing results show correct rule match for Marketing department with appropriate approver assignment, confirming dynamic rule application |

**Postconditions:**
- Test routing functionality validated without affecting production data
- Routing rules correctly matched sample requests based on conditions
- No test data persisted in production tables
- Rule evaluation performance met 1-second requirement

---

## Story: As Approver, I want to escalate pending schedule change approvals to achieve timely decision making
**Story ID:** story-7

### Test Case: Validate automatic escalation of pending approvals
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Escalation rules are configured with threshold set to 24 hours
- At least one backup approver is designated in the system
- Escalation service is running and operational
- Email/notification service is configured and functional
- Test schedule change request exists in pending approval status

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a new schedule change request as an employee and submit for approval | Schedule change request is created successfully with status 'Pending Approval' and timestamp recorded |
| 2 | Verify the request is assigned to primary approver and remains in pending status | Request appears in primary approver's queue with 'Pending' status and no escalation flag |
| 3 | Simulate time passage by adjusting system time or waiting for the configured escalation threshold (24 hours) to be exceeded | Request remains in pending status throughout the threshold period without any action from primary approver |
| 4 | Wait for escalation processing service to run its scheduled check (within 1 minute of threshold breach) | Escalation service detects the pending request exceeding threshold and triggers automatic escalation process |
| 5 | Verify the request status is updated to 'Escalated' in the ApprovalActions table | Request status changes to 'Escalated' with escalation timestamp recorded and escalation flag set to true |
| 6 | Check the backup approver's notification inbox or email | Escalation notification is received by backup approver containing request details, original approver name, escalation reason, and action link |
| 7 | Verify the request now appears in backup approver's pending approvals queue | Escalated request is visible in backup approver's queue with 'Escalated' badge and priority indicator |

**Postconditions:**
- Request status is 'Escalated' in the database
- Backup approver has received notification and can access the request
- Original approver retains visibility of the escalated request
- Escalation event is logged in system audit trail
- Escalation metrics are updated for reporting

---

### Test Case: Verify escalation logging and status tracking
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User has authorized access to escalation monitoring interface
- At least one schedule change request is pending beyond escalation threshold
- Escalation service is active and monitoring pending requests
- Escalation logging functionality is enabled
- Database tables ApprovalActions and EscalationRules are accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify a pending schedule change request that has exceeded the escalation threshold | Pending request is identified with timestamp showing it has been pending for more than configured threshold |
| 2 | Wait for or manually trigger the escalation process for the identified request | Escalation process executes and escalates the pending request to backup approver |
| 3 | Query the ApprovalActions table to retrieve escalation log entry for the request | Escalation action record exists with fields: request ID, action type 'Escalated', timestamp of escalation, original approver ID, backup approver ID, and escalation reason |
| 4 | Verify the timestamp in the log entry matches the actual escalation time within acceptable margin | Timestamp is accurate and reflects the exact time escalation was triggered (within 1 minute of threshold breach) |
| 5 | Verify user details in the log include both original approver and backup approver information | Log entry contains complete user details: original approver name and ID, backup approver name and ID, and escalation initiator (system) |
| 6 | Log in as authorized user and navigate to the escalation monitoring UI dashboard | Escalation monitoring dashboard loads displaying list of all escalated requests with status indicators |
| 7 | Locate the escalated request in the monitoring interface and review displayed status information | Request is displayed with accurate status 'Escalated', escalation timestamp, current assignee (backup approver), days pending, and escalation level |
| 8 | Click on the escalated request to view detailed escalation history | Detailed view shows complete escalation timeline including original submission, threshold breach time, escalation trigger time, and all notification events |

**Postconditions:**
- Escalation action is permanently logged in ApprovalActions table
- Escalation status is accurately reflected in monitoring UI
- Audit trail is complete with all timestamps and user details
- Escalation data is available for reporting and analytics
- No data inconsistencies exist between database and UI

---

### Test Case: Ensure escalation processing meets performance requirements
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Escalation service is running with performance monitoring enabled
- Multiple schedule change requests are in pending status
- Escalation threshold is configured to a testable value (e.g., 5 minutes for testing)
- System performance monitoring tools are active
- Notification service has capacity to handle multiple simultaneous notifications
- Test environment mirrors production load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create 10 schedule change requests and submit them for approval simultaneously | All 10 requests are created successfully with 'Pending Approval' status and identical submission timestamps |
| 2 | Configure or simulate time to exceed the escalation threshold for all 10 requests simultaneously | All requests reach threshold breach point at the same time, triggering bulk escalation scenario |
| 3 | Start performance timer and monitor escalation service processing | Escalation service detects all 10 pending requests exceeding threshold and begins processing |
| 4 | Measure the time taken from threshold breach to completion of escalation processing for all requests | All 10 requests are escalated and status updated within 1 minute of threshold breach, meeting performance requirement |
| 5 | Verify all escalation records are created in the database with accurate timestamps | Database contains 10 escalation log entries, all with timestamps within 1 minute of threshold breach time |
| 6 | Check notification delivery timestamps for all backup approvers | All 10 escalation notifications are generated and queued for delivery within the 1-minute processing window |
| 7 | Verify notifications are delivered to backup approvers within SLA (95% within defined timeframe) | At least 9 out of 10 notifications (95%) are delivered successfully within the SLA timeframe, confirming prompt delivery |
| 8 | Review system performance metrics including CPU usage, memory consumption, and database query times during escalation processing | System resources remain within acceptable limits, no performance degradation observed, and all operations complete within 1-minute requirement |
| 9 | Verify no escalations were missed or delayed beyond the 1-minute processing requirement | 100% of eligible requests were escalated within performance threshold with no failures or delays |

**Postconditions:**
- All test requests successfully escalated within performance requirements
- Performance metrics documented and meet specified thresholds
- Notification delivery meets 95% SLA requirement
- System stability maintained under load conditions
- No pending requests remain unprocessed
- Performance test results logged for compliance verification

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
| 4 | Enter detailed comments explaining what additional information is needed (e.g., 'Please provide justification for the extended hours and manager approval') | Comments are entered successfully in the text field with character count displayed if applicable |
| 5 | Click 'Submit' or 'Send Request' button | System displays a confirmation message indicating the information request has been submitted successfully |
| 6 | Verify the request status has changed to 'Info Requested' or similar status | Request status is updated and displayed on the request details page |
| 7 | Check that the notification has been sent to the requester by verifying notification logs or system notifications panel | Notification entry shows successful delivery to requester with timestamp and notification content |
| 8 | Log in as the requester user in a separate browser or session | Requester successfully logs in and dashboard is displayed |
| 9 | Check notifications or inbox for the information request notification | Notification is visible showing the approver's request for additional information with the comments entered |

**Postconditions:**
- Schedule change request status is updated to 'Info Requested'
- Notification is successfully delivered to requester
- Info request is logged in the system with timestamp and approver details
- Request remains in pending state awaiting additional information
- Approver can view the info request in the request history

---

### Test Case: Verify requester can submit additional information
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Schedule Coordinator (requester) role
- An information request has been submitted by an approver for one of the requester's schedule change requests
- Notification for info request is present in the requester's notification panel
- Original schedule change request is in 'Info Requested' status
- Requester has permission to update their schedule change requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as Schedule Coordinator | User successfully logs in and is redirected to the dashboard |
| 2 | Navigate to the notifications panel or inbox | Notifications panel displays with unread notification badge or indicator |
| 3 | Locate and view the information request notification | Notification is visible showing the approver's name, request details, and comments explaining what information is needed |
| 4 | Click on the notification to open the associated schedule change request | Schedule change request details page opens showing original request details and the approver's information request with comments |
| 5 | Locate the 'Submit Additional Information' or 'Respond' section on the request page | A text entry field or form is displayed for entering additional information |
| 6 | Enter the requested additional information in the response field (e.g., 'Manager approval attached. Extended hours needed due to project deadline on March 15th') | Additional information is entered successfully in the text field |
| 7 | Attach any supporting documents if applicable | Documents are uploaded and attached successfully with file names displayed |
| 8 | Click 'Submit' or 'Send Response' button | System displays confirmation message that additional information has been submitted successfully |
| 9 | Verify the request status has changed to 'Pending Review' or similar status | Request status is updated and displayed on the request details page |
| 10 | Verify the submitted information is linked to the original request by checking the request history or timeline | Additional information appears in the request timeline with timestamp and is clearly linked to the original request |
| 11 | Log in as the approver in a separate browser or session | Approver successfully logs in and dashboard is displayed |
| 12 | Open the same schedule change request | Request details page opens with all information displayed |
| 13 | Locate and review the additional information section | Additional information submitted by the requester is visible and clearly displayed with timestamp, including any attached documents |

**Postconditions:**
- Additional information is saved and linked to the original schedule change request
- Request status is updated to 'Pending Review' or equivalent
- Approver can view the additional information provided
- Response action is logged in the audit trail
- Notification may be sent to approver indicating response has been submitted

---

### Test Case: Ensure all info request actions are logged
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User has Approver role access
- User has Schedule Coordinator (requester) role access or separate test accounts for both roles
- At least one pending schedule change request exists
- Audit logging is enabled in the system
- User has permission to view audit logs or system administrator access is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Approver | Approver successfully logs in and dashboard is displayed |
| 2 | Open a pending schedule change request | Request details page is displayed with all request information |
| 3 | Click 'Request More Info' button and enter comments 'Need clarification on shift timing' | Comment entry form is displayed and comments are entered successfully |
| 4 | Submit the information request | Confirmation message is displayed and request status is updated to 'Info Requested' |
| 5 | Navigate to the audit log or system logs section (may require admin access) | Audit log page is displayed with list of recent system actions |
| 6 | Filter or search for the schedule change request ID or recent 'Info Request' actions | Audit log entries are filtered to show relevant actions |
| 7 | Verify the info request action is logged with complete details | Audit log entry shows: Action type 'Info Request', Approver username, Request ID, Timestamp (date and time), Comments entered, and any other relevant metadata |
| 8 | Log out and log in as Schedule Coordinator (requester) | Requester successfully logs in and dashboard is displayed |
| 9 | Navigate to the schedule change request with info request | Request details page opens showing the info request from approver |
| 10 | Submit additional information in response to the info request (e.g., 'Shift timing is 2 PM to 10 PM') | Additional information is submitted successfully with confirmation message |
| 11 | Navigate back to the audit log section | Audit log page is displayed |
| 12 | Search for the same schedule change request ID or recent 'Info Response' actions | Audit log entries are filtered to show the response action |
| 13 | Verify the info response action is logged in the audit trail with complete details | Audit log entry shows: Action type 'Info Response' or 'Additional Info Submitted', Requester username, Request ID, Timestamp (date and time), Response content or reference, and any other relevant metadata |
| 14 | Verify both actions (info request and info response) are visible in chronological order in the audit trail | Both audit log entries are displayed in sequence showing the complete information request workflow with all required details preserved |

**Postconditions:**
- Info request action is permanently logged in audit trail with user and timestamp
- Info response action is permanently logged in audit trail with user and timestamp
- Audit logs are accessible for compliance and review purposes
- Complete audit trail shows the information request workflow from request to response
- All logged data includes sufficient detail for audit and compliance requirements

---

