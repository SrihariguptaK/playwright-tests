# Manual Test Cases

## Story: As Approver, I want to review and approve schedule change requests to ensure proper schedule management
**Story ID:** story-15

### Test Case: Approve a schedule change request successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Approver account exists with valid credentials
- Approver has appropriate approval permissions assigned
- At least one pending schedule change request exists in the system
- Schedule change request is assigned to the logged-in approver
- System is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid approver credentials (username and password), then click Login button | Approver is successfully authenticated and redirected to the dashboard/home page |
| 2 | Navigate to the pending approvals section/dashboard from the main menu | List of pending schedule change requests assigned to the approver is displayed with request details (requester name, date, type, submission date) |
| 3 | Select a specific pending schedule change request from the list by clicking on it | Request details page opens showing complete information including requester details, requested changes, reason, and any attachments |
| 4 | Click the 'Approve' button and optionally enter a comment in the comment field, then click 'Submit' or 'Confirm' | Request status updates to 'Approved' within 1 second, success message is displayed, and the request is removed from pending list or marked as approved |
| 5 | Verify that the requester receives notification of approval by checking the notification system or requester's notification inbox | Notification is successfully sent to the requester containing approval status, approver name, timestamp, and any comments provided |
| 6 | Navigate to approval history or audit log section | Approval action is logged with timestamp, approver details, request ID, action taken (approved), and comments |

**Postconditions:**
- Schedule change request status is 'Approved' in the database
- Requester has received approval notification via configured channels
- Approval action is recorded in audit trail with complete details
- Request is no longer in pending approvals list
- Approver remains logged in to the system

---

### Test Case: Reject a schedule change request with mandatory comment
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Approver account exists with valid credentials and approval permissions
- Approver is logged into the system
- At least one pending schedule change request exists assigned to the approver
- System validation rules for mandatory rejection comments are configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the pending approvals dashboard, select a schedule change request that needs to be rejected by clicking on it | Request details page is displayed with complete information about the schedule change request |
| 2 | Click the 'Reject' button | Rejection form is displayed with a mandatory comment input field clearly marked as required, and Submit/Cancel buttons |
| 3 | Leave the comment field empty and click the 'Submit' or 'Confirm Rejection' button | Validation error message is displayed indicating 'Comment is required for rejection' or similar message, and rejection is not processed |
| 4 | Enter a valid rejection comment in the comment field (e.g., 'Request conflicts with operational requirements') and click 'Submit' or 'Confirm Rejection' | Request status updates to 'Rejected' within 1 second, success message is displayed, and request is removed from pending list or marked as rejected |
| 5 | Verify that notification is sent to the requester by checking notification logs or requester's notification inbox | Rejection notification is sent to the requester containing rejection status, approver name, timestamp, and the mandatory rejection comment |
| 6 | Navigate to approval history or audit log section and locate the rejected request | Rejection action is logged with timestamp, approver details, request ID, action taken (rejected), and the rejection comment |

**Postconditions:**
- Schedule change request status is 'Rejected' in the database
- Rejection comment is stored with the request
- Requester has received rejection notification with comments
- Rejection action is recorded in audit trail
- Request is no longer in pending approvals list

---

### Test Case: Prevent unauthorized approval actions
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Two user accounts exist: one unauthorized user without approval permissions and one authorized approver
- At least one pending schedule change request exists in the system
- Authorization and authentication mechanisms are properly configured
- API endpoint security is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system using unauthorized user credentials (user without approval permissions) | User is successfully authenticated and logged into the system |
| 2 | Attempt to navigate to the pending approvals dashboard or directly access a schedule change request approval page via URL manipulation | Access is denied with error message 'You do not have permission to access this resource' or similar, and user is redirected to appropriate page or shown 403 Forbidden error |
| 3 | Attempt to call the approval API endpoint directly (PUT /api/schedule-change-requests/{id}/approval) using unauthorized user credentials | API returns 403 Forbidden or 401 Unauthorized status code with appropriate error message, and no changes are made to the request status |
| 4 | Log out the unauthorized user and log in using authorized approver credentials | Authorized approver is successfully authenticated and logged into the system |
| 5 | Navigate to pending approvals dashboard | Pending approvals dashboard is accessible and displays list of pending schedule change requests |
| 6 | Select a pending request and click 'Approve' button, optionally add a comment, and submit the approval | Approval is processed successfully, request status updates to 'Approved' within 1 second, and success message is displayed |
| 7 | Verify the approval action in the audit log | Approval action is logged with authorized approver's details, timestamp, and action taken |

**Postconditions:**
- Unauthorized access attempts are blocked and logged in security audit trail
- Schedule change request status is 'Approved' only after authorized approver action
- System security integrity is maintained
- Authorized approver remains logged in

---

## Story: As Employee, I want to receive notifications about schedule change request status to stay informed
**Story ID:** story-16

### Test Case: Verify notification sent on schedule change request submission
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has valid email address configured in the system
- Employee is logged into the system
- Notification service is operational and configured
- Email server is accessible and functional
- In-app notification system is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request submission page from the employee dashboard | Schedule change request form is displayed with all required fields (date, time, reason, etc.) |
| 2 | Fill in all required fields with valid data (select date, time, enter reason for change) and click 'Submit' button | Request is successfully submitted, confirmation message is displayed, and request is saved in the system with 'Pending' status |
| 3 | Check the employee's email inbox for submission confirmation notification within 1 minute | Email notification is received containing submission confirmation, request ID, submitted date/time, requested changes, and current status (Pending) |
| 4 | Navigate to the in-app notifications section or notification bell icon in the application | In-app notification is displayed showing submission confirmation with request details including request ID, submission timestamp, and status |
| 5 | Click on the in-app notification to view details | Notification expands or navigates to show complete details of the submitted request matching the information in the email notification |
| 6 | Navigate to notification history or logs section in the admin panel or system logs | Notification record is logged with timestamp, recipient (employee), notification type (submission confirmation), delivery status (sent), and channels used (email and in-app) |

**Postconditions:**
- Employee has received submission confirmation via both email and in-app channels
- Notification is logged in the system with timestamp and delivery status
- Schedule change request remains in 'Pending' status
- Employee can view notification history
- Notification was delivered within 1 minute of submission

---

### Test Case: Verify notification sent on approval decision
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee has submitted a schedule change request that is in 'Pending' status
- Approver account exists with approval permissions
- Employee has valid email address and in-app notification access
- Notification service is operational
- Request is assigned to an active approver

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as an approver with valid credentials | Approver is successfully authenticated and logged into the system |
| 2 | Navigate to pending approvals dashboard and select the employee's schedule change request | Request details are displayed with all relevant information |
| 3 | Click 'Approve' button, optionally enter approval comments (e.g., 'Approved as requested'), and submit the approval | Request status updates to 'Approved', success message is displayed, and approval is processed |
| 4 | Log out as approver and log in as the employee who submitted the request | Employee is successfully authenticated and logged into the system |
| 5 | Check the employee's email inbox for approval notification within 1 minute | Email notification is received containing approval status, approver name, approval timestamp, request details, and any comments provided by the approver |
| 6 | Navigate to in-app notifications section in the employee dashboard | In-app notification is displayed showing approval status with complete details including approver name, timestamp, and comments |
| 7 | Click on the notification to view full details | Notification details page opens displaying approval status, approver comments, approval date/time, and updated request status with all relevant information |
| 8 | Verify notification logging in the system logs or notification history | Approval notification is logged with timestamp, recipient (employee), notification type (approval), delivery channels (email and in-app), and delivery status (sent) |

**Postconditions:**
- Employee has received approval notification via email and in-app channels
- Notification includes approval status and approver comments
- Notification is logged with complete details and timestamp
- Schedule change request status is 'Approved'
- Employee is informed of the approval decision

---

### Test Case: Ensure notifications are not sent to unauthorized users
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Multiple user accounts exist in the system
- A schedule change request exists submitted by Employee A
- Employee B exists but is not associated with the request
- Notification service is operational with security controls enabled
- System has authorization checks configured for notification delivery

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify a schedule change request submitted by Employee A and note the request ID | Request details are visible showing Employee A as the requester |
| 2 | Attempt to trigger a notification for this request to Employee B (unauthorized user) either through API call, system manipulation, or notification service directly using POST /api/notifications endpoint | System validates the recipient against the request and blocks the notification attempt with error message 'Unauthorized recipient' or similar |
| 3 | Check Employee B's email inbox and in-app notifications | No notification related to Employee A's schedule change request is received by Employee B |
| 4 | Review notification logs or security audit logs for the blocked notification attempt | Blocked notification attempt is logged with timestamp, attempted recipient (Employee B), request ID, reason for blocking (unauthorized user), and security event details |
| 5 | Trigger a legitimate notification for the same request to Employee A (the actual requester) by having an approver approve or reject the request | Notification is successfully sent to Employee A via email and in-app channels |
| 6 | Verify Employee A receives the notification while Employee B does not | Employee A has the notification in email and in-app, Employee B has no notifications related to this request |
| 7 | Check notification logs to confirm proper delivery | Notification log shows successful delivery to Employee A only, with no delivery attempts to Employee B for legitimate notifications |

**Postconditions:**
- Unauthorized user (Employee B) did not receive any notifications for requests they are not associated with
- Blocked notification attempt is logged in security audit trail
- Authorized user (Employee A) received notifications successfully
- System security controls for notification delivery are validated
- Notification service maintains authorization integrity

---

## Story: As Manager, I want to view reports on schedule change approvals to monitor workflow efficiency
**Story ID:** story-17

### Test Case: View schedule change approval dashboard with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Schedule change approval data exists in the system
- User has network connectivity
- Browser is supported (Chrome, Firefox, Safari, Edge)
- Manager has authorization to access reporting portal

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the reporting portal by clicking on 'Reports' menu option | Reporting portal page loads successfully |
| 2 | Manager selects 'Schedule Change Approval Reports' from the available report types | Dashboard with metrics and charts is displayed showing approval times, pending requests, volumes, and outcomes with visual representations |
| 3 | Manager clicks on the date range filter and selects a custom date range (e.g., last 30 days) | Date range filter is applied and displayed in the filter section |
| 4 | Manager selects a specific department from the department dropdown filter | Department filter is applied and displayed in the filter section |
| 5 | Manager clicks 'Apply Filters' button | Dashboard updates to reflect filtered data showing only schedule change approvals for the selected date range and department. Charts and tables refresh with filtered metrics |
| 6 | Manager clicks on 'Export' button and selects 'CSV' format from the export options | CSV file is downloaded to the default download location with correct filtered data including all visible metrics, properly formatted columns, and accurate values matching the dashboard display |

**Postconditions:**
- Dashboard remains in filtered state
- CSV file is saved locally on manager's device
- Export action is logged in system audit trail
- User session remains active

---

### Test Case: Verify dashboard load time under normal load
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role credentials
- System is under normal load conditions (peak hours)
- Network connection is stable with normal bandwidth
- Schedule change approval data exists in the system
- Performance monitoring tools are available to measure load time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the reporting portal during peak business hours (e.g., 9 AM - 11 AM) | Reporting portal navigation is initiated |
| 2 | Manager selects 'Schedule Change Approval Reports' and starts timer to measure load time | Dashboard loads completely with all metrics, charts, and tables displayed within 3 seconds. All visual elements are rendered properly and data is fully populated |
| 3 | Verify all dashboard components are interactive and responsive | All filters, buttons, charts, and tables are functional and respond to user interactions without delay |

**Postconditions:**
- Dashboard is fully loaded and functional
- Performance metrics are recorded
- User session remains active
- System maintains normal load performance

---

### Test Case: Ensure unauthorized users cannot access reports
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with non-manager role (e.g., Employee, Contractor)
- Role-based access control is configured in the system
- User does not have managerial permissions
- Reporting portal exists and is accessible to authorized users

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Non-manager user attempts to navigate to the reporting dashboard by entering the URL directly or clicking on Reports menu (if visible) | Access denied message is displayed with text similar to 'You do not have permission to access this resource' or 'Access Restricted to Managers Only' |
| 2 | Verify that no report data or dashboard elements are visible to the unauthorized user | No sensitive data, metrics, charts, or tables are displayed. User remains on access denied page or is redirected to their authorized home page |
| 3 | Check system logs for the unauthorized access attempt | Unauthorized access attempt is logged in security audit trail with timestamp, user ID, and attempted resource |

**Postconditions:**
- User remains logged in with their original role
- No unauthorized access to reporting data occurred
- Security event is logged
- User is redirected to appropriate authorized page

---

## Story: As Approver, I want to escalate pending schedule change approvals to ensure timely decisions
**Story ID:** story-18

### Test Case: Automatic escalation of overdue approvals
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Escalation rules and thresholds are configured in the system (e.g., 48 hours)
- Schedule change request exists and is pending approval
- Higher-level approver is designated in the escalation hierarchy
- Email/notification service is operational
- System monitoring service is running and checking for overdue approvals

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a schedule change request and submit it for approval | Schedule change request is created successfully and status is set to 'Pending Approval' |
| 2 | Wait for the configured threshold period to elapse without approval action (or simulate time passage in test environment) | System detects that the approval is overdue based on the configured threshold. Approval status shows as 'Overdue' or 'Escalated' |
| 3 | System automatically triggers escalation process and sends notification to higher-level approver | Escalation notification is sent to the designated higher-level approver via email/system notification containing request details, original approver information, and escalation reason. Notification is received within 5 minutes of threshold breach |
| 4 | Higher-level approver logs in and views the escalated request in their approval queue | Escalated request appears in the higher-level approver's queue with 'Escalated' indicator and shows escalation timestamp |
| 5 | Escalated approver reviews and approves the schedule change request | Approval status updates to 'Approved'. Original requester receives approval notification. Escalation is marked as resolved in the system |
| 6 | Verify escalation history log for the request | Escalation history shows complete audit trail including: original submission time, threshold breach time, escalation trigger time, escalated approver details, and resolution time with timestamps |

**Postconditions:**
- Schedule change request is approved
- Escalation is logged in system history
- All stakeholders are notified of approval
- Escalation metrics are updated in reporting dashboard
- Request is removed from pending escalation queue

---

### Test Case: Manual escalation by approver
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Approver role credentials
- Schedule change request is pending approval and assigned to the approver
- Approver has permission to perform manual escalations
- Higher-level approver is designated in escalation hierarchy
- Manual escalation feature is enabled in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver navigates to their pending approvals queue | List of pending schedule change requests is displayed |
| 2 | Approver selects a specific pending request that requires urgent attention | Request details page opens showing full information about the schedule change |
| 3 | Approver clicks on 'Escalate' button or selects 'Manual Escalation' option from the actions menu | Escalation dialog or form appears prompting for escalation reason and designated approver selection |
| 4 | Approver enters escalation reason (e.g., 'Requires senior management review') and confirms the escalation | Manual escalation is processed successfully. Escalation notification is sent to the designated higher-level approver with the reason provided. Confirmation message is displayed to the approver |
| 5 | Navigate to escalation history or audit log for the request | Escalation history shows the manual escalation entry with timestamp, escalating approver name, escalated-to approver name, escalation reason, and 'Manual' escalation type indicator |
| 6 | Verify the designated higher-level approver receives the escalation notification | Higher-level approver receives notification with request details, manual escalation indicator, and reason provided by the original approver |

**Postconditions:**
- Request is escalated to higher-level approver
- Manual escalation is logged with complete details
- Original approver is notified of escalation confirmation
- Request appears in escalated approver's queue
- Escalation metrics are updated

---

### Test Case: Prevent unauthorized manual escalation
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in without Approver role or escalation permissions (e.g., Employee, Requester)
- Schedule change request exists in the system
- Authorization controls are configured for escalation actions
- User does not have escalation privileges in their role permissions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Unauthorized user attempts to access a schedule change request details page | Request details page loads with limited view permissions (if allowed) or access is denied |
| 2 | Unauthorized user attempts to locate and click on 'Escalate' button or manual escalation option | Escalate button is either not visible/hidden for unauthorized users, or is disabled/grayed out |
| 3 | If escalation option is visible, unauthorized user attempts to click it or attempts to access escalation API endpoint directly | Access denied error is displayed with message such as 'You do not have permission to escalate approvals' or 'Unauthorized action'. No escalation is processed |
| 4 | Verify system security logs for the unauthorized escalation attempt | Unauthorized escalation attempt is logged in security audit trail with timestamp, user ID, attempted action, and denial reason |
| 5 | Verify that no escalation notification was sent and escalation history remains unchanged | No escalation notifications are sent. Escalation history for the request shows no new entries. Request status remains unchanged |

**Postconditions:**
- No unauthorized escalation occurred
- Request status and assignment remain unchanged
- Security violation is logged
- User remains on current page or is redirected appropriately
- System security integrity is maintained

---

## Story: As Manager, I want to receive alerts for failed schedule change approval processes to promptly address issues
**Story ID:** story-21

### Test Case: Detect and alert on approval workflow failure
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager user account is active and has proper authorization
- Manager email address is configured in the system
- Alert settings are properly configured for the manager
- Schedule change approval workflow is operational
- WorkflowLogs database is accessible
- Email and in-app notification services are running
- Manager has access to the alert history interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the test environment and access the workflow simulation tool | Workflow simulation tool loads successfully |
| 2 | Simulate a failure in the schedule change approval workflow by triggering a test failure event (e.g., invalid approver, system timeout, or data validation error) | System detects the failure event and logs it in WorkflowLogs with timestamp and failure type |
| 3 | Wait for the system to process the failure event and trigger the alert mechanism | Alert is generated and queued for delivery to the designated manager |
| 4 | Check the manager's email inbox for the alert notification | Manager receives an email alert containing failure details including workflow ID, failure type, timestamp, affected schedule, and recommended actions |
| 5 | Log in to the system as the manager and check the in-app notification center | Manager sees an in-app notification with the same detailed failure information including workflow ID, failure type, timestamp, affected schedule, and recommended actions |
| 6 | As the manager, navigate to the alert history section in the application | Alert history page loads successfully showing all historical alerts |
| 7 | Search for the recently triggered alert in the alert history | Alert is logged in the history with correct details including timestamp, recipient name, failure type, workflow ID, delivery status (email and in-app), and alert content |
| 8 | Verify the alert details match the simulated failure event | All alert details accurately reflect the simulated failure including correct workflow ID, failure reason, and timestamp |

**Postconditions:**
- Alert is successfully logged in the alert history database
- Manager has received both email and in-app notifications
- Failure event is properly recorded in WorkflowLogs
- Alert delivery status is marked as successful
- System is ready to detect and alert on subsequent failures

---

### Test Case: Verify alert delivery within SLA
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager user account is active with proper authorization
- Alert settings are configured for the manager
- Email and in-app notification services are operational
- System clock is synchronized and accurate
- WorkflowLogs database is accessible
- Performance monitoring tools are available to track timing
- Schedule change approval workflow is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare timing measurement tools and note the current system time | Timing tools are ready and baseline time is recorded |
| 2 | Trigger a failure event in the schedule change approval workflow and record the exact timestamp of the failure | Failure event is triggered and timestamp is captured (T0) |
| 3 | Monitor the system logs and alert queue for alert generation | System detects the failure and generates an alert entry in the queue |
| 4 | Check the manager's email inbox and record the timestamp when the email alert is received | Email alert is received and timestamp is recorded (T1) |
| 5 | Log in as the manager and check the in-app notification center, recording the timestamp when the notification appears | In-app notification is displayed and timestamp is recorded (T2) |
| 6 | Calculate the time difference between failure trigger (T0) and email delivery (T1) | Time difference is less than or equal to 2 minutes (120 seconds) |
| 7 | Calculate the time difference between failure trigger (T0) and in-app notification delivery (T2) | Time difference is less than or equal to 2 minutes (120 seconds) |
| 8 | Review the alert history log to verify the recorded delivery timestamps | Alert history shows delivery timestamps that confirm SLA compliance (within 2 minutes of failure detection) |

**Postconditions:**
- Alert delivery time is documented and meets SLA requirements
- Performance metrics are recorded for reporting
- Alert is logged with accurate delivery timestamps
- System demonstrates compliance with 2-minute SLA requirement

---

### Test Case: Prevent unauthorized access to alert management
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Unauthorized user account exists in the system (non-manager role)
- Unauthorized user has valid login credentials
- Alert configuration interface is deployed and accessible
- Security and access control mechanisms are active
- Manager role permissions are properly configured in the system
- Alert management features are protected by role-based access control

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system using unauthorized user credentials (user without manager role) | User successfully logs in to the system with limited permissions |
| 2 | Attempt to navigate to the alert configuration page by entering the URL directly or through navigation menu | Access is denied and an error message is displayed stating 'Access Denied: You do not have permission to access alert configuration' or similar authorization error |
| 3 | Attempt to access the alert configuration API endpoint directly using POST /api/alerts with unauthorized credentials | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 4 | Attempt to view the alert history page as an unauthorized user | Access is denied with appropriate error message indicating the feature is restricted to authorized managers only |
| 5 | Attempt to modify alert settings by manipulating request parameters or using browser developer tools | All modification attempts are blocked and security logs record the unauthorized access attempt |
| 6 | Verify that no alert configuration data or sensitive information is exposed in the error response | Error messages do not reveal system architecture, database structure, or sensitive configuration details |
| 7 | Check security audit logs for the unauthorized access attempts | All unauthorized access attempts are logged with user ID, timestamp, attempted action, and denial reason |

**Postconditions:**
- Unauthorized user remains unable to access alert management features
- No unauthorized changes were made to alert configurations
- Security audit logs contain records of all access attempts
- System security integrity is maintained
- Alert configuration remains protected and unchanged

---

