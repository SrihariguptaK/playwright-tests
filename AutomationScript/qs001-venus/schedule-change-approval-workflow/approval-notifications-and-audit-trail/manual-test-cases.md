# Manual Test Cases

## Story: As Employee, I want to view the status of my schedule change requests to stay informed about approvals
**Story ID:** story-4

### Test Case: Validate employee can view their schedule change request statuses
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee has valid login credentials
- At least one schedule change request has been submitted by the employee
- Another employee's schedule change request exists in the system for access control testing
- Database tables ScheduleChangeRequests and ApprovalActions are accessible
- API endpoint GET /api/schedule-change-requests/status is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click Login button | Employee is successfully authenticated and redirected to the dashboard |
| 3 | Verify the dashboard displays the list of schedule change requests submitted by the logged-in employee | Dashboard displays a list showing all schedule change requests with columns for request ID, date submitted, requested changes, and current status (pending/approved/rejected) |
| 4 | Review the displayed requests to confirm they belong to the logged-in employee only | All displayed requests are associated with the logged-in employee's ID and no other employee's requests are visible |
| 5 | Select a specific schedule change request from the list by clicking on it | Request details page opens showing comprehensive information about the selected request |
| 6 | Verify the detailed approval history is displayed on the request details page | Detailed approval history is shown including: approval workflow stages, approver names, action taken (approved/rejected/pending), comments from approvers, and timestamps for each status change in chronological order |
| 7 | Verify the current status is prominently displayed and matches the latest approval action | Current status (pending/approved/rejected) is clearly visible and accurately reflects the most recent approval action in the history |
| 8 | Manually construct a URL or API call to attempt accessing another employee's schedule change request using a different request ID | Access is denied with HTTP 403 Forbidden status or appropriate error message stating 'You do not have permission to view this request' or 'Access denied' |
| 9 | Verify that no data from the other employee's request is displayed or leaked in the error response | Error message is generic and does not reveal any information about the other employee's request |

**Postconditions:**
- Employee remains logged into the system
- No unauthorized data access has occurred
- All viewed data matches the employee's own schedule change requests
- Audit logs record the employee's access to their own requests only
- System security controls have been validated

---

### Test Case: Verify filtering and sorting of schedule change requests
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the system
- Employee has submitted multiple schedule change requests with different statuses (pending, approved, rejected)
- Schedule change requests have different submission dates spanning at least 2 weeks
- Schedule change requests page is accessible
- Filtering and sorting functionality is enabled in the UI

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the 'My Schedule Change Requests' page from the dashboard or main menu | Schedule change requests page loads successfully displaying the complete list of employee's requests in default order |
| 2 | Verify the initial list displays all schedule change requests without any filters applied | All schedule change requests are visible with columns showing request ID, date submitted, requested changes, and status |
| 3 | Locate the filter controls on the page (typically dropdowns or checkboxes for status filtering) | Filter controls are visible and accessible, showing options for filtering by status: All, Pending, Approved, Rejected |
| 4 | Apply a filter to show only 'Pending' status requests by selecting 'Pending' from the status filter dropdown | List immediately updates to display only schedule change requests with 'Pending' status, hiding all approved and rejected requests |
| 5 | Verify the count of displayed requests matches the number of pending requests | Request count indicator updates to show the correct number of pending requests, and all visible requests show 'Pending' status |
| 6 | Change the filter to show only 'Approved' status requests | List updates to display only approved requests, and all visible requests show 'Approved' status |
| 7 | Clear the status filter to show all requests again | List returns to showing all schedule change requests regardless of status |
| 8 | Locate the sorting controls (typically column headers or sort dropdown) and click on the 'Date Submitted' column header or select 'Date' from sort options | Sorting control is activated and list is sorted by submission date in descending order (newest first) |
| 9 | Verify the requests are sorted correctly by date with the most recent submission at the top | Requests are displayed in descending chronological order with dates decreasing from top to bottom |
| 10 | Click the 'Date Submitted' column header again to reverse the sort order | List is re-sorted in ascending order (oldest first) with the earliest submission date at the top |
| 11 | Apply both a status filter ('Pending') and date sorting (descending) simultaneously | List displays only pending requests sorted by date in descending order, showing the most recent pending request first |
| 12 | Verify the combined filter and sort results are accurate by manually checking the displayed data | All displayed requests have 'Pending' status and are arranged from newest to oldest submission date |

**Postconditions:**
- Employee remains on the schedule change requests page
- Filter and sort preferences may be saved for the session
- All data displayed remains accurate and belongs to the logged-in employee
- System performance remains within acceptable limits (page response under 2 seconds)
- No errors or warnings are displayed

---

## Story: As Manager, I want to receive notifications for pending schedule change approvals to ensure timely processing
**Story ID:** story-5

### Test Case: Validate notification sent on new pending approval
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Manager account exists and is active in the system
- Manager is configured as an approver in the approval workflow
- Manager has a valid email address registered in the system
- Email notification service is operational and configured
- In-app notification system is enabled
- Employee account exists with permission to submit schedule change requests
- Notification service API endpoints are accessible
- NotificationLogs table is accessible for verification
- Manager's notification preferences are set to receive both email and in-app notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as an employee who can submit schedule change requests | Employee is successfully logged into the system and dashboard is displayed |
| 2 | Navigate to the schedule change request submission page | Schedule change request form is displayed with all required fields |
| 3 | Fill in all required fields for a schedule change request (date, shift time, reason) and submit the request | Request is successfully submitted and confirmation message is displayed with request ID |
| 4 | Verify the request enters pending approval status and is assigned to the designated manager | Request status shows as 'Pending Approval' and the assigned approver is the test manager |
| 5 | Wait for up to 1 minute and verify that a notification is triggered by the system | System generates a notification event for the pending approval within 1 minute of request submission |
| 6 | Check the manager's email inbox for the notification email | Manager receives an email notification with subject line indicating a pending schedule change approval, email contains request ID, employee name, requested changes, submission date, and a direct link to review the request |
| 7 | Log in as the manager and check the in-app notification center or notification icon | Manager sees a new in-app notification badge or indicator showing unread notifications |
| 8 | Click on the in-app notification to view its details | In-app notification displays with accurate content including request ID, employee name, requested schedule changes, submission timestamp, and an actionable link or button to review the request |
| 9 | Verify the notification content is accurate by comparing it with the actual submitted request details | All information in both email and in-app notifications matches the submitted request details exactly (employee name, request ID, dates, changes requested) |
| 10 | Click the review link in the notification to verify it is actionable | Link directs the manager to the specific schedule change request approval page where they can review details and take action |
| 11 | Access the NotificationLogs table or notification logs page in the admin/system area | Notification logs page or database table is accessible and displays recent notification records |
| 12 | Search for the notification record corresponding to the submitted request using request ID or manager ID | Notification log entry is found with details including: notification ID, request ID, recipient (manager), notification type (email and in-app), timestamp, and delivery status |
| 13 | Verify the delivery status in the logs shows successful delivery for both email and in-app notifications | Delivery status is recorded as 'Successful' or 'Delivered' for both notification channels with timestamps showing delivery within 1 minute of request submission |

**Postconditions:**
- Manager has received notifications via both email and in-app channels
- Notification delivery is logged in NotificationLogs table with successful status
- Schedule change request remains in pending approval status
- Manager can access the request for approval action
- Notification delivery time is within the 1-minute SLA requirement
- System is ready for manager to process the approval

---

### Test Case: Verify escalation notification after SLA breach
- **ID:** tc-004
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Manager account exists and is active as primary approver
- Escalation manager or secondary approver account exists in the system
- SLA threshold for approval processing is configured in the system (e.g., 24 hours)
- A schedule change request exists in pending approval status
- Notification service is operational
- Escalation workflow is configured and enabled
- System has capability to simulate or fast-forward time for testing purposes, OR sufficient time has passed to trigger SLA breach
- NotificationLogs table is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify a schedule change request is in pending approval status and note the submission timestamp | Request is confirmed to be in 'Pending Approval' status with a recorded submission timestamp |
| 2 | Identify the configured SLA threshold time for approvals (e.g., 24 hours from submission) | SLA threshold is confirmed in system configuration (e.g., 24 hours or 1440 minutes) |
| 3 | Simulate the passage of time beyond the SLA threshold using system time manipulation, test environment fast-forward, or wait for actual time to pass | System time advances beyond the SLA threshold while the request remains in pending status without approval action |
| 4 | Verify the system detects the SLA breach condition | System's SLA monitoring process identifies the request as exceeding the approval time threshold |
| 5 | Confirm that an escalation notification event is triggered by the system | Escalation notification is generated and queued for delivery to the escalation manager or secondary approver |
| 6 | Wait for up to 1 minute after SLA breach detection for notification delivery | Escalation notification is sent within 1 minute of SLA breach detection |
| 7 | Check the escalation manager's email inbox for the escalation notification | Escalation manager receives an email with subject indicating 'Escalation' or 'SLA Breach' for schedule change approval, email contains request ID, original submission date, time pending, employee name, and urgency indicator |
| 8 | Log in as the escalation manager and check in-app notifications | Escalation manager sees an in-app notification marked as high priority or urgent regarding the pending approval |
| 9 | Verify the escalation notification content includes SLA breach information | Notification clearly states the request has exceeded the approval SLA, shows how long it has been pending, and emphasizes the need for immediate action |
| 10 | Verify the notification is received promptly by checking the timestamp of email receipt and in-app notification | Both email and in-app notifications are received within 1 minute of the SLA breach trigger, timestamps confirm prompt delivery |
| 11 | Access the NotificationLogs to verify escalation notification logging | Notification log contains an entry for the escalation notification with type 'Escalation', recipient as escalation manager, delivery status as successful, and timestamp within 1 minute of SLA breach |
| 12 | Verify that the original manager also receives a reminder or escalation notice | Original manager receives a notification indicating the request has been escalated due to SLA breach (if configured in escalation workflow) |

**Postconditions:**
- Escalation notification has been successfully delivered to the escalation manager
- Notification delivery is logged with successful status and appropriate timestamps
- Schedule change request remains in pending status awaiting escalated approval
- SLA breach is recorded in the system for reporting purposes
- Escalation manager can access and act on the request
- Notification delivery time meets the 1-minute SLA requirement

---

## Story: As System Administrator, I want to audit all schedule change approval actions to ensure compliance and traceability
**Story ID:** story-6

### Test Case: Validate logging of approval actions
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User with Manager role is logged into the system
- User with Administrator role is logged into the system
- At least one pending schedule change request exists in the system
- ApprovalAuditLogs table is accessible and functioning
- System logging service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change approval queue as Manager | Approval queue displays with pending schedule change requests |
| 2 | Select a pending schedule change request from the queue | Request details are displayed with approval options |
| 3 | Enter approval comments in the comments field (e.g., 'Approved due to business requirements') | Comments are entered successfully in the text field |
| 4 | Click the 'Approve' button to approve the schedule change request | System displays confirmation message that the request has been approved |
| 5 | Note the exact timestamp of the approval action | Current timestamp is recorded for verification |
| 6 | Switch to Administrator user account and navigate to the audit logs interface | Audit logs interface is displayed with search and filter options |
| 7 | Search for the recently approved schedule change request in the audit logs | Audit log entry for the approval action is displayed in the results |
| 8 | Verify the audit log entry contains the Manager's username | Audit log displays the correct Manager username who performed the approval |
| 9 | Verify the audit log entry contains the accurate timestamp of the approval action | Timestamp in audit log matches the noted approval time (within acceptable system delay) |
| 10 | Verify the audit log entry contains the approval comments entered by the Manager | Audit log displays the exact comments: 'Approved due to business requirements' |
| 11 | Verify the audit log entry contains the action type as 'Approval' | Audit log clearly indicates the action type as 'Approval' or equivalent status |

**Postconditions:**
- Approval action is permanently logged in ApprovalAuditLogs table
- Schedule change request status is updated to 'Approved'
- Audit log entry is accessible to authorized administrators
- System maintains data integrity of the audit record

---

### Test Case: Verify audit report filtering and export
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User with Administrator role is logged into the system
- Multiple approval and rejection actions exist in the audit logs (minimum 10 records)
- Audit logs contain records from different users and different date ranges
- Audit report UI is accessible to the administrator
- System has export functionality enabled for CSV format

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit report interface as Administrator | Audit report UI is displayed with all available audit log records and filter options |
| 2 | Identify the total number of unfiltered audit log records displayed | Total record count is visible and shows all existing audit logs |
| 3 | Apply a date range filter to show only records from the last 7 days | Filter is applied and only records within the last 7 days are displayed |
| 4 | Verify the filtered results contain only records within the specified date range | All displayed records have timestamps within the last 7 days; records outside this range are not shown |
| 5 | Apply an additional user filter to show only actions performed by a specific Manager | Results are further filtered to show only records for the selected Manager within the date range |
| 6 | Verify the filtered results display only the selected user's actions | All displayed records show the selected Manager's username; no other users' actions are visible |
| 7 | Apply an action type filter to show only 'Approval' actions | Results are filtered to display only approval actions, excluding rejection actions |
| 8 | Verify the accuracy of the multi-filter results (date + user + action type) | Displayed records match all three filter criteria: last 7 days, specific Manager, approval actions only |
| 9 | Click the 'Export to CSV' button to export the filtered audit report | System initiates CSV file download with a meaningful filename (e.g., 'audit_report_YYYY-MM-DD.csv') |
| 10 | Open the downloaded CSV file in a spreadsheet application | CSV file opens successfully and displays data in properly formatted columns |
| 11 | Verify the CSV file contains all columns: User, Timestamp, Action Type, Request ID, Comments | All required columns are present with appropriate headers |
| 12 | Verify the CSV file contains only the filtered records matching the applied criteria | Record count in CSV matches the filtered results count in the UI; all records meet filter criteria |
| 13 | Verify the data accuracy by comparing a sample record from CSV with the UI display | Data in CSV exactly matches the corresponding record in the UI (user, timestamp, action, comments) |

**Postconditions:**
- Filters remain applied in the audit report UI for further analysis
- CSV export file is saved to the administrator's download location
- Audit logs remain unchanged and unaffected by filtering and export operations
- Export action may be logged in system activity logs

---

### Test Case: Ensure audit logs are secure and immutable
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User with Administrator role is logged into the system
- At least one audit log record exists in the ApprovalAuditLogs table
- Database access tools or API testing tools are available
- System security logging is enabled to capture unauthorized access attempts
- Test environment allows simulation of unauthorized modification attempts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit logs interface as Administrator and identify a specific audit log record | Audit log record is displayed with all details (user, timestamp, action, comments) |
| 2 | Note the complete details of the selected audit log record for verification | Record details are documented including ID, user, timestamp, action type, and comments |
| 3 | Attempt to access the audit log edit functionality through the UI | No edit, modify, or delete buttons are available for audit log records in the UI |
| 4 | Attempt to directly modify the audit log record using database access (UPDATE SQL command on ApprovalAuditLogs table) | Database rejects the UPDATE operation with an error message indicating audit logs are immutable |
| 5 | Verify the system logs the unauthorized modification attempt | Security log contains an entry recording the attempted unauthorized modification with timestamp and user details |
| 6 | Attempt to delete the audit log record using database access (DELETE SQL command) | Database rejects the DELETE operation with an error message preventing deletion of audit records |
| 7 | Verify the system logs the unauthorized deletion attempt | Security log contains an entry recording the attempted unauthorized deletion with timestamp and user details |
| 8 | Attempt to modify the audit log record using API endpoint (PUT or PATCH request to /api/audit-logs/{id}) | API returns 403 Forbidden or 405 Method Not Allowed error, preventing modification |
| 9 | Verify the API logs the unauthorized modification attempt | API security log contains an entry with the attempted request details, timestamp, and source |
| 10 | Return to the audit logs interface and retrieve the same audit log record | Audit log record is displayed with identical details as originally noted; no changes have occurred |
| 11 | Verify all fields of the audit log record remain unchanged (user, timestamp, action, comments) | All field values exactly match the originally documented values; record integrity is maintained |
| 12 | Review the security logs to confirm all unauthorized attempts were properly logged | Security logs contain complete entries for all attempted unauthorized modifications with appropriate severity levels |

**Postconditions:**
- Audit log record remains completely unchanged and intact
- All unauthorized modification attempts are logged in security audit trail
- System security mechanisms are confirmed to be functioning correctly
- Database integrity constraints for audit logs are validated
- No data corruption or unauthorized changes exist in the audit log system

---

