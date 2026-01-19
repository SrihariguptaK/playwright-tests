# Manual Test Cases

## Story: As Manager, I want to submit schedule change requests to achieve proper approval and tracking
**Story ID:** story-2

### Test Case: Submit schedule change request with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Manager user account exists and is active
- Manager is logged into the system with valid credentials
- Manager has authorization to submit schedule change requests
- Schedule change request form is accessible
- At least one approver is configured in the workflow
- Valid document files are prepared for attachment (PDF, DOC, or DOCX format, under 10MB)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to schedule change request page from the main dashboard or menu | Schedule change request submission form is displayed with all mandatory fields clearly marked (employee name, current schedule, proposed schedule, effective date, reason for change, and document attachment option) |
| 2 | Manager enters employee name in the designated field | Employee name is accepted and displayed in the field without validation errors |
| 3 | Manager enters current schedule details (days and times) | Current schedule information is accepted and properly formatted in the field |
| 4 | Manager enters proposed schedule details (days and times) | Proposed schedule information is accepted and properly formatted in the field |
| 5 | Manager selects effective date using the date picker | Selected date is populated in the effective date field and is in the correct format (MM/DD/YYYY) |
| 6 | Manager enters reason for schedule change in the text area | Reason text is accepted and displayed in the text area without character limit errors |
| 7 | Manager clicks on the attachment button and selects valid document files (PDF format, 2MB size) | Files are successfully attached, file names are displayed, and no validation errors appear |
| 8 | Manager reviews all entered information for accuracy | All fields display the entered data correctly and no validation errors are present |
| 9 | Manager clicks the Submit button | System displays a confirmation message stating 'Schedule change request submitted successfully' with a unique request ID, request is routed to the first approver in the configured workflow, and manager receives an email notification confirming submission |
| 10 | Manager navigates to the request tracking page | Submitted request appears in the list with status 'Pending Approval' and displays the assigned approver name |

**Postconditions:**
- Schedule change request is saved in the database with status 'Pending Approval'
- Request is assigned to the first approver in the workflow queue
- Manager receives confirmation email with request ID
- Approver receives notification of new pending request
- Request is visible in manager's submitted requests list
- Audit log entry is created for the submission

---

### Test Case: Reject submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Manager user account exists and is active
- Manager is logged into the system with valid credentials
- Manager has authorization to submit schedule change requests
- Schedule change request form is accessible
- Real-time validation is enabled on the form

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to schedule change request page | Schedule change request submission form is displayed with all mandatory fields clearly marked with asterisks (*) |
| 2 | Manager leaves the employee name field empty and moves to the next field | Real-time validation triggers and displays error message 'Employee name is required' in red text below the field, and the field border turns red |
| 3 | Manager leaves the current schedule field empty and moves to the next field | Real-time validation triggers and displays error message 'Current schedule is required' in red text below the field, and the field border turns red |
| 4 | Manager leaves the proposed schedule field empty and moves to the next field | Real-time validation triggers and displays error message 'Proposed schedule is required' in red text below the field, and the field border turns red |
| 5 | Manager leaves the effective date field empty and moves to the next field | Real-time validation triggers and displays error message 'Effective date is required' in red text below the field, and the field border turns red |
| 6 | Manager leaves the reason for change field empty | Real-time validation triggers and displays error message 'Reason for change is required' in red text below the field, and the field border turns red |
| 7 | Manager attempts to click the Submit button with all mandatory fields still empty | Submit button is disabled (grayed out) and cannot be clicked, or if clicked, displays a summary error message at the top of the form stating 'Please complete all mandatory fields before submitting' with a list of missing fields |
| 8 | Manager fills in only the employee name field and attempts to submit again | Submission is still blocked, and error messages remain visible for all other empty mandatory fields |
| 9 | Manager scrolls through the form to view all validation errors | All mandatory fields that are empty display individual error messages, and the form clearly indicates which fields need to be completed |

**Postconditions:**
- No schedule change request is created in the database
- Form remains on the submission page with all entered data preserved
- All validation error messages remain visible
- No notifications are sent to approvers
- No confirmation email is sent to the manager
- Manager can correct the errors and resubmit

---

### Test Case: Validate attachment file types and sizes
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager user account exists and is active
- Manager is logged into the system with valid credentials
- Manager has authorization to submit schedule change requests
- Schedule change request form is accessible
- Test files are prepared: unsupported file type (e.g., .exe, .zip), oversized file (e.g., 15MB PDF), and valid file (e.g., 2MB PDF)
- Maximum file size limit is set to 10MB
- Allowed file types are PDF, DOC, DOCX

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to schedule change request page | Schedule change request submission form is displayed with attachment section visible |
| 2 | Manager fills in all mandatory fields with valid data (employee name, current schedule, proposed schedule, effective date, reason for change) | All mandatory fields accept the data without validation errors |
| 3 | Manager clicks on the attachment button and attempts to select an unsupported file type (e.g., .exe file) | System displays validation error message 'File type not supported. Please upload PDF, DOC, or DOCX files only' and the file is not attached |
| 4 | Manager clicks on the attachment button and attempts to select an oversized file (e.g., 15MB PDF file) | System displays validation error message 'File size exceeds maximum limit of 10MB. Please upload a smaller file' and the file is not attached |
| 5 | Manager attempts to submit the form without any valid attachments | System displays error message 'At least one valid document attachment is required' and submission is blocked |
| 6 | Manager clicks on the attachment button and selects a valid file (e.g., 2MB PDF file) | File is successfully attached, file name and size are displayed in the attachment section, and a green checkmark or success indicator appears |
| 7 | Manager adds another valid file (e.g., 3MB DOCX file) | Second file is successfully attached and both files are listed in the attachment section with their names and sizes |
| 8 | Manager reviews the form to ensure all data is correct and valid files are attached | All fields display correct data, valid attachments are listed, and no validation errors are present |
| 9 | Manager clicks the Submit button | System displays confirmation message 'Schedule change request submitted successfully' with a unique request ID, request is routed to the first approver, and attached files are included with the request |
| 10 | Manager navigates to the request tracking page and opens the submitted request | Request details page displays all attached files with download links, and files can be successfully downloaded and opened |

**Postconditions:**
- Schedule change request is saved in the database with status 'Pending Approval'
- Valid attached files are stored in the document repository and linked to the request
- Invalid file attempts are logged but not stored
- Request is assigned to the first approver with access to attachments
- Manager receives confirmation email with request ID
- Approver can view and download all attached documents

---

## Story: As Approver, I want to review and approve schedule change requests to ensure authorized modifications
**Story ID:** story-3

### Test Case: Approve schedule change request successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Approver user account exists and is active
- Approver is logged into the system with valid credentials
- Approver has authorization role to approve schedule change requests
- At least one schedule change request is pending approval and assigned to the approver
- Request contains all required information and valid attachments
- Manager who submitted the request has a valid email address for notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver logs into the system and navigates to the pending approvals dashboard from the main menu | Pending approvals dashboard is displayed showing a list of all schedule change requests assigned to the approver with columns for request ID, employee name, submission date, and status |
| 2 | Approver reviews the list of pending requests | List displays all pending requests with accurate information, sorted by submission date (newest first), and shows the total count of pending requests |
| 3 | Approver clicks on a specific schedule change request from the list | Request details page opens displaying full information including employee name, current schedule, proposed schedule, effective date, reason for change, submission date, requester name, and attached documents section |
| 4 | Approver reviews the current schedule details | Current schedule information is clearly displayed with days and times in an easy-to-read format |
| 5 | Approver reviews the proposed schedule details | Proposed schedule information is clearly displayed with days and times, and differences from current schedule are highlighted or easily identifiable |
| 6 | Approver reviews the reason for change provided by the manager | Reason for change is displayed in full text and is clearly readable |
| 7 | Approver clicks on the attached document link to view supporting documentation | Document opens in a new tab or viewer, displays correctly, and content is readable |
| 8 | Approver closes the document and returns to the request details page | Request details page remains open with all information intact |
| 9 | Approver clicks the Approve button | Confirmation dialog appears asking 'Are you sure you want to approve this schedule change request?' with optional comment field and Confirm/Cancel buttons |
| 10 | Approver enters optional approval comment (e.g., 'Approved as requested') and clicks Confirm button | System displays success message 'Schedule change request approved successfully', request status updates to 'Approved', approval timestamp is recorded, and approver is redirected to the pending approvals dashboard |
| 11 | Approver verifies the approved request is no longer in the pending list | Approved request is removed from the pending approvals list, and the pending count is decremented by one |
| 12 | Approver navigates to the approval history or completed approvals section | Approved request appears in the completed approvals list with status 'Approved', approval date, and approver name |
| 13 | Manager (requester) checks their email inbox | Manager receives email notification with subject 'Schedule Change Request Approved' containing request ID, approval date, approver name, and optional approval comment |

**Postconditions:**
- Schedule change request status is updated to 'Approved' in the database
- Approval timestamp and approver ID are recorded in the request record
- Manager receives email notification of approval
- Request is removed from approver's pending queue
- Request appears in approval history with complete audit trail
- Approved request is available for next workflow step if configured
- System logs the approval action for audit purposes

---

### Test Case: Reject schedule change request with mandatory comment
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Approver user account exists and is active
- Approver is logged into the system with valid credentials
- Approver has authorization role to reject schedule change requests
- At least one schedule change request is pending approval and assigned to the approver
- Request contains all required information
- Manager who submitted the request has a valid email address for notifications
- Rejection comment is configured as mandatory in system settings

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver navigates to the pending approvals dashboard | Pending approvals dashboard is displayed showing a list of all schedule change requests assigned to the approver |
| 2 | Approver selects a schedule change request to reject by clicking on it | Request details page opens displaying full information including employee name, current schedule, proposed schedule, effective date, reason for change, and attached documents |
| 3 | Approver reviews the request details and determines it should be rejected | All request information is visible and clearly displayed for review |
| 4 | Approver clicks the Reject button | Rejection dialog appears with a mandatory comment text area field marked with an asterisk (*), character counter showing minimum required characters (e.g., 10 characters minimum), and Confirm/Cancel buttons |
| 5 | Approver leaves the comment field empty and attempts to click the Confirm button | System prevents rejection and displays validation error message 'Rejection comment is required. Please provide a reason for rejection' in red text below the comment field, and the Confirm button remains disabled or clicking it has no effect |
| 6 | Approver enters only 3 characters in the comment field (below minimum requirement) | System displays validation error message 'Comment must be at least 10 characters long' and the Confirm button remains disabled |
| 7 | Approver clears the field and enters a valid rejection comment with sufficient detail (e.g., 'The proposed schedule conflicts with operational requirements and cannot be accommodated at this time') | Comment is accepted, character counter shows the comment meets minimum requirements, validation error disappears, and the Confirm button becomes enabled |
| 8 | Approver clicks the Confirm button to submit the rejection | System displays success message 'Schedule change request rejected successfully', request status updates to 'Rejected', rejection timestamp is recorded, and approver is redirected to the pending approvals dashboard |
| 9 | Approver verifies the rejected request is no longer in the pending list | Rejected request is removed from the pending approvals list, and the pending count is decremented by one |
| 10 | Approver navigates to the approval history or completed approvals section | Rejected request appears in the completed approvals list with status 'Rejected', rejection date, approver name, and rejection comment visible |
| 11 | Manager (requester) checks their email inbox | Manager receives email notification with subject 'Schedule Change Request Rejected' containing request ID, rejection date, approver name, and the full rejection comment explaining the reason |
| 12 | Manager logs into the system and navigates to their submitted requests | Rejected request is displayed with status 'Rejected' and the rejection comment is visible in the request details |

**Postconditions:**
- Schedule change request status is updated to 'Rejected' in the database
- Rejection timestamp, approver ID, and rejection comment are recorded in the request record
- Manager receives email notification of rejection with detailed comment
- Request is removed from approver's pending queue
- Request appears in approval history with complete audit trail including rejection reason
- Manager can view rejection details and resubmit a modified request if needed
- System logs the rejection action for audit purposes

---

### Test Case: Prevent unauthorized access to approval tasks
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Multiple user accounts exist with different roles (approver, manager, regular employee)
- User without approver role is logged into the system with valid credentials
- User has a role such as 'Manager' or 'Employee' but not 'Approver'
- Role-based access control (RBAC) is properly configured in the system
- At least one schedule change request exists in pending approval status
- Approval dashboard URL is known (e.g., /approvals/pending)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | User without approver role logs into the system successfully | User is logged in and redirected to their appropriate dashboard based on their role (e.g., manager dashboard or employee dashboard) |
| 2 | User reviews the main navigation menu | Navigation menu does not display 'Pending Approvals' or 'Approval Dashboard' option, as user does not have approver role |
| 3 | User manually types the approval dashboard URL in the browser address bar (e.g., /approvals/pending) and presses Enter | System denies access and displays error page with HTTP 403 Forbidden status and message 'Access Denied: You do not have permission to access this page. Approver role is required.' |
| 4 | User attempts to navigate back using browser back button | User is returned to their previous authorized page or dashboard |
| 5 | User attempts to access a specific approval task by manually entering the URL with a request ID (e.g., /approvals/12345) | System denies access and displays error page with HTTP 403 Forbidden status and message 'Access Denied: You do not have permission to view this approval task' |
| 6 | User attempts to access the approval API endpoint directly using browser developer tools or API client (e.g., GET /api/approvals/pending) | API returns HTTP 403 Forbidden response with JSON error message {'error': 'Unauthorized', 'message': 'Approver role required to access this resource'} |
| 7 | User attempts to submit an approval decision via API endpoint (e.g., POST /api/approvals/12345/decision) | API returns HTTP 403 Forbidden response with JSON error message {'error': 'Unauthorized', 'message': 'You do not have permission to approve or reject requests'} |
| 8 | System administrator reviews the security audit log | Audit log contains entries for all unauthorized access attempts with timestamp, user ID, attempted URL, and 'Access Denied' result |
| 9 | User logs out and logs back in to verify role has not changed | User successfully logs in but still does not have access to approval features, confirming role-based restrictions are persistent |

**Postconditions:**
- User without approver role remains unable to access approval dashboard
- No schedule change requests are modified or accessed by unauthorized user
- All unauthorized access attempts are logged in the security audit trail
- System security integrity is maintained
- User's own role and permissions remain unchanged
- No data breach or unauthorized data access occurs
- Error messages do not reveal sensitive system information

---

## Story: As Manager, I want to track the status of my schedule change requests to achieve transparency and timely updates
**Story ID:** story-5

### Test Case: View schedule change request statuses
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Manager account exists and is active in the system
- Manager has previously submitted at least one schedule change request
- Manager has valid login credentials
- Status dashboard feature is enabled and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid manager credentials | Manager is successfully authenticated and redirected to the home page |
| 2 | Click on the 'Schedule Change Status' or 'Dashboard' menu option | Status dashboard page loads and displays a list of all schedule change requests submitted by the manager |
| 3 | Verify that the dashboard shows request details including request ID, submission date, requested changes, and current status | All submitted requests are visible with complete information including status indicators (Pending, Approved, Rejected, etc.) |
| 4 | Select a specific request from the list by clicking on it | Request detail view opens showing comprehensive approval history including approver names, timestamps, actions taken, and any comments or notes |
| 5 | Review the detailed approval history and comments section | All historical actions are displayed chronologically with complete audit trail information |

**Postconditions:**
- Manager remains logged into the system
- Dashboard data remains accessible for further review
- No changes are made to any request status

---

### Test Case: Filter requests by status and date
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Manager is logged into the system
- Manager is on the schedule change status dashboard
- Multiple schedule change requests exist with different statuses and dates
- Filter functionality is available on the dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the filter section on the status dashboard | Filter controls are visible including status dropdown and date range selectors |
| 2 | Click on the status filter dropdown and select a specific status (e.g., 'Pending') | Status filter is applied and dropdown shows the selected status |
| 3 | Observe the request list after applying status filter | Dashboard updates to display only requests matching the selected status, other requests are hidden |
| 4 | Click on the date range filter and select a start date and end date | Date range is selected and displayed in the filter controls |
| 5 | Apply the date range filter by clicking 'Apply' or equivalent button | Dashboard updates to show only requests submitted within the specified date range that also match the status filter |
| 6 | Verify the filtered results count and displayed requests | Only requests matching both status and date criteria are shown, with accurate count displayed |
| 7 | Click 'Clear Filters' or 'Reset' button | All filters are removed and the complete list of requests is displayed again |

**Postconditions:**
- Dashboard returns to unfiltered state if filters are cleared
- Filter selections are available for reuse
- No data is modified during filtering operations

---

### Test Case: Export request history
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 3 mins

**Preconditions:**
- Manager is logged into the system
- Manager is viewing the schedule change status dashboard
- At least one schedule change request exists in the system
- Browser allows file downloads
- Manager has permissions to export data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the 'Export' or 'Download' button on the status dashboard | Export button is visible and enabled on the dashboard interface |
| 2 | Click the 'Export' button | Export process initiates and browser prompts to download a CSV file or file downloads automatically to default location |
| 3 | Wait for the download to complete and locate the downloaded CSV file | CSV file is successfully downloaded with a meaningful filename (e.g., 'schedule_change_requests_YYYY-MM-DD.csv') |
| 4 | Open the downloaded CSV file using a spreadsheet application (Excel, Google Sheets, etc.) | CSV file opens successfully and displays request history data in tabular format |
| 5 | Verify the CSV contains all expected columns including Request ID, Submission Date, Status, Approver, Comments, and Timestamps | All relevant data fields are present as columns with appropriate headers |
| 6 | Verify the CSV contains all requests visible on the dashboard (or filtered requests if filters were applied) | Row count and data in CSV matches the requests displayed on the dashboard |

**Postconditions:**
- CSV file is saved to the manager's local system
- Dashboard remains in the same state after export
- Export action is logged in system audit trail
- No data is modified during export operation

---

## Story: As Approver, I want to escalate pending schedule change approvals to achieve timely decision-making
**Story ID:** story-6

### Test Case: Manual escalation of pending approval
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Approver account exists with valid escalation permissions
- Approver is logged into the system
- At least one schedule change request is pending approval and exceeds the configured time threshold
- Higher-level approver exists in the system to receive escalation
- Escalation time threshold is configured in the system (e.g., 48 hours)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the 'Pending Approvals' section from the approver dashboard | Pending approvals page loads displaying all requests awaiting the approver's action |
| 2 | Observe the list of pending approvals for escalation indicators or flags | Requests that have been pending beyond the configured time threshold are visually flagged with indicators such as warning icons, highlighted rows, or 'Escalation Required' labels |
| 3 | Verify the escalation indicator shows time information (e.g., 'Pending for 3 days') | Each flagged request displays accurate time elapsed since submission |
| 4 | Select a flagged request by clicking on it to view details | Request detail page opens showing full information including escalation option |
| 5 | Click the 'Escalate' button or select 'Escalate to Higher Authority' option | Escalation confirmation dialog appears asking for confirmation and optional comments |
| 6 | Enter optional escalation comments (e.g., 'Requires urgent attention') and click 'Confirm Escalation' | System processes the escalation request and displays success message |
| 7 | Verify the request status updates to 'Escalated' in the pending approvals list | Request is marked as escalated and moved to appropriate section or shows updated status |
| 8 | Check that the higher-level approver receives notification (verify through notification panel or email) | Higher-level approver receives notification containing request details and escalation reason |

**Postconditions:**
- Request status is updated to 'Escalated' in the database
- Request is assigned to higher-level approver's queue
- Original approver can still view the request but cannot approve/reject
- Escalation is recorded in audit logs with timestamp and approver details
- Notification is sent to higher-level approver

---

### Test Case: Automatic escalation after time threshold
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Automatic escalation feature is enabled in system configuration
- Escalation time threshold is configured (e.g., 72 hours)
- A schedule change request has been pending approval for exactly the threshold duration
- Higher-level approver is configured and active in the system
- System background job or scheduler is running to detect threshold violations

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Wait for or simulate the system's scheduled escalation check process to run (typically runs every hour or as configured) | System background process executes and scans for requests exceeding the time threshold |
| 2 | Verify the system detects the request that has been pending beyond the configured time threshold | System identifies the request as requiring automatic escalation based on timestamp comparison |
| 3 | Observe the system automatically escalating the request without manual intervention | Request status is automatically updated to 'Auto-Escalated' and is reassigned to the higher-level approver |
| 4 | Check the higher-level approver's pending approvals queue | Escalated request appears in the higher-level approver's queue with 'Auto-Escalated' indicator |
| 5 | Verify that the higher-level approver receives an escalation notification | Notification is delivered successfully via configured channels (email, in-app notification, etc.) containing request details and escalation reason |
| 6 | Check the notification content for completeness | Notification includes request ID, original submission date, original approver name, escalation reason, and action link |
| 7 | Verify the original approver is notified that the request has been escalated | Original approver receives notification informing them of the automatic escalation |

**Postconditions:**
- Request is removed from original approver's active queue
- Request is added to higher-level approver's queue
- Request status reflects automatic escalation
- All notifications are sent and logged
- Escalation event is recorded in audit logs
- System continues monitoring other pending requests

---

### Test Case: Audit trail records escalation actions
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Audit logging system is enabled and functioning
- At least one escalation has occurred (manual or automatic)
- Administrator account exists with permissions to view audit logs
- Administrator is logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Trigger an escalation event by either performing manual escalation or waiting for automatic escalation to occur | Escalation is successfully processed (manual or automatic) and completed |
| 2 | Verify the escalation completes and request status is updated | Request shows escalated status and is assigned to higher-level approver |
| 3 | Log in as an administrator or user with audit log access permissions | Administrator successfully authenticates and accesses the admin dashboard |
| 4 | Navigate to the 'Audit Logs' or 'System Logs' section | Audit log interface loads displaying recent system activities |
| 5 | Search or filter audit logs for escalation-related events using keywords like 'escalation' or the specific request ID | Audit log displays filtered results showing escalation events |
| 6 | Locate the specific escalation entry in the audit logs | Escalation event is visible in the audit log with a dedicated entry |
| 7 | Verify the audit log entry contains complete escalation details including timestamp, request ID, escalation type (manual/automatic), original approver, target approver, and reason | All escalation details are logged accurately with precise timestamp in ISO format or system standard |
| 8 | Check that the audit log entry includes the user who initiated the escalation (for manual) or 'SYSTEM' (for automatic) | Initiator information is correctly recorded showing either the approver's username or 'SYSTEM' identifier |
| 9 | Verify the audit log is immutable by attempting to edit or delete the entry (if UI allows) | Audit log entries cannot be modified or deleted, ensuring data integrity |
| 10 | Export or view the complete audit trail for the escalated request showing all actions from submission to escalation | Complete chronological history is available showing submission, pending duration, escalation trigger, and all subsequent actions |

**Postconditions:**
- Audit logs remain intact and unmodified
- Escalation events are permanently recorded in the audit system
- Administrator can access audit logs for compliance and reporting
- Audit trail provides complete traceability for the escalation process
- System continues logging all subsequent actions on the escalated request

---

## Story: As Approver, I want to add comments during schedule change approval to achieve clear communication
**Story ID:** story-9

### Test Case: Reject request with mandatory comment
- **ID:** tc-001
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Approver role
- At least one pending schedule change request exists in the system
- Approver has permission to approve/reject the request
- Request is in 'Pending Approval' status

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change approval dashboard | Dashboard displays with list of pending approval requests |
| 2 | Select a pending schedule change request to review | Request details page opens showing all request information and approval options |
| 3 | Click on the 'Reject' button without entering any comment in the comment field | System prevents submission and displays validation error message 'Comment is required when rejecting a request' |
| 4 | Verify that the request status has not changed | Request remains in 'Pending Approval' status |
| 5 | Enter a comment in the comment field explaining the reason for rejection (e.g., 'Insufficient coverage during requested time period') | Comment text appears in the comment field as typed |
| 6 | Click on the 'Reject' button with the comment entered | System accepts the submission, request status changes to 'Rejected', comment is saved, and success message is displayed |
| 7 | Navigate to the request history or details page | Rejection comment is visible in the request history with timestamp and approver name |

**Postconditions:**
- Request status is 'Rejected'
- Rejection comment is saved in the database
- Comment is visible in request history
- Requester receives notification with rejection comment
- Approver remains on the approval dashboard or confirmation page

---

### Test Case: Approve request with optional comment
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Approver role
- At least one pending schedule change request exists in the system
- Approver has permission to approve/reject the request
- Request is in 'Pending Approval' status

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change approval dashboard | Dashboard displays with list of pending approval requests |
| 2 | Select a pending schedule change request to review | Request details page opens showing all request information and approval options |
| 3 | Click on the 'Approve' button without entering any comment in the comment field | System accepts the submission, request status changes to 'Approved', and success message is displayed |
| 4 | Verify the request status has been updated | Request status shows as 'Approved' in the system |
| 5 | Select another pending schedule change request to review | Second request details page opens showing all request information and approval options |
| 6 | Enter a comment in the comment field (e.g., 'Approved. Please ensure handover notes are updated') | Comment text appears in the comment field as typed |
| 7 | Click on the 'Approve' button with the comment entered | System accepts the submission, request status changes to 'Approved', comment is saved, and success message is displayed |
| 8 | Navigate to the request history or details page for the second request | Approval comment is visible in the request history with timestamp and approver name |

**Postconditions:**
- Both requests have status 'Approved'
- First request has no comment saved
- Second request has approval comment saved in the database
- Comments (if provided) are visible in request history
- Requesters receive notifications with approval decision and any comments
- Approved schedule changes are reflected in the system

---

### Test Case: Display comments in request history and notifications
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- A schedule change request has been submitted
- Approver has processed the request with a decision (approved or rejected)
- Approver has added comments during the approval/rejection process
- Comments have been saved in the system
- Requester user is logged into the system
- Notification system is functioning properly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as the requester who submitted the schedule change request | Requester successfully logs in and lands on the dashboard |
| 2 | Navigate to 'My Requests' or 'Request History' section | List of submitted requests is displayed with their current statuses |
| 3 | Select the schedule change request that was processed by the approver | Request details page opens showing full request information and approval history |
| 4 | Scroll to the approval history or comments section | Comments from the approver are clearly visible with approver name, timestamp, and decision (approved/rejected) |
| 5 | Verify the comment content matches what the approver entered | Comment text is displayed accurately and completely, including any rich text formatting if used |
| 6 | Navigate to the notifications section or check email notifications | Notification about the approval decision is present in the notifications list |
| 7 | Open the notification related to the schedule change request decision | Notification displays the decision (approved/rejected) along with the approver's comments in full |
| 8 | Verify the notification includes all relevant information (request ID, decision, approver name, comments, timestamp) | All information is present and correctly formatted in the notification |

**Postconditions:**
- Requester has viewed the comments in request history
- Requester has viewed the comments in notification
- Comments remain permanently stored in request history
- Notification remains accessible for future reference
- Requester is informed of the decision and reasoning

---

