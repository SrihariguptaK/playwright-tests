# Manual Test Cases

## Story: As Approver, I want to receive notifications for pending schedule change approvals to achieve timely decision-making
**Story ID:** story-3

### Test Case: Validate notification sent upon schedule change request submission
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user account exists and has permission to submit schedule change requests
- Approver user account exists with valid email address configured
- Approver has notification preferences set to receive both email and in-app notifications
- User is logged into the system
- NotificationQueue service is running and operational
- Email service is configured and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Scheduler navigates to the schedule change request submission form | Schedule change request form is displayed with all required fields |
| 2 | Scheduler fills in all required fields (date, time, reason, etc.) and submits the schedule change request | System accepts the submission, displays success message, and generates a unique request ID |
| 3 | System processes the request and identifies the assigned approver based on workflow rules | Notification is generated for the assigned approver and queued in NotificationQueue within 1 minute |
| 4 | Check approver's email inbox for notification | Approver receives email notification containing request ID, scheduler name, requested changes, submission timestamp, and direct link to review the request |
| 5 | Approver logs into the system and checks in-app notifications | In-app notification appears in notification center with same details as email, marked as unread with notification badge |
| 6 | Approver clicks on the in-app notification link | System navigates directly to the schedule change request details page showing complete request information including scheduler details, requested changes, reason, and action buttons |
| 7 | Verify notification content accuracy by comparing with submitted request details | All information in notification matches the original schedule change request data (dates, times, scheduler name, request ID) |

**Postconditions:**
- Notification is marked as delivered in system logs
- Notification delivery status is logged in NotificationQueue table
- In-app notification remains accessible until approver takes action or marks as read
- Request status remains 'Pending Approval'
- Audit trail records notification sent event with timestamp

---

### Test Case: Verify no duplicate notifications for the same pending approval
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Schedule change request has been submitted and is in pending approval status
- Initial notification has already been sent to approver
- Approver has not yet taken action on the request
- NotificationQueue service is operational
- System has duplicate detection mechanism enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify initial notification was sent by checking NotificationQueue table for the request ID | One notification record exists with status 'Delivered' for the pending approval request |
| 2 | Count the number of email notifications in approver's inbox for this specific request ID | Exactly one email notification exists for the request |
| 3 | Count the number of in-app notifications for this specific request ID | Exactly one in-app notification exists for the request |
| 4 | Trigger a system event that would normally generate a notification (e.g., refresh workflow, system restart, or manual notification trigger) | System checks NotificationQueue and identifies existing notification for the pending approval |
| 5 | Wait 2 minutes and check approver's email inbox again | No additional email notification is received; count remains at one |
| 6 | Check in-app notification center for duplicate notifications | No duplicate in-app notification appears; only the original notification is displayed |
| 7 | Query NotificationQueue table for all notifications related to this request ID | Only one notification record exists; no duplicate entries are created |
| 8 | Review system logs for duplicate prevention messages | System logs show duplicate detection triggered and prevented duplicate notification from being sent |

**Postconditions:**
- Only one notification exists for the pending approval in NotificationQueue
- Approver has received exactly one email and one in-app notification
- System logs document duplicate prevention action
- Request status remains 'Pending Approval'
- No unnecessary notification records are created in the database

---

### Test Case: Ensure escalation notifications are sent for overdue approvals
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Schedule change request has been submitted and is in pending approval status
- Initial notification has been sent to primary approver
- Escalation threshold time period is configured in system (e.g., 24 hours)
- Escalation recipients are configured (e.g., manager, secondary approver)
- Primary approver has not taken action on the request
- System escalation job/scheduler is running
- Current time has exceeded the escalation threshold since request submission

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify the schedule change request submission timestamp and calculate time elapsed | Request has been pending for longer than the configured escalation threshold (e.g., 24 hours) |
| 2 | Check the request status in the system | Request status shows 'Pending Approval' with no approval decision recorded |
| 3 | Wait for the system escalation job to run (or manually trigger escalation check if available) | System identifies the overdue approval and triggers escalation workflow |
| 4 | Query NotificationQueue table for escalation notifications | Escalation notification records are created for designated escalation recipients with notification type 'Escalation' |
| 5 | Check email inbox of designated escalation recipients (e.g., manager, secondary approver) | Escalation notification email is received containing request ID, original approver name, overdue duration, urgency indicator, and direct link to request |
| 6 | Check in-app notifications for escalation recipients | In-app escalation notification appears with high priority indicator, showing overdue status and request details |
| 7 | Verify escalation notification content includes overdue information | Notification clearly states the approval is overdue, shows how long it has been pending, and identifies the original approver who has not responded |
| 8 | Check that original approver also receives escalation reminder notification | Original approver receives reminder notification indicating the request is overdue and has been escalated |
| 9 | Review system audit logs for escalation event | Audit trail records escalation event with timestamp, original approver, escalation recipients, and reason for escalation |

**Postconditions:**
- Escalation notifications are delivered to all designated recipients
- NotificationQueue contains escalation notification records with 'Delivered' status
- Request status is updated to include escalation flag or indicator
- Audit trail documents complete escalation event
- Original approver is notified of escalation
- Request remains in 'Pending Approval' status awaiting decision

---

## Story: As Approver, I want to review and make decisions on schedule change requests to achieve timely and accurate approvals
**Story ID:** story-4

### Test Case: Validate approval decision submission with comments
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Approver user account exists with appropriate approval permissions
- Schedule change request exists in 'Pending Approval' status
- Approver has received notification for the pending request
- Approver is logged into the system
- ScheduleChangeRequests and ApprovalDecisions tables are accessible
- API endpoint PUT /api/approval-decisions is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver logs into the system and navigates to the 'Pending Approvals' section from the main dashboard | Pending Approvals page displays with a list of all schedule change requests awaiting the approver's decision |
| 2 | Approver locates the specific schedule change request and clicks to view details | Request details page is displayed showing complete information including: request ID, scheduler name, current schedule, requested changes, reason for change, submission date/time, and any supporting documentation |
| 3 | Approver reviews all request details and supporting information | All request information is clearly visible and formatted for easy review; action buttons (Approve/Reject) are prominently displayed |
| 4 | Approver clicks the 'Reject' button | Decision form expands showing comment input field marked as required, with character counter and submit/cancel buttons |
| 5 | Approver enters detailed rejection comments in the comment field (e.g., 'Request conflicts with existing coverage requirements for the emergency department. Please coordinate with shift supervisor before resubmitting.') | Comment text is accepted and displayed in the input field; character count updates; submit button becomes enabled |
| 6 | Approver reviews the entered comments for accuracy and completeness | Comments are clearly visible in the input field and can be edited if needed |
| 7 | Approver clicks the 'Submit Decision' button | System displays confirmation dialog asking approver to confirm the rejection decision |
| 8 | Approver confirms the decision in the confirmation dialog | System processes the decision within 2 seconds and displays success message confirming rejection has been recorded |
| 9 | Verify the request status has been updated by refreshing the pending approvals list | Request no longer appears in pending approvals list; status is updated to 'Rejected' |
| 10 | Navigate to the request details or history page to view the decision | Request shows status 'Rejected' with approver name, rejection timestamp, and entered comments clearly displayed |
| 11 | Query ApprovalDecisions table to verify audit trail entry | New record exists containing: request ID, approver ID, decision (Rejected), comments, timestamp, and IP address |
| 12 | Verify scheduler receives notification of the rejection decision | Scheduler receives email and in-app notification containing rejection decision and approver's comments |

**Postconditions:**
- Request status is permanently updated to 'Rejected' in ScheduleChangeRequests table
- Approval decision is recorded in ApprovalDecisions table with complete audit information
- Approver's comments are stored and associated with the decision
- Scheduler is notified of the rejection with comments
- Request is removed from approver's pending queue
- Audit trail is complete with timestamp, approver identity, and decision details
- System logs record the decision processing event

---

### Test Case: Verify rejection is blocked without comments
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Approver user account exists with appropriate approval permissions
- Schedule change request exists in 'Pending Approval' status
- Approver is logged into the system
- Approver has navigated to the request details page
- Validation rules for mandatory comments on rejection are configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver navigates to the pending schedule change request details page | Request details page displays with all relevant information and Approve/Reject action buttons |
| 2 | Approver clicks the 'Reject' button | Decision form expands showing comment input field with required field indicator (asterisk or 'Required' label) |
| 3 | Approver leaves the comment field completely empty (no text entered) | Comment field remains empty; submit button may be disabled or validation is pending |
| 4 | Approver attempts to click the 'Submit Decision' button without entering any comments | System prevents submission and displays validation error message: 'Comments are required when rejecting a request' or similar message in red text near the comment field |
| 5 | Verify the comment field is highlighted or marked to indicate the validation error | Comment field is highlighted with red border or error styling to draw attention to the required field |
| 6 | Verify the request status has not changed by checking the database or UI | Request status remains 'Pending Approval'; no decision record is created in ApprovalDecisions table |
| 7 | Approver enters only whitespace characters (spaces, tabs) in the comment field | Comment field shows the whitespace but validation still treats it as empty |
| 8 | Approver attempts to submit the decision with only whitespace in comments | System prevents submission and displays validation error: 'Please enter meaningful comments' or 'Comments cannot be empty' |
| 9 | Approver enters a very short comment (e.g., 1-2 characters like 'No') | System either accepts if minimum length is met, or displays error if minimum character requirement exists (e.g., 'Comments must be at least 10 characters') |
| 10 | Verify no audit trail entry was created for the failed submission attempts | ApprovalDecisions table contains no new records; audit logs may show validation failures but no decision records |

**Postconditions:**
- Request status remains 'Pending Approval' unchanged
- No decision record is created in ApprovalDecisions table
- No notification is sent to scheduler about rejection
- Request remains in approver's pending queue
- Approver remains on the decision page with error message displayed
- System maintains data integrity by preventing incomplete rejection decisions

---

### Test Case: Ensure unauthorized users cannot approve or reject requests
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Schedule change request exists in 'Pending Approval' status
- User account exists without approver role (e.g., regular scheduler, viewer, or other non-approver role)
- Role-based access control (RBAC) is configured and enforced
- User is logged into the system with non-approver credentials
- Security policies are active and enforced at UI and API levels

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | User without approver role logs into the system | User successfully logs in and is directed to their role-appropriate dashboard |
| 2 | User attempts to navigate to the 'Pending Approvals' section via menu or direct URL | System denies access and displays error message: 'Access Denied - You do not have permission to view pending approvals' or redirects to unauthorized access page |
| 3 | Verify the Pending Approvals menu option is not visible or is disabled for this user | Pending Approvals menu item is either hidden from navigation or displayed as disabled/grayed out |
| 4 | User attempts to access a specific approval request details page by manually entering the URL (e.g., /approvals/request/12345) | System blocks access and displays 403 Forbidden error or 'Access Denied' page with message indicating insufficient permissions |
| 5 | User attempts to access the approval decision UI by constructing the direct URL | System prevents access and returns authorization error; user is not able to view approval action buttons |
| 6 | Using API testing tool (e.g., Postman) or browser developer tools, attempt to send PUT request to /api/approval-decisions endpoint with unauthorized user's authentication token | API returns 403 Forbidden status code with error message: 'User does not have approver role' or 'Insufficient permissions to make approval decisions' |
| 7 | Verify the request payload is rejected before any database operations occur | No changes are made to ScheduleChangeRequests or ApprovalDecisions tables; request status remains unchanged |
| 8 | Check system security logs for the unauthorized access attempts | Security logs record the unauthorized access attempts with user ID, timestamp, attempted action, and denial reason |
| 9 | Verify no audit trail entry is created for the unauthorized attempt in ApprovalDecisions table | ApprovalDecisions table contains no records from the unauthorized user; only security logs capture the attempt |
| 10 | Attempt the same unauthorized access with a different non-approver role (e.g., viewer role) | System consistently denies access regardless of the specific non-approver role; same security behavior is enforced |

**Postconditions:**
- Request status remains 'Pending Approval' unchanged
- No approval or rejection decision is recorded
- No unauthorized access is granted to approval functionality
- Security logs document all unauthorized access attempts
- System maintains data integrity and security
- No notifications are sent regarding approval decisions
- User remains restricted to their authorized role permissions

---

