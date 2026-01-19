# Manual Test Cases

## Story: As Approver, I want to review and approve schedule change requests to ensure authorized modifications
**Story ID:** story-10

### Test Case: Validate approver can view and approve schedule change request
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has valid approver role and credentials
- At least one pending schedule change request exists in the system
- Schedule change request contains all required details and attachments
- System is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid approver credentials | User is successfully authenticated and redirected to the dashboard |
| 2 | Navigate to the approval queue section from the main menu | List of pending schedule change requests is displayed with request ID, requester name, submission date, and status |
| 3 | Select a specific schedule change request from the list by clicking on it | Request details page opens showing all relevant information including requester details, requested changes, justification, affected schedules, and any attached documents |
| 4 | Review all details and attachments displayed on the request details page | All information is clearly visible, readable, and attachments are accessible for download or preview |
| 5 | Click the 'Approve' button and enter comments in the comments field (e.g., 'Approved - request meets all requirements') | Comments field accepts text input and approve button remains enabled |
| 6 | Click the 'Submit Decision' button to finalize the approval | Success confirmation message is displayed, decision is recorded with timestamp and approver identity, and request status updates to 'Approved' |

**Postconditions:**
- Schedule change request status is updated to 'Approved' in the database
- Approval decision is logged in ApprovalDecisions table with timestamp and approver ID
- Requester receives notification of approval
- Request is removed from pending approval queue
- Audit trail contains complete record of the approval action

---

### Test Case: Verify rejection with comments is recorded and notified
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with valid approver role
- At least one pending schedule change request exists in the approval queue
- Notification system is configured and operational
- Requester has valid contact information in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the approval queue and select a schedule change request to reject | Request details page opens displaying all relevant information including requester details, requested changes, and justification |
| 2 | Click the 'Reject' button on the request details page | Rejection dialog or form appears with a mandatory comments field |
| 3 | Enter detailed rejection comments in the comments field (e.g., 'Request rejected - insufficient justification provided for schedule change') | Comments field accepts the text input and character count is displayed if applicable |
| 4 | Click the 'Submit Decision' button to finalize the rejection | Success confirmation message is displayed indicating rejection has been recorded |
| 5 | Verify the rejection is recorded by checking the audit trail or decision history | Rejection decision appears in audit trail with timestamp, approver identity, and rejection comments |
| 6 | Verify notification was sent by checking notification logs or requester's notification inbox | Notification is sent to requester containing rejection decision, approver comments, and timestamp |

**Postconditions:**
- Schedule change request status is updated to 'Rejected' in ScheduleChangeRequests table
- Rejection decision is logged in ApprovalDecisions table with complete details
- Requester receives email and/or in-app notification of rejection
- Request is removed from pending approval queue
- Rejection comments are permanently stored and accessible in audit trail

---

### Test Case: Ensure unauthorized users cannot access approval actions
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Test user account exists without approver role assigned
- Role-based access control is configured in the system
- API endpoints for approval actions are protected
- At least one pending schedule change request exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using credentials of a user without approver role (e.g., regular employee or requester role) | User is successfully authenticated and redirected to appropriate dashboard for their role |
| 2 | Attempt to navigate to the approval queue section from the main menu or by direct URL | Approval queue menu option is not visible or navigation is blocked with 'Access Denied' or '403 Forbidden' error message |
| 3 | Attempt to access approval actions (approve, reject, request modifications) through the UI | Approval action buttons are not displayed or are disabled, preventing any approval actions |
| 4 | Using API testing tool (e.g., Postman), attempt to directly call GET /api/approvals endpoint with the unauthorized user's authentication token | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 5 | Using API testing tool, attempt to directly call POST /api/approvals/{id}/decision endpoint with a valid request ID and decision payload | API returns 403 Forbidden status code with error message 'User does not have approver role' or similar authorization error |
| 6 | Verify that no approval decision was recorded in the system by checking the ApprovalDecisions table or audit logs | No new approval decision entries exist for the unauthorized user, confirming access was properly denied |

**Postconditions:**
- No unauthorized approval actions were executed
- System security logs record the unauthorized access attempts
- Schedule change request status remains unchanged
- No notifications were sent based on unauthorized actions
- System integrity and role-based access control remain intact

---

## Story: As Approver, I want to receive notifications for pending schedule change approvals to ensure timely processing
**Story ID:** story-12

### Test Case: Validate notification delivery for new pending approvals
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Approver user account exists with valid email address configured
- Notification system is operational and configured
- Email server is accessible and functioning
- Approver has default notification preferences enabled
- User has permissions to submit schedule change requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login as a requester user and navigate to the schedule change request submission form | Schedule change request form is displayed with all required fields |
| 2 | Fill in all required fields (schedule details, justification, affected dates) and select an approver from the approver dropdown | Form accepts all input and approver is successfully selected |
| 3 | Click 'Submit' button to submit the schedule change request | Request is successfully submitted with confirmation message and request ID is generated |
| 4 | Wait up to 5 minutes and check the assigned approver's email inbox | Email notification is received within 5 minutes containing request ID, requester name, summary of changes, and link to review the request |
| 5 | Login as the assigned approver and check the in-app notification center or dashboard | In-app notification is displayed showing the new pending approval with request details and action buttons |
| 6 | Click on the notification link in either email or in-app notification | User is redirected to the specific schedule change request details page with all information displayed and actionable approve/reject buttons available |
| 7 | Verify notification content includes all required information (request ID, requester, date submitted, summary) | All notification content is accurate, complete, and matches the submitted request details |

**Postconditions:**
- Notification is logged in notification history with delivery timestamp
- Email notification is successfully delivered to approver's inbox
- In-app notification appears in approver's notification center
- Notification links are functional and direct to correct request
- Notification delivery time is recorded and within 5-minute SLA

---

### Test Case: Verify escalation notification for overdue approvals
- **ID:** tc-005
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- SLA threshold for approvals is configured in the system (e.g., 24 hours)
- At least one schedule change request exists in pending status
- Escalation notification rules are configured
- Approver has valid email and notification preferences enabled
- System time can be manipulated or test data with past submission dates exists

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create or identify a schedule change request that has been pending beyond the configured SLA threshold (simulate by adjusting submission timestamp or waiting for actual SLA breach) | Schedule change request exists with submission timestamp exceeding SLA threshold |
| 2 | Trigger the escalation notification job manually or wait for scheduled job execution | Escalation notification process executes and identifies overdue approval requests |
| 3 | Check the approver's email inbox for escalation notification | Escalation email is received with subject line indicating urgency (e.g., 'URGENT: Overdue Approval Required'), request details, time pending, and SLA breach information |
| 4 | Check the approver's in-app notification center for escalation alert | Escalation notification appears with high priority indicator or different visual styling to distinguish from regular notifications |
| 5 | Navigate to notification logs or admin panel to verify escalation notification was logged | Notification log shows escalation notification entry with notification type 'Escalation', timestamp, recipient, and request ID |
| 6 | Verify the escalation notification contains accurate information about how long the request has been pending | Notification displays correct pending duration (e.g., 'Pending for 26 hours - SLA: 24 hours') and emphasizes urgency |

**Postconditions:**
- Escalation notification is logged in NotificationSettings or notification history table
- Escalation email is delivered to approver
- Escalation alert is visible in approver's notification center
- Notification log contains complete escalation notification record
- Request remains in pending status awaiting approval action

---

### Test Case: Test notification preference management
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 15 mins

**Preconditions:**
- Approver user is logged into the system
- Notification preferences UI is accessible to approvers
- Default notification preferences are enabled (email and in-app)
- At least one notification preference option is available (e.g., email, in-app, SMS)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user settings or profile section and locate notification preferences | Notification preferences page is displayed showing current settings for different notification types |
| 2 | Review current notification preferences displayed (email, in-app, frequency settings) | Current preferences are clearly displayed with toggle switches or checkboxes for each notification type |
| 3 | Disable email notifications by unchecking or toggling off the email notification option | Email notification toggle changes to disabled state visually |
| 4 | Keep in-app notifications enabled and click 'Save' or 'Update Preferences' button | Success message is displayed confirming 'Notification preferences updated successfully' |
| 5 | Verify preferences are saved by refreshing the page or logging out and back in, then checking notification preferences again | Updated preferences persist showing email notifications disabled and in-app notifications enabled |
| 6 | Trigger a notification event by having another user submit a new schedule change request assigned to this approver | New schedule change request is submitted successfully |
| 7 | Wait up to 5 minutes and check the approver's email inbox | No email notification is received, respecting the disabled email preference |
| 8 | Check the approver's in-app notification center | In-app notification is displayed for the new pending approval, confirming preferences are respected |
| 9 | Verify in notification logs that only in-app notification was sent | Notification log shows in-app notification delivery but no email notification entry for this event |

**Postconditions:**
- Notification preferences are saved in NotificationSettings table
- Updated preferences are applied to all future notifications
- Only enabled notification channels deliver notifications
- Preference changes are logged in audit trail
- User can modify preferences again at any time

---

