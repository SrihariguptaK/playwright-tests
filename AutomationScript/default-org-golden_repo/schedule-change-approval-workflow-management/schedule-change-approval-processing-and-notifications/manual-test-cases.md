# Manual Test Cases

## Story: As Approver, I want to request modifications on schedule change requests to ensure accuracy before approval
**Story ID:** story-8

### Test Case: Validate approver can request modifications with comments
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Approver role
- At least one pending schedule change request exists in the system
- Approver has permission to review and act on schedule change requests
- Schedule change request is in 'Pending Approval' status

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change requests approval queue | List of pending schedule change requests is displayed |
| 2 | Select a schedule change request to review | Schedule change request details page opens with all request information visible |
| 3 | Click on 'Request Modifications' button | Comment input field is displayed with mandatory indicator (asterisk or 'required' label) |
| 4 | Enter detailed comments in the comment field explaining required changes (e.g., 'Please adjust the shift end time to 5:00 PM instead of 6:00 PM') | Comments are accepted and displayed in the input field |
| 5 | Click 'Submit' button to submit the modification request | Modification request is saved successfully, confirmation message is displayed, and scheduler receives notification |
| 6 | Verify the request status has changed to 'Modifications Requested' | Request status is updated to 'Modifications Requested' in the system |

**Postconditions:**
- Modification request is recorded in the approval workflow history
- Scheduler receives notification about the modification request
- Request status is changed to 'Modifications Requested'
- Approver comments are stored and visible in request history

---

### Test Case: Verify scheduler receives notification and can edit request
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduler has previously submitted a schedule change request
- Approver has requested modifications on the scheduler's request
- Notification system is operational
- Scheduler has valid email address and in-app notification access

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Check scheduler's notification inbox (email and in-app) | Modification request notification is received by the scheduler |
| 2 | Open the modification request notification | Notification displays approver's comments detailing required changes and contains a clickable link to edit the request |
| 3 | Click on the link to edit the request in the notification | System navigates to the schedule change request edit page with current request details pre-populated |
| 4 | Review approver's modification comments displayed on the edit page | Approver's comments are clearly visible on the edit page |
| 5 | Make necessary changes to the schedule change request based on approver's comments | Changes are accepted and reflected in the form fields |
| 6 | Click 'Resubmit' button to resubmit the updated request | Updated request is saved successfully and confirmation message is displayed |
| 7 | Verify the request status has changed back to 'Pending Approval' | Request status is updated to 'Pending Approval' and workflow resumes with the updated request |

**Postconditions:**
- Updated schedule change request is saved in the system
- Request status is changed to 'Pending Approval'
- Approver receives notification of resubmission
- Modification history is tracked in the workflow
- Original and updated request details are preserved in history

---

### Test Case: Test validation prevents empty comments on modification request
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Approver role
- At least one pending schedule change request exists in the system
- Approver has permission to review and act on schedule change requests
- Schedule change request is in 'Pending Approval' status

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change requests approval queue | List of pending schedule change requests is displayed |
| 2 | Select a schedule change request to review | Schedule change request details page opens |
| 3 | Click on 'Request Modifications' button | Comment input field is displayed with mandatory indicator |
| 4 | Leave the comment field empty (do not enter any text) | Comment field remains empty |
| 5 | Click 'Submit' button to attempt submission without comments | System blocks the submission and displays validation error message (e.g., 'Comments are required for modification requests') |
| 6 | Verify that the modification request was not saved | Request status remains 'Pending Approval' and no modification request is recorded |
| 7 | Verify that no notification was sent to the scheduler | Scheduler does not receive any notification about modification request |

**Postconditions:**
- Modification request is not saved in the system
- Request status remains unchanged at 'Pending Approval'
- No notification is sent to the scheduler
- Error message is displayed to the approver
- Approver remains on the modification request page

---

## Story: As Scheduler, I want to receive notifications about approval decisions on my schedule change requests to stay informed
**Story ID:** story-10

### Test Case: Validate notification delivery upon approval decision
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Scheduler user is logged in and has submitted a schedule change request
- Approver user is logged in with approval permissions
- Schedule change request is in 'Pending Approval' status
- Notification system is operational and configured
- Scheduler has valid email address registered in the system
- System time synchronization is accurate for measuring 1-minute delivery SLA

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver navigates to the schedule change request approval queue | Pending schedule change requests are displayed |
| 2 | Approver selects the scheduler's schedule change request | Request details are displayed with approval action options |
| 3 | Approver clicks 'Approve' button and confirms the approval | Request is approved and confirmation message is displayed |
| 4 | Note the timestamp of approval action | Current timestamp is recorded for SLA verification |
| 5 | Wait and monitor for notification delivery (check within 1 minute) | Notification is sent to scheduler via email and in-app alert within 1 minute of approval |
| 6 | Scheduler checks email inbox and in-app notification center | Notification is received in both email and in-app notification center |
| 7 | Scheduler opens the notification | Notification displays approval decision details including approver name, approval timestamp, and any comments |
| 8 | Click on the dashboard link provided in the notification | System navigates to the schedule change request dashboard showing the approved request with updated status |

**Postconditions:**
- Notification is delivered within 1-minute SLA
- Notification is recorded in notification history
- Request status is updated to 'Approved'
- Scheduler is informed of the approval decision
- Dashboard reflects the approved status

---

### Test Case: Verify notifications are restricted to requestor
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler A is logged in and has submitted a schedule change request
- Scheduler B is logged in as a different scheduler user
- Approver has acted on Scheduler A's request (approved, rejected, or requested modifications)
- Notification has been sent to Scheduler A
- Both schedulers have access to the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Scheduler B (different user from the original requestor) | Scheduler B is successfully logged into the system |
| 2 | Navigate to the notification center as Scheduler B | Notification center opens showing only Scheduler B's notifications |
| 3 | Search or browse for notifications related to Scheduler A's schedule change request | No notifications related to Scheduler A's request are visible to Scheduler B |
| 4 | Attempt to access Scheduler A's notification directly using URL manipulation (if applicable) | Access is denied with appropriate error message (e.g., '403 Forbidden' or 'Access Denied') |
| 5 | Check Scheduler B's email inbox for any notifications about Scheduler A's request | No emails related to Scheduler A's schedule change request are present in Scheduler B's inbox |
| 6 | Log out and log back in as Scheduler A (original requestor) | Scheduler A is successfully logged in |
| 7 | Navigate to notification center as Scheduler A | Notification about the approval decision on Scheduler A's request is visible and accessible |

**Postconditions:**
- Notifications remain restricted to the original requestor only
- Security and privacy of notifications are maintained
- Unauthorized access attempts are blocked and logged
- Scheduler A can still access their own notifications

---

### Test Case: Test notification content accuracy
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Scheduler is logged in and has submitted a schedule change request
- Approver is logged in with approval permissions
- Schedule change request is in 'Pending Approval' status
- Notification system is operational
- Scheduler has valid email address and in-app notification access

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver navigates to the schedule change request approval queue | Pending schedule change requests are displayed |
| 2 | Approver selects the scheduler's schedule change request | Request details are displayed |
| 3 | Approver clicks 'Request Modifications' button | Comment input field is displayed |
| 4 | Approver enters specific modification comments (e.g., 'Please change shift start time from 8:00 AM to 9:00 AM and provide justification for the change') | Comments are entered and displayed in the input field |
| 5 | Approver submits the modification request | Modification request is submitted successfully and confirmation is displayed |
| 6 | Scheduler checks email and in-app notifications within 1 minute | Notification is received via both email and in-app alert |
| 7 | Scheduler opens the notification and reviews the content | Notification includes the decision type ('Modification Requested'), approver's name, timestamp, and the exact comments entered by the approver |
| 8 | Verify that the modification comments match exactly what the approver entered | Comments displayed in notification match: 'Please change shift start time from 8:00 AM to 9:00 AM and provide justification for the change' |
| 9 | Verify that notification includes a link to the schedule change request | Clickable link to the request dashboard is present in the notification |
| 10 | Click the link in the notification | System navigates to the schedule change request page with modification details and comments visible |

**Postconditions:**
- Notification content accurately reflects the modification request details
- All approver comments are preserved and displayed correctly
- Scheduler has complete information needed to address the modification request
- Notification is logged in notification history with accurate content

---

