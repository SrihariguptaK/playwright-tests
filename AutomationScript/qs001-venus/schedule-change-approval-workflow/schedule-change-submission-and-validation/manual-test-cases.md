# Manual Test Cases

## Story: As Scheduler, I want to submit schedule change requests to achieve accurate and timely schedule updates
**Story ID:** story-1

### Test Case: Validate successful schedule change submission with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated as a Scheduler
- User has access to the schedule change submission page
- System is operational and responsive
- Test document file is prepared (size less than 10MB)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change submission page | Submission form is displayed with all mandatory fields including date, time, reason, and attachment option clearly visible and accessible |
| 2 | Enter valid date in the date field (e.g., future date in correct format) | Date field accepts the input without validation errors |
| 3 | Enter valid time in the time field (e.g., HH:MM format) | Time field accepts the input without validation errors |
| 4 | Enter a valid reason for the schedule change in the reason field (e.g., 'Resource unavailability') | Reason field accepts the input without validation errors |
| 5 | Click on the attachment button and select a valid document file (size less than 10MB) | Document is successfully attached and file name is displayed in the form |
| 6 | Click the Submit button | Request is accepted and processed within 2 seconds |
| 7 | Verify the status of the submitted request | Request status is set to 'Pending Approval' |
| 8 | Check for confirmation message on the screen | Success confirmation message is displayed indicating the schedule change request has been submitted successfully |

**Postconditions:**
- Schedule change request is saved in ScheduleChangeRequests table
- Request status is 'Pending Approval'
- Request is available for approval workflow
- Scheduler can view the submitted request in their request list

---

### Test Case: Reject submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is authenticated as a Scheduler
- User has access to the schedule change submission page
- System is operational and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change submission page | Submission form is displayed with all mandatory fields clearly marked |
| 2 | Enter valid data in the date field only, leaving time and reason fields empty | Date field accepts the input |
| 3 | Tab out or click outside the empty mandatory fields | Real-time validation highlights the empty time and reason fields with visual indicators (e.g., red border or asterisk) |
| 4 | Click the Submit button without filling all mandatory fields | Submission is blocked and prevented from processing |
| 5 | Verify error messages displayed on the screen | Clear error messages are displayed for each missing mandatory field (e.g., 'Time is required', 'Reason is required') |
| 6 | Verify the form remains on the submission page | User remains on the submission page with all previously entered data retained |

**Postconditions:**
- No schedule change request is created in the system
- Form data is retained for user to complete
- User can correct errors and resubmit

---

### Test Case: Reject attachment exceeding size limit
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is authenticated as a Scheduler
- User has access to the schedule change submission page
- Test file larger than 10MB is prepared (e.g., 11MB file)
- System is operational and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change submission page | Submission form is displayed with attachment option available |
| 2 | Enter valid data in all mandatory fields (date, time, reason) | All mandatory fields accept the input without validation errors |
| 3 | Click on the attachment button and select a file larger than 10MB (e.g., 11MB file) | Attachment is rejected immediately with a clear error message indicating 'File size exceeds the maximum limit of 10MB' |
| 4 | Verify that the oversized file is not attached to the form | No file name is displayed in the attachment area and the attachment field remains empty |
| 5 | Click the Submit button without a valid attachment | Submission is blocked with an error message indicating attachment size requirement is not met |
| 6 | Remove the oversized file and attach a valid file (size less than 10MB) | Valid file is successfully attached and file name is displayed |
| 7 | Click the Submit button with valid attachment | Request is accepted and submitted successfully |

**Postconditions:**
- Only requests with attachments within size limit are accepted
- System enforces 10MB attachment size limit consistently
- User is informed of size restrictions clearly

---

## Story: As Scheduler, I want to edit or withdraw pending schedule change requests to achieve flexibility and error correction
**Story ID:** story-10

### Test Case: Edit a pending schedule change request successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is authenticated as a Scheduler
- At least one schedule change request with status 'Pending Approval' exists in the system
- The pending request was submitted by the currently logged-in scheduler
- System is operational and responsive
- Approvers are configured to receive notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the list of schedule change requests | List of schedule change requests is displayed showing all requests submitted by the scheduler |
| 2 | Identify and select a request with 'Pending Approval' status | Request details are displayed in edit mode with all fields (date, time, reason, attachments) accessible for modification |
| 3 | Modify the date field to a new valid date | Date field accepts the new value without validation errors |
| 4 | Modify the reason field with updated text (e.g., 'Updated: Resource conflict resolved') | Reason field accepts the updated text without validation errors |
| 5 | Remove existing attachment and upload a new document (size less than 10MB) | Old attachment is removed and new attachment is successfully uploaded and displayed |
| 6 | Click the Submit or Update button to save changes | Changes are accepted and processed within 2 seconds |
| 7 | Verify confirmation message is displayed | Success message is displayed confirming the request has been updated |
| 8 | Wait for 1 minute and verify approver notification | Approvers are notified of the changes within 1 minute via configured notification method |
| 9 | View the updated request details | Request displays the modified date, reason, and new attachment with status still 'Pending Approval' |

**Postconditions:**
- Schedule change request is updated in ScheduleChangeRequests table
- Request status remains 'Pending Approval'
- Approvers have been notified of the modifications
- Updated request is available in the pending requests list

---

### Test Case: Withdraw a pending schedule change request
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated as a Scheduler
- At least one schedule change request with status 'Pending Approval' exists in the system
- The pending request was submitted by the currently logged-in scheduler
- System is operational and responsive
- Approvers are configured to receive notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the list of schedule change requests | List of schedule change requests is displayed showing all requests submitted by the scheduler |
| 2 | Identify and select a request with 'Pending Approval' status | Request details are displayed with withdraw option available |
| 3 | Click the Withdraw button | Confirmation dialog is displayed asking 'Are you sure you want to withdraw this request?' |
| 4 | Click Confirm or Yes to proceed with withdrawal | Withdrawal is processed within 2 seconds |
| 5 | Verify the request status is updated | Request status is changed to 'Withdrawn' and displayed in the request list |
| 6 | Verify confirmation message is displayed | Success message is displayed confirming the request has been withdrawn |
| 7 | Wait for 1 minute and verify approver notification | Approvers are notified of the withdrawal within 1 minute via configured notification method |
| 8 | Verify the withdrawn request is no longer in the pending list | Request is removed from pending requests list or clearly marked as 'Withdrawn' |

**Postconditions:**
- Schedule change request status is updated to 'Withdrawn' in ScheduleChangeRequests table
- Request is no longer in the approval workflow
- Approvers have been notified of the withdrawal
- Request cannot be edited or resubmitted without creating a new request

---

### Test Case: Prevent editing or withdrawing approved requests
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is authenticated as a Scheduler
- At least one schedule change request with status 'Approved' exists in the system
- The approved request was submitted by the currently logged-in scheduler
- System is operational and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the list of schedule change requests | List of schedule change requests is displayed showing all requests including approved ones |
| 2 | Identify and select a request with 'Approved' status | Request details are displayed in read-only mode |
| 3 | Attempt to click the Edit button or modify any field | Edit option is disabled (grayed out) or an error message is displayed stating 'Cannot edit approved requests' |
| 4 | Verify all input fields are non-editable | All fields (date, time, reason, attachments) are displayed as read-only and cannot be modified |
| 5 | Attempt to click the Withdraw button | Withdrawal option is disabled (grayed out) or an error message is displayed stating 'Cannot withdraw approved requests' |
| 6 | Verify no confirmation dialog appears for withdrawal | No withdrawal confirmation dialog is displayed and no action is taken |
| 7 | Navigate back to the request list | Request status remains 'Approved' and no changes have been made |

**Postconditions:**
- Approved request remains unchanged in the system
- Request status remains 'Approved'
- No notifications are sent to approvers
- System integrity is maintained by preventing modification of approved requests

---

