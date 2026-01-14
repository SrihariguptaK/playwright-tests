# Manual Test Cases

## Story: As Scheduler, I want to create and save draft schedule change requests to achieve accurate and complete submissions
**Story ID:** story-1

### Test Case: Validate saving and editing draft schedule change requests
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- User has access to schedule change request functionality
- ScheduleChangeRequests table is accessible
- No existing drafts are open in the current session

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request form | Form is displayed with all fields including mandatory and optional fields, all fields are empty and editable |
| 2 | Enter partial data in some fields (e.g., employee name, date) without completing all mandatory fields | Data is entered successfully in the fields without validation errors |
| 3 | Click 'Save as Draft' button | Draft is saved successfully with confirmation message displayed, draft ID is generated and visible |
| 4 | Navigate away from the form or close the browser | User is able to leave the page without data loss warning |
| 5 | Return to schedule change request page and retrieve the saved draft | Draft is listed in drafts section with correct draft ID and timestamp |
| 6 | Open the saved draft for editing | Draft data is loaded correctly with all previously entered data intact and all fields remain editable |
| 7 | Modify existing data and add additional information | Changes are accepted and fields update accordingly |
| 8 | Click 'Save as Draft' button again | Updated draft is saved successfully with confirmation message, same draft ID is retained |

**Postconditions:**
- Draft remains in 'Draft' status
- All entered data is persisted in ScheduleChangeRequests table
- Draft is available for future editing
- No submission or approval workflow is triggered

---

### Test Case: Validate submission with all mandatory fields completed
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- User has access to schedule change request form
- User knows all mandatory field requirements
- System validation rules are configured correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request form or open an existing draft | Form is displayed with all fields visible and editable |
| 2 | Complete all mandatory fields (e.g., employee name, current schedule, proposed schedule, reason, effective date) | All mandatory fields accept valid data without errors |
| 3 | Verify no validation errors are displayed on the form | No validation errors or warning messages are shown, all mandatory field indicators are satisfied |
| 4 | Click 'Submit' button | System processes the submission without errors |
| 5 | Verify the request status | Request status is updated to 'Pending Approval' |
| 6 | Check for confirmation message | Confirmation message is displayed indicating successful submission with request ID |
| 7 | Verify the request appears in submitted requests list | Request is visible in the submitted requests list with status 'Pending Approval' and correct timestamp |

**Postconditions:**
- Request status is 'Pending Approval'
- Request is no longer editable by scheduler
- Request is available for approver review
- All submitted data is persisted in ScheduleChangeRequests table
- Draft status (if applicable) is removed

---

### Test Case: Validate submission blocked with missing mandatory fields
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- User has access to schedule change request form
- Mandatory field validation is enabled
- Form validation rules are properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request form | Form is displayed with all fields and mandatory field indicators visible |
| 2 | Fill in some fields but intentionally leave one or more mandatory fields empty (e.g., leave 'Reason' field blank) | Partial data is entered successfully in completed fields |
| 3 | Click 'Submit' button | Submission is blocked and form remains on the same page |
| 4 | Verify validation error messages are displayed | Validation errors are displayed inline next to each empty mandatory field with clear error messages (e.g., 'Reason is required') |
| 5 | Verify the request status has not changed | Request remains in draft status or unsaved state, no 'Pending Approval' status is assigned |
| 6 | Attempt to navigate away from the form | System may display warning about unsaved changes |
| 7 | Fill in the previously empty mandatory field | Field accepts the data and inline error message disappears |
| 8 | Click 'Submit' button again | Submission is successful with confirmation message and status 'Pending Approval' |

**Postconditions:**
- Invalid submission attempt is prevented
- No incomplete request is created in 'Pending Approval' status
- User is informed of required corrections
- Data entered in valid fields is retained
- After correction, request can be submitted successfully

---

## Story: As Scheduler, I want to cancel submitted schedule change requests before approval to correct errors or changes
**Story ID:** story-9

### Test Case: Validate successful cancellation of pending requests
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one schedule change request exists with status 'Pending Approval'
- User is the owner of the request to be cancelled
- Approvers are assigned to the request
- Notification system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the list of submitted schedule change requests | List of submitted requests is displayed showing all requests with their current statuses |
| 2 | Locate and select a schedule change request with status 'Pending Approval' | Request details are displayed with status clearly showing 'Pending Approval' |
| 3 | Verify that cancellation option is available | Cancel button or option is visible and enabled for the selected request |
| 4 | Click 'Cancel Request' button | Cancellation confirmation dialog appears asking user to confirm the action |
| 5 | Confirm the cancellation action | System processes the cancellation request within 2 seconds |
| 6 | Verify the request status is updated | Request status is changed to 'Cancelled' and displayed in the request details |
| 7 | Check for confirmation message | Confirmation message is displayed indicating successful cancellation with request ID |
| 8 | Verify the cancelled request appears in the requests list with updated status | Request is visible in the list with status 'Cancelled' and cancellation timestamp |
| 9 | Verify notification sent to approvers | Approvers receive cancellation notification via configured notification channels with request details |
| 10 | Attempt to edit or resubmit the cancelled request | Edit and submit options are disabled or unavailable for cancelled request |

**Postconditions:**
- Request status is permanently set to 'Cancelled'
- Request is removed from approvers' pending approval queue
- Cancellation notification is sent to all assigned approvers
- Request cannot be approved or rejected after cancellation
- Cancellation action is logged with timestamp and user information

---

### Test Case: Validate cancellation prevention for approved requests
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one schedule change request exists with status 'Approved'
- User is the owner of the approved request
- System security rules prevent cancellation of approved requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the list of submitted schedule change requests | List of all submitted requests is displayed with various statuses |
| 2 | Locate and select a schedule change request with status 'Approved' | Request details are displayed with status clearly showing 'Approved' |
| 3 | Check for cancellation option availability | Cancel button is either disabled, hidden, or not present for approved requests |
| 4 | If cancel button is visible but disabled, hover over or click the disabled button | Tooltip or error message is displayed explaining that approved requests cannot be cancelled |
| 5 | Attempt to cancel the request through any available means (if technically possible) | System blocks the cancellation attempt and displays error message such as 'Cannot cancel approved requests' |
| 6 | Verify the request status remains unchanged | Request status remains 'Approved' and no changes are made to the request |
| 7 | Repeat steps 2-6 for a request with status 'Rejected' | Cancellation is also prevented for rejected requests with appropriate error message |

**Postconditions:**
- Request status remains 'Approved' or 'Rejected' unchanged
- No cancellation notification is sent
- Request data integrity is maintained
- User is informed that cancellation is not allowed for approved/rejected requests
- System security rules are enforced successfully

---

