# Manual Test Cases

## Story: As Schedule Coordinator, I want to perform schedule change request submission to achieve accurate and complete change requests
**Story ID:** story-1

### Test Case: Validate successful schedule change request submission with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated as Schedule Coordinator
- User has necessary permissions to submit schedule change requests
- Schedule change request submission page is accessible
- Valid attachment file is available for upload (PDF, DOC, or DOCX format, max 10MB)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request submission page | Submission form is displayed with all mandatory fields including schedule date, time, reason, and optional attachment upload field |
| 2 | Enter valid schedule date in the date field | Date field accepts the input and displays the selected date without validation errors |
| 3 | Enter valid time in the time field | Time field accepts the input and displays the selected time without validation errors |
| 4 | Enter a valid reason for the schedule change in the reason text field | Reason field accepts the text input without validation errors |
| 5 | Click on the attachment upload button and select a valid document file | File upload dialog opens, file is selected and uploaded successfully, file name is displayed in the attachment field |
| 6 | Click the Submit button | System validates all inputs, processes the submission within 2 seconds, saves the request to ScheduleChangeRequests table, and displays a confirmation message with the request ID and timestamp |

**Postconditions:**
- Schedule change request is saved in the database with status 'Submitted'
- Submission is timestamped and logged in the system
- Attachment is stored and associated with the request
- User remains on confirmation page or is redirected to requests dashboard

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is authenticated as Schedule Coordinator
- User has necessary permissions to submit schedule change requests
- Schedule change request submission page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request submission page | Submission form is displayed with all mandatory fields marked with asterisks or required indicators |
| 2 | Leave the schedule date field empty | Field remains empty without pre-filled data |
| 3 | Leave the time field empty | Field remains empty without pre-filled data |
| 4 | Leave the reason field empty | Field remains empty without pre-filled data |
| 5 | Click the Submit button without filling mandatory fields | Inline validation errors are displayed next to each empty mandatory field with user-friendly error messages (e.g., 'Schedule date is required', 'Time is required', 'Reason is required'), submission is blocked, and no data is sent to the server |
| 6 | Fill in the schedule date field with a valid date | Date field accepts the input and the validation error for this field is cleared |
| 7 | Fill in the time field with a valid time | Time field accepts the input and the validation error for this field is cleared |
| 8 | Fill in the reason field with a valid reason | Reason field accepts the input and the validation error for this field is cleared |
| 9 | Click the Submit button again with all mandatory fields completed | System validates all inputs successfully, processes the submission within 2 seconds, saves the request, and displays a confirmation message with the request ID and timestamp |

**Postconditions:**
- Schedule change request is saved in the database only after all mandatory fields are filled
- Submission is timestamped and logged in the system
- User sees confirmation of successful submission

---

### Test Case: Test attachment upload functionality
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is authenticated as Schedule Coordinator
- User has necessary permissions to submit schedule change requests
- Schedule change request submission page is accessible
- Valid document file is available for upload (PDF format, size less than 10MB)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request submission page | Submission form is displayed with attachment upload option visible and enabled |
| 2 | Click on the attachment upload button or drag-and-drop area | File selection dialog opens allowing user to browse and select files |
| 3 | Select a valid document attachment (e.g., PDF file within size limits) | File is uploaded successfully, attachment file name is displayed in the form, file size is shown, and a preview or icon indicating successful upload is displayed |
| 4 | Fill in all mandatory fields (schedule date, time, and reason) with valid data | All mandatory fields accept the input without validation errors |
| 5 | Click the Submit button | System validates all inputs including the attachment, processes the submission within 2 seconds, saves the request with the attachment linked to it, and displays a confirmation message |
| 6 | Verify the attachment is associated with the schedule change request by checking the request details or database | Attachment is saved in the Attachments storage, properly linked to the schedule change request ID, and is retrievable |

**Postconditions:**
- Schedule change request is saved in the database with status 'Submitted'
- Attachment file is stored in the Attachments storage system
- Attachment is linked to the schedule change request via request ID
- User can view the attached document in the request details

---

## Story: As Schedule Coordinator, I want to perform viewing of schedule change request status to achieve transparency in approval progress
**Story ID:** story-3

### Test Case: Validate display of user's schedule change requests
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated as Schedule Coordinator
- User has previously submitted at least 3 schedule change requests
- Schedule change requests have different statuses (e.g., Pending, Approved, Rejected)
- User has permissions to view their own schedule change requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Schedule Coordinator logs into the system using valid credentials | User is successfully authenticated and redirected to the dashboard or home page |
| 2 | Navigate to 'My Schedule Change Requests' page from the main menu or dashboard | 'My Schedule Change Requests' dashboard is displayed within 3 seconds, showing a list view of all schedule change requests |
| 3 | View the list of submitted schedule change requests | All requests submitted by the logged-in user are listed with columns showing request ID, schedule date, time, reason, current status, and submission date |
| 4 | Verify that each request displays its current status (e.g., Pending, Approved, Rejected, In Review) | Each request in the list shows its current status clearly with appropriate visual indicators (e.g., color coding or status badges) |
| 5 | Click on one of the schedule change requests to view details | Detailed view page opens showing complete request information including schedule date, time, reason, attachments, current status, and approval history section |
| 6 | Review the approval history and comments section | Detailed approval history is displayed showing all approval actions taken, approver names, timestamps, decision (approved/rejected/pending), and any comments provided by approvers in chronological order |

**Postconditions:**
- User remains on the detailed view page
- All request data is displayed accurately
- User can navigate back to the list view
- No unauthorized data is exposed

---

### Test Case: Verify filtering and sorting functionality
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is authenticated as Schedule Coordinator
- User has submitted multiple schedule change requests with various statuses (Pending, Approved, Rejected)
- User is on the 'My Schedule Change Requests' dashboard page
- At least one request has status 'Pending'

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the filter options on the 'My Schedule Change Requests' dashboard | Filter controls are visible, including status filter dropdown and date range filters |
| 2 | Click on the status filter dropdown and select 'Pending' | Filter is applied and only schedule change requests with status 'Pending' are displayed in the list, other statuses are hidden |
| 3 | Verify the count of displayed requests matches the number of pending requests | The number of requests shown corresponds to the actual number of pending requests, and a filter indicator shows 'Filtered by: Status = Pending' |
| 4 | Locate the sort options and click on the 'Submission Date' column header to sort in descending order | Requests are reordered from newest to oldest based on submission date, with the most recent submission appearing first, and a descending sort indicator (down arrow) is displayed |
| 5 | Verify the order of requests by checking submission dates | All displayed requests are ordered correctly with the newest submission date at the top and oldest at the bottom |
| 6 | Click the 'Clear Filters' or 'Reset' button | All filters and sorting are removed, and all schedule change requests submitted by the user are displayed in the default order (typically by submission date descending or request ID) |
| 7 | Verify all requests are now visible | The complete list of all user's schedule change requests is displayed without any filters applied |

**Postconditions:**
- Filters and sorting are cleared
- All user's requests are visible
- Dashboard is in default state
- User can apply new filters or sorting as needed

---

### Test Case: Test access restriction to own requests
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is authenticated as Schedule Coordinator
- Another Schedule Coordinator user exists in the system with their own schedule change requests
- User knows or can obtain the request ID or URL of another user's schedule change request
- Security controls are implemented to restrict access to own requests only

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Obtain the URL or request ID of a schedule change request belonging to another user | URL or request ID is available for testing (e.g., /api/schedule-change-requests/12345 where 12345 belongs to another user) |
| 2 | Attempt to access another user's schedule change request by directly entering the URL in the browser or manipulating the request ID parameter | System denies access and displays an 'Access Denied' error message, or returns a 403 Forbidden status, or redirects to an error page, or displays no data with a message 'Request not found' |
| 3 | Verify that no sensitive data from the other user's request is displayed or leaked in the response | No details of the other user's schedule change request are visible, and no sensitive information is exposed in the error message or page source |
| 4 | Navigate back to 'My Schedule Change Requests' dashboard using the normal navigation menu | User is returned to their own dashboard showing only their own schedule change requests |
| 5 | Select and view one of the user's own schedule change requests | Request details are displayed successfully with full approval history and comments, confirming normal access to own requests is working |
| 6 | Verify that all displayed requests belong to the logged-in user by checking the submitter information | All requests shown are confirmed to be submitted by the current logged-in user, with no requests from other users visible |

**Postconditions:**
- User can only access their own schedule change requests
- Security controls are verified to be working correctly
- No unauthorized data access occurred
- System maintains data privacy and access restrictions

---

## Story: As Schedule Coordinator, I want to perform editing of submitted schedule change requests to achieve correction of errors before approval
**Story ID:** story-6

### Test Case: Validate editing of pending schedule change request
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- At least one schedule change request exists in pending status
- User has permission to edit own schedule change requests
- ScheduleChangeRequests table is accessible
- Audit logging system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to 'My Schedule Change Requests' page | Page loads successfully displaying list of schedule change requests |
| 2 | Locate and select a pending schedule change request from the list | Request details are displayed with edit option visible and enabled |
| 3 | Click the edit button to enter edit mode | Request form opens in edit mode with all fields populated with current values |
| 4 | Modify schedule details (e.g., change date, time, or reason) | Modified values are accepted in the form fields without errors |
| 5 | Click save button to submit changes | Changes are saved successfully, confirmation message displayed, and submission timestamp is updated to current date/time |
| 6 | Navigate to audit log section or view audit trail for the request | Audit log displays the edit action with coordinator username, timestamp, and details of changes made |
| 7 | Verify the update response time | System processes and saves the update within 2 seconds |

**Postconditions:**
- Schedule change request remains in pending status with updated details
- Submission timestamp reflects the time of the edit
- Audit log contains complete record of the edit action
- Original request data is preserved in audit history

---

### Test Case: Verify editing is blocked for approved requests
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- At least one schedule change request exists in approved status
- User has permission to view schedule change requests
- Security rules are properly configured to restrict editing of approved requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to 'My Schedule Change Requests' page | Page loads successfully displaying list of schedule change requests including approved ones |
| 2 | Locate and select an approved schedule change request from the list | Request details are displayed |
| 3 | Attempt to access the edit functionality for the approved request | Edit option is disabled, grayed out, or not visible for approved requests |
| 4 | If edit button is visible, click it to attempt editing | System displays access denied message or error notification indicating editing is not allowed for approved requests |
| 5 | Attempt direct API call to PUT /api/schedule-change-requests/{id} for approved request (if applicable) | API returns 403 Forbidden or appropriate error response preventing the edit |

**Postconditions:**
- Approved request remains unchanged
- No audit log entry is created for failed edit attempt
- Request status remains as approved

---

### Test Case: Test validation prevents saving invalid edits
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- At least one schedule change request exists in pending status
- Validation rules are configured for schedule change request fields
- User has permission to edit own schedule change requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to 'My Schedule Change Requests' page | Page loads successfully displaying list of schedule change requests |
| 2 | Select a pending schedule change request and click edit | Request form opens in edit mode with current values populated |
| 3 | Enter invalid data in one or more required fields (e.g., past date, empty required field, invalid format) | Form accepts the input temporarily for validation testing |
| 4 | Click save button to attempt saving invalid data | Validation errors are displayed next to invalid fields with clear error messages, save operation is blocked, and form remains in edit mode |
| 5 | Verify that no changes were saved to the database | Original request data remains unchanged, submission timestamp is not updated |
| 6 | Correct the invalid data by entering valid values in all fields | Validation errors clear as valid data is entered |
| 7 | Click save button with corrected valid data | Changes are saved successfully, confirmation message displayed, and submission timestamp is updated |
| 8 | Verify audit log for the successful save | Audit log shows only the successful edit action with user and timestamp, no record of failed validation attempt |

**Postconditions:**
- Schedule change request contains valid updated data
- Request remains in pending status
- Submission timestamp reflects the successful edit time
- Audit log contains record of successful edit only

---

## Story: As Schedule Coordinator, I want to perform cancellation of schedule change requests to achieve withdrawal of requests before approval
**Story ID:** story-8

### Test Case: Validate cancellation of pending schedule change request
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- At least one schedule change request exists in pending status
- User has permission to cancel own schedule change requests
- Approvers are assigned to the schedule change request
- Notification system is operational
- Audit logging system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to 'My Schedule Change Requests' page | Page loads successfully displaying list of schedule change requests |
| 2 | Locate and select a pending schedule change request from the list | Request details are displayed with cancel option visible and enabled |
| 3 | Click the cancel button | Confirmation dialog appears asking user to confirm the cancellation action with message like 'Are you sure you want to cancel this request?' |
| 4 | Click confirm button in the confirmation dialog | Request status is updated to 'cancelled', confirmation message is displayed to user (e.g., 'Request successfully cancelled') |
| 5 | Verify the cancellation processing time | Cancellation is processed and confirmed within 2 seconds |
| 6 | Refresh the request list or view the cancelled request details | Request status shows as 'cancelled' and cancel option is no longer available |
| 7 | Navigate to audit log section or view audit trail for the request | Audit log displays the cancellation action with coordinator username, timestamp, and cancellation details |
| 8 | Verify notification was sent to approvers (check notification queue or approver inbox) | Notification has been sent to all assigned approvers informing them of the cancellation |

**Postconditions:**
- Schedule change request status is set to 'cancelled'
- Request cannot be edited or cancelled again
- Audit log contains complete record of cancellation action
- Approvers have been notified of the cancellation
- Request is no longer in pending approval queue

---

### Test Case: Verify cancellation blocked for approved requests
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- At least one schedule change request exists in approved status
- User has permission to view schedule change requests
- Security rules are properly configured to restrict cancellation of approved requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to 'My Schedule Change Requests' page | Page loads successfully displaying list of schedule change requests including approved ones |
| 2 | Locate and select an approved schedule change request from the list | Request details are displayed showing approved status |
| 3 | Attempt to access the cancel functionality for the approved request | Cancel option is disabled, grayed out, or not visible for approved requests |
| 4 | If cancel button is visible, click it to attempt cancellation | System displays access denied message or error notification indicating cancellation is not allowed for approved requests |
| 5 | Attempt direct API call to POST /api/schedule-change-requests/{id}/cancel for approved request (if applicable) | API returns 403 Forbidden or appropriate error response preventing the cancellation |
| 6 | Verify request status remains unchanged | Request status remains as 'approved' with no modifications |

**Postconditions:**
- Approved request remains unchanged with approved status
- No audit log entry is created for failed cancellation attempt
- No notifications are sent to approvers
- Request remains in approved state

---

### Test Case: Test notification sent to approvers upon cancellation
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- At least one schedule change request exists in pending status
- One or more approvers are assigned to the request
- Notification system is configured and operational
- User has permission to cancel own schedule change requests
- Ability to verify notification delivery (access to notification logs or approver accounts)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to 'My Schedule Change Requests' page | Page loads successfully displaying list of schedule change requests |
| 2 | Note the approvers assigned to a pending schedule change request | Approver names/IDs are visible in the request details |
| 3 | Select the pending schedule change request | Request details are displayed with cancel option available |
| 4 | Click cancel button and confirm the cancellation action | Request is cancelled successfully and confirmation message is displayed |
| 5 | Check notification system logs or queue for outgoing notifications | Notification entry exists for each assigned approver regarding the cancellation |
| 6 | Verify notification content includes request details and cancellation information | Notification contains request ID, coordinator name, cancellation timestamp, and relevant request details |
| 7 | If possible, check approver's notification inbox or email | Approvers have received notification about the cancelled request |
| 8 | Verify all assigned approvers received the notification | Notification was sent to all approvers listed on the original request |

**Postconditions:**
- Request status is 'cancelled'
- All assigned approvers have been notified of the cancellation
- Notification delivery is logged in the system
- Audit log contains cancellation action record

---

