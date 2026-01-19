# Manual Test Cases

## Story: As Employee, I want to submit schedule change requests to achieve timely updates to my work schedule
**Story ID:** story-11

### Test Case: Validate successful schedule change request submission with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Scheduling portal is accessible and operational
- Employee has a valid work schedule in the system
- Supporting document is available and under 10MB in size

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling portal login page and enter valid employee credentials | Employee is successfully authenticated and redirected to the scheduling portal dashboard |
| 2 | Click on the 'Schedule Change Request' menu option or button | Schedule change request form is displayed with all mandatory fields clearly marked |
| 3 | Fill in the 'Date' field with a current or future date | Date field accepts the input and displays the selected date in the correct format |
| 4 | Fill in the 'Time' field with the desired schedule time | Time field accepts the input and displays the selected time |
| 5 | Fill in the 'Reason' field with a valid explanation for the schedule change | Reason field accepts the text input without validation errors |
| 6 | Click on the 'Attach Document' button and select a valid document file under 10MB | Document is successfully uploaded and file name is displayed in the attachment section |
| 7 | Click the 'Submit' button to submit the schedule change request | System processes the request within 2 seconds, saves the data to ScheduleChangeRequests table, and displays a confirmation message with timestamp and request ID |
| 8 | Verify the confirmation message contains request details and submission timestamp | Confirmation message displays all submitted information including date, time, reason, and unique request identifier |

**Postconditions:**
- Schedule change request is saved in the ScheduleChangeRequests table with status 'Pending'
- Request is timestamped with current date and time
- Attached document is stored securely and linked to the request
- Employee can view the submitted request in their request history
- Request is available for approver review

---

### Test Case: Reject submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid login credentials
- Scheduling portal is accessible and operational
- Employee is authenticated and on the schedule change request form

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request form after successful login | Schedule change request form is displayed with all mandatory fields marked with asterisks or 'required' indicators |
| 2 | Leave the 'Date' field empty | Date field remains empty without any value |
| 3 | Leave the 'Reason' field empty | Reason field remains empty without any text |
| 4 | Click the 'Submit' button without filling mandatory fields | System prevents form submission and displays inline error messages next to each empty mandatory field indicating 'This field is required' or similar validation message |
| 5 | Verify that no data is saved to the database | No new record is created in the ScheduleChangeRequests table and submission is blocked |
| 6 | Fill in the 'Date' field with a valid current or future date | Date field accepts the input and error message for date field is cleared |
| 7 | Fill in the 'Reason' field with a valid explanation | Reason field accepts the text and error message for reason field is cleared |
| 8 | Fill in the 'Time' field with a valid time | Time field accepts the input and all validation errors are cleared |
| 9 | Click the 'Submit' button with all mandatory fields completed | System successfully validates the form, saves the request, and displays confirmation message with request details |

**Postconditions:**
- Schedule change request is saved in the database only after all mandatory fields are filled
- Employee receives confirmation of successful submission
- Request is timestamped and available for approval processing

---

### Test Case: Handle attachment size limit enforcement
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee has valid login credentials and is authenticated
- Schedule change request form is accessible
- Test files are prepared: one file larger than 10MB and one file within the 10MB limit
- Employee is on the schedule change request form page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request form and fill in all mandatory fields with valid data | All mandatory fields are populated with valid information and form is ready for attachment |
| 2 | Click on the 'Attach Document' or 'Browse' button | File selection dialog opens allowing user to browse and select files |
| 3 | Select a file larger than 10MB from the file system | System detects the file size exceeds the 10MB limit and displays an error message stating 'File size exceeds maximum allowed size of 10MB' or similar, preventing the upload |
| 4 | Verify that the oversized file is not attached to the form | No file name appears in the attachment section and the attachment field remains empty |
| 5 | Click on the 'Attach Document' button again | File selection dialog opens again for new file selection |
| 6 | Select a valid file that is within the 10MB size limit (e.g., 5MB file) | File is successfully uploaded and the file name is displayed in the attachment section without any error messages |
| 7 | Verify the attachment indicator shows the uploaded file name and size | Attachment section displays the file name, size, and possibly a remove/delete option |
| 8 | Click the 'Submit' button to submit the request with the valid attachment | System validates all inputs including the attachment, saves the request to ScheduleChangeRequests table, stores the attachment securely with proper linkage, and displays confirmation message |
| 9 | Verify the confirmation message includes details about the attached document | Confirmation message shows request was submitted successfully with attachment information included |

**Postconditions:**
- Schedule change request is saved with status 'Pending'
- Valid attachment (under 10MB) is stored securely and linked to the request record
- Oversized file was rejected and not stored in the system
- Request is available for approver review with the attached document accessible

---

## Story: As Employee, I want to edit my pending schedule change requests to achieve flexibility before approval
**Story ID:** story-17

### Test Case: Edit pending schedule change request successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has at least one pending schedule change request in the system
- Pending request has status 'Pending' and has not been approved or rejected
- Scheduling portal is accessible and operational
- Approver notification system is configured and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling portal using valid employee credentials | Employee is successfully authenticated and redirected to the scheduling portal dashboard |
| 2 | Navigate to the 'My Requests' section or menu option | 'My Requests' page is displayed showing a list of all schedule change requests submitted by the employee with their current statuses |
| 3 | Identify and click on a pending schedule change request from the list | Request details page opens displaying all current information including date, time, reason, attachments, and an 'Edit' button or option is visible |
| 4 | Click the 'Edit' button to enable editing mode | Form fields become editable and the employee can modify the request details |
| 5 | Update the 'Date' field with a new valid future date | Date field accepts the new date and displays it correctly |
| 6 | Update the 'Reason' field with modified or additional explanation | Reason field accepts the updated text without validation errors |
| 7 | Optionally update or add a new attachment within the 10MB size limit | New attachment is uploaded successfully and displayed, or existing attachment is replaced |
| 8 | Click the 'Submit' or 'Save Changes' button to save the updated request | System validates the updated data within 2 seconds, saves changes to ScheduleChangeRequests table, creates a version history entry, and displays confirmation message |
| 9 | Verify the confirmation message indicates successful update | Confirmation message displays stating 'Request updated successfully' or similar with updated timestamp |
| 10 | Verify that approvers receive notification of the updated request | Notification is sent to the assigned approver(s) indicating the request has been modified, and notification is logged in the system |
| 11 | Navigate back to 'My Requests' and verify the updated request shows the new information | Updated request displays the modified date, reason, and attachment with a new timestamp indicating when it was last updated |

**Postconditions:**
- Schedule change request is updated in the ScheduleChangeRequests table with new values
- Version history record is created capturing the previous state and the changes made
- Request status remains 'Pending'
- Approvers are notified of the update via configured notification channels
- Updated request is available for approver review with the latest information
- Audit trail shows who made the changes and when

---

### Test Case: Prevent editing of approved requests
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has at least one schedule change request with status 'Approved' in the system
- Scheduling portal is accessible and operational
- Employee is authenticated and logged into the portal

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the 'My Requests' section after successful login | 'My Requests' page displays all schedule change requests including those with 'Approved' status |
| 2 | Identify a schedule change request with status 'Approved' from the list | Approved request is visible in the list with status clearly marked as 'Approved' |
| 3 | Click on the approved schedule change request to view details | Request details page opens showing all information including date, time, reason, attachments, and approval details |
| 4 | Verify that the 'Edit' button is either disabled, hidden, or not present for the approved request | No 'Edit' option is available for the approved request, or if present, it is visually disabled (grayed out) |
| 5 | If an 'Edit' button is visible but disabled, attempt to click on it | System prevents the edit action and displays an appropriate message such as 'Approved requests cannot be edited' or 'This request has already been approved and cannot be modified' |
| 6 | Attempt to directly access the edit functionality via URL manipulation (if applicable) by modifying the URL to include edit parameters for the approved request | System denies access and redirects to an error page or displays a message stating 'You do not have permission to edit this request' or 'Only pending requests can be edited' |
| 7 | Verify that the request details remain unchanged and no edit form is displayed | Request details are displayed in read-only mode with no editable fields, and the approved status is maintained |

**Postconditions:**
- Approved schedule change request remains unchanged in the database
- Request status remains 'Approved'
- No version history entry is created for the approved request
- System security prevents unauthorized modification of approved requests
- Employee is informed that approved requests cannot be edited

---

## Story: As Employee, I want to receive notifications about my schedule change request status to achieve timely awareness
**Story ID:** story-19

### Test Case: Verify employee receives notification on status change
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system
- Employee has submitted a schedule change request
- Schedule change request is in 'Pending' status
- Approver has appropriate permissions to approve requests
- Notification service is operational
- Employee has default notification preferences enabled (email and in-app)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as an approver with appropriate permissions | Approver successfully logs in and can access the schedule change request approval dashboard |
| 2 | Navigate to the pending schedule change requests list | List of pending schedule change requests is displayed, including the employee's request |
| 3 | Select the employee's schedule change request from the list | Request details are displayed with option to approve, reject, or request more information |
| 4 | Change the schedule change request status to 'Approved' and submit the decision | Status is updated to 'Approved' in the system and confirmation message is displayed to approver |
| 5 | Verify notification is triggered and sent to the employee within 1 minute | System logs show notification was sent successfully to the employee via configured channels (email and in-app) |
| 6 | Log in as the employee who submitted the request | Employee successfully logs in to the system |
| 7 | Check in-app notifications by clicking on the notification icon | In-app notification is displayed showing the schedule change request has been approved with clear status details including request ID, date, and approval information |
| 8 | Check employee's email inbox for notification email | Email notification is received containing clear information about the approved status, request details, and any next steps required |
| 9 | Click on the notification link or navigate to schedule change requests section | Employee is directed to the schedule change request details page |
| 10 | View the schedule change request details in the system | Request status is displayed as 'Approved' with timestamp of approval and approver information visible |

**Postconditions:**
- Schedule change request status is 'Approved' in the system
- Employee has received and viewed notification via both email and in-app channels
- Notification delivery is logged in the system audit trail
- Employee is aware of the approved status and can proceed with schedule changes

---

### Test Case: Test employee notification preference settings
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the system
- Employee has an active account with notification preferences accessible
- Employee has at least one schedule change request in the system
- Notification service is operational
- Employee currently has both email and in-app notifications enabled by default

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as the employee | Employee successfully logs in and is directed to the dashboard |
| 2 | Navigate to user profile settings by clicking on profile icon or settings menu | Profile settings page is displayed with various configuration options |
| 3 | Locate and click on 'Notification Preferences' or 'Notifications' section | Notification preferences page is displayed showing available notification channels and options |
| 4 | Review current notification settings for schedule change requests | Current settings show both 'Email Notifications' and 'In-App Notifications' are enabled (checked) |
| 5 | Uncheck or toggle off the 'Email Notifications' option for schedule change request updates | Email notification checkbox is unchecked while in-app notification remains checked |
| 6 | Click 'Save' or 'Update Preferences' button to save the changes | Success message is displayed confirming 'Notification preferences saved successfully' and settings are persisted in the database |
| 7 | Refresh the notification preferences page to verify persistence | Email notifications remain disabled and in-app notifications remain enabled, confirming preferences were saved correctly |
| 8 | Log out and log back in as an approver | Approver successfully logs in with appropriate permissions |
| 9 | Navigate to the employee's schedule change request and change its status (e.g., from 'Pending' to 'Approved' or 'Rejected') | Status change is successfully processed and saved in the system |
| 10 | Wait for notification processing (up to 1 minute) and verify notification delivery logs | System logs show in-app notification was sent but email notification was not sent, respecting employee's preferences |
| 11 | Log back in as the employee | Employee successfully logs in to the system |
| 12 | Check in-app notifications by clicking on the notification icon | In-app notification is displayed showing the status change with clear details about the new status |
| 13 | Check employee's email inbox for any notification emails | No email notification is received for this status change, confirming email notifications are disabled as per preferences |
| 14 | Verify the notification contains only in-app delivery and no email was sent by checking notification delivery logs | Audit logs confirm only in-app notification was delivered, email notification was skipped based on user preferences |

**Postconditions:**
- Employee notification preferences are updated with email notifications disabled
- Employee receives only in-app notifications for schedule change request status updates
- No email notifications are sent to the employee for schedule change requests
- Notification preference changes are logged in the system
- Employee can still access all status updates through in-app notifications

---

