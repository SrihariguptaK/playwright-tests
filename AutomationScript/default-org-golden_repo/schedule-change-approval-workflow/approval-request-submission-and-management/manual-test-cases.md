# Manual Test Cases

## Story: As Scheduler, I want to submit schedule change requests to achieve formal approval before implementation
**Story ID:** story-11

### Test Case: Validate successful schedule change request submission
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Scheduler user account exists and is active
- Scheduler has valid login credentials
- Schedule change request page is accessible
- At least one valid document file is available for attachment (PDF, DOC, or DOCX format, under size limit)
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open web browser and navigate to the system login page | Login page is displayed with username and password fields |
| 2 | Enter valid scheduler credentials and click Login button | Scheduler is authenticated and redirected to the dashboard |
| 3 | Navigate to the schedule change request page from the main menu | Submission form is displayed with all mandatory fields including: Change Type, Effective Date, Reason for Change, Description, and Attachment option |
| 4 | Fill in the 'Change Type' field by selecting an option from the dropdown | Selected change type is displayed in the field without errors |
| 5 | Enter a future date in the 'Effective Date' field using the date picker | Date is accepted and displayed in the correct format |
| 6 | Enter a valid reason in the 'Reason for Change' text field (minimum 10 characters) | Text is accepted and character count updates if displayed |
| 7 | Enter detailed description in the 'Description' text area (minimum 20 characters) | Description text is accepted without validation errors |
| 8 | Click on 'Attach Document' button and select a valid document file (PDF format, under 5MB) | File upload dialog opens, file is selected, and attachment preview is displayed with file name and size |
| 9 | Review all entered information for accuracy | All fields display the entered information correctly with no validation errors |
| 10 | Click the 'Submit Request' button | System processes the submission and displays a confirmation message with a unique request ID (format: SCR-YYYYMMDD-XXXX) |
| 11 | Note the unique request ID from the confirmation message | Request ID is clearly visible and can be copied for future reference |
| 12 | Navigate to 'My Requests' dashboard | Newly submitted request appears in the list with status 'Pending' and correct timestamp |

**Postconditions:**
- Schedule change request is created in the database with status 'Pending'
- Unique request ID is generated and associated with the request
- Attached document is stored in the system and linked to the request
- Request appears in scheduler's dashboard
- Approval workflow is initiated
- Scheduler remains logged in

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Scheduler user account exists and is active
- Scheduler is logged into the system
- Schedule change request submission form is accessible
- Browser supports JavaScript for real-time validation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request submission form from the dashboard | Form is displayed with all mandatory fields marked with asterisks (*) or 'Required' labels |
| 2 | Leave the 'Change Type' field empty and click on the next field | Real-time validation highlights the 'Change Type' field with red border and displays inline error message 'This field is required' |
| 3 | Leave the 'Effective Date' field empty and click on the next field | Real-time validation highlights the 'Effective Date' field with red border and displays inline error message 'Effective Date is required' |
| 4 | Leave the 'Reason for Change' field empty and click on the next field | Real-time validation highlights the 'Reason for Change' field with red border and displays inline error message 'Reason is required' |
| 5 | Leave the 'Description' field empty | Field remains empty without any entered text |
| 6 | Scroll down and click the 'Submit Request' button without filling any mandatory fields | Submission is blocked and form does not proceed to confirmation page |
| 7 | Observe the error messages displayed on the form | All mandatory fields are highlighted with red borders and inline error messages are displayed: 'Change Type is required', 'Effective Date is required', 'Reason for Change is required', 'Description is required' |
| 8 | Verify that a summary error message appears at the top of the form | Error summary banner is displayed stating 'Please complete all required fields before submitting' with count of errors |
| 9 | Fill in only the 'Change Type' field and attempt to submit again | Submission is still blocked, 'Change Type' field error is cleared, but other mandatory field errors remain visible |
| 10 | Verify that the page focus moves to the first field with an error | Browser automatically scrolls to and focuses on the first empty mandatory field |

**Postconditions:**
- No schedule change request is created in the database
- No request ID is generated
- Form remains on the submission page with entered data preserved
- Validation errors are clearly visible to the user
- Scheduler remains logged in

---

### Test Case: Test attachment upload and validation
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Scheduler user account exists and is active
- Scheduler is logged into the system
- Schedule change request submission form is accessible
- Test document files are available in supported formats (PDF, DOC, DOCX)
- Test document is under the maximum file size limit (5MB)
- Browser supports file upload functionality

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request submission form | Form is displayed with 'Attach Document' button or file upload field visible |
| 2 | Fill in all mandatory fields (Change Type, Effective Date, Reason for Change, Description) with valid data | All mandatory fields accept the input without validation errors |
| 3 | Click on the 'Attach Document' button or file upload field | File browser dialog opens allowing file selection from local system |
| 4 | Select a supported document file (e.g., 'schedule_change_justification.pdf', 2MB size) | File browser closes and selected file is loaded into the form |
| 5 | Observe the attachment preview area | Attachment preview is displayed showing file name 'schedule_change_justification.pdf', file size '2MB', file type icon (PDF icon), and a remove/delete option |
| 6 | Verify that the file upload progress indicator shows completion | Progress bar shows 100% or success checkmark appears next to the file name |
| 7 | Review the complete form with all fields filled and attachment added | All mandatory fields contain valid data and attachment is displayed in the preview area |
| 8 | Click the 'Submit Request' button | System processes the submission successfully and displays confirmation message with unique request ID |
| 9 | Note the request ID and navigate to 'My Requests' dashboard | Dashboard displays the list of submitted requests including the newly created one |
| 10 | Locate the newly submitted request in the list and click on it to view details | Request details page opens showing all submitted information including Change Type, Effective Date, Reason, Description, Status, and Attachments section |
| 11 | Scroll to the Attachments section in the request details | Attachments section displays the uploaded file 'schedule_change_justification.pdf' with file size and upload timestamp |
| 12 | Click on the attachment file name or download icon | File download is initiated and the document 'schedule_change_justification.pdf' is downloaded to the local system |
| 13 | Open the downloaded file using appropriate application (PDF reader) | File opens successfully without corruption, displaying the original content correctly |

**Postconditions:**
- Schedule change request is created with status 'Pending'
- Attachment is stored in the system database or file storage
- Attachment is linked to the request record
- Attachment is accessible and downloadable from request details page
- File integrity is maintained (no corruption)
- Request appears in scheduler's dashboard with attachment indicator
- Scheduler remains logged in

---

## Story: As Scheduler, I want to track the status of my schedule change requests to stay informed about approval progress
**Story ID:** story-14

### Test Case: Validate display of scheduler's submitted requests with status
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user account exists and is active
- Scheduler has valid login credentials
- At least 3 schedule change requests have been previously submitted by the scheduler with different statuses (Pending, Approved, Rejected)
- At least one request has approval history with comments
- Notification system is enabled and configured
- Email notification settings are configured (if applicable)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open web browser and navigate to the system login page | Login page is displayed with username and password fields |
| 2 | Enter valid scheduler credentials and click Login button | Scheduler is authenticated and redirected to the main dashboard |
| 3 | Locate and click on 'My Requests' menu item or dashboard widget | 'My Requests' dashboard page loads and displays a list view of all submitted schedule change requests |
| 4 | Observe the list of submitted requests displayed on the dashboard | List displays all requests submitted by the logged-in scheduler with columns: Request ID, Change Type, Submission Date, Effective Date, Current Status, and Actions |
| 5 | Verify that each request shows a status indicator with appropriate visual styling | Status indicators are displayed with color coding: 'Pending' (yellow/orange), 'Approved' (green), 'Rejected' (red), 'More Info Required' (blue) |
| 6 | Check the timestamps displayed for each request | Each request shows submission date and time in consistent format (e.g., 'MM/DD/YYYY HH:MM AM/PM') |
| 7 | Verify that requests are sorted by submission date with most recent first | Requests are listed in descending order by submission date |
| 8 | Select a request with status 'Approved' by clicking on the request row or 'View Details' button | Request details page opens displaying comprehensive information including Request ID, Change Type, Effective Date, Reason, Description, Current Status, and Approval History section |
| 9 | Scroll to the Approval History section in the request details | Approval History section displays a timeline of all approval actions including: Date/Time, Approver Name, Action Taken (Submitted, Reviewed, Approved), and Comments |
| 10 | Review the comments provided by approvers in the approval history | Comments are displayed clearly with approver name, timestamp, and full comment text visible |
| 11 | Navigate back to 'My Requests' dashboard | Dashboard reloads showing the complete list of requests |
| 12 | Have an administrator or approver change the status of one of the scheduler's pending requests to 'Approved' in the backend | Status change is processed in the system |
| 13 | Observe the 'My Requests' dashboard without refreshing the page | Within 5 seconds, the status indicator for the updated request automatically changes from 'Pending' to 'Approved' with updated color coding (real-time update) |
| 14 | Check for in-app notification indicator (bell icon or notification badge) | Notification indicator shows a new notification count (e.g., red badge with number '1') |
| 15 | Click on the notification indicator to view notifications | Notification panel opens displaying the status change notification: 'Your schedule change request [Request ID] has been Approved' with timestamp |
| 16 | Check the email inbox associated with the scheduler account (if email notifications are enabled) | Email notification is received with subject line 'Schedule Change Request [Request ID] - Status Update' containing request details and new status |
| 17 | Click on the notification to navigate to the request details | System navigates directly to the detailed view of the updated request showing the new 'Approved' status and updated approval history |

**Postconditions:**
- All submitted requests are visible on the dashboard
- Status indicators accurately reflect current request states
- Approval history and comments are accessible
- Real-time status updates are functioning
- Notifications are delivered successfully
- Scheduler remains logged in
- No unauthorized access to other users' requests

---

### Test Case: Verify access restriction to own requests only
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Two scheduler user accounts exist: Scheduler A and Scheduler B
- Scheduler A is logged into the system
- Scheduler B has submitted at least one schedule change request
- Scheduler B's request ID is known (e.g., SCR-20240115-0042)
- Direct URL access to request details is possible via format: /requests/{requestId}
- Role-based access control is implemented and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as Scheduler A using valid credentials | Scheduler A is authenticated and redirected to the dashboard |
| 2 | Navigate to 'My Requests' dashboard | Dashboard displays only the requests submitted by Scheduler A |
| 3 | Verify that Scheduler B's requests are not visible in the list | Only Scheduler A's requests are displayed; no requests from other schedulers are shown |
| 4 | Note the URL format of one of Scheduler A's request detail pages (e.g., /requests/SCR-20240115-0035) | URL format is identified and accessible for Scheduler A's own request |
| 5 | Manually modify the URL in the browser address bar to access Scheduler B's request by entering the known request ID (e.g., change URL to /requests/SCR-20240115-0042) | URL is entered in the address bar |
| 6 | Press Enter to navigate to the modified URL | System processes the request and performs authorization check |
| 7 | Observe the response from the system | Access is denied and an error page is displayed with HTTP 403 Forbidden status or similar authorization error |
| 8 | Verify the error message displayed on the page | Appropriate error message is shown: 'Access Denied - You do not have permission to view this request' or 'Error 403: Unauthorized access to this resource' |
| 9 | Check that no sensitive information from Scheduler B's request is visible on the error page | Error page does not display any details of the unauthorized request (no data leakage) |
| 10 | Verify that the browser URL remains at the attempted unauthorized URL | URL shows the attempted request ID but content is blocked |
| 11 | Click on 'Back to My Requests' link or navigate back using browser back button | System redirects to Scheduler A's 'My Requests' dashboard showing only authorized requests |
| 12 | Check system logs or audit trail (if accessible) for the unauthorized access attempt | Security event is logged with details: User ID (Scheduler A), Attempted Resource (Scheduler B's request ID), Timestamp, and Action (Access Denied) |

**Postconditions:**
- Scheduler A remains logged in
- No unauthorized access to Scheduler B's request data occurred
- Security event is logged in the audit trail
- Scheduler A is returned to authorized area of the application
- System security controls are validated as functioning correctly
- No data breach or information leakage occurred

---

## Story: As Scheduler, I want to edit or withdraw pending schedule change requests to correct errors or cancel changes
**Story ID:** story-17

### Test Case: Validate editing of pending schedule change request
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one schedule change request exists with 'Pending' status
- Scheduler is the owner of the pending request
- Request has not been approved yet
- System has PUT /api/schedule-change-requests/{id} endpoint available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change requests dashboard | Dashboard displays list of all schedule change requests with their current statuses |
| 2 | Filter or locate a request with 'Pending' status | Pending requests are visible and identifiable in the list |
| 3 | Click on the pending request to view details | Request details page opens showing all current information including date, time, reason, and attachments with edit options enabled |
| 4 | Click the 'Edit' button or icon | Request fields become editable and modification interface is displayed |
| 5 | Modify request details such as schedule date, time, or reason text | Changes are accepted in the input fields without validation errors |
| 6 | Remove an existing attachment from the request | Attachment is removed from the request and interface updates to reflect removal |
| 7 | Add a new attachment to the request | New attachment is uploaded successfully and appears in the attachments list |
| 8 | Click 'Submit' or 'Save Changes' button | System processes the update request and displays a confirmation message indicating successful update |
| 9 | Verify the confirmation message content | Confirmation message states 'Request updated successfully' and indicates that approvers have been notified |
| 10 | Check the request details page after update | Updated information is displayed correctly with all modifications saved |
| 11 | Verify notification was sent to assigned approvers | Approvers receive notification about the request modification with details of changes made |

**Postconditions:**
- Schedule change request is updated with new details
- Request status remains 'Pending'
- All changes are logged in the audit trail
- Approvers are notified of the modifications
- Modified timestamp is updated on the request

---

### Test Case: Verify withdrawal of pending request with reason
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one schedule change request exists with 'Pending' status
- Scheduler is the owner of the pending request
- Request has not been approved or withdrawn yet
- Approvers are assigned to the request

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change requests dashboard | Dashboard displays list of schedule change requests |
| 2 | Locate and select a pending request to withdraw | Request details are displayed with available actions |
| 3 | Click the 'Withdraw' button or option | Withdrawal confirmation dialog appears on screen |
| 4 | Verify the withdrawal dialog content | Dialog displays request summary, warning message about withdrawal action, and a required reason field |
| 5 | Attempt to confirm withdrawal without providing a reason | System displays validation error indicating that withdrawal reason is required |
| 6 | Enter a valid withdrawal reason in the text field (e.g., 'Schedule conflict resolved, request no longer needed') | Reason text is accepted and validation error clears |
| 7 | Click 'Confirm Withdrawal' button | System processes the withdrawal and displays success confirmation message |
| 8 | Verify the confirmation message | Message confirms 'Request withdrawn successfully' and indicates approvers have been notified |
| 9 | Check the request status in the dashboard | Request status is updated to 'Withdrawn' and is no longer in pending list |
| 10 | Open the withdrawn request details | Request shows 'Withdrawn' status, displays the withdrawal reason, and shows timestamp of withdrawal |
| 11 | Verify approvers received withdrawal notification | Assigned approvers receive notification about request withdrawal including the reason provided |

**Postconditions:**
- Request status is changed to 'Withdrawn'
- Withdrawal reason is stored with the request
- Approvers are notified of the withdrawal
- Withdrawal action is logged in audit trail
- Request is no longer actionable by approvers

---

### Test Case: Test prevention of edits after approval
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one schedule change request exists with 'Approved' status
- Scheduler is the owner of the approved request
- Request was previously in pending status and has been approved by an approver

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change requests dashboard | Dashboard displays list of all schedule change requests including approved ones |
| 2 | Filter or locate a request with 'Approved' status | Approved request is visible in the list with 'Approved' status indicator |
| 3 | Click on the approved request to view details | Request details page opens showing all information in read-only mode |
| 4 | Verify the availability of edit controls | Edit button is either disabled, hidden, or not present on the approved request |
| 5 | Attempt to click the edit button if visible but disabled | No action occurs or tooltip displays message indicating editing is not allowed for approved requests |
| 6 | Attempt to directly access the edit endpoint via URL manipulation (e.g., /edit?id=approved-request-id) | System redirects to request details page or displays error message |
| 7 | Verify the error message content | Error message clearly states 'Cannot edit approved requests' or 'Editing is not allowed for requests that have been approved' |
| 8 | Attempt to withdraw the approved request | Withdraw option is either disabled, hidden, or displays error message preventing withdrawal |
| 9 | Verify withdrawal prevention message if applicable | System displays message 'Cannot withdraw approved requests' or similar appropriate error |
| 10 | Attempt to modify request via API call using PUT /api/schedule-change-requests/{approved-id} | API returns error response with status code 403 or 400 and error message indicating operation not permitted on approved requests |

**Postconditions:**
- Approved request remains unchanged
- Request status remains 'Approved'
- No modifications are saved to the database
- Attempt to edit is logged in audit trail as unauthorized action
- User receives clear feedback about why edit was prevented

---

