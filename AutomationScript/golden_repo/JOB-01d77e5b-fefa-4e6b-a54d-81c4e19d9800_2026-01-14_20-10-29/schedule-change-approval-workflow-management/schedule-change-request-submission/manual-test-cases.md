# Manual Test Cases

## Story: As Employee, I want to submit schedule change requests to achieve timely and accurate schedule updates
**Story ID:** story-1

### Test Case: Validate successful schedule change request submission with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is authenticated via OAuth2
- Schedule change request submission page is accessible
- Supporting document is prepared (PDF/DOC format, under size limit)
- ScheduleChangeRequests table is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request submission page | Submission form is displayed with all mandatory fields including employee ID, current schedule, requested schedule, reason, effective date, and file upload option |
| 2 | Enter valid employee ID in the employee ID field | Employee ID is accepted and no validation error is shown |
| 3 | Enter valid current schedule details (date and time) | Current schedule data is accepted in correct date format without validation errors |
| 4 | Enter valid requested schedule details (date and time) | Requested schedule data is accepted in correct date format without validation errors |
| 5 | Enter a valid reason for the schedule change request | Reason text is accepted without validation errors |
| 6 | Select a valid effective date for the schedule change | Effective date is accepted in correct format without validation errors |
| 7 | Upload a supporting document using the file upload option | Document is uploaded successfully, file name is displayed, and no size limit error occurs |
| 8 | Click the Submit button to submit the schedule change request | Request is saved to ScheduleChangeRequests table, confirmation message is displayed with request ID, timestamp is logged, and submission completes within 2 seconds |
| 9 | Verify the request appears in the submitted requests list | Newly submitted request is visible in the list with status 'Pending' and correct timestamp |

**Postconditions:**
- Schedule change request is stored in ScheduleChangeRequests table
- Request has a unique ID and timestamp
- Request status is set to 'Pending'
- Supporting document is attached to the request
- Audit log contains submission entry
- Employee can view the submitted request in their request history

---

### Test Case: Verify validation errors on incomplete schedule change request submission
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is authenticated via OAuth2
- Schedule change request submission page is accessible
- ScheduleChangeRequests table is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request submission page | Submission form is displayed with all mandatory fields clearly marked |
| 2 | Leave the employee ID field empty | Field remains empty without pre-filled data |
| 3 | Leave the current schedule field empty | Field remains empty without pre-filled data |
| 4 | Leave the requested schedule field empty | Field remains empty without pre-filled data |
| 5 | Leave the reason field empty | Field remains empty without pre-filled data |
| 6 | Leave the effective date field empty | Field remains empty without pre-filled data |
| 7 | Click the Submit button to attempt submission with empty mandatory fields | Inline validation errors are displayed for each missing mandatory field with clear error messages such as 'Employee ID is required', 'Current schedule is required', 'Requested schedule is required', 'Reason is required', and 'Effective date is required' |
| 8 | Fill in the employee ID field with valid data | Validation error for employee ID is cleared and field shows valid state |
| 9 | Fill in the current schedule field with valid date and time | Validation error for current schedule is cleared and field shows valid state |
| 10 | Fill in the requested schedule field with valid date and time | Validation error for requested schedule is cleared and field shows valid state |
| 11 | Fill in the reason field with valid text | Validation error for reason is cleared and field shows valid state |
| 12 | Fill in the effective date field with valid date | Validation error for effective date is cleared and field shows valid state |
| 13 | Click the Submit button to resubmit with all corrected data | Submission succeeds, confirmation message is displayed with request ID, and request is saved to ScheduleChangeRequests table |

**Postconditions:**
- Schedule change request is stored in ScheduleChangeRequests table after correction
- Request has a unique ID and timestamp
- Request status is set to 'Pending'
- No incomplete requests are saved in the database
- Validation errors are cleared after successful submission

---

### Test Case: Ensure draft saving and editing functionality works correctly
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is authenticated via OAuth2
- Schedule change request submission page is accessible
- ScheduleChangeRequests table is accessible and operational
- Draft saving functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request submission page | Submission form is displayed with all fields and Save as Draft button is visible |
| 2 | Enter valid employee ID in the employee ID field | Employee ID is accepted without validation errors |
| 3 | Enter valid current schedule details (date and time) | Current schedule data is accepted without validation errors |
| 4 | Leave the requested schedule field empty | Field remains empty without triggering validation errors |
| 5 | Leave the reason field empty | Field remains empty without triggering validation errors |
| 6 | Leave the effective date field empty | Field remains empty without triggering validation errors |
| 7 | Click the Save as Draft button | Draft is saved to ScheduleChangeRequests table with status 'Draft', confirmation message is displayed with draft ID, and no validation errors are shown for incomplete fields |
| 8 | Navigate away from the schedule change request submission page | Page navigation occurs without data loss warning |
| 9 | Navigate to the list of draft schedule change requests | List of drafts is displayed showing the previously saved draft with correct employee ID and current schedule |
| 10 | Select the saved draft to edit | Draft loads correctly in the submission form with previously entered data (employee ID and current schedule) pre-filled |
| 11 | Enter valid requested schedule details in the previously empty field | Requested schedule data is accepted without validation errors |
| 12 | Enter valid reason in the previously empty field | Reason text is accepted without validation errors |
| 13 | Enter valid effective date in the previously empty field | Effective date is accepted without validation errors |
| 14 | Click the Submit button to submit the completed request | Request is saved with status changed from 'Draft' to 'Pending', confirmation message is displayed, and request appears in submitted requests list |

**Postconditions:**
- Draft is initially saved with status 'Draft' in ScheduleChangeRequests table
- Draft can be retrieved and edited multiple times before submission
- After final submission, request status changes to 'Pending'
- Completed request has all mandatory fields filled
- Request has a unique ID and timestamp for both draft creation and final submission
- Draft is no longer visible in drafts list after submission

---

## Story: As Employee, I want to edit or withdraw my schedule change requests before approval to maintain control over submissions
**Story ID:** story-6

### Test Case: Validate editing of pending schedule change requests
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is authenticated via OAuth2
- Employee has at least one pending schedule change request in the system
- Employee has at least one approved schedule change request in the system
- ScheduleChangeRequests table is accessible and operational
- Employee is the owner of the requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the list of submitted schedule change requests | List of all submitted requests is displayed showing requests with different statuses (Pending, Approved, etc.) with request ID, submission date, status, and action options |
| 2 | Filter or identify pending schedule change requests in the list | Pending requests are clearly visible with status 'Pending' and Edit option is available |
| 3 | Select a pending request and click the Edit button | Request details load in edit mode with all fields pre-filled with current data and fields are editable |
| 4 | Modify the requested schedule field with a new valid date and time | New requested schedule data is accepted without validation errors |
| 5 | Modify the reason field with updated text | Updated reason text is accepted without validation errors |
| 6 | Click the Save button to save the edited request | Changes are saved to ScheduleChangeRequests table via PUT /api/schedule-change-requests/{id}, confirmation message is displayed, request status remains 'Pending', and changes are reflected immediately |
| 7 | Verify the updated request in the submitted requests list | Request shows updated details with modified requested schedule and reason, and last modified timestamp is updated |
| 8 | Select an approved request from the list and attempt to click Edit | Edit option is either disabled/hidden or clicking it displays an error message such as 'Cannot edit approved requests' and no edit form is displayed |
| 9 | Attempt to access the edit endpoint directly for an approved request | System prevents edit action, returns appropriate error response, and displays error message indicating that only pending requests can be edited |

**Postconditions:**
- Pending request is successfully updated with new details in ScheduleChangeRequests table
- Request status remains 'Pending' after edit
- Last modified timestamp is updated
- Approved requests remain unchanged and cannot be edited
- Audit log contains entry for the edit action
- Only request owner can see and perform edit actions

---

### Test Case: Verify withdrawal of pending schedule change requests
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is authenticated via OAuth2
- Employee has at least one pending schedule change request in the system
- Employee has at least one approved schedule change request in the system
- ScheduleChangeRequests table is accessible and operational
- Employee is the owner of the requests
- Approvers are configured to receive notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the list of submitted schedule change requests | List of all submitted requests is displayed showing requests with different statuses and action options |
| 2 | Select a pending request from the list | Request is selected and Withdraw option is available and enabled |
| 3 | Click the Withdraw button for the selected pending request | System displays a confirmation dialog with message such as 'Are you sure you want to withdraw this request?' and options to Confirm or Cancel |
| 4 | Click the Confirm button in the confirmation dialog | Request status is updated to 'Withdrawn' in ScheduleChangeRequests table via DELETE /api/schedule-change-requests/{id}, confirmation message is displayed, and approvers are notified immediately of the withdrawal |
| 5 | Verify the withdrawn request in the submitted requests list | Request status shows 'Withdrawn', withdrawal timestamp is recorded, and Edit/Withdraw options are no longer available for this request |
| 6 | Verify that approvers received notification of the withdrawal | Notification is sent to all assigned approvers with request ID and withdrawal details |
| 7 | Select an approved request from the list and attempt to click Withdraw | Withdraw option is either disabled/hidden or clicking it displays an error message such as 'Cannot withdraw approved requests' |
| 8 | Attempt to access the withdraw endpoint directly for an approved request | System prevents withdrawal action, returns appropriate error response, and displays error message indicating that only pending requests can be withdrawn |

**Postconditions:**
- Pending request status is changed to 'Withdrawn' in ScheduleChangeRequests table
- Withdrawal timestamp is recorded
- Approvers receive notification of withdrawal
- Approved requests remain unchanged and cannot be withdrawn
- Withdrawn request cannot be edited or withdrawn again
- Audit log contains entry for the withdrawal action

---

### Test Case: Ensure only request owner can edit or withdraw requests
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Two employees (Employee A and Employee B) have valid login credentials
- Both employees are authenticated via OAuth2
- Employee A has at least one pending schedule change request in the system
- Employee B is logged into the system
- ScheduleChangeRequests table is accessible and operational
- Security controls are properly configured to enforce ownership validation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Employee B | Employee B is successfully authenticated and logged into the system |
| 2 | Attempt to navigate to Employee A's pending schedule change request using direct URL or request ID | System denies access and displays error message such as 'You do not have permission to access this request' or redirects to Employee B's own requests |
| 3 | Attempt to call PUT /api/schedule-change-requests/{id} endpoint directly for Employee A's request with modified data | API returns 403 Forbidden or 401 Unauthorized error, no changes are made to Employee A's request, and appropriate error message is returned |
| 4 | Attempt to call DELETE /api/schedule-change-requests/{id} endpoint directly for Employee A's request | API returns 403 Forbidden or 401 Unauthorized error, Employee A's request status remains unchanged, and appropriate error message is returned |
| 5 | Verify that Employee A's request remains unchanged in the database | Request details, status, and timestamps remain exactly as they were before Employee B's unauthorized attempts |
| 6 | Log out Employee B and log in as Employee A | Employee A is successfully authenticated and logged into the system |
| 7 | Navigate to Employee A's pending schedule change request and click Edit | Request loads in edit mode successfully, allowing Employee A to modify their own request |
| 8 | Navigate to Employee A's pending schedule change request and click Withdraw | Withdrawal confirmation dialog is displayed, allowing Employee A to withdraw their own request |

**Postconditions:**
- Employee B cannot edit or withdraw Employee A's requests
- Security controls successfully prevent unauthorized access
- Employee A's requests remain unchanged after unauthorized access attempts
- Employee A retains full control over their own requests
- Audit log may contain entries for unauthorized access attempts
- No data breach or unauthorized modifications occur

---

## Story: As Employee, I want to view the history and audit trail of my schedule change requests to ensure transparency
**Story ID:** story-9

### Test Case: Validate audit trail display for schedule change requests
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has at least one schedule change request with multiple status changes and comments
- Database contains complete audit log entries for the request
- Employee has appropriate permissions to view their own requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to the schedule change requests section from the main dashboard | List of all employee's schedule change requests is displayed with request IDs, dates, and current status |
| 2 | Employee selects a specific schedule change request from the list by clicking on it | Request details page opens showing the request information and an audit trail section |
| 3 | Employee views the audit trail section on the request details page | Complete chronological history is displayed showing all actions including submission timestamp, status changes (pending, approved, rejected), approver comments, any edits made, and the user who performed each action |
| 4 | Employee verifies the timestamps are in chronological order from oldest to newest | All audit entries are displayed in correct chronological sequence with accurate date and time stamps |
| 5 | Employee checks that all status changes are reflected in the audit trail | Each status transition (submitted, under review, approved/rejected) is logged with the user who made the change and timestamp |
| 6 | Employee reviews approver comments in the audit trail | All comments added by approvers are visible with the commenter's name and timestamp |
| 7 | Employee verifies the audit trail loaded within acceptable time | Audit trail data loads and displays within 3 seconds of opening the request details |

**Postconditions:**
- Employee remains on the request details page
- Audit trail remains accessible for future viewing
- No data is modified during the viewing process
- Session remains active

---

### Test Case: Verify export of audit trail
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has at least one schedule change request with audit trail data
- Browser allows file downloads
- Employee has access to view their own schedule change requests
- PDF export functionality is enabled in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to their schedule change requests list | List of employee's schedule change requests is displayed |
| 2 | Employee selects a specific request to view its details | Request details page opens with audit trail section visible |
| 3 | Employee views the audit trail section for the selected request | Complete audit trail is displayed with all historical actions, comments, and status changes |
| 4 | Employee locates and verifies the export option is available in the audit trail section | Export button or link is clearly visible and enabled, labeled as 'Export as PDF' or similar |
| 5 | Employee clicks on the 'Export as PDF' button | System processes the export request and initiates PDF file download |
| 6 | Employee waits for the PDF file to download to their device | PDF file downloads successfully with a meaningful filename (e.g., 'AuditTrail_RequestID_Date.pdf') |
| 7 | Employee opens the downloaded PDF file | PDF opens successfully and is properly formatted |
| 8 | Employee verifies the PDF contains complete audit information including request ID, all timestamps, status changes, approver comments, and user actions | PDF contains all audit trail data matching what was displayed on screen, properly formatted with headers, chronological order, and readable text |
| 9 | Employee checks that the PDF includes request metadata such as request ID, employee name, and export date | PDF header or footer contains request identification information and export timestamp |

**Postconditions:**
- PDF file is saved to employee's download folder
- Original audit trail data remains unchanged in the system
- Employee remains logged in and on the request details page
- Export action is logged in the system audit trail

---

### Test Case: Ensure access control for audit trail
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Two employee accounts exist in the system (Employee A and Employee B)
- Employee A has created at least one schedule change request
- Employee B is logged into the system
- Employee B does not own Employee A's schedule change request
- Access control security measures are properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee B logs into the system with their valid credentials | Employee B successfully logs in and sees their dashboard |
| 2 | Employee B attempts to access the audit trail of Employee A's schedule change request by directly navigating to the URL (e.g., /api/schedule-change-requests/{Employee_A_Request_ID}/audit) or through any available interface | System denies access and displays an error message such as 'Access Denied: You do not have permission to view this audit trail' or 'Error 403: Forbidden' |
| 3 | Employee B verifies they cannot see Employee A's request in their own request list | Employee A's schedule change requests do not appear in Employee B's request list |
| 4 | Employee B attempts to access the audit trail using different methods (direct URL manipulation, API calls if accessible) | All access attempts are blocked with appropriate error messages and no audit trail data is displayed |
| 5 | Employee B verifies they are redirected or remain on an error page without access to sensitive information | No audit trail information from Employee A's request is visible, and Employee B sees only an error message or is redirected to their own requests page |
| 6 | System administrator or Employee A checks system logs for unauthorized access attempts | Unauthorized access attempt by Employee B is logged in the security audit log with timestamp and user details |

**Postconditions:**
- Employee A's audit trail data remains secure and unaccessed by Employee B
- Security violation is logged in the system
- Employee B remains logged in but has not gained unauthorized access
- No data breach or unauthorized data exposure has occurred

---

