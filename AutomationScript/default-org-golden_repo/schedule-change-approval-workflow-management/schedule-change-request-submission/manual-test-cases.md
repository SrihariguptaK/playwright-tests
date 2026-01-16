# Manual Test Cases

## Story: As Scheduler, I want to submit schedule change requests to initiate approval workflows
**Story ID:** story-1

### Test Case: Validate successful schedule change request submission
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user account exists and is active
- Scheduler has valid authentication credentials
- Schedule change request form is accessible in the system
- Test document file (under 10MB) is prepared for attachment
- Database connection is active and ScheduleChangeRequests table is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using valid scheduler credentials | Scheduler is successfully authenticated and redirected to the home dashboard |
| 2 | Navigate to the schedule change request form from the main menu | Schedule change request form is displayed with all mandatory fields visible including: schedule ID, change date, reason, description, and attachment option |
| 3 | Enter valid data in the schedule ID field (e.g., 'SCH-2024-001') | Schedule ID field accepts the input without validation errors |
| 4 | Select a valid future date in the change date field | Date picker displays and accepts the selected date in correct format |
| 5 | Enter a valid reason for the schedule change (e.g., 'Operational requirement') | Reason field accepts the text input without errors |
| 6 | Enter detailed description of the schedule change in the description field | Description field accepts the text input without character limit errors |
| 7 | Click on the attachment button and select a valid document file (PDF, under 10MB) | File is successfully attached and file name is displayed in the attachment section |
| 8 | Review all entered data for accuracy | All fields display the entered data correctly with no validation errors shown |
| 9 | Click the Submit button | System processes the submission within 2 seconds, request is saved to ScheduleChangeRequests table, approval workflow is automatically triggered |
| 10 | Observe the confirmation message displayed on screen | Confirmation message is displayed with unique request ID (e.g., 'Request SCR-2024-12345 submitted successfully') and timestamp |

**Postconditions:**
- Schedule change request is saved in the database with status 'Pending'
- Approval workflow is initiated and assigned to appropriate approver
- Request ID is generated and associated with the submission
- Attached document is stored and linked to the request
- Scheduler can view the submitted request in their dashboard

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Scheduler user account exists and is active
- Scheduler is logged into the system
- Schedule change request form is accessible
- Form validation rules are configured for all mandatory fields

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request form | Schedule change request form is displayed with all mandatory fields marked with asterisks or 'required' indicators |
| 2 | Leave the schedule ID field empty | Field remains empty without any data entered |
| 3 | Leave the change date field empty | Field remains empty without any date selected |
| 4 | Leave the reason field empty | Field remains empty without any text entered |
| 5 | Click or tab away from the empty mandatory fields to trigger real-time validation | Red border or highlight appears around empty mandatory fields with inline error messages such as 'This field is required' |
| 6 | Scroll through the form to verify all validation messages are displayed | All empty mandatory fields show clear validation error messages |
| 7 | Click the Submit button without filling any mandatory fields | Form submission is blocked and prevented from processing |
| 8 | Observe error messages displayed at the top of the form or near the Submit button | Summary error message is displayed (e.g., 'Please complete all required fields before submitting') and focus moves to the first empty mandatory field |
| 9 | Verify that no request ID is generated | No confirmation message appears and no request is created in the system |

**Postconditions:**
- No schedule change request is saved in the database
- No approval workflow is initiated
- Form remains on screen with validation errors displayed
- User can correct errors and resubmit

---

### Test Case: Test attachment size validation
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Scheduler user account exists and is active
- Scheduler is logged into the system
- Schedule change request form is accessible
- Test file larger than 10MB is prepared (e.g., 12MB PDF)
- Test file within size limit is prepared (e.g., 5MB PDF)
- Attachment size validation is configured to 10MB limit

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request form | Schedule change request form is displayed with attachment section visible |
| 2 | Fill in all mandatory fields with valid data (schedule ID, change date, reason, description) | All mandatory fields accept the data without validation errors |
| 3 | Click on the attachment button or drag-and-drop area | File selection dialog opens or drag-and-drop area is active |
| 4 | Select and attempt to attach a file larger than 10MB (e.g., 12MB PDF file) | System immediately validates the file size and displays error message: 'File size exceeds maximum limit of 10MB. Please select a smaller file.' |
| 5 | Verify that the large file is not attached to the form | Attachment section remains empty or shows previous attachment, large file is rejected and not displayed in attachment list |
| 6 | Click on the attachment button again to select a different file | File selection dialog opens again for new file selection |
| 7 | Select and attach a valid file within the size limit (e.g., 5MB PDF file) | File is successfully attached, file name and size are displayed in the attachment section without any error messages |
| 8 | Verify the attachment icon or file name is visible in the form | Attached file is clearly indicated with file name, size, and option to remove if needed |
| 9 | Click the Submit button | Form is successfully submitted within 2 seconds, system processes the request with the valid attachment |
| 10 | Observe the confirmation message | Confirmation message is displayed with request ID indicating successful submission with attachment |

**Postconditions:**
- Schedule change request is saved with the valid attachment (5MB file)
- Large file (12MB) is not stored in the system
- Approval workflow is initiated with the attached document
- Request can be viewed in dashboard with attachment accessible

---

## Story: As Scheduler, I want to track the status of my schedule change requests to stay informed
**Story ID:** story-5

### Test Case: Validate scheduler dashboard displays correct requests and statuses
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler user account exists and is active
- Scheduler has previously submitted multiple schedule change requests with various statuses (pending, approved, rejected, changes requested)
- Database contains at least 5 schedule change requests associated with the scheduler
- Dashboard is configured to display all request statuses
- Search and filter functionality is enabled on the dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using valid scheduler credentials | Scheduler is successfully authenticated and redirected to the home dashboard |
| 2 | Navigate to the schedule change request dashboard from the main menu | Dashboard page loads within 3 seconds displaying a list view of all schedule change requests submitted by the logged-in scheduler |
| 3 | Verify the dashboard displays request columns including: Request ID, Submission Date, Schedule ID, Status, and Last Updated | All column headers are visible and properly labeled with sortable indicators |
| 4 | Review the status indicators for each request in the list | Each request displays accurate status with color-coded indicators: Pending (yellow/orange), Approved (green), Rejected (red), Changes Requested (blue) |
| 5 | Verify the request count matches the expected number of submitted requests | Dashboard shows the correct total count of requests (e.g., 'Showing 5 of 5 requests') |
| 6 | Click on a specific request row to view detailed information | Detailed view panel or page opens displaying complete request information including: request ID, submission date, schedule details, current status, and approval history section |
| 7 | Scroll down to the approval history section in the detailed view | Approval history is displayed chronologically showing: approver names, action taken (approved/rejected/requested changes), timestamp, and comments for each approval action |
| 8 | Read the comments provided by approvers in the history | All approver comments are visible and readable with proper formatting and timestamps |
| 9 | Return to the dashboard main view by clicking Back or Close button | Dashboard list view is displayed again with all requests visible |
| 10 | Locate the filter section on the dashboard (typically at the top or side panel) | Filter options are visible including: Status filter dropdown, Date range picker, and Search box |
| 11 | Select 'Approved' from the Status filter dropdown | Dashboard refreshes and displays only requests with 'Approved' status, count updates to show filtered results |
| 12 | Clear the status filter and enter a specific Request ID in the search box | Dashboard filters in real-time and displays only the matching request with the entered Request ID |
| 13 | Clear the search box and apply a date range filter for the last 30 days | Dashboard displays only requests submitted within the selected date range with accurate count |
| 14 | Clear all filters to return to the full list view | All scheduler's requests are displayed again without any filters applied |

**Postconditions:**
- Dashboard displays accurate and up-to-date information
- All filters can be cleared and reapplied
- Scheduler remains on the dashboard page
- No data is modified during the viewing process

---

### Test Case: Verify access restriction to own requests
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Two scheduler user accounts exist: Scheduler A and Scheduler B
- Scheduler A is logged into the system
- Scheduler B has submitted schedule change requests with known Request IDs
- Authorization rules are configured to restrict access to own requests only
- Direct URL access to request details is possible via pattern: /requests/{requestId}

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as Scheduler A using valid credentials | Scheduler A is successfully authenticated and can access their dashboard |
| 2 | Navigate to Scheduler A's dashboard and note their own Request IDs | Dashboard displays only Scheduler A's requests with their specific Request IDs |
| 3 | Obtain a Request ID that belongs to Scheduler B (e.g., SCR-2024-99999) | Request ID from Scheduler B is identified for testing purposes |
| 4 | Manually modify the browser URL to access Scheduler B's request by entering: /requests/SCR-2024-99999 | System detects unauthorized access attempt |
| 5 | Press Enter to navigate to the manipulated URL | Access is denied and system displays error page with message: 'Access Denied: You do not have permission to view this request' or 'Error 403: Forbidden' |
| 6 | Verify that no request details from Scheduler B are displayed | No sensitive information about Scheduler B's request is visible on the error page |
| 7 | Attempt to access Scheduler B's request via API endpoint by opening browser developer tools and sending GET request to: /api/schedule-change-requests/SCR-2024-99999 | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 8 | Verify the response body does not contain any request data | API response contains only error message without exposing any request details |
| 9 | Navigate back to Scheduler A's dashboard using the navigation menu | Dashboard loads successfully showing only Scheduler A's own requests |
| 10 | Verify that Scheduler A can still access their own requests by clicking on one | Scheduler A's request details open successfully without any access restrictions |

**Postconditions:**
- Scheduler A cannot access Scheduler B's requests
- Authorization rules are enforced at both UI and API levels
- Security audit log records the unauthorized access attempt
- Scheduler A retains access to their own requests

---

### Test Case: Test dashboard performance under load
- **ID:** tc-006
- **Type:** boundary
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- Scheduler user account exists and is active
- Database contains 100 or more schedule change requests associated with the scheduler
- Test data includes requests with various statuses, attachments, and approval histories
- Network conditions are stable for accurate performance measurement
- Browser performance monitoring tools are available (e.g., browser DevTools)
- Performance requirement is set to 3 seconds maximum load time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab to monitor page load times | Developer tools are open and ready to capture network performance metrics |
| 2 | Clear browser cache and cookies to ensure accurate performance measurement | Cache and cookies are cleared, browser is ready for fresh page load |
| 3 | Log into the system using valid scheduler credentials | Scheduler is successfully authenticated |
| 4 | Start performance timer and navigate to the schedule change request dashboard | Dashboard begins loading and network requests are captured in developer tools |
| 5 | Monitor the page load progress and observe the loading indicators | Loading spinner or progress indicator is displayed while data is being fetched |
| 6 | Wait for the dashboard to fully load and display all 100+ requests | Dashboard completes loading and displays the complete list of requests with all data visible |
| 7 | Check the total page load time in the Network tab of developer tools | Total page load time is 3 seconds or less from navigation start to page fully loaded |
| 8 | Verify that all request data is displayed correctly including Request IDs, dates, statuses, and other columns | All 100+ requests are rendered with complete and accurate information in all columns |
| 9 | Scroll through the entire list of requests to verify smooth rendering | Scrolling is smooth without lag, all rows render properly as they come into view |
| 10 | Check for any JavaScript errors in the browser console | No JavaScript errors or warnings are displayed in the console |
| 11 | Apply a filter to the loaded data (e.g., filter by 'Pending' status) | Filter is applied quickly (under 1 second) and filtered results are displayed without reloading the entire page |
| 12 | Click on a request to open the detailed view | Detailed view opens within 2 seconds showing complete request information and approval history |
| 13 | Return to the dashboard and verify the list is still loaded | Dashboard displays the previously loaded data without requiring a full page reload |
| 14 | Document the actual load time and compare against the 3-second requirement | Performance metrics confirm dashboard loads within 3 seconds meeting the acceptance criteria |

**Postconditions:**
- Dashboard successfully handles 100+ requests within performance requirements
- All data is accurately displayed without errors
- System remains responsive for subsequent interactions
- Performance metrics are documented for future reference

---

## Story: As Scheduler, I want to edit submitted schedule change requests before approval to correct errors
**Story ID:** story-7

### Test Case: Validate successful editing of pending schedule change request
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Scheduler
- At least one schedule change request exists in 'Pending' status
- The logged-in scheduler is the owner of the pending request
- System has access to ScheduleChangeRequests table
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the list of submitted schedule change requests | List of schedule change requests is displayed showing all requests submitted by the scheduler |
| 2 | Identify and select a request with 'Pending' status from the list | Request details are displayed with an option to edit |
| 3 | Click on the 'Edit' button for the selected pending request | Edit form opens and is pre-filled with existing request data including all fields such as date, time, reason, and other relevant details |
| 4 | Update one or more fields with valid data (e.g., change schedule date, update reason text) | Fields accept the new input without displaying any validation errors, updated data is visible in the form fields |
| 5 | Review all updated fields to ensure accuracy | All changes are correctly reflected in the form |
| 6 | Click the 'Submit' or 'Save Changes' button to submit the edited request | System processes the update within 2 seconds, success message is displayed confirming the changes have been saved |
| 7 | Verify the request status remains 'Pending' and workflow continues | Request status is still 'Pending', updated details are reflected in the request list, workflow continues with the updated information |
| 8 | Check version history for the edited request | Version history shows the edit with timestamp, user who made the edit, and changes made |

**Postconditions:**
- Schedule change request is updated with new data
- Request remains in 'Pending' status
- Version history contains a record of the edit
- Workflow continues with updated request details
- No duplicate requests are created

---

### Test Case: Verify editing is blocked for approved requests
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as a Scheduler
- At least one schedule change request exists in 'Approved' status
- The logged-in scheduler is the owner of the approved request
- System has access to ScheduleChangeRequests table

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the list of submitted schedule change requests | List of schedule change requests is displayed including requests with various statuses |
| 2 | Identify and select a request with 'Approved' status from the list | Request details are displayed showing 'Approved' status |
| 3 | Attempt to click on the 'Edit' button or option for the approved request | Edit button is either disabled/grayed out or not visible for approved requests |
| 4 | If edit button is clickable, attempt to access the edit form | System prevents editing and displays an appropriate error message such as 'Cannot edit approved requests' or 'Editing is only allowed for pending requests' |
| 5 | Verify that no edit form is displayed | Edit form does not open, request details remain in read-only view |
| 6 | Attempt to directly access the edit endpoint via URL manipulation (if applicable) | System blocks access and returns an error or redirects to the request list with an error message |

**Postconditions:**
- Approved request remains unchanged
- No edit form is accessible for approved requests
- Appropriate error message is displayed to the user
- System security prevents unauthorized edits

---

### Test Case: Test validation errors on edit form
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as a Scheduler
- At least one schedule change request exists in 'Pending' status
- The logged-in scheduler is the owner of the pending request
- System has validation rules configured for schedule change requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the list of submitted schedule change requests | List of schedule change requests is displayed |
| 2 | Select a request with 'Pending' status and click 'Edit' | Edit form opens pre-filled with existing request data |
| 3 | Clear a required field (e.g., schedule date or reason) and leave it empty | Field is cleared and ready for validation check |
| 4 | Attempt to submit the form with the empty required field | Validation error is displayed indicating the field is required (e.g., 'Schedule date is required'), form submission is prevented |
| 5 | Enter invalid data format in a date field (e.g., text instead of date format) | Validation error is displayed indicating invalid date format (e.g., 'Please enter a valid date'), form submission is prevented |
| 6 | Enter a past date if only future dates are allowed | Validation error is displayed indicating date must be in the future (e.g., 'Schedule date must be a future date'), form submission is prevented |
| 7 | Enter data exceeding maximum character limit in a text field (e.g., reason field) | Validation error is displayed indicating character limit exceeded (e.g., 'Reason cannot exceed 500 characters'), form submission is prevented |
| 8 | Verify that multiple validation errors are displayed simultaneously if multiple fields have invalid data | All validation errors are displayed at once, clearly indicating which fields need correction |
| 9 | Correct all validation errors by entering valid data in all fields | Validation errors disappear as valid data is entered |
| 10 | Submit the form with all valid data | Form is successfully submitted, updates are saved, and success message is displayed |

**Postconditions:**
- Invalid data is not saved to the database
- Validation errors are clearly communicated to the user
- Form submission is prevented until all validation errors are resolved
- Once corrected, the request is successfully updated with valid data

---

