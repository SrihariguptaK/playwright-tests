# Manual Test Cases

## Story: As Employee, I want to submit schedule change requests to achieve timely and accurate schedule updates
**Story ID:** story-13

### Test Case: Validate successful schedule change request submission with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is registered in the system with valid credentials
- Employee is logged into the scheduling system
- Employee has active employment status
- Schedule change request page is accessible
- Test document file (under 5MB) is available for attachment

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request page from the main dashboard | Schedule change request form is displayed with all mandatory fields visible (date, time, reason) and optional attachment field |
| 2 | Enter valid future date in the date field (e.g., tomorrow's date in correct format) | Date field accepts the input without validation errors and displays the date in the correct format |
| 3 | Enter valid time in the time field (e.g., 09:00 AM) | Time field accepts the input without validation errors and displays the time in the correct format |
| 4 | Enter a valid reason for the schedule change in the reason field (e.g., 'Medical appointment') | Reason field accepts the text input without character limit errors |
| 5 | Click on the attachment button and select a valid document file (PDF, DOC, or image) under 5MB | File is successfully attached and file name is displayed in the attachment area without errors |
| 6 | Click the Submit button to submit the schedule change request | Request is saved to the ScheduleChangeRequests table, confirmation message is displayed with request ID, and page shows success status |

**Postconditions:**
- Schedule change request is stored in the database with status 'Pending'
- Request appears in the employee's request history
- Employee remains on confirmation page or is redirected to dashboard
- Attached document is stored in the system and linked to the request

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is registered in the system with valid credentials
- Employee is logged into the scheduling system
- Employee has active employment status
- Schedule change request page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request page from the main dashboard | Schedule change request form is displayed with all mandatory fields visible and marked with asterisks or 'required' indicators |
| 2 | Leave the date field empty and move focus to the next field | Real-time validation highlights the date field with red border or error indicator showing 'Date is required' |
| 3 | Leave the time field empty and move focus to the next field | Real-time validation highlights the time field with red border or error indicator showing 'Time is required' |
| 4 | Leave the reason field empty | Real-time validation highlights the reason field with red border or error indicator showing 'Reason is required' |
| 5 | Attempt to submit the form by clicking the Submit button with all mandatory fields empty | Submission is blocked, form does not submit, error messages are displayed for all missing mandatory fields, and focus moves to the first empty required field |
| 6 | Fill in only the date field with valid data and attempt to submit again | Submission is still blocked, error messages remain for time and reason fields, date field error is cleared |

**Postconditions:**
- No data is saved to the database
- Employee remains on the schedule change request form
- All validation error messages are visible
- Form retains any data that was entered

---

### Test Case: Test file attachment size validation
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is registered in the system with valid credentials
- Employee is logged into the scheduling system
- Schedule change request page is accessible
- Test file larger than 5MB is available (e.g., 6MB PDF)
- Test file smaller than 5MB is available (e.g., 3MB PDF)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request page and locate the file attachment section | File attachment button is visible with indication of maximum file size limit (5MB) |
| 2 | Click on the attachment button and select a file larger than 5MB (e.g., 6MB file) | Validation error message is displayed stating 'File size exceeds maximum limit of 5MB' and file is not attached to the form |
| 3 | Verify that the attachment field remains empty after the error | No file name is displayed in the attachment area and the field shows as empty |
| 4 | Click on the attachment button again and select a file smaller than 5MB (e.g., 3MB file) | File is accepted without errors, file name is displayed in the attachment area with file size indicator |
| 5 | Fill in all mandatory fields (date, time, reason) with valid data | All fields accept valid data without validation errors |
| 6 | Submit the form with the valid attachment by clicking the Submit button | Submission succeeds, confirmation message is displayed with request ID, and attached file is successfully linked to the request |

**Postconditions:**
- Schedule change request is saved in the database with the valid attachment
- File under 5MB is stored in the system storage
- File over 5MB was rejected and not stored
- Employee sees confirmation of successful submission

---

## Story: As Employee, I want to view the status and history of my schedule change requests to track progress
**Story ID:** story-19

### Test Case: View schedule change requests dashboard
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is registered in the system with valid credentials
- Employee has previously submitted at least 3 schedule change requests with different statuses (pending, approved, rejected)
- Database contains approval history with timestamps and comments for at least one request
- Employee is logged into the scheduling system
- Dashboard page is accessible and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee logs into the system using valid credentials | Employee is successfully authenticated and redirected to the main dashboard or home page |
| 2 | Navigate to the schedule change requests dashboard by clicking on 'My Requests' or 'Schedule Requests' menu option | Dashboard page loads and displays a list of all submitted schedule change requests with columns showing request ID, date, time, reason, and current status |
| 3 | Verify that all previously submitted requests are visible in the list | All requests submitted by the logged-in employee are displayed with accurate information including submission date and current status (pending, approved, or rejected) |
| 4 | Select a request from the list by clicking on it to view detailed approval history | Detailed history panel or page opens showing complete approval workflow with timestamps, approver names, actions taken (submitted, reviewed, approved/rejected), and any comments provided by approvers |
| 5 | Return to the dashboard list view and locate the filter section | Filter options are visible including status filter dropdown with options: All, Pending, Approved, Rejected |
| 6 | Select 'Approved' from the status filter dropdown | The request list updates immediately to show only requests with 'Approved' status, other status requests are hidden from view |
| 7 | Clear the status filter and apply a date range filter to find requests from the last 30 days | Filtered list updates to display only requests submitted within the specified date range, showing accurate results |

**Postconditions:**
- Employee remains logged into the system
- Dashboard displays filtered or unfiltered list based on last action
- No data is modified in the database
- Filter selections are retained during the session

---

### Test Case: Ensure access restriction to own requests
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Two employee accounts exist in the system: Employee A and Employee B
- Employee A is logged into the system
- Employee B has submitted schedule change requests with known request IDs
- Direct URL format for accessing requests is known (e.g., /requests/{requestId})
- Access control and authentication mechanisms are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | While logged in as Employee A, navigate to Employee A's own schedule change requests dashboard | Dashboard displays only Employee A's requests successfully |
| 2 | Note the URL structure and request ID format from Employee A's requests | URL structure is visible in the browser address bar (e.g., /requests/dashboard or /requests/{requestId}) |
| 3 | Manually modify the URL in the browser to attempt accessing Employee B's request by entering Employee B's known request ID (e.g., change /requests/123 to /requests/456 where 456 belongs to Employee B) | System detects unauthorized access attempt and displays 'Access Denied' or '403 Forbidden' error message |
| 4 | Attempt to access Employee B's requests dashboard by manipulating the userId parameter in the URL (e.g., /requests?userId=EmployeeB) | System validates user identity, denies access, and displays error message 'You do not have permission to view this content' or redirects to Employee A's own dashboard |
| 5 | Verify that Employee A is still logged in and can access their own requests normally | Employee A can successfully navigate back to their own dashboard and view their own requests without any issues |

**Postconditions:**
- Employee A remains logged into the system
- No unauthorized access to Employee B's data occurred
- Security logs record the unauthorized access attempts
- Employee A can only view their own requests

---

### Test Case: Dashboard performance under normal load
- **ID:** tc-006
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists with 100+ schedule change requests in the database
- Test data includes requests with various statuses and approval histories
- Network conditions are stable and normal
- Browser cache is cleared to ensure accurate load time measurement
- Performance monitoring tools or browser developer tools are available to measure load time
- Employee is logged into the scheduling system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab to monitor page load performance | Developer tools are open and ready to capture network activity and timing metrics |
| 2 | Clear browser cache and refresh the page to ensure clean test conditions | Cache is cleared and page is ready for fresh load test |
| 3 | Navigate to the schedule change requests dashboard that contains 100+ requests | Dashboard begins loading and network activity is captured in developer tools |
| 4 | Measure the total page load time from initial request to complete rendering of all 100+ requests in the list | Dashboard loads completely within 2 seconds, all request records are visible, status indicators are displayed, and page is fully interactive |
| 5 | Verify that all UI elements are rendered correctly including headers, filters, pagination controls, and request data | All dashboard components are properly displayed, no missing data, no layout issues, and all interactive elements are functional |
| 6 | Test dashboard responsiveness by applying a filter to the 100+ requests | Filter is applied and results are updated within 1 second, maintaining good performance |
| 7 | Record the actual load time from the Network tab (DOMContentLoaded and Load events) | Recorded metrics confirm that dashboard loaded within the 2-second performance requirement |

**Postconditions:**
- Dashboard remains functional and responsive
- All 100+ requests are accessible and viewable
- Performance metrics are documented for future reference
- Employee can continue to interact with the dashboard normally

---

