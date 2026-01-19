# Manual Test Cases

## Story: As Scheduler, I want to submit schedule change requests to achieve accurate and auditable schedule modifications
**Story ID:** story-1

### Test Case: Validate successful schedule change request submission with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has valid scheduler role credentials
- User is logged into the system
- Schedule change request form is accessible
- Test attachment file is prepared (size less than 10MB)
- Database is accessible and ScheduleChangeRequests table is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Scheduler navigates to schedule change request page | Schedule change request form is displayed with all mandatory fields visible and enabled |
| 2 | Scheduler fills all mandatory fields with valid data (employee name, current schedule, proposed schedule, effective date, reason for change) | All input fields accept the data without any validation errors or warnings |
| 3 | Scheduler clicks on the attachment upload button and selects a valid file (less than 10MB) | File is successfully uploaded and file name is displayed in the attachment section |
| 4 | Scheduler clicks the Submit button | Submission succeeds within 2 seconds, confirmation message is displayed with unique request ID, and request enters approval workflow queue |

**Postconditions:**
- Schedule change request is saved in ScheduleChangeRequests table
- Request status is set to 'Pending Approval'
- Attachment is associated with the request record
- Approval workflow is initiated
- Confirmation message with request ID is visible to scheduler

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User has valid scheduler role credentials
- User is logged into the system
- Schedule change request form is accessible
- Form validation rules are configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Scheduler navigates to schedule change request page | Schedule change request form is displayed with all mandatory fields marked with asterisks or required indicators |
| 2 | Scheduler fills some fields but intentionally leaves one or more mandatory fields empty (e.g., effective date, reason for change) | Real-time validation highlights the missing mandatory fields with red borders or error indicators as scheduler tabs out of empty fields |
| 3 | Scheduler attempts to submit the form by clicking the Submit button | Submission is blocked, form is not submitted, and clear error messages are displayed next to each missing mandatory field indicating which fields are required |

**Postconditions:**
- No record is created in ScheduleChangeRequests table
- Form remains on screen with entered data preserved
- Error messages are clearly visible
- Submit button remains enabled for retry after corrections

---

### Test Case: Ensure unauthorized users cannot access submission form
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User has valid credentials but does NOT have scheduler role
- User is logged into the system
- Role-based access control is configured and enforced
- Schedule change request page URL is known

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | User without scheduler role attempts to access schedule change request page by navigating to the URL or clicking menu option | Access is denied immediately and user is redirected to an error page or shown an appropriate error message stating 'Access Denied: You do not have permission to submit schedule change requests' or similar |

**Postconditions:**
- User remains on error page or is redirected to authorized page
- No access to schedule change request form is granted
- Security event is logged in system audit trail
- User session remains active

---

## Story: As Scheduler, I want to view the status and history of my schedule change requests to achieve transparency and tracking
**Story ID:** story-5

### Test Case: Validate dashboard displays scheduler's submitted requests with statuses
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User has valid scheduler role credentials
- User is logged into the system
- Scheduler has previously submitted at least 3 schedule change requests
- Submitted requests have different statuses (Pending, Approved, Rejected)
- Dashboard page is accessible
- Database contains approval history with comments and timestamps

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Scheduler logs into the system using valid credentials | Login is successful and scheduler is redirected to home page or dashboard |
| 2 | Scheduler navigates to the schedule change request dashboard | Dashboard loads within 3 seconds and displays a list of all schedule change requests submitted by the logged-in scheduler with columns showing request ID, date submitted, employee name, current status, and action buttons |
| 3 | Scheduler reviews the list and verifies that all their submitted requests are visible with current status indicators | All requests submitted by the scheduler are displayed with accurate status values (Pending Approval, Approved, Rejected, etc.) |
| 4 | Scheduler selects a specific request by clicking on it or clicking a 'View Details' button | Detailed view opens showing complete approval history including approver names, approval/rejection decisions, comments provided by approvers, and timestamps for each action in chronological order |
| 5 | Scheduler applies filters by selecting a date range (e.g., last 30 days) and status (e.g., Approved) | Dashboard refreshes and displays only the requests matching the selected filter criteria, showing accurate count of filtered results |
| 6 | Scheduler clicks the Export button to download the report | CSV file is generated and downloaded to the scheduler's device containing all filtered request data with columns for request ID, submission date, employee name, status, approver, comments, and timestamps |

**Postconditions:**
- Dashboard remains accessible for further queries
- CSV file is successfully downloaded and can be opened
- Filters remain applied until cleared by user
- No data is modified in the database
- User session remains active

---

### Test Case: Ensure schedulers cannot view requests submitted by others
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User has valid scheduler role credentials
- User is logged into the system
- Multiple schedulers exist in the system
- Other schedulers have submitted schedule change requests
- Request IDs from other schedulers are known for testing
- Role-based data access control is configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Scheduler attempts to access request details not submitted by them by directly entering the URL with another scheduler's request ID (e.g., /api/schedule-change-requests/12345) or manipulating dashboard filters | Access is denied with error message 'Access Denied: You do not have permission to view this request' or similar, and request details are not displayed |
| 2 | Scheduler verifies the dashboard list to confirm only their own requests are visible | Dashboard displays only requests where the logged-in scheduler is the submitter, with no requests from other schedulers visible in the list |

**Postconditions:**
- Scheduler can only see their own requests
- Security event is logged in system audit trail
- No unauthorized data is exposed
- User session remains active
- Dashboard continues to function normally for authorized requests

---

