# Manual Test Cases

## Story: As Schedule Manager, I want to submit schedule change requests to achieve formal approval before implementation
**Story ID:** story-9

### Test Case: Validate successful schedule change request submission
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Schedule Manager with valid credentials
- User has authorization to submit schedule change requests
- Schedule change submission page is accessible
- At least one supported file type is available for attachment (PDF, DOC, DOCX, XLS, XLSX)
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change submission page from the main dashboard or menu | Schedule change submission form is displayed with all mandatory fields clearly marked (asterisk or 'required' label), attachment section is visible, and submit button is present |
| 2 | Fill in all mandatory fields with valid data: Schedule ID, Change Type, Effective Date, Reason for Change, Impact Description, and any other required fields | All fields accept the input without errors, no validation warnings are displayed, field formatting is applied correctly (dates, text limits) |
| 3 | Click on the attachment section and select one or more files with allowed file types (PDF, DOC, DOCX, XLS, XLSX) within the size limit | Files are successfully attached, file names are displayed in the attachment section, file size is shown, no validation errors appear |
| 4 | Review all entered information and click the 'Submit' button | System processes the submission, loading indicator appears briefly, request is accepted and saved to ScheduleChangeRequests table |
| 5 | Observe the system response after submission | Approval workflow is automatically initiated, confirmation message is displayed with a unique request tracking ID (e.g., 'Request #SCR-2024-001 submitted successfully'), success notification appears on screen |
| 6 | Note the tracking ID and verify it can be used for future reference | Tracking ID is clearly visible and can be copied, user is redirected to confirmation page or dashboard showing the newly submitted request |

**Postconditions:**
- Schedule change request is stored in the database with status 'Pending'
- Approval workflow is initiated and assigned to appropriate approvers
- Request tracking ID is generated and associated with the submission
- Notification is sent to approvers about the new request
- User can view the submitted request in their submission history
- Attached documents are stored securely and linked to the request

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Schedule Manager with valid credentials
- User has authorization to submit schedule change requests
- Schedule change submission page is accessible
- Form validation rules are configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change submission page from the main dashboard or menu | Schedule change submission form is displayed with all mandatory fields clearly marked with asterisks or 'required' labels |
| 2 | Fill in only some of the mandatory fields, intentionally leaving one or more required fields empty (e.g., leave 'Reason for Change' blank) | Filled fields accept the input, empty mandatory fields remain blank without triggering immediate validation |
| 3 | Attempt to click the 'Submit' button without completing all mandatory fields | Submission is blocked and prevented from processing, form does not submit to the server |
| 4 | Observe the validation error messages displayed on the form | Clear error messages appear next to or above each missing mandatory field (e.g., 'Reason for Change is required'), empty fields are highlighted in red or with error styling, error summary may appear at the top of the form listing all validation issues |
| 5 | Attempt to navigate away from the page or refresh | System may display a warning that unsaved changes will be lost, no partial submission is created in the database |
| 6 | Fill in the previously missing mandatory fields with valid data | Error messages disappear as fields are completed, field highlighting returns to normal state, submit button becomes enabled or validation passes |
| 7 | Click the 'Submit' button after all mandatory fields are completed | Form submits successfully, confirmation message with tracking ID is displayed |

**Postconditions:**
- No incomplete request is saved to the database during failed submission attempts
- User remains on the submission form with entered data preserved
- After successful completion, request is submitted and workflow is initiated
- Validation rules are confirmed to be working correctly

---

### Test Case: Test attachment validation for unsupported file types
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Schedule Manager with valid credentials
- User has authorization to submit schedule change requests
- Schedule change submission page is accessible
- Test files with unsupported formats are available (e.g., .exe, .bat, .zip, .rar)
- Test files with supported formats are available (e.g., .pdf, .doc, .docx, .xls, .xlsx)
- File type validation rules are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change submission page and locate the attachment section | Submission form is displayed with attachment section visible, allowed file types and size limits are indicated (e.g., 'Supported formats: PDF, DOC, DOCX, XLS, XLSX. Max size: 10MB') |
| 2 | Click on the attachment button and select a file with an unsupported format (e.g., .exe, .bat, .zip, or .rar file) | System detects the unsupported file type immediately |
| 3 | Observe the validation response from the system | Clear validation error message is displayed (e.g., 'File type .exe is not supported. Please upload PDF, DOC, DOCX, XLS, or XLSX files only'), file is not added to the attachment list, error styling appears in the attachment section |
| 4 | Attempt to attach multiple unsupported file types simultaneously | All unsupported files are rejected with individual or grouped error messages, no unsupported files appear in the attachment list |
| 5 | Remove the unsupported file attempt and click the attachment button again | Error messages clear, attachment section returns to normal state ready for new file selection |
| 6 | Select and attach files with supported formats (e.g., .pdf, .docx, .xlsx) within the size limit | Files are successfully attached without any errors, file names and sizes are displayed in the attachment section, no validation error messages appear, files are ready for submission |
| 7 | Complete all mandatory fields and submit the form with the valid attachments | Form submits successfully with the supported file attachments, confirmation message with tracking ID is displayed |

**Postconditions:**
- Only files with supported formats are attached to the request
- Unsupported files are rejected and not stored in the system
- Request is submitted successfully with valid attachments
- File validation rules are confirmed to be working correctly
- Attached files are securely stored and linked to the request

---

## Story: As Schedule Manager, I want to track the status of my schedule change requests to stay informed of approval progress
**Story ID:** story-11

### Test Case: Verify schedule change request status is displayed correctly
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as a Schedule Manager with valid credentials
- User has previously submitted at least one schedule change request
- Status dashboard is accessible to the user
- At least one request has undergone a status change (e.g., from Pending to Approved or Rejected)
- Notification system is configured and operational
- Database contains approval decisions and comments for at least one request

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using valid Schedule Manager credentials | User is successfully authenticated and redirected to the main dashboard or home page |
| 2 | Navigate to the schedule change request status dashboard from the main menu or navigation bar | Status dashboard page loads successfully, list of all submitted schedule change requests is displayed in a table or card format |
| 3 | Observe the displayed information for each request in the list | Each request shows: Request ID/Tracking Number, Submission Date, Change Type, Current Status (Pending, Approved, Rejected, Modification Requested) with appropriate visual indicators (colors, icons), and brief description or title |
| 4 | Verify that status indicators are clearly visible and distinguishable | Status indicators use distinct colors or icons (e.g., yellow/orange for Pending, green for Approved, red for Rejected, blue for Modification Requested), status labels are clearly readable |
| 5 | Select a specific request from the list by clicking on it | Detailed view of the selected request opens, showing comprehensive information including all submitted details, current status, and history section |
| 6 | Review the detailed history section of the selected request | Complete chronological history is displayed showing: Initial submission timestamp, all status changes with dates and times, approver names or roles for each decision, comments or feedback from approvers, modification requests if any, and any attached documents or responses |
| 7 | Verify that all approval decisions are visible with associated comments | Each approval decision shows: Decision maker's name, Decision date and time, Decision type (Approved/Rejected/Modification Requested), detailed comments or reasons for the decision, and any action items or next steps |
| 8 | Trigger a status change on one of the requests (if test environment allows) or wait for a scheduled status change notification | System detects the status change in real-time or near real-time (within acceptable polling interval) |
| 9 | Observe the notification mechanism when status changes | Notification is displayed promptly through one or more channels: In-app notification banner or popup, email notification to registered email address, notification badge on dashboard icon, notification includes request ID, old status, new status, and timestamp |
| 10 | Refresh the status dashboard page | Updated status is reflected immediately, request list shows the new status, notification counter updates if applicable |

**Postconditions:**
- User has successfully viewed all submitted requests and their statuses
- Detailed history and comments are accessible for each request
- Notification system has been verified to work correctly
- Status updates are confirmed to be real-time or near real-time
- User remains logged in and can continue to monitor requests
- No data inconsistencies are observed between list view and detail view

---

### Test Case: Test filtering and searching of schedule change requests
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as a Schedule Manager with valid credentials
- User has submitted multiple schedule change requests with varying statuses (Pending, Approved, Rejected, Modification Requested)
- Requests have different submission dates spanning multiple days or weeks
- Status dashboard is accessible with filter and search functionality enabled
- At least 5-10 requests exist to effectively test filtering and searching

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system and navigate to the schedule change request status dashboard | Status dashboard loads successfully displaying the complete list of all submitted schedule change requests without any filters applied |
| 2 | Locate the filter controls on the dashboard (typically at the top or side of the request list) | Filter section is visible with options for: Status filter (dropdown or checkboxes for Pending, Approved, Rejected, Modification Requested), Date range filter (from date and to date pickers), and possibly additional filters like Change Type or Priority |
| 3 | Select a specific status from the status filter (e.g., select 'Approved' only) | Request list immediately updates to show only requests with 'Approved' status, all other status requests are hidden from view, count or summary shows number of filtered results |
| 4 | Verify that the filtered results match the selected criteria | All displayed requests show 'Approved' status, no requests with other statuses are visible, request count matches the number of approved requests |
| 5 | Add a date range filter by selecting a start date and end date | Request list further filters to show only approved requests submitted within the selected date range, requests outside the date range are excluded, multiple filters work together correctly (AND logic) |
| 6 | Clear the status filter while keeping the date filter active | Request list updates to show all requests (regardless of status) within the selected date range, filter controls reflect the current active filters |
| 7 | Clear all filters by clicking 'Clear Filters' or 'Reset' button | All filters are removed, complete list of all requests is displayed again, filter controls return to default state |
| 8 | Locate the search functionality (search box or search field) on the dashboard | Search box is visible and accessible, placeholder text indicates search capability (e.g., 'Search by Request ID') |
| 9 | Enter a specific request ID or tracking number in the search box | Search executes automatically (as you type) or after clicking search button, request list filters to show only the matching request |
| 10 | Verify the search result displays the correct request | Only the request matching the entered ID is displayed, all request details are correct and match the search criteria, if no match is found, appropriate 'No results found' message is displayed |
| 11 | Clear the search box and test searching with partial request ID or keywords | Search supports partial matching, all requests containing the search term are displayed, search is case-insensitive |
| 12 | Combine search with filters by entering a search term and applying a status filter | Results show requests that match both the search term AND the selected filter criteria, combined filtering works correctly without conflicts |
| 13 | Clear all search terms and filters to return to the full list view | Complete unfiltered list of all requests is displayed, all controls are reset to default state |

**Postconditions:**
- User has successfully tested all filtering options
- Search functionality is confirmed to work with exact and partial matches
- Combined filters and search work together correctly
- Dashboard returns to unfiltered state showing all requests
- No performance issues observed during filtering or searching
- Filter and search states can be cleared and reset properly

---

