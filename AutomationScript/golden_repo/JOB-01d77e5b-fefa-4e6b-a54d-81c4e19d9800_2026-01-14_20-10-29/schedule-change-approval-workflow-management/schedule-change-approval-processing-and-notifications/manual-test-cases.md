# Manual Test Cases

## Story: As Approver, I want to review and act on schedule change requests to ensure proper authorization
**Story ID:** story-3

### Test Case: Validate approver can view and act on pending requests
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Approver user account exists with valid credentials
- Approver has been assigned the 'Approver' role in the system
- At least one pending schedule change request exists in the system
- Schedule change request has been submitted by an employee
- System is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid approver credentials (username and password), then click Login button | Approver is successfully authenticated and redirected to the home page or dashboard |
| 2 | Click on the 'Approval Dashboard' or 'Pending Approvals' menu option in the navigation | Approval dashboard page loads and displays a list of all pending schedule change requests assigned to the logged-in approver with columns showing request ID, employee name, request date, and current status |
| 3 | Select a pending schedule change request from the list by clicking on it | Request details page opens displaying complete information including employee details, requested schedule changes, reason for change, submission date, and any attached supporting documents |
| 4 | Review all request details and attachments, then click the 'Approve' button | A comment box appears prompting the approver to add optional comments |
| 5 | Enter approval comments in the comment box (e.g., 'Approved as requested. Schedule change is justified.') and click 'Submit' or 'Confirm Approval' button | System processes the approval action, request status updates to 'Approved', a confirmation message is displayed (e.g., 'Request has been successfully approved'), and the approver is redirected back to the approval dashboard |
| 6 | Verify the approved request no longer appears in the pending requests list | The approved request is removed from the pending list or moved to an 'Approved' section, confirming the status change |

**Postconditions:**
- Schedule change request status is updated to 'Approved' in the database
- Approval action is logged with timestamp and approver details
- Employee who submitted the request receives notification of approval
- Request is removed from approver's pending queue
- Audit trail is created for the approval action

---

### Test Case: Verify rejection and request for additional information actions
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Approver is logged into the system with valid credentials
- Approver has appropriate role-based permissions
- Multiple pending schedule change requests exist in the system
- Approver is on the approval dashboard page
- System notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the approval dashboard, select a pending schedule change request by clicking on it | Request details page opens displaying all relevant information including employee name, requested changes, reason, submission date, and attachments |
| 2 | Review the request details and click the 'Reject' button | A comment box appears requiring the approver to provide a reason for rejection |
| 3 | Enter rejection comments in the comment box (e.g., 'Request denied due to insufficient staffing coverage during requested period.') and click 'Submit' or 'Confirm Rejection' button | System processes the rejection, request status updates to 'Rejected', a confirmation message is displayed (e.g., 'Request has been rejected'), and notification is queued to be sent to the requester |
| 4 | Verify the rejection notification was sent by checking the notification log or system activity | System log shows notification was successfully sent to the employee with rejection status and comments |
| 5 | Navigate back to the approval dashboard and select another pending schedule change request | A different pending request details page opens with all relevant information displayed |
| 6 | Click the 'Request Additional Information' or 'Request More Info' button | A comment box appears prompting the approver to specify what additional information is needed |
| 7 | Enter specific information request in the comment box (e.g., 'Please provide manager approval and detailed justification for the extended leave period.') and click 'Submit' | System updates request status to 'Additional Information Required' or 'Pending Employee Response', confirmation message is displayed, and notification is queued to be sent to the requester |
| 8 | Verify the requester receives notification with the information request | System log confirms notification was delivered to the employee with status update and specific information requirements |

**Postconditions:**
- First request status is updated to 'Rejected' in the database
- Second request status is updated to 'Additional Information Required'
- Both actions are logged with timestamps and approver details
- Employees receive appropriate notifications for their respective requests
- Rejected request is moved out of pending queue
- Request requiring more info remains accessible to employee for updates
- Audit trail is created for both actions

---

### Test Case: Ensure unauthorized users cannot perform approval actions
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Non-approver user account exists (regular employee without approver role)
- Non-approver user is logged into the system
- At least one pending schedule change request exists in the system
- Role-based access control is configured and active
- API endpoints for approval actions are protected

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | As a non-approver user, attempt to navigate to the approval dashboard by entering the URL directly (e.g., /approvals/dashboard) or clicking on approval menu if visible | System denies access and displays an error message such as 'Access Denied: You do not have permission to view this page' or 'Unauthorized Access' and redirects user to home page or displays 403 Forbidden error |
| 2 | Attempt to access the API endpoint directly by sending a GET request to /api/approvals/pending using browser developer tools or API testing tool | API returns 403 Forbidden or 401 Unauthorized status code with error message indicating insufficient permissions |
| 3 | Obtain a valid schedule change request ID and attempt to access the approval action endpoint by sending a POST request to /api/approvals/{requestId}/action with action payload (e.g., {"action": "approve", "comments": "test"}) | API rejects the request with 403 Forbidden status code and returns error message such as 'You are not authorized to perform approval actions' |
| 4 | Verify the unauthorized access attempt is logged in the system security log | System security log contains entry showing the unauthorized access attempt with timestamp, user ID, attempted action, and denial reason |
| 5 | Check the schedule change request status in the database | Request status remains unchanged at 'Pending' and no approval action record was created, confirming the unauthorized attempt had no effect |
| 6 | As a non-approver, attempt to manipulate request parameters or session tokens to bypass authorization and submit an approval action | System validates user permissions server-side, rejects the action regardless of client-side manipulation, returns appropriate error message, and logs the security violation attempt |

**Postconditions:**
- No schedule change request statuses were modified
- No approval actions were recorded in the database
- All unauthorized access attempts are logged in security audit trail
- System security remains intact with no unauthorized data access
- Non-approver user permissions remain unchanged
- Alert may be generated for security team if multiple unauthorized attempts detected

---

## Story: As Employee, I want to receive notifications about my schedule change request status to stay informed
**Story ID:** story-4

### Test Case: Validate notification sent upon schedule change request submission
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee user account exists and is active
- Employee is logged into the system with valid credentials
- Employee has permission to submit schedule change requests
- Notification service is operational and configured
- Employee email address is registered in the system
- In-app notification center is functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request form by clicking on 'Request Schedule Change' or similar menu option | Schedule change request form loads with all required fields displayed (date range, reason, attachments, etc.) |
| 2 | Fill in all required fields: select date range for schedule change, enter reason for request (e.g., 'Personal appointment'), attach any supporting documents if needed, and click 'Submit' button | Form validation passes, request is successfully submitted, and a confirmation message appears (e.g., 'Your schedule change request has been submitted successfully') |
| 3 | Check for immediate notification delivery by observing the notification icon or badge in the application header | Notification icon shows a new notification indicator (e.g., red badge with number '1' or notification bell animation) |
| 4 | Click on the notification icon or navigate to the notification center | Notification center opens displaying the submission confirmation notification with details including request ID, submission timestamp, and message such as 'Your schedule change request #12345 has been submitted and is pending approval' |
| 5 | Verify notification details include correct request information: request ID, submission date/time, requested schedule change dates, and current status ('Submitted' or 'Pending Approval') | All notification details match the submitted request information accurately, including request ID, dates, and status |
| 6 | Check employee's registered email inbox for submission confirmation email | Email notification is received with subject line such as 'Schedule Change Request Submitted - Request #12345' containing the same details as in-app notification and next steps information |
| 7 | Verify the notification timestamp shows it was sent immediately after submission | Notification timestamp is within 1 minute of the request submission time |

**Postconditions:**
- Schedule change request is saved in the database with 'Pending' status
- Submission notification is stored in notification history
- Email notification is sent to employee's registered email address
- In-app notification is visible in employee's notification center
- Notification delivery is logged in the system
- Request is queued for approver review

---

### Test Case: Verify notifications sent upon approval and rejection
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Employee has submitted at least two schedule change requests
- Both requests are in 'Pending' status
- Approver user is logged into the system
- Notification service is operational
- Employee notification center is accessible
- Employee email is configured and deliverable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | As an approver, navigate to the approval dashboard and select the first pending schedule change request | Request details page opens showing all information about the employee's schedule change request |
| 2 | Review the request details and click 'Approve' button, add comments (e.g., 'Approved as requested'), and submit the approval | Request status updates to 'Approved', confirmation message is displayed, and approval action is processed by the system |
| 3 | Log out from approver account and log in as the employee who submitted the request | Employee successfully logs in and is directed to the employee dashboard |
| 4 | Check the notification icon or badge in the application header | Notification indicator shows a new unread notification (e.g., badge with number or highlighted icon) |
| 5 | Click on the notification icon to open the notification center | Notification center displays the approval notification with message such as 'Your schedule change request #12345 has been approved' including approver comments, approval date/time, and next steps |
| 6 | Verify the approval notification contains complete details: request ID, approval status, approver name, approval timestamp, comments, and any next steps or actions required | All details are present and accurate, matching the approval action taken by the approver |
| 7 | Check employee's email inbox for approval notification email | Email is received with subject like 'Schedule Change Request Approved - Request #12345' containing approval details and approver comments |
| 8 | Log out from employee account and log back in as approver | Approver successfully logs in and accesses the approval dashboard |
| 9 | Select the second pending schedule change request from the same employee | Request details page opens with all information displayed |
| 10 | Click 'Reject' button, enter rejection reason in comments (e.g., 'Unable to approve due to staffing constraints during requested period'), and submit the rejection | Request status updates to 'Rejected', confirmation message is displayed, and rejection action is processed |
| 11 | Log out from approver account and log back in as the employee | Employee successfully logs in and notification indicator shows new notification |
| 12 | Open the notification center and locate the rejection notification | Notification center displays the rejection notification with message such as 'Your schedule change request #12346 has been rejected' including rejection reason, approver comments, and guidance on next steps (e.g., 'You may submit a new request with different dates') |
| 13 | Verify the rejection notification contains complete details: request ID, rejection status, approver name, rejection timestamp, detailed comments explaining the reason, and available options | All details are present, accurate, and provide clear information about why the request was rejected |
| 14 | Check employee's email inbox for rejection notification email | Email is received with subject like 'Schedule Change Request Rejected - Request #12346' containing rejection details and approver's explanation |

**Postconditions:**
- First request status is 'Approved' in the database
- Second request status is 'Rejected' in the database
- Both approval and rejection notifications are stored in notification history
- Employee has received both in-app and email notifications for both actions
- All notifications are logged with delivery timestamps
- Employee can view complete notification history in the application
- Audit trail exists for both approval and rejection actions

---

### Test Case: Ensure notifications are delivered within 1 minute of status change
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee has submitted a schedule change request in 'Pending' status
- Approver is logged into the system
- Notification service is running and operational
- System clock is synchronized and accurate
- Employee notification center is accessible
- Test environment allows for timestamp verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current system time before initiating the status change action | Current timestamp is recorded (e.g., 2024-01-15 10:30:00) |
| 2 | As an approver, navigate to the approval dashboard and select a pending schedule change request | Request details page opens displaying the pending request information |
| 3 | Click 'Approve' button, add comments, and click 'Submit' to change the request status to 'Approved', then immediately note the exact timestamp of submission | Request is approved, confirmation message appears, and approval timestamp is recorded (e.g., 2024-01-15 10:30:15) |
| 4 | Immediately switch to the employee account (or have a second browser/session already logged in as the employee) and refresh the notification center | Notification center refreshes and displays notifications |
| 5 | Check for the approval notification and note its delivery timestamp shown in the notification | Approval notification is visible in the notification center with a timestamp indicating when it was delivered |
| 6 | Calculate the time difference between the status change timestamp (approval submission) and the notification delivery timestamp | Time difference is 60 seconds or less (e.g., if approval was at 10:30:15 and notification shows 10:30:45, difference is 30 seconds) |
| 7 | Check the system notification log or database to verify the exact notification creation and delivery timestamps | System log shows notification was created and queued immediately after status change, and delivery timestamp confirms it was sent within 1 minute |
| 8 | Verify email notification delivery time by checking email headers or system email log | Email notification was sent within 1 minute of the status change, as confirmed by email timestamp or system email delivery log |
| 9 | Repeat the test with a rejection action: have approver reject another pending request and measure notification delivery time | Rejection notification is also delivered within 1 minute of status change, confirming consistent performance across different status types |
| 10 | Review notification service performance metrics or logs to confirm no delays or queuing issues | Service logs show notification processing time is well within the 1-minute requirement with no errors or delays |

**Postconditions:**
- All notifications were delivered within the 1-minute SLA
- Notification delivery timestamps are logged in the system
- Performance metrics confirm notification service is meeting requirements
- No notification delivery failures occurred during the test
- Employee received timely updates for all status changes
- System performance logs show acceptable processing times

---

## Story: As Manager, I want to view reports on schedule change approvals to monitor workflow efficiency
**Story ID:** story-5

### Test Case: Validate report generation with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has authorization to access reporting portal
- Schedule change approval data exists in the system (at least 10 records)
- Multiple departments have schedule change requests in the system
- Date range covers at least 30 days of historical data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the reporting portal from the main dashboard | Reporting portal homepage loads successfully within 3 seconds |
| 2 | Manager clicks on 'Schedule Change Approval Reports' menu option | Reporting dashboard is displayed with default view showing all available data, filter options are visible on the left panel, and initial charts/tables render correctly |
| 3 | Manager selects a specific department from the department filter dropdown | Department filter is applied and highlighted, report begins to refresh with loading indicator |
| 4 | Manager selects a date range (e.g., last 30 days) using the date range picker | Date range filter is applied and displayed, report updates to reflect both department and date range filters within 5 seconds |
| 5 | Manager reviews the updated charts section displaying approval metrics | Charts render correctly showing approval times, volumes, and statuses with accurate data matching the applied filters, visual elements are clear and properly labeled |
| 6 | Manager scrolls down to view the data tables section | Data tables display detailed records with columns for request ID, employee name, submission date, approval date, status, and approver name. Data is accurate and matches the filtered criteria |
| 7 | Manager verifies the total count of records displayed matches the filter criteria | Record count is accurate and displayed prominently, pagination controls are visible if records exceed page limit |

**Postconditions:**
- Report remains in filtered state for current session
- Filter selections are preserved if manager navigates away and returns
- System logs the report generation activity for audit purposes

---

### Test Case: Verify report export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager is on the schedule change approval reports dashboard
- A report has been generated with at least 5 records
- Browser allows file downloads
- PDF reader and Excel application are available on the test machine

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager applies desired filters and generates a report with visible data | Report is displayed with charts, tables, and data matching the filter criteria |
| 2 | Manager locates and clicks the 'Export' button in the report toolbar | Export options dropdown menu appears showing 'Export as PDF' and 'Export as Excel' options |
| 3 | Manager selects 'Export as PDF' from the dropdown menu | Export process initiates with a progress indicator, PDF file is generated and downloaded to the default downloads folder within 10 seconds, filename includes report type and timestamp |
| 4 | Manager opens the downloaded PDF file | PDF opens correctly in the default PDF reader, contains all report data including charts and tables, formatting is preserved, data is readable and matches the on-screen report |
| 5 | Manager returns to the reporting dashboard and clicks the 'Export' button again | Export options dropdown menu appears again |
| 6 | Manager selects 'Export as Excel' from the dropdown menu | Export process initiates with a progress indicator, Excel file (.xlsx) is generated and downloaded to the default downloads folder within 10 seconds, filename includes report type and timestamp |
| 7 | Manager opens the downloaded Excel file | Excel file opens correctly in the spreadsheet application, contains all report data in structured format with proper column headers, data is accurate and matches the on-screen report, charts are included as embedded objects or separate sheets |

**Postconditions:**
- Two export files (PDF and Excel) are saved in the downloads folder
- Export activity is logged in the system audit trail
- Report remains displayed on screen in its current state
- Manager can continue working with the report or export again

---

### Test Case: Ensure unauthorized users cannot access reports
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with a non-manager role (e.g., Employee or Approver without manager privileges)
- Role-based access control is properly configured in the system
- Reporting dashboard URL is known or accessible via navigation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Non-manager user attempts to navigate to the reporting portal from the main dashboard menu | Reporting portal option is either not visible in the navigation menu or is displayed as disabled/grayed out |
| 2 | Non-manager user attempts to directly access the reporting dashboard by entering the URL in the browser address bar (e.g., /reports/schedule-change-approvals) | Access is denied immediately, user is redirected to an error page or unauthorized access page |
| 3 | Non-manager user views the error message displayed on the screen | Appropriate error message is displayed stating 'Access Denied: You do not have permission to view this page' or similar message, HTTP 403 Forbidden status is returned |
| 4 | Non-manager user attempts to access the reporting API endpoint directly using browser developer tools or API client (GET /api/reports/schedule-change-approvals) | API request is rejected with 403 Forbidden status code, error response includes message indicating insufficient permissions |
| 5 | Non-manager user verifies they can still access other authorized areas of the application | User can successfully navigate to and access pages and features appropriate for their role without any issues |

**Postconditions:**
- Non-manager user remains on an authorized page or error page
- No report data is exposed or accessible to the unauthorized user
- Access attempt is logged in the security audit trail with user ID, timestamp, and denied action
- System security remains intact with no unauthorized access granted

---

## Story: As Approver, I want to request additional information on schedule change requests to make informed decisions
**Story ID:** story-7

### Test Case: Validate approver can request additional information
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Approver role credentials
- At least one pending schedule change request exists in the system
- Approver has permission to review and act on the schedule change request
- Employee who submitted the request has a valid email address and notification preferences enabled
- Notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver navigates to the pending schedule change requests queue from the dashboard | List of pending schedule change requests is displayed with request IDs, employee names, submission dates, and current status |
| 2 | Approver clicks on a specific schedule change request to view details | Request details page opens displaying full information including employee name, requested schedule changes, reason for change, submission date, and available action buttons (Approve, Reject, Request Additional Information) |
| 3 | Approver reviews the request details and identifies missing or unclear information | All current request information is clearly displayed and readable |
| 4 | Approver clicks the 'Request Additional Information' button | A modal dialog or form appears with a text area for entering comments and a field to specify what additional information is needed |
| 5 | Approver enters detailed comments in the text area specifying the required information (e.g., 'Please provide the business justification for this schedule change and confirm coverage for your current shift') | Text is entered successfully in the comment field, character count is displayed if there is a limit, field validation shows no errors |
| 6 | Approver clicks the 'Submit Request' button in the modal dialog | Modal closes, success message appears confirming 'Additional information request has been sent to the employee', request status updates from 'Pending' to 'Information Requested' or 'Pending Additional Info' |
| 7 | Approver verifies the request status has been updated in the request details page | Request status badge displays 'Information Requested', approver's comment is visible in the request history/timeline section with timestamp and approver name |
| 8 | Approver checks that a notification has been sent to the employee | System confirmation indicates notification was sent successfully within 1 minute, notification appears in the employee's notification center (can be verified by checking employee account or notification logs) |

**Postconditions:**
- Schedule change request status is updated to 'Information Requested'
- Employee receives notification via email and in-app notification center
- Approver's comment and action are logged in the audit trail with timestamp
- Request remains in approver's queue but is marked as awaiting employee response
- Request cannot be approved or rejected until additional information is provided

---

### Test Case: Verify employee can respond to additional information requests
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Employee role credentials
- Employee has a schedule change request with status 'Information Requested'
- Approver has previously requested additional information with specific comments
- Employee has access to notification center
- Employee has permission to edit their own schedule change requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee logs into the system and views the notification center icon/badge | Notification center icon displays a badge indicating unread notifications (e.g., red dot or number) |
| 2 | Employee clicks on the notification center icon to open the notification panel | Notification panel opens displaying list of notifications, notification for additional information request is visible at the top with title 'Additional Information Required for Schedule Change Request #[ID]' |
| 3 | Employee clicks on the notification for the additional information request | Employee is redirected to the schedule change request details page, notification is marked as read, request status shows 'Information Requested', approver's comments requesting additional information are prominently displayed |
| 4 | Employee reviews the approver's comments to understand what information is needed | Approver's comments are clearly visible with timestamp and approver name, employee can read the specific information being requested |
| 5 | Employee clicks the 'Update Request' or 'Provide Additional Information' button | Request edit form opens with existing request details pre-populated, additional text area or fields are available for adding the requested information |
| 6 | Employee enters the required additional information in the designated field (e.g., adds business justification and shift coverage details) | Text is entered successfully, field validation passes, employee can see their updates in real-time |
| 7 | Employee clicks the 'Submit Updates' or 'Resubmit Request' button | Form is submitted successfully, success message appears confirming 'Your updates have been submitted and the approver has been notified', request status changes from 'Information Requested' to 'Pending' or 'Under Review' |
| 8 | Employee verifies the updated information is saved and visible in the request details | Updated information is displayed in the request details, update timestamp is shown, employee's response is added to the request history/timeline |
| 9 | System sends notification to the approver about the updated information | Approver receives notification within 1 minute via email and in-app notification indicating the employee has provided the requested information |

**Postconditions:**
- Schedule change request is updated with additional information provided by employee
- Request status is changed back to 'Pending' or 'Under Review'
- Approver receives notification about the update
- Employee's response is logged in the audit trail with timestamp
- Request returns to approver's queue for review
- Notification is marked as read in employee's notification center

---

### Test Case: Ensure audit trail of information requests and responses
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with appropriate role to access audit logs (Manager or System Administrator)
- At least one schedule change request exists with a complete cycle of information request and response
- Approver has requested additional information on the schedule change request
- Employee has responded with the requested information
- Audit logging is enabled in the system
- User has permission to view audit trails

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | User navigates to the audit log or system logs section from the admin dashboard | Audit log interface loads successfully with search and filter options available |
| 2 | User enters the schedule change request ID in the search field or filters by request ID | Search executes successfully, audit log entries related to the specific schedule change request are displayed |
| 3 | User reviews the audit log entries for the information request action | Audit log contains an entry for 'Additional Information Requested' action with details including: timestamp of when approver requested information, approver's user ID and name, request ID, approver's comments/message, status change from 'Pending' to 'Information Requested' |
| 4 | User reviews the audit log entries for the employee's response action | Audit log contains an entry for 'Additional Information Provided' action with details including: timestamp of when employee responded, employee's user ID and name, request ID, employee's response/updated information, status change from 'Information Requested' to 'Pending' |
| 5 | User verifies the chronological order of audit entries | Audit entries are displayed in chronological order showing the complete sequence: initial request submission, information request by approver, employee response, and any subsequent actions |
| 6 | User checks for notification-related audit entries | Audit log includes entries for notifications sent: notification to employee when information was requested, notification to approver when employee responded, timestamps confirm notifications were sent within 1 minute of the triggering action |
| 7 | User verifies all audit entries contain required metadata | Each audit entry includes: unique audit log ID, timestamp (date and time), user ID and name of actor, action type, request ID, before and after status values, IP address or session information, any relevant comments or data changes |
| 8 | User attempts to export the audit trail for the schedule change request | Export option is available, audit trail can be exported in a standard format (CSV, PDF, or Excel), exported file contains all audit entries with complete information |

**Postconditions:**
- Complete audit trail is preserved in the system database
- All information requests and responses are permanently logged
- Audit logs remain immutable and cannot be edited or deleted by unauthorized users
- Audit trail is available for compliance and reporting purposes
- User can access the audit trail again for future reference

---

## Story: As Approver, I want to filter and search schedule change requests to efficiently manage approvals
**Story ID:** story-10

### Test Case: Validate filtering of schedule change requests by status and date
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Approver role credentials
- Approver has access to the approval dashboard
- Multiple schedule change requests exist in the system with varying statuses (pending, approved, rejected)
- Schedule change requests exist across different date ranges
- Database contains at least 10 schedule change requests for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the approval dashboard | Approval dashboard loads successfully displaying all schedule change requests |
| 2 | Locate and click on the status filter dropdown | Status filter dropdown expands showing available status options (pending, approved, rejected, all) |
| 3 | Select 'Pending' from the status filter dropdown | Status filter is set to 'Pending' and the selection is visually indicated |
| 4 | Click on the date range filter and select a start date and end date | Date range picker opens, allows selection of dates, and displays the selected date range |
| 5 | Click 'Apply' or 'Filter' button to apply the selected filters | Filtered list displays only schedule change requests with 'Pending' status within the selected date range. Results are returned within 2 seconds |
| 6 | Verify the filtered results by checking each displayed request | All displayed requests have 'Pending' status and submission dates fall within the selected date range |
| 7 | Click on 'Clear Filters' or 'Reset' button | All applied filters are removed and filter controls return to default state |
| 8 | Observe the request list after clearing filters | Full list of all schedule change requests is displayed without any filtering applied |

**Postconditions:**
- All filters are cleared and system is in default state
- Full unfiltered list of schedule change requests is visible
- No filter presets are saved during this test

---

### Test Case: Verify keyword search functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Approver role credentials
- Approver has access to the approval dashboard
- Multiple schedule change requests exist in the system
- Schedule change requests are associated with different employee names
- At least one employee named 'John Smith' has submitted schedule change requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the approval dashboard | Approval dashboard loads successfully displaying all schedule change requests |
| 2 | Locate the search box on the approval dashboard | Search box is visible and active with placeholder text indicating search functionality |
| 3 | Click inside the search box to focus on it | Search box is focused and cursor is blinking, ready for text input |
| 4 | Type 'John Smith' in the search box | Text 'John Smith' appears in the search box as it is typed |
| 5 | Observe the request list as the keyword is entered | List updates dynamically to show only schedule change requests where employee name matches 'John Smith'. Results are returned within 2 seconds |
| 6 | Verify each displayed request contains the search keyword | All displayed requests are associated with employee 'John Smith' and the keyword is highlighted or clearly visible |
| 7 | Clear the search box by deleting the text or clicking a clear icon | Search box is cleared and full list of schedule change requests is restored |

**Postconditions:**
- Search box is cleared
- Full unfiltered list of schedule change requests is displayed
- System is ready for next search operation

---

### Test Case: Ensure saved filter presets function correctly
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Approver role credentials
- Approver has access to the approval dashboard
- Multiple schedule change requests exist with varying statuses and dates
- No existing filter presets are saved for this approver
- System supports saving and loading filter presets

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the approval dashboard | Approval dashboard loads successfully displaying all schedule change requests |
| 2 | Apply multiple filters: select 'Pending' status and set date range to last 7 days | Filters are applied and list displays only pending requests from the last 7 days |
| 3 | Locate and click on 'Save Filter' or 'Save Preset' button | A dialog or input field appears prompting for preset name |
| 4 | Enter preset name 'Pending Last Week' and click 'Save' or 'Confirm' | Preset is saved successfully and a confirmation message is displayed |
| 5 | Verify the saved preset appears in the presets list or dropdown | Preset 'Pending Last Week' is visible and selectable in the saved presets section |
| 6 | Clear all current filters to return to default view | All filters are cleared and full list of requests is displayed |
| 7 | Click on or select the saved preset 'Pending Last Week' from the presets list | Preset is selected and system begins applying the saved filters |
| 8 | Observe the filter controls and request list | Filters are automatically applied as per the saved preset: status is set to 'Pending' and date range is set to last 7 days |
| 9 | Verify the filtered results match the preset criteria | List displays only pending schedule change requests from the last 7 days, matching the original preset configuration |

**Postconditions:**
- Filter preset 'Pending Last Week' remains saved in the system
- Preset is available for future use by the approver
- Filtered view is active showing results based on the applied preset

---

