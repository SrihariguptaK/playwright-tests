# Manual Test Cases

## Story: As Scheduler, I want to receive notifications about approval decisions to stay informed on schedule changes
**Story ID:** story-3

### Test Case: Validate notification delivery on approval decision
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user account exists and is active in the system
- Scheduler has valid email address configured in profile
- Approver user account exists with approval permissions
- NotificationService is running and operational
- System time is synchronized for accurate timestamp tracking

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as a Scheduler user | Scheduler is successfully authenticated and redirected to dashboard |
| 2 | Navigate to schedule change request submission page | Schedule change request form is displayed with all required fields |
| 3 | Fill in all required fields for schedule change request (date, time, reason, etc.) and submit the request | Request is successfully submitted and confirmation message is displayed with request ID |
| 4 | Note the current system timestamp and log out from Scheduler account | Timestamp is recorded and Scheduler is logged out successfully |
| 5 | Log in to the system as an Approver user | Approver is successfully authenticated and can access pending requests |
| 6 | Navigate to pending schedule change requests and locate the submitted request | The submitted request is visible in the pending requests list with correct details |
| 7 | Select the request and approve it by clicking the Approve button and adding approval comments | Request status changes to Approved and approval is confirmed with timestamp |
| 8 | Note the approval timestamp and wait for notification delivery | System processes the approval decision |
| 9 | Check the time difference between approval timestamp and current time (should be within 1 minute) | Time elapsed is less than or equal to 60 seconds |
| 10 | Log in to Scheduler's email account and check for notification email | Notification email is received with subject indicating schedule change request approval |
| 11 | Open the notification email and verify it contains request ID, request details, approval status, and approver comments | Email contains all required information: request ID, date/time of change, approval status, approver name, and comments provided during approval |
| 12 | Log in to the system as Scheduler and check system alerts/notifications panel | System alert notification is displayed showing the approval decision |
| 13 | Click on the system alert to view full notification details | Notification displays complete request details including request ID, approval status, approver comments, and timestamp matching the email notification |

**Postconditions:**
- Notification is successfully delivered via both email and system alert
- Notification delivery is logged in the system
- Scheduler is informed of the approval decision
- Request status remains as Approved in the system

---

### Test Case: Validate notification delivery on rejection decision
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 9 mins

**Preconditions:**
- Scheduler user account exists and is active in the system
- Scheduler has valid email address configured in profile
- Approver user account exists with approval permissions
- NotificationService is running and operational
- System time is synchronized for accurate timestamp tracking

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as a Scheduler user | Scheduler is successfully authenticated and redirected to dashboard |
| 2 | Navigate to schedule change request submission page | Schedule change request form is displayed with all required fields |
| 3 | Fill in all required fields for schedule change request and submit the request | Request is successfully submitted and confirmation message is displayed with request ID |
| 4 | Note the current system timestamp and log out from Scheduler account | Timestamp is recorded and Scheduler is logged out successfully |
| 5 | Log in to the system as an Approver user | Approver is successfully authenticated and can access pending requests |
| 6 | Navigate to pending schedule change requests and locate the submitted request | The submitted request is visible in the pending requests list |
| 7 | Select the request and reject it by clicking the Reject button and adding rejection reason/comments | Request status changes to Rejected and rejection is confirmed with timestamp |
| 8 | Note the rejection timestamp and calculate time difference (should be within 1 minute for notification delivery) | Rejection timestamp is recorded and system processes the decision |
| 9 | Verify that notification delivery time is within 1 minute of rejection decision | Time elapsed between rejection and notification trigger is less than or equal to 60 seconds |
| 10 | Log in to Scheduler's email account and check for rejection notification email | Notification email is received with subject indicating schedule change request rejection |
| 11 | Open the notification email and verify content includes request ID, rejection status, and rejection comments | Email accurately reflects rejection decision with complete details: request ID, rejection status, approver name, rejection reason/comments, and timestamp |
| 12 | Log in to the system as Scheduler and check system alerts/notifications panel | System alert notification is displayed showing the rejection decision |
| 13 | Click on the system alert to view full notification details | Notification displays complete rejection information matching the email content |
| 14 | Navigate to notification logs or admin panel to verify delivery status | Notification delivery status is logged as 'Delivered' with successful delivery timestamp for both email and system alert |

**Postconditions:**
- Rejection notification is successfully delivered via both email and system alert
- Notification delivery attempt and status are logged in the system
- Scheduler is informed of the rejection decision with reasons
- Request status remains as Rejected in the system

---

### Test Case: Validate notification history display
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Scheduler user account exists and is logged into the system
- Multiple schedule change requests have been submitted by the scheduler
- At least some requests have been approved or rejected generating notifications
- Notification history feature is enabled and accessible
- Historical notification data exists in the system database

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as a Scheduler user | Scheduler is successfully authenticated and redirected to dashboard |
| 2 | Locate and click on the Notifications or Notification History menu option in the scheduler's dashboard | Navigation menu displays the Notification History option |
| 3 | Click on Notification History to navigate to the notification history page | Notification history page loads and displays a list view of notifications |
| 4 | Verify that the page displays all past notifications received by the scheduler | All historical notifications are listed in chronological order (most recent first) |
| 5 | Check that each notification entry displays key information: notification date/time, request ID, notification type (approval/rejection), and status | Each notification entry shows complete summary information including timestamp, request ID, decision type, and read/unread status |
| 6 | Select and click on a specific notification from the history list | Notification details page or modal opens displaying full notification content |
| 7 | Verify the detailed notification view includes request details, decision type, approver name, comments, and timestamp | All notification details are displayed accurately including request ID, schedule change details, approval/rejection status, approver information, comments, and decision timestamp |
| 8 | Navigate back to notification history list and select a different notification | Different notification details are displayed correctly |
| 9 | Verify that notification history includes both approval and rejection notifications | History list contains notifications for both approved and rejected requests with appropriate indicators |
| 10 | Check if the notification history page has pagination or scroll functionality if many notifications exist | Page handles multiple notifications appropriately with pagination controls or infinite scroll |
| 11 | Verify that notification timestamps are accurate and match the actual decision times | All timestamps displayed in notification history match the actual approval/rejection decision times recorded in the system |

**Postconditions:**
- Scheduler has successfully viewed notification history
- All past notifications remain accessible in the system
- Notification read status may be updated if applicable
- No data is modified during the viewing process

---

## Story: As Scheduler, I want to view the status and history of my schedule change requests to track progress and decisions
**Story ID:** story-6

### Test Case: Validate accurate display of request statuses
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Scheduler user account exists and is active in the system
- Scheduler has submitted multiple schedule change requests with varying statuses (Pending, Approved, Rejected)
- Request dashboard feature is accessible to scheduler users
- Database contains accurate status information for all requests
- User has valid authentication credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as a Scheduler user with valid credentials | Scheduler is successfully authenticated and redirected to the main dashboard |
| 2 | Locate and click on the Schedule Change Requests or My Requests menu option | Navigation menu displays the Schedule Change Requests option clearly |
| 3 | Click on Schedule Change Requests to navigate to the request dashboard | Request dashboard page loads within 3 seconds displaying the list of submitted requests |
| 4 | Verify that the dashboard displays a list of all schedule change requests submitted by the logged-in scheduler | Complete list of scheduler's requests is displayed with no missing entries |
| 5 | Check that each request entry displays key information: request ID, submission date, requested schedule change details, and current status | Each request shows request ID, submission timestamp, schedule change summary, and status badge/indicator |
| 6 | Identify a request with 'Pending' status and verify the status indicator is displayed correctly | Pending status is clearly indicated with appropriate visual indicator (e.g., yellow badge, pending icon) and text label 'Pending' |
| 7 | Identify a request with 'Approved' status and verify the status indicator is displayed correctly | Approved status is clearly indicated with appropriate visual indicator (e.g., green badge, checkmark icon) and text label 'Approved' |
| 8 | Identify a request with 'Rejected' status and verify the status indicator is displayed correctly | Rejected status is clearly indicated with appropriate visual indicator (e.g., red badge, X icon) and text label 'Rejected' |
| 9 | Cross-reference displayed statuses with actual request statuses in the system database or by checking approval history | All displayed statuses match the actual current status of each request in the system with 100% accuracy |
| 10 | Refresh the dashboard page and verify that statuses remain consistent | Page reloads within 3 seconds and all request statuses are displayed consistently without changes |
| 11 | Verify that the dashboard displays requests in a logical order (e.g., most recent first or grouped by status) | Requests are organized in a user-friendly manner with clear sorting logic |

**Postconditions:**
- Scheduler has successfully viewed all request statuses
- No data is modified during the viewing process
- Dashboard remains accessible for future access
- All request statuses remain accurate in the system

---

### Test Case: Validate detailed approval history display
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user account exists and is logged into the system
- At least one schedule change request has been submitted and processed (approved or rejected)
- Request has approval history with decisions, timestamps, and comments
- Scheduler has access to view detailed request history
- Request dashboard is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as a Scheduler user | Scheduler is successfully authenticated and redirected to dashboard |
| 2 | Navigate to the Schedule Change Requests dashboard | Request dashboard loads displaying list of submitted requests |
| 3 | Identify a request that has been processed (approved or rejected) from the list | Processed request is visible with appropriate status indicator |
| 4 | Click on the request or click on a 'View Details' or 'View History' button/link associated with the request | Request detail page or history modal opens displaying detailed information |
| 5 | Verify that the detailed view displays the approval history section | Approval history section is clearly visible and labeled |
| 6 | Check that the approval history shows the approval decision (Approved or Rejected) | Decision type is clearly displayed with appropriate visual indicator and text |
| 7 | Verify that the approval history displays the approver's name or user ID | Approver information is shown accurately identifying who made the decision |
| 8 | Check that the approval history includes the timestamp of when the decision was made | Decision timestamp is displayed in a clear format (e.g., 'MM/DD/YYYY HH:MM AM/PM' or 'YYYY-MM-DD HH:MM:SS') |
| 9 | Verify that the timestamp shown matches the actual time the approval/rejection decision was made in the system | Timestamp is accurate and matches system records with no discrepancies |
| 10 | Check that the approval history displays any comments or notes provided by the approver | Approver comments are displayed in full with proper formatting and readability |
| 11 | Verify that all comments are complete and match what the approver entered during the approval/rejection process | Comments are accurate, complete, and match the approver's input with no truncation or data loss |
| 12 | If the request has multiple approval stages or history entries, verify that all entries are displayed chronologically | All approval history entries are shown in chronological order with clear separation between entries |
| 13 | Select a different processed request and repeat the verification of approval history details | Different request's approval history is displayed accurately with all required information |
| 14 | Verify that the approval history is read-only and cannot be modified by the scheduler | No edit controls are available and history information is displayed in read-only format |

**Postconditions:**
- Scheduler has successfully viewed detailed approval history
- No data is modified during the viewing process
- Approval history remains accurate and unchanged in the system
- Request status and history remain accessible for future reference

---

### Test Case: Validate filtering and export functionality
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- Scheduler user account exists and is logged into the system
- Multiple schedule change requests exist with different statuses (Pending, Approved, Rejected)
- Requests have been submitted on different dates to enable date filtering
- Filter and export features are enabled and accessible
- System has PDF generation capability configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as a Scheduler user | Scheduler is successfully authenticated and redirected to dashboard |
| 2 | Navigate to the Schedule Change Requests dashboard | Request dashboard loads displaying the complete list of submitted requests |
| 3 | Locate the filter controls on the dashboard (typically at the top or side of the request list) | Filter section is visible with options for filtering by status and date |
| 4 | Click on the Status filter dropdown and select 'Approved' status | Status filter dropdown opens showing available status options (All, Pending, Approved, Rejected) |
| 5 | Apply the status filter by clicking Apply or confirming the selection | Request list refreshes and displays only requests with 'Approved' status, hiding all other requests |
| 6 | Verify that all displayed requests have 'Approved' status and no other status requests are shown | Filtered list contains only approved requests with accurate count displayed |
| 7 | Change the status filter to 'Rejected' and apply | Request list updates to show only rejected requests |
| 8 | Clear the status filter and locate the date filter controls | All requests are displayed again and date filter options are visible (date range picker or from/to date fields) |
| 9 | Select a date range by choosing a start date and end date that includes some but not all requests | Date range is selected successfully with visual confirmation of selected dates |
| 10 | Apply the date filter | Request list refreshes and displays only requests submitted within the selected date range |
| 11 | Verify that all displayed requests have submission dates within the selected date range | Filtered list shows only requests matching the date criteria with accurate results |
| 12 | Apply both status filter (e.g., 'Approved') and date filter simultaneously | Request list displays only requests that match both filter criteria (approved AND within date range) |
| 13 | Verify that the combined filters work correctly and display accurate results | Filtered list shows only requests matching all applied filter criteria |
| 14 | Locate the Export button or Export option on the dashboard (typically near the filter controls or at the top of the list) | Export button is visible and enabled |
| 15 | Click on the Export button to initiate the export process | Export dialog or confirmation appears, indicating PDF format and requesting confirmation |
| 16 | Confirm the export action to generate the PDF report | System processes the export request and generates PDF file (progress indicator may be shown) |
| 17 | Wait for the PDF generation to complete and download the file | PDF file is generated successfully and download begins automatically or download link is provided |
| 18 | Open the downloaded PDF file using a PDF reader | PDF file opens successfully without errors |
| 19 | Verify that the PDF report contains the filtered request history data matching what was displayed on screen | PDF report includes all requests from the filtered list with complete details: request ID, submission date, status, schedule change details, and approval history |
| 20 | Check that the PDF report is properly formatted with clear headers, readable text, and organized layout | PDF report is well-formatted, professional-looking, with clear sections, proper alignment, and all data is readable |
| 21 | Verify that the PDF includes report metadata such as generation date, scheduler name, and filter criteria applied | PDF header or footer shows report generation timestamp, scheduler information, and applied filters |

**Postconditions:**
- Filtered request list is displayed accurately based on applied criteria
- PDF report is successfully generated and downloaded
- Original request data remains unchanged in the system
- Filters can be cleared or modified for subsequent searches
- Downloaded PDF file is saved to the user's device

---

## Story: As System Administrator, I want to audit all schedule change approval activities to ensure compliance and traceability
**Story ID:** story-7

### Test Case: Validate completeness and accuracy of audit logs
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Administrator account with audit access permissions is available
- System is operational and audit logging is enabled
- At least one schedule change request exists in the system
- Test user accounts with approval permissions are configured
- Database connection to AuditLogs table is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as a user with approval permissions | User successfully logs in and dashboard is displayed |
| 2 | Navigate to a pending schedule change request and approve it with comment 'Approved for testing purposes' | Request is approved successfully and confirmation message is displayed |
| 3 | Navigate to another schedule change request and reject it with comment 'Rejected due to resource constraints' | Request is rejected successfully and confirmation message is displayed |
| 4 | Navigate to a third schedule change request and escalate it with comment 'Escalating to senior management' | Request is escalated successfully and confirmation message is displayed |
| 5 | Log out from the approval user account and log in as System Administrator | Administrator successfully logs into the audit portal |
| 6 | Navigate to the audit logs section and retrieve logs for the actions performed in steps 2-4 | Audit logs are displayed showing all three actions (approval, rejection, escalation) |
| 7 | Verify the approval action log entry contains user identity, timestamp, action type, and comment 'Approved for testing purposes' | Log entry displays correct user identity, accurate timestamp, action type as 'APPROVED', and the exact comment text |
| 8 | Verify the rejection action log entry contains user identity, timestamp, action type, and comment 'Rejected due to resource constraints' | Log entry displays correct user identity, accurate timestamp, action type as 'REJECTED', and the exact comment text |
| 9 | Verify the escalation action log entry contains user identity, timestamp, action type, and comment 'Escalating to senior management' | Log entry displays correct user identity, accurate timestamp, action type as 'ESCALATED', and the exact comment text |
| 10 | Verify all timestamps are accurate and match the time when actions were performed (within acceptable system time variance) | All timestamps are accurate and reflect the actual time of action execution |

**Postconditions:**
- All approval workflow actions are logged in AuditLogs table
- Audit logs contain complete and accurate information
- System remains in stable state
- Test data is available for subsequent test cases

---

### Test Case: Validate access control to audit logs
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- System is operational with audit logging enabled
- Non-administrator user account exists (regular user or approver without admin rights)
- Administrator account with audit access exists
- Access control policies are properly configured
- Audit logs contain data from previous test execution

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as a non-administrator user (regular user without admin privileges) | User successfully logs in and standard user dashboard is displayed |
| 2 | Attempt to navigate directly to the audit logs URL or menu option | Audit logs menu option is not visible or navigation is blocked |
| 3 | Attempt to access audit logs via direct URL entry (e.g., /audit/logs) | Access is denied with HTTP 403 Forbidden error or appropriate access denied message |
| 4 | Verify the error message displayed indicates insufficient permissions | Error message states 'Access Denied: You do not have permission to view audit logs' or similar appropriate message |
| 5 | Attempt to access audit logs API endpoint GET /audit/logs using non-administrator credentials | API returns 403 Forbidden status code with error response indicating insufficient permissions |
| 6 | Log out from non-administrator account and log in as System Administrator | Administrator successfully logs into the audit portal with full access |
| 7 | Navigate to audit logs section | Audit logs are accessible and displayed successfully, confirming proper access control differentiation |
| 8 | Verify that the failed access attempt by non-administrator is logged in the audit trail | Audit log contains entry showing unauthorized access attempt with user identity and timestamp |

**Postconditions:**
- Access control policies remain enforced
- Unauthorized access attempt is logged
- System security is maintained
- No audit data was exposed to unauthorized users

---

### Test Case: Validate export functionality of audit logs
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Administrator account with audit access and export permissions is available
- System is operational and audit logs contain test data
- At least 5-10 audit log entries exist from previous test executions
- Export functionality is enabled in the system
- Browser allows file downloads
- CSV and PDF export libraries are properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as System Administrator | Administrator successfully logs into the audit portal |
| 2 | Navigate to the audit logs section | Audit logs page is displayed with list of audit entries |
| 3 | Apply filter to select audit logs for a specific date range (e.g., last 7 days) | Audit logs are filtered and display only entries within the specified date range |
| 4 | Locate and click the 'Export' button or menu option | Export options menu is displayed showing CSV and PDF format options |
| 5 | Select 'Export as CSV' option | CSV file download is initiated and file is saved to downloads folder |
| 6 | Open the downloaded CSV file using spreadsheet application (Excel, Google Sheets, etc.) | CSV file opens successfully and displays audit log data in tabular format |
| 7 | Verify CSV file contains all required columns: User Identity, Timestamp, Action Type, Request ID, Comments, and IP Address | All required columns are present with proper headers |
| 8 | Verify CSV file contains all filtered audit log entries with accurate data matching the portal display | All audit entries from the filtered view are present in CSV with correct data values |
| 9 | Return to audit logs page and click 'Export' button again, then select 'Export as PDF' option | PDF file download is initiated and file is saved to downloads folder |
| 10 | Open the downloaded PDF file using PDF reader application | PDF file opens successfully and displays audit log data in formatted report layout |
| 11 | Verify PDF file contains report header with title 'Audit Log Report', date range, and generation timestamp | PDF header displays proper report title, filter criteria, and generation timestamp |
| 12 | Verify PDF file contains all filtered audit log entries with all required fields in readable format | All audit entries are present in PDF with proper formatting, columns are aligned, and data is complete and readable |
| 13 | Compare data between CSV and PDF exports to ensure consistency | Both CSV and PDF files contain identical audit log data with same number of entries and matching values |
| 14 | Verify file names include timestamp or date identifier (e.g., audit_logs_2024-01-15.csv) | Both exported files have descriptive names with date/timestamp identifiers for easy identification |

**Postconditions:**
- CSV and PDF files are successfully generated and downloaded
- Exported files contain accurate and complete audit log data
- Export action is logged in the audit trail
- Downloaded files are available in the designated download location
- System remains in stable state ready for next operation

---

