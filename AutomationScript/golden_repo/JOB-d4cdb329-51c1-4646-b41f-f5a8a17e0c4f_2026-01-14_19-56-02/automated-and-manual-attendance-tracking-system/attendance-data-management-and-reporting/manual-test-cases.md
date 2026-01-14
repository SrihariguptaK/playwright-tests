# Manual Test Cases

## Story: As HR Analyst, I want to generate attendance reports combining biometric and manual data to achieve comprehensive attendance insights
**Story ID:** story-3

### Test Case: Generate attendance report with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- HR Analyst user account exists with appropriate permissions
- User is logged into the reporting portal
- Attendance database contains both biometric and manual attendance records
- Test data includes attendance records for multiple employees across different date ranges
- System is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to attendance reports section from the main dashboard | Report filter form is displayed with options for date range, employee, and department filters |
| 2 | Select a start date and end date for the date range filter (e.g., 01/01/2024 to 31/01/2024) | Date range is accepted and displayed in the filter fields without validation errors |
| 3 | Select one or more employees from the employee filter dropdown | Selected employees are displayed in the filter section and filters are accepted without errors |
| 4 | Click the 'Generate Report' button | Report is generated and displays aggregated attendance data that matches the selected filters, showing both biometric and manual attendance entries for the specified employees and date range |
| 5 | Verify the report contains summary statistics and displays data in a readable format | Report shows attendance records with employee names, dates, check-in/check-out times, attendance type (biometric/manual), and summary statistics |

**Postconditions:**
- Report is displayed on screen with filtered data
- Report data matches the applied filters
- User remains logged in and can perform additional actions
- System logs the report generation activity

---

### Test Case: Export attendance report to CSV and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- HR Analyst user is logged into the reporting portal
- User has navigated to the attendance reports section
- Attendance data exists in the system
- Browser allows file downloads
- User has appropriate export permissions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select date range and any desired filters for the attendance report | Filters are applied successfully |
| 2 | Click the 'Generate Report' button | Report is displayed on screen with attendance data including employee names, dates, times, and attendance types |
| 3 | Locate and click the 'Export to CSV' button | CSV file is downloaded to the default download location with filename format 'attendance_report_YYYYMMDD.csv' |
| 4 | Open the downloaded CSV file using a text editor or spreadsheet application | CSV file opens successfully and contains all report data with correct formatting, including headers and all data rows matching the displayed report without data loss |
| 5 | Return to the report page and click the 'Export to Excel' button | Excel file (.xlsx) is downloaded to the default download location with filename format 'attendance_report_YYYYMMDD.xlsx' |
| 6 | Open the downloaded Excel file using Microsoft Excel or compatible application | Excel file opens successfully and contains all report data with proper formatting, including headers, data rows, and cell formatting matching the displayed report without data loss |
| 7 | Compare the data in both exported files with the on-screen report | Both CSV and Excel exports contain identical data to the on-screen report with no missing or corrupted records |

**Postconditions:**
- Two files are downloaded successfully (CSV and Excel formats)
- Both files contain complete and accurate attendance data
- Files are accessible and readable in their respective applications
- Export activity is logged in the system
- User remains on the report page

---

### Test Case: Schedule automated attendance report
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- HR Analyst user is logged into the reporting portal
- User has permissions to schedule automated reports
- Email delivery system is configured and operational
- Valid email addresses are available for report delivery
- System scheduler service is running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance reports section and locate the 'Schedule Report' option | Scheduling interface or button is visible and accessible |
| 2 | Click on 'Schedule Report' button | Scheduling form is displayed with fields for report name, frequency (daily/weekly/monthly), time, filters, format, and recipient email addresses |
| 3 | Enter a report name (e.g., 'Monthly Attendance Summary') | Report name is accepted and displayed in the field |
| 4 | Select report frequency as 'Weekly' and choose day of week (e.g., Monday) | Frequency and day selections are accepted |
| 5 | Set the time for report generation (e.g., 08:00 AM) | Time is accepted and displayed in the correct format |
| 6 | Configure report filters (date range: previous 7 days, department: All) | Filter parameters are accepted and displayed |
| 7 | Select export format as 'Excel' and enter recipient email addresses | Format and email addresses are validated and accepted |
| 8 | Click 'Save Schedule' button | Schedule is saved successfully and a confirmation message is displayed with schedule details |
| 9 | Navigate to 'Scheduled Reports' list view | The newly created schedule appears in the list with correct parameters and status as 'Active' |
| 10 | Wait for the scheduled time or trigger a test execution of the scheduled report | Report is generated automatically at the scheduled time |
| 11 | Check the recipient email inbox for the scheduled report | Email is received with the attendance report attached in Excel format, containing data matching the configured filters and schedule parameters |

**Postconditions:**
- Scheduled report is saved and active in the system
- Schedule appears in the list of automated reports
- Report will be generated and delivered according to the schedule
- Email notifications are sent to specified recipients
- Schedule activity is logged in the system

---

## Story: As System Auditor, I want to review audit logs of biometric and manual attendance entries to ensure compliance and traceability
**Story ID:** story-5

### Test Case: Verify audit logging of attendance events
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- System Auditor user account exists with audit log access permissions
- Audit logging service is enabled and operational
- Biometric device is connected and functional
- Test employee records exist in the system
- User with manual attendance entry permissions is available
- Audit log database is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Perform a biometric attendance capture by scanning fingerprint or using biometric device for a test employee | Biometric attendance is captured successfully and confirmation message is displayed |
| 2 | Login as System Auditor and navigate to the audit log interface | Audit log interface is displayed with search and filter options |
| 3 | Search for the most recent audit log entry for the test employee's biometric attendance | Audit log entry is displayed showing event type as 'Biometric Attendance Capture', employee ID, timestamp, biometric device ID, and status |
| 4 | Verify the audit log entry contains all required metadata (timestamp, user ID, employee ID, action type, IP address, device information) | All metadata fields are populated with correct and complete information |
| 5 | Logout as Auditor and login as a user with manual attendance entry permissions | User is logged in successfully with access to manual attendance entry interface |
| 6 | Add a manual attendance entry for a test employee with date, check-in time, and reason | Manual attendance entry is saved successfully and confirmation message is displayed |
| 7 | Login again as System Auditor and search audit logs for the manual attendance entry | Audit log entry is created showing event type as 'Manual Attendance Entry Created', with user ID of the person who created it, employee ID, timestamp, and entry details |
| 8 | Navigate back to manual attendance interface (as authorized user) and edit the previously created manual attendance entry by changing the check-in time | Manual attendance entry is updated successfully |
| 9 | Login as System Auditor and search audit logs for the modification event | Audit log entry is created showing event type as 'Manual Attendance Entry Modified', with user ID, timestamp, employee ID, old values, new values, and modification reason |
| 10 | Verify all three audit log entries contain complete traceability information | All audit log entries show complete audit trail with who performed the action, what was changed, when it occurred, and from which location/device |

**Postconditions:**
- All attendance events are logged in the audit database
- Audit logs contain complete metadata for traceability
- Audit logs are searchable and retrievable
- No attendance events are missing from audit logs
- System maintains data integrity

---

### Test Case: Search and export audit logs
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- System Auditor user account exists with valid credentials
- Audit log database contains historical attendance event logs
- Multiple audit log entries exist for different employees and date ranges
- System is operational and audit log interface is accessible
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the audit portal login page and enter System Auditor credentials | Login is successful and user is redirected to the auditor dashboard |
| 2 | Verify that access is granted to the audit log interface | Audit log interface is displayed with search filters and log entries table |
| 3 | Select a specific employee from the employee filter dropdown | Employee is selected and displayed in the filter |
| 4 | Enter a date range filter (e.g., start date: 01/01/2024, end date: 31/01/2024) | Date range is accepted and displayed in the filter fields |
| 5 | Click 'Search' or 'Apply Filters' button and start a timer | Search is executed and filtered audit logs are displayed within 5 seconds |
| 6 | Verify the search results display only logs matching the selected employee and date range | All displayed log entries match the filter criteria with correct employee name and dates within the specified range |
| 7 | Review the displayed audit log entries for completeness (timestamp, action type, user, details) | Each log entry shows complete information including timestamp, event type, user who performed action, employee affected, and action details |
| 8 | Locate and click the 'Export to CSV' button | CSV file is downloaded with filename format 'audit_logs_YYYYMMDD_HHMMSS.csv' |
| 9 | Open the downloaded CSV file using a text editor or spreadsheet application | CSV file opens successfully and contains all filtered audit log entries with headers and complete data matching the on-screen results |
| 10 | Verify the exported CSV contains all columns (timestamp, event type, user ID, employee ID, action details, IP address, device info) | All data columns are present in the CSV with correct data and no missing or corrupted information |

**Postconditions:**
- Audit logs are successfully searched and filtered
- Search results are returned within performance SLA (5 seconds)
- CSV export file is downloaded with complete data
- Export activity is logged in the system
- User remains logged in to the audit portal

---

### Test Case: Restrict audit log access to authorized users
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System has role-based access control configured
- Non-auditor user account exists (e.g., HR Analyst, Employee, Manager)
- Audit log interface and API endpoints are protected by authorization
- System Auditor role is properly configured with audit log permissions
- API authentication is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using non-auditor user credentials (e.g., HR Analyst account) | Login is successful and user is redirected to their appropriate dashboard |
| 2 | Attempt to navigate to the audit logs section by entering the audit log URL directly or looking for audit log menu option | Access to audit logs is denied with an error message stating 'Access Denied: Insufficient Permissions' or 'You do not have permission to view audit logs', and user is redirected to their dashboard or an error page |
| 3 | Verify that no audit log menu option or navigation link is visible in the user interface for non-auditor users | Audit log menu items and navigation links are not displayed in the interface for non-auditor roles |
| 4 | Open browser developer tools and attempt to access the audit log API endpoint directly (GET /api/audit/logs) using the current session token | API request returns HTTP 403 Forbidden status code with error message 'Authorization error: User does not have auditor role' |
| 5 | Attempt to access audit log API with different parameters (e.g., GET /api/audit/logs?employee=123&date=2024-01-01) | API request returns HTTP 403 Forbidden status code with authorization error, regardless of query parameters |
| 6 | Logout and login as a System Auditor user | Login is successful and auditor dashboard is displayed |
| 7 | Navigate to the audit logs section | Access is granted and audit log interface is displayed with full functionality |
| 8 | Verify that the System Auditor can successfully view and search audit logs | Audit logs are accessible, searchable, and all features are functional for the authorized auditor user |
| 9 | Check system logs for the unauthorized access attempts | System logs record the unauthorized access attempts with user ID, timestamp, and denied action details |

**Postconditions:**
- Non-auditor users cannot access audit logs through UI or API
- Authorization errors are properly returned for unauthorized access attempts
- System Auditor users retain full access to audit logs
- Unauthorized access attempts are logged for security monitoring
- System security controls are functioning as designed

---

## Story: As Attendance Supervisor, I want to receive alerts for attendance anomalies to proactively address issues
**Story ID:** story-7

### Test Case: Detect and alert missing attendance records
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Attendance system is operational and accessible
- Supervisor account with valid credentials exists
- Email notification service is configured and active
- At least one employee with expected attendance schedule exists in the system
- Anomaly detection service is running and scheduled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate missing attendance record for an employee by ensuring no check-in/check-out entry exists for a scheduled work day | System detects the missing attendance record anomaly and generates an alert within 1 hour of detection |
| 2 | Login as Supervisor and check email inbox and system notification panel | Supervisor receives alert via both email and system notification containing detailed information about the missing record including employee name, date, expected schedule, and anomaly type |
| 3 | Navigate to the anomaly details page and click 'Mark as Resolved' button | Anomaly status is updated to 'Resolved', alert is cleared from active notifications, and confirmation message is displayed |

**Postconditions:**
- Anomaly is marked as resolved in the system
- Alert is removed from active notifications list
- Audit log contains record of resolution action with supervisor ID and timestamp

---

### Test Case: Detect and alert duplicate attendance entries
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Attendance system is operational and accessible
- Supervisor account with valid credentials exists
- Email notification service is configured and active
- At least one employee exists in the system
- Anomaly detection service is running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create duplicate attendance entries for an employee by submitting two identical check-in/check-out records for the same date and time | System detects the duplicate attendance entries and generates an alert within 1 hour of detection |
| 2 | Login as Supervisor and navigate to anomaly alerts section to review the duplicate entry alert details | Alert is displayed with detailed information including employee name, date, time, duplicate entry details, entry IDs, and suggested corrective action to remove duplicate |

**Postconditions:**
- Duplicate anomaly alert remains active until resolved
- Alert details are accessible to supervisor for review and action

---

### Test Case: Restrict alert access to supervisors
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Attendance system is operational and accessible
- Non-supervisor user account with valid credentials exists
- At least one active anomaly alert exists in the system
- API endpoints for anomaly access are configured with role-based authentication

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the attendance system using non-supervisor user credentials | User successfully logs in but access to anomaly alerts section is denied or not visible in navigation menu |
| 2 | Attempt to directly access anomaly alerts page via URL or attempt API call to GET /api/attendance/anomalies endpoint | System returns authorization error (HTTP 403 Forbidden) with message indicating insufficient permissions to access anomaly alerts |

**Postconditions:**
- Non-supervisor user remains unable to access anomaly alerts
- Security audit log records unauthorized access attempt with user ID and timestamp
- System security integrity is maintained

---

## Story: As HR Manager, I want to configure attendance tracking policies to align system behavior with organizational rules
**Story ID:** story-9

### Test Case: Configure and save attendance policies successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Attendance system is operational and accessible
- HR Manager account with valid credentials exists
- Policy configuration portal is accessible
- Database connection for policy storage is active
- User has HR Manager role assigned with policy configuration permissions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance system login page and enter HR Manager credentials, then click Login button | HR Manager is successfully authenticated and redirected to dashboard with access to policy configuration UI visible in navigation menu |
| 2 | Navigate to attendance policy settings page and define working hours (e.g., 9:00 AM - 5:00 PM) and grace periods (e.g., 15 minutes for late arrival, 10 minutes for early departure) | Input fields accept the values without validation errors, fields are properly formatted, and no error messages are displayed |
| 3 | Click 'Save' button to save the policy changes | Policy changes are successfully saved to the database, confirmation message is displayed (e.g., 'Policy updated successfully'), and policy summary shows updated values |

**Postconditions:**
- New attendance policy is saved in the policy configuration database
- Policy changes are logged in audit trail with HR Manager ID and timestamp
- Updated policies are applied to attendance processing within 5 minutes
- Policy summary reflects the new configuration

---

### Test Case: Validate policy parameter errors
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Attendance system is operational and accessible
- HR Manager is logged in with valid credentials
- Policy configuration page is accessible
- Validation rules for policy parameters are configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to attendance policy settings and enter inconsistent or invalid policy parameters such as negative grace period (e.g., -15 minutes) or end time before start time | System displays validation error messages next to the invalid fields indicating the specific errors (e.g., 'Grace period cannot be negative', 'End time must be after start time') |
| 2 | Click 'Save' button while validation errors are present | Save operation is blocked, error summary is displayed at the top of the form, and user is prompted to correct errors before saving. No changes are persisted to the database |

**Postconditions:**
- Invalid policy parameters are not saved to the database
- Existing policy configuration remains unchanged
- User remains on policy configuration page with error messages visible
- No audit log entry is created for failed save attempt

---

### Test Case: Restrict policy configuration access
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Attendance system is operational and accessible
- Non-HR user account with valid credentials exists
- Policy configuration portal has role-based access control enabled
- API endpoints for policy management are secured with authentication

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the attendance system using non-HR user credentials (e.g., regular employee or supervisor without HR role) | User successfully logs in but policy configuration option is not visible in navigation menu or dashboard, access to policy configuration UI is denied |
| 2 | Attempt to directly access policy configuration page via URL or make API call to GET/POST /api/policies/attendance endpoints | System returns authorization error (HTTP 403 Forbidden) with message indicating insufficient permissions such as 'Access denied: HR Manager role required' |

**Postconditions:**
- Non-HR user remains unable to access policy configuration features
- Security audit log records unauthorized access attempt with user ID, timestamp, and attempted resource
- Policy configuration data remains secure and unchanged
- System access control integrity is maintained

---

## Story: As Attendance Manager, I want to audit attendance data changes to ensure data integrity and compliance
**Story ID:** story-10

### Test Case: Verify audit logging of attendance data changes
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has Attendance Manager role with permissions to create, update, and delete attendance records
- User is logged into the attendance management system
- Audit logging service is active and operational
- Database has sufficient storage for audit logs
- Test employee record exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the manual attendance entry page | Manual attendance entry form is displayed with all required fields |
| 2 | Create a new manual attendance entry by selecting employee, entering date (today's date), check-in time (09:00 AM), and check-out time (05:00 PM), then click Save | Success message displayed confirming attendance entry created. Entry appears in attendance records list |
| 3 | Navigate to the audit log interface and search for the most recent create action for the employee | Audit log entry is displayed showing: Action Type = 'CREATE', User = current logged-in user, Timestamp = current date/time, Record Details = employee ID, date, check-in/check-out times, Status = 'Success' |
| 4 | Navigate back to attendance records, locate the newly created entry, click Edit, change check-out time to 06:00 PM, and click Save | Success message displayed confirming attendance entry updated. Updated time is reflected in the attendance records list |
| 5 | Return to the audit log interface and search for the most recent update action for the employee | Audit log entry is displayed showing: Action Type = 'UPDATE', User = current logged-in user, Timestamp = current date/time, Old Value = '05:00 PM', New Value = '06:00 PM', Field Changed = 'check-out time', Status = 'Success' |
| 6 | Navigate back to attendance records, locate the updated entry, click Delete, and confirm deletion | Success message displayed confirming attendance entry deleted. Entry is removed from attendance records list |
| 7 | Return to the audit log interface and search for the most recent delete action for the employee | Audit log entry is displayed showing: Action Type = 'DELETE', User = current logged-in user, Timestamp = current date/time, Deleted Record Details = employee ID, date, check-in/check-out times, Status = 'Success' |
| 8 | Verify all three audit log entries (create, update, delete) contain complete metadata including user ID, username, IP address, and session ID | All audit log entries display complete metadata: User ID, Username, IP Address, Session ID, Timestamp (with timezone), Action Type, Record ID, Before/After values where applicable |

**Postconditions:**
- Three audit log entries exist for the test attendance record (create, update, delete)
- All audit logs contain accurate timestamps and user information
- Test attendance record is deleted from the system
- Audit logs remain intact and accessible for future reference

---

### Test Case: Search and export attendance audit logs
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has valid Attendance Manager credentials
- Audit log database contains at least 10 attendance-related audit entries
- Audit entries exist for multiple users and date ranges
- System supports CSV export functionality
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid Attendance Manager username and password, then click Login | User is successfully authenticated and redirected to the dashboard. Welcome message displays with user's name and role |
| 2 | From the main navigation menu, click on 'Audit' or 'Audit Logs' section | Audit log interface is displayed showing the attendance data audit section with search filters and audit log table |
| 3 | Verify the audit log interface displays filter options for User, Date Range, and Action Type | Filter panel is visible with dropdown for User selection, date picker for Start Date and End Date, and dropdown for Action Type (Create, Update, Delete, All) |
| 4 | Select a specific user from the User filter dropdown | User is selected and displayed in the filter field |
| 5 | Set the date range filter by selecting Start Date as 7 days ago and End Date as today | Date range is set and displayed in the filter fields |
| 6 | Click the 'Search' or 'Apply Filters' button and start a timer | Filtered audit logs are displayed in the table within 5 seconds. Results show only entries matching the selected user and date range. Timer confirms response time is under 5 seconds |
| 7 | Verify the displayed audit log entries contain columns: Timestamp, User, Action Type, Record ID, Details, IP Address, and Status | All specified columns are visible and populated with data. Data is sorted by timestamp in descending order (most recent first) |
| 8 | Change the Action Type filter to 'UPDATE' and click Search again | Results refresh within 5 seconds showing only UPDATE actions for the selected user and date range |
| 9 | Click the 'Export' or 'Export to CSV' button | Export dialog appears or CSV file download begins immediately. File name follows format: 'attendance_audit_logs_YYYYMMDD_HHMMSS.csv' |
| 10 | Open the downloaded CSV file in a spreadsheet application | CSV file opens successfully and contains all filtered audit log entries with proper column headers: Timestamp, User ID, Username, Action Type, Record ID, Field Changed, Old Value, New Value, IP Address, Session ID, Status |
| 11 | Verify the data in the CSV matches the data displayed in the audit log interface | All rows in CSV match the filtered results shown in the interface. Data integrity is maintained with no missing or corrupted entries |
| 12 | Clear all filters and click Search to view all audit logs | All attendance audit logs are displayed within 5 seconds, showing entries for all users, dates, and action types |

**Postconditions:**
- User remains logged in as Attendance Manager
- CSV file is successfully downloaded and saved to local system
- Audit log interface remains accessible for further queries
- No changes made to audit log data
- Search filters can be reset for new queries

---

### Test Case: Restrict audit log access to authorized users
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- System has role-based access control (RBAC) implemented
- Test user account exists with a role other than Attendance Manager (e.g., Regular Employee, HR Staff without audit permissions)
- Audit log API endpoints are protected with authorization checks
- Valid Attendance Manager account exists for comparison
- API testing tool or browser developer tools available for API testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter credentials for an unauthorized user (non-Attendance Manager role), then click Login | User is successfully authenticated and redirected to their role-appropriate dashboard |
| 2 | Attempt to navigate to the audit log interface by entering the audit log URL directly in the browser address bar (e.g., /audit/attendance) | Access is denied. User is redirected to an error page or dashboard with message: 'Access Denied - You do not have permission to view audit logs' or 'Unauthorized Access - Attendance Manager role required' |
| 3 | Check the main navigation menu for any audit or audit log menu items | Audit log menu items are not visible or are disabled/grayed out for the unauthorized user |
| 4 | Open browser developer tools, navigate to Network tab, and attempt to make a direct GET request to the audit log API endpoint: GET /api/audit/attendance | API returns HTTP 403 Forbidden or HTTP 401 Unauthorized status code with error response body: {'error': 'Unauthorized', 'message': 'Insufficient permissions to access audit logs'} |
| 5 | Attempt to access audit logs with query parameters by making a GET request to: GET /api/audit/attendance?userId=123&startDate=2024-01-01&endDate=2024-01-31 | API returns HTTP 403 Forbidden or HTTP 401 Unauthorized status code. No audit log data is returned in the response |
| 6 | Attempt to export audit logs by making a GET request to: GET /api/audit/attendance/export?format=csv | API returns HTTP 403 Forbidden or HTTP 401 Unauthorized status code. No CSV file is generated or downloaded |
| 7 | Log out the unauthorized user and log in with valid Attendance Manager credentials | Attendance Manager is successfully authenticated and redirected to dashboard with full access rights |
| 8 | Navigate to the audit log interface from the main menu | Audit log interface is accessible and displays successfully. Audit log menu item is visible and clickable |
| 9 | Make a GET request to the audit log API endpoint: GET /api/audit/attendance using the Attendance Manager session | API returns HTTP 200 OK status code with audit log data in JSON format. Response contains array of audit log entries with all required fields |
| 10 | Verify that the authorization error messages do not expose sensitive system information or internal architecture details | Error messages are generic and security-focused. No stack traces, database details, or internal system paths are exposed in error responses |

**Postconditions:**
- Unauthorized user cannot access audit logs through UI or API
- Authorized Attendance Manager retains full access to audit logs
- All unauthorized access attempts are logged in security audit trail
- System security remains intact with no data leakage
- Role-based access control is confirmed to be functioning correctly

---

