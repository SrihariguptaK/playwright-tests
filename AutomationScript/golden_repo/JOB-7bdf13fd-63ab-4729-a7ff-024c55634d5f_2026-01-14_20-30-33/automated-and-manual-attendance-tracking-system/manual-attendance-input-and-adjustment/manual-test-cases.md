# Manual Test Cases

## Story: As HR Officer, I want to manually input attendance records to handle exceptions and corrections
**Story ID:** story-14

### Test Case: Validate manual attendance record creation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- HR officer account exists with valid credentials and manual attendance input permissions
- Attendance database is accessible and operational
- At least one valid employee record exists in the system
- No existing attendance record exists for the test employee at the target timestamp

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid HR officer credentials (username and password), then click Login button | HR officer is successfully authenticated and redirected to the dashboard with access to manual attendance input page option visible |
| 2 | Click on the manual attendance input page link from the navigation menu | Manual attendance input page loads successfully displaying input form with fields for employee selection, date, time-in, time-out, and submit button |
| 3 | Select a valid employee from the employee dropdown list | Employee is selected and displayed in the employee field |
| 4 | Enter a valid date in the date field (e.g., current date in DD/MM/YYYY format) | Date is accepted and displayed in the correct format |
| 5 | Enter valid time-in timestamp (e.g., 09:00 AM) | Time-in value is accepted and displayed in the correct time format |
| 6 | Enter valid time-out timestamp (e.g., 05:00 PM) that is after the time-in value | Time-out value is accepted and displayed in the correct time format |
| 7 | Click the Submit button to save the manual attendance record | System validates the input data, saves the manual attendance record to the database within 2 seconds, and displays a success confirmation message (e.g., 'Manual attendance record created successfully') |
| 8 | Navigate to the audit logs page from the navigation menu | Audit logs page loads successfully displaying a list of recent audit entries |
| 9 | Search or filter audit logs for the newly created manual attendance record using employee name and timestamp | Audit log entry is displayed showing the HR officer username, timestamp of creation, action type (CREATE), employee name, date, time-in, and time-out values matching the submitted data |

**Postconditions:**
- Manual attendance record is successfully saved in the attendance database
- Audit log entry is created with complete details of the manual input operation
- HR officer remains logged in to the system
- System is ready for additional manual attendance operations

---

### Test Case: Verify prevention of overlapping manual attendance entries
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- HR officer is logged in with valid credentials and manual attendance input permissions
- Manual attendance input page is accessible
- An existing attendance record exists for a specific employee (e.g., Employee A on 15/01/2024 from 09:00 AM to 05:00 PM)
- Attendance database is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the manual attendance input page | Manual attendance input page loads successfully with the input form displayed |
| 2 | Select the same employee (Employee A) who already has an existing attendance record for the target date | Employee A is selected and displayed in the employee field |
| 3 | Enter the same date as the existing record (15/01/2024) | Date is accepted and displayed in the date field |
| 4 | Enter a time-in value that overlaps with the existing record (e.g., 10:00 AM which falls within 09:00 AM to 05:00 PM) | Time-in value is entered and displayed |
| 5 | Enter a time-out value (e.g., 06:00 PM) | Time-out value is entered and displayed |
| 6 | Click the Submit button to attempt saving the overlapping manual attendance record | System performs validation, detects the overlapping attendance period, prevents the record from being saved, and displays a clear validation error message (e.g., 'Error: Attendance record overlaps with existing entry for this employee on this date. Please verify the time period.') |
| 7 | Verify that the form remains on the screen with the entered data still visible | Input form remains displayed with all entered values intact, allowing the HR officer to correct the data |
| 8 | Query the attendance database or view attendance records for Employee A on 15/01/2024 | Only the original attendance record (09:00 AM to 05:00 PM) exists; no duplicate or overlapping record has been created |

**Postconditions:**
- No overlapping attendance record is saved in the database
- Data integrity is maintained with only valid non-overlapping records
- HR officer can correct the input and resubmit
- No audit log entry is created for the rejected submission

---

### Test Case: Ensure unauthorized users cannot perform manual attendance operations
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- A non-HR user account exists with valid credentials but without manual attendance input permissions (e.g., regular employee or manager role)
- Manual attendance API endpoints are configured with role-based access control
- Authentication and authorization mechanisms are active
- System is operational and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid non-HR user credentials (username and password), then click Login button | Non-HR user is successfully authenticated and redirected to their role-appropriate dashboard |
| 2 | Attempt to navigate to the manual attendance input page by entering the URL directly in the browser or looking for the option in the navigation menu | Access is denied with an appropriate error message (e.g., 'Access Denied: You do not have permission to access this page') or the manual attendance input option is not visible in the navigation menu. User is either redirected to the dashboard or shown an access denied page |
| 3 | Open browser developer tools or API testing tool (e.g., Postman) and attempt to make a POST request to the manual attendance API endpoint (POST /api/manual-attendance) with valid attendance data in the request body | API returns HTTP 401 Unauthorized or 403 Forbidden status code with an authorization error message (e.g., 'Authorization error: Insufficient permissions to perform this operation') |
| 4 | Attempt to make a PUT request to the manual attendance API endpoint (PUT /api/manual-attendance/{id}) to edit an existing record | API returns HTTP 401 Unauthorized or 403 Forbidden status code with an authorization error message indicating insufficient permissions |
| 5 | Attempt to make a DELETE request to the manual attendance API endpoint (DELETE /api/manual-attendance/{id}) to delete an existing record | API returns HTTP 401 Unauthorized or 403 Forbidden status code with an authorization error message indicating insufficient permissions |
| 6 | Verify the attendance database to ensure no records were created, modified, or deleted by the unauthorized user | Attendance database remains unchanged with no unauthorized modifications |
| 7 | Check audit logs for any unauthorized access attempts | Audit logs may contain entries showing failed authorization attempts by the non-HR user, but no successful manual attendance operations are logged |

**Postconditions:**
- No unauthorized changes are made to the attendance database
- System security and role-based access control remain intact
- Non-HR user remains logged in with access only to their authorized features
- Failed authorization attempts may be logged for security monitoring

---

## Story: As HR Officer, I want to view audit logs of manual attendance changes to ensure data integrity
**Story ID:** story-15

### Test Case: Validate audit log retrieval and filtering
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- HR officer account exists with valid credentials and audit log access permissions
- Audit log database contains multiple manual attendance change entries with various users, dates, and employees
- At least 5-10 audit log entries exist for testing filtering functionality
- System is operational and audit logs API is accessible
- PDF and CSV export functionality is configured and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system as an authorized HR officer using valid credentials | HR officer is successfully authenticated and redirected to the dashboard with audit logs option visible in the navigation menu |
| 2 | Click on the audit logs link from the navigation menu | Audit logs page loads successfully within 3 seconds displaying the audit logs UI with a list of recent audit entries in a table format showing columns for timestamp, user, action type, employee, date, and change details |
| 3 | Review the displayed audit log entries without applying any filters | All available audit log entries are displayed in reverse chronological order (most recent first) with complete information including user who made the change, timestamp, action performed (CREATE/UPDATE/DELETE), employee affected, and specific change details |
| 4 | Locate the filter section on the audit logs page and select a specific user from the user filter dropdown | User filter is applied and the audit log list refreshes to display only entries where the selected user performed manual attendance operations |
| 5 | Apply an additional date range filter by selecting a start date and end date (e.g., last 7 days) | Combined filters are applied and the audit log list displays only entries matching both the selected user and the specified date range. Results load within 3 seconds |
| 6 | Verify the filtered results by checking that all displayed entries match the applied filter criteria (correct user and within date range) | All displayed audit log entries match the filter criteria with correct user and timestamps falling within the selected date range |
| 7 | Clear the existing filters and apply a new filter by selecting a specific employee from the employee filter dropdown | Employee filter is applied and the audit log list displays only entries related to manual attendance changes for the selected employee |
| 8 | Locate the export button and click on 'Export as PDF' option | System generates a PDF file containing the currently filtered audit log entries with proper formatting, headers, and all relevant columns. PDF file download begins automatically or a download link is provided |
| 9 | Open the downloaded PDF file using a PDF reader | PDF file opens successfully displaying the audit log data in a well-formatted table with all columns (timestamp, user, action, employee, change details) clearly visible and readable |
| 10 | Return to the audit logs page and click on 'Export as CSV' option | System generates a CSV file containing the currently filtered audit log entries. CSV file download begins automatically or a download link is provided |
| 11 | Open the downloaded CSV file using a spreadsheet application (e.g., Excel, Google Sheets) | CSV file opens successfully with audit log data properly structured in columns with headers (timestamp, user, action, employee, change details) and all data values correctly populated and readable |
| 12 | Verify that both exported files (PDF and CSV) contain the same filtered data that was displayed on the audit logs page | Both PDF and CSV exports contain identical data matching the filtered results shown on the audit logs UI, confirming data consistency across all formats |

**Postconditions:**
- Audit logs are successfully retrieved and displayed with accurate information
- Filters are applied correctly and results match the filter criteria
- PDF and CSV files are generated and downloaded successfully
- Exported files contain accurate and complete audit log data
- HR officer remains logged in and can perform additional audit log operations
- System maintains audit log data integrity and availability

---

### Test Case: Verify access restriction for unauthorized users
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- A non-HR user account exists with valid credentials but without audit log access permissions (e.g., regular employee or manager role)
- Audit logs API endpoint is configured with role-based access control (GET /api/manual-attendance/audit-logs)
- Authentication and authorization mechanisms are active and properly configured
- Audit log database contains data but should not be accessible to unauthorized users
- System is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid non-HR user credentials (username and password), then click Login button | Non-HR user is successfully authenticated and redirected to their role-appropriate dashboard without audit logs access option |
| 2 | Check the navigation menu for audit logs option | Audit logs link is not visible in the navigation menu for the non-HR user, indicating proper UI-level access control |
| 3 | Attempt to access the audit logs page directly by entering the audit logs URL in the browser address bar (e.g., /audit-logs or /manual-attendance/audit-logs) | Access is denied and the system displays an appropriate error message (e.g., 'Access Denied: You do not have permission to view audit logs') or redirects the user to their dashboard or an access denied page. HTTP 403 Forbidden status is returned |
| 4 | Open browser developer tools or API testing tool (e.g., Postman, cURL) and attempt to make a GET request to the audit logs API endpoint (GET /api/manual-attendance/audit-logs) using the non-HR user's authentication token | API returns HTTP 401 Unauthorized or 403 Forbidden status code with an authorization error message in the response body (e.g., 'Authorization error: Insufficient permissions to access audit logs') |
| 5 | Attempt to make a GET request with query parameters to filter audit logs (e.g., GET /api/manual-attendance/audit-logs?user=someuser&date=2024-01-15) | API returns HTTP 401 Unauthorized or 403 Forbidden status code with an authorization error message, preventing any access to audit log data regardless of query parameters |
| 6 | Verify that no audit log data is returned in any API response to the unauthorized user | No audit log data is exposed or returned in any API response. Response body contains only the authorization error message without any sensitive audit information |
| 7 | Check system security logs or audit logs (as an authorized administrator) for the unauthorized access attempts | Security logs or audit logs contain entries showing the failed authorization attempts by the non-HR user, including timestamp, username, attempted resource, and denial reason for security monitoring purposes |
| 8 | Verify that the non-HR user can still access their authorized features and pages | Non-HR user retains access to their authorized features and can navigate to pages appropriate for their role, confirming that access denial is specific to audit logs only |

**Postconditions:**
- No audit log data is exposed to unauthorized users
- System security and role-based access control for audit logs remain intact
- Failed access attempts are logged for security monitoring
- Non-HR user remains logged in with access only to their authorized features
- Audit log data integrity and confidentiality are maintained
- Zero unauthorized audit log access incidents are recorded

---

