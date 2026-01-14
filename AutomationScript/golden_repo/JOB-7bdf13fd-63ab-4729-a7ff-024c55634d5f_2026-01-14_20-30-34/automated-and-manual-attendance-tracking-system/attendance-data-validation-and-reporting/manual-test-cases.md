# Manual Test Cases

## Story: As Attendance Analyst, I want to generate attendance anomaly reports to identify missing or duplicate records
**Story ID:** story-16

### Test Case: Validate detection of missing attendance punches
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Attendance Analyst with valid credentials
- Test data exists with known missing check-ins and check-outs for specific date range
- Attendance database contains at least 5 employees with missing punches
- Reporting dashboard is accessible and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting dashboard | Reporting dashboard loads successfully with anomaly report options visible |
| 2 | Select 'Anomaly Report' from the report type dropdown | Anomaly report configuration panel is displayed |
| 3 | Select date range that includes known missing punches (e.g., last 7 days) | Date range is accepted and displayed in the selection field |
| 4 | Click 'Generate Report' button | System processes the request and generates the report within 5 seconds |
| 5 | Review the generated anomaly report for missing check-ins and check-outs | Report lists all missing check-ins and check-outs accurately with employee names, dates, and punch type (check-in/check-out) |
| 6 | Verify that all known missing punches from test data are present in the report | All expected missing punches are displayed with correct details and no false positives are shown |

**Postconditions:**
- Anomaly report is displayed on screen
- Report data matches the attendance database records
- System logs the report generation activity
- Report is available for export or further review

---

### Test Case: Verify identification of duplicate attendance entries
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Attendance Analyst with valid credentials
- Test data exists with known duplicate attendance entries for specific date range
- Attendance database contains at least 3 employees with duplicate punch records
- Reporting dashboard is accessible and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting dashboard | Reporting dashboard loads successfully |
| 2 | Select 'Anomaly Report' from the report type dropdown | Anomaly report configuration panel is displayed |
| 3 | Select date range that includes known duplicate entries (e.g., specific week with duplicates) | Date range is accepted and displayed in the selection field |
| 4 | Click 'Generate Report' button | System processes the request and generates the report within 5 seconds |
| 5 | Review the generated anomaly report for duplicate attendance entries section | Report highlights duplicate attendance records with details including employee name, date, time, and number of duplicates |
| 6 | Verify that all known duplicate entries from test data are identified in the report | All expected duplicate entries are displayed with accurate details and visual highlighting (e.g., color coding or icons) |
| 7 | Check that duplicate entries show both original and duplicate timestamps | Report displays complete information for each duplicate instance with timestamps and punch details |

**Postconditions:**
- Anomaly report with duplicate entries is displayed
- Duplicate records are clearly highlighted and distinguishable
- System logs the report generation activity
- Report is ready for export or follow-up action

---

### Test Case: Ensure unauthorized users cannot access anomaly reports
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Test user account exists with non-analyst role (e.g., Employee or Manager role)
- Anomaly report API endpoint is active and secured with role-based access control
- Authentication system is functional
- API testing tool or browser console is available for API testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system as non-analyst user (e.g., regular employee) | User successfully logs in and is redirected to their role-appropriate dashboard |
| 2 | Attempt to navigate to the reporting dashboard URL directly | Access to anomaly reports is denied with appropriate error message (e.g., 'Access Denied' or '403 Forbidden') |
| 3 | Verify that anomaly report menu options are not visible in the navigation | Anomaly report options are hidden or not displayed in the user interface |
| 4 | Logout from the non-analyst user account | User is successfully logged out and redirected to login page |
| 5 | Login again as non-analyst user and obtain authentication token | User logs in successfully and authentication token is available |
| 6 | Attempt to call anomaly report API endpoint (GET /api/reports/anomalies) using the non-analyst user's token | Authorization error is returned with HTTP status code 403 and error message indicating insufficient permissions |
| 7 | Verify the error response contains appropriate security message | Response includes clear error message such as 'Unauthorized access' or 'Insufficient privileges to access this resource' |

**Postconditions:**
- Non-analyst user remains unable to access anomaly reports
- Security logs record the unauthorized access attempts
- System security remains intact with no data exposure
- User session remains active for their authorized functions

---

## Story: As Attendance Analyst, I want to export attendance reports to share with management for compliance review
**Story ID:** story-17

### Test Case: Validate successful export of attendance report in PDF
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Attendance Analyst with valid credentials and export permissions
- Attendance data exists for the selected date range
- Reporting system is functional and accessible
- Export functionality is enabled for the user role
- PDF generation service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting dashboard | Reporting dashboard loads successfully with report generation options |
| 2 | Select 'Attendance Report' from the report type dropdown | Attendance report configuration panel is displayed |
| 3 | Apply filters (e.g., select date range, department, or specific employees) | Filters are applied and displayed in the filter summary section |
| 4 | Click 'Generate Report' button | Report is generated and displayed on screen with filtered data within 5 seconds |
| 5 | Review the displayed report to note the content and applied filters | Report shows attendance data matching the applied filters with correct employee names, dates, and punch times |
| 6 | Click on 'Export' button and select 'PDF' format from the export options | PDF export option is selected and export dialog or confirmation appears |
| 7 | Click 'Initiate Export' or 'Download' button | Export process starts with progress indicator displayed |
| 8 | Wait for export completion | Export completes within 10 seconds and download link or file download prompt is provided |
| 9 | Download the PDF file using the provided link | PDF file downloads successfully to local system |
| 10 | Open the downloaded PDF file using a PDF reader | PDF file opens without errors and displays properly formatted content |
| 11 | Verify that the PDF content matches the displayed report data | Report content in PDF exactly matches the on-screen displayed data including all filtered records, dates, and employee information |
| 12 | Verify that applied filters are shown in the PDF header or summary section | PDF includes filter information showing the date range, department, or other filters that were applied |

**Postconditions:**
- PDF file is successfully downloaded and saved
- Export activity is logged in the system audit trail
- Original report remains displayed on screen
- System is ready for additional export operations
- Downloaded PDF is accessible and shareable

---

### Test Case: Verify export access restriction for unauthorized users
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Test user account exists with unauthorized role (e.g., Employee or Contractor role without export permissions)
- Export API endpoint is active and secured with role-based access control
- Authentication system is functional
- API testing tool is available for direct API calls

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system as unauthorized user (user without export permissions) | User successfully logs in and is redirected to their role-appropriate dashboard |
| 2 | Navigate to any available reports section (if accessible to the user) | User can view their permitted reports or dashboard |
| 3 | Look for export options or buttons in the user interface | Export options are not visible or accessible in the UI (buttons are hidden or disabled) |
| 4 | If any report is displayed, attempt to access export functionality through UI | Export functionality is not available, or attempting to access it shows 'Access Denied' message |
| 5 | Note the current authentication token for the unauthorized user | Authentication token is available for API testing |
| 6 | Attempt to call export API endpoint (POST /api/reports/export) directly using the unauthorized user's token with valid report parameters | Authorization error is returned with HTTP status code 403 Forbidden |
| 7 | Verify the API error response message and structure | Response includes clear error message such as 'Unauthorized: Insufficient permissions to export reports' and proper error code |
| 8 | Check system audit logs for the unauthorized access attempt | System logs record the unauthorized export attempt with user details, timestamp, and action denied |

**Postconditions:**
- Unauthorized user remains unable to export reports
- No data is exported or exposed to unauthorized user
- Security logs contain records of the unauthorized access attempts
- System security controls remain effective
- User session remains active for their authorized functions only

---

