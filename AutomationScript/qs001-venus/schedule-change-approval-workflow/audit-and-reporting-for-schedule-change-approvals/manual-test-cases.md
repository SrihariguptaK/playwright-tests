# Manual Test Cases

## Story: As Auditor, I want to access audit logs of schedule change approvals to achieve compliance verification
**Story ID:** story-6

### Test Case: Access and filter audit logs successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has valid auditor role credentials
- Audit logs database contains test data with various dates, users, and approval statuses
- System is accessible and operational
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid auditor credentials (username and password), then click Login button | System authenticates the auditor successfully and redirects to the audit logs page. Page loads completely with audit log interface visible including filter options and log entries table |
| 2 | Locate the filter section and select a date range (e.g., last 30 days) from the date picker, then select a specific user from the user dropdown filter | Date range and user filters are applied successfully. Filtered audit logs are displayed in the table showing only entries matching the selected criteria. Results are returned and displayed within 5 seconds |
| 3 | Click on a specific log entry row to view its detailed information | Detailed log entry view opens displaying complete information including timestamp, user who performed the action, action type, approval status, schedule change details, and any associated metadata |

**Postconditions:**
- Auditor remains logged into the system
- Filtered audit logs remain displayed on screen
- Applied filters remain active for subsequent operations
- System logs the auditor's access to audit logs

---

### Test Case: Export audit logs in PDF and Excel formats
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Auditor is logged into the system with valid credentials
- Auditor is on the audit logs page
- Audit logs contain exportable data
- Browser has download permissions enabled
- Sufficient disk space available for downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Apply desired filters on audit logs by selecting date range (e.g., last 7 days) and approval status (e.g., Approved) | Filters are applied successfully and filtered audit logs are displayed in the table showing only entries matching the selected criteria |
| 2 | Locate and click the 'Export to PDF' button in the export options section | System processes the export request, generates a PDF file containing the filtered audit logs with proper formatting, headers, and data. PDF file is automatically downloaded to the default download location. File opens successfully showing all filtered log entries |
| 3 | Return to the audit logs page and click the 'Export to Excel' button in the export options section | System processes the export request, generates an Excel file (.xlsx format) containing the filtered audit logs with proper column headers and data. Excel file is automatically downloaded to the default download location. File opens successfully in Excel showing all filtered log entries in a structured spreadsheet format |

**Postconditions:**
- Two files are downloaded: one PDF and one Excel file
- Both exported files contain identical data matching the filtered audit logs
- Data integrity is maintained in both export formats
- Auditor remains on the audit logs page
- Export actions are logged in the system audit trail

---

### Test Case: Restrict audit log access to authorized users
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- System has role-based access control configured
- Test user accounts exist: one with auditor role and one without auditor role (e.g., regular employee or manager)
- Audit logs page URL is known
- System is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using credentials of a non-auditor user (e.g., regular employee account) | User is successfully authenticated and logged into the system with their assigned role |
| 2 | Attempt to navigate to the audit logs page by entering the URL directly or clicking on audit logs link if visible | System denies access and displays an 'Access Denied' or 'Unauthorized Access' error message. User is either redirected to their home page or shown an error page indicating insufficient permissions. Audit logs data is not displayed |
| 3 | Log out from the non-auditor account and log back in using valid auditor credentials | Auditor is successfully authenticated and logged into the system |
| 4 | Navigate to the audit logs page using the menu or direct URL | Access is granted successfully. Audit logs page loads completely displaying the audit log interface with filter options and log entries table. All audit log functionality is accessible to the auditor |

**Postconditions:**
- Non-auditor access attempt is logged in security audit trail
- Auditor has full access to audit logs functionality
- System security controls are validated as functioning correctly
- No unauthorized data exposure occurred

---

## Story: As Auditor, I want to generate compliance reports on schedule change approvals to achieve regulatory adherence
**Story ID:** story-11

### Test Case: Generate compliance report with parameters
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Auditor is logged into the system with valid credentials
- Reporting module is accessible to auditor role
- Database contains schedule change approval data for testing
- System has approval counts, processing times, and exception data available
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module from the main menu and locate the compliance report section | Reporting module page loads successfully displaying available report types and parameter selection options |
| 2 | Select 'Schedule Change Approval Compliance' as the report type from the dropdown menu | Report type is selected and relevant parameter fields are displayed for customization |
| 3 | Select a date range using the date picker (e.g., start date: first day of last month, end date: last day of last month) | Date range parameters are accepted and displayed correctly in the parameter fields |
| 4 | Optionally select specific departments or leave as 'All Departments', then click the 'Generate Report' button | System processes the request and generates the compliance report within 10 seconds. Report is displayed on screen showing approval counts, average processing times, exception details, and summary statistics organized by sections |
| 5 | Review the generated report content to verify it includes all required sections: approval counts, processing times, and exceptions | Report displays complete and accurate data including total approval counts, breakdown by status, average and median processing times, list of exceptions with details, and summary metrics |
| 6 | Click the 'Export to PDF' button to download the report | PDF file is generated successfully containing the complete report with proper formatting, headers, charts if applicable, and all data sections. File is downloaded to the default download location and opens correctly showing all report content |

**Postconditions:**
- Compliance report is generated and displayed
- PDF export file is downloaded successfully
- Report generation action is logged in audit trail
- Data integrity is maintained in exported report
- Auditor remains in the reporting module for additional operations

---

### Test Case: Restrict reporting access to auditors
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- System has role-based access control configured for reporting module
- Test user accounts exist: one with auditor role and one without auditor role
- Reporting module URL is known
- System is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using credentials of a non-auditor user (e.g., manager or regular employee account) | User is successfully authenticated and logged into the system with their assigned non-auditor role |
| 2 | Attempt to access the reporting module by navigating through the menu or entering the reporting module URL directly in the browser | System denies access and displays an 'Access Denied', 'Unauthorized', or '403 Forbidden' error message. User is prevented from viewing the reporting module interface. No report data or generation options are displayed |
| 3 | Log out from the non-auditor account completely | User is successfully logged out and redirected to the login page |
| 4 | Log back into the system using valid auditor credentials | Auditor is successfully authenticated and logged into the system |
| 5 | Navigate to the reporting module using the menu or direct URL | Access is granted successfully. Reporting module page loads completely displaying all available report types, parameter options, and report generation functionality. Auditor has full access to all reporting features |

**Postconditions:**
- Non-auditor access attempt is logged in security audit trail
- Auditor has full access to reporting module
- System access controls are validated as functioning correctly
- No unauthorized access to compliance reports occurred
- Security integrity is maintained

---

