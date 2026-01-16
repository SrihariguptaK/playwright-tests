# Manual Test Cases

## Story: As Administrator, I want to audit approval workflows and decisions to ensure compliance and traceability
**Story ID:** story-20

### Test Case: Validate logging of approval workflow configuration changes
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Administrator is logged into the system with valid credentials
- Administrator has permissions to modify approval workflows
- Administrator has access to audit logs module
- At least one approval workflow exists in the system
- Audit logging service is active and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the approval workflow configuration page | Workflow configuration page loads successfully displaying existing workflows |
| 2 | Select an existing approval workflow to modify | Workflow details are displayed with editable fields |
| 3 | Modify workflow parameters (e.g., change approval threshold, add/remove approver, update workflow name) | Changes are accepted and validation passes |
| 4 | Save the workflow configuration changes | System displays success message confirming workflow has been updated |
| 5 | Navigate to the audit logs module | Audit logs interface loads successfully with search and filter options |
| 6 | Search for audit logs related to the modified workflow using workflow ID or name | Search results display relevant audit log entries |
| 7 | Locate and open the most recent workflow modification entry | Audit log entry displays complete details including: workflow ID, modification type, changed fields, old values, new values, administrator username, timestamp, and session information |
| 8 | Verify the timestamp matches the time of modification | Timestamp is accurate within acceptable system time tolerance (±2 seconds) |
| 9 | Verify the logged user matches the administrator who made the change | User identity in audit log matches the currently logged-in administrator |
| 10 | Verify all modified fields are accurately recorded in the audit log | All changes made to the workflow are present in the audit log with correct before and after values |

**Postconditions:**
- Workflow configuration change is successfully saved in the system
- Complete audit trail entry exists for the workflow modification
- Audit log entry is immutable and timestamped
- No system errors or warnings are present

---

### Test Case: Verify audit log immutability and access control
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- System has multiple user roles configured (authorized and unauthorized users)
- Audit logs contain existing entries from previous approval activities
- Unauthorized user account exists without audit log access permissions
- Authorized administrator account exists with audit log read permissions
- Role-based access control (RBAC) is properly configured
- Audit log database is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log out any currently logged-in user | User is successfully logged out and redirected to login page |
| 2 | Log in with unauthorized user credentials (user without audit log access permissions) | User successfully logs into the system with standard user interface |
| 3 | Attempt to navigate to the audit logs module URL directly | System denies access and displays 'Access Denied' or '403 Forbidden' error message |
| 4 | Verify that audit logs menu option is not visible in the navigation | Audit logs option is hidden or disabled in the user interface for unauthorized user |
| 5 | Attempt to access audit logs via API endpoint GET /api/audit-logs using unauthorized user token | API returns 403 Forbidden status code with appropriate error message |
| 6 | Log out the unauthorized user | Unauthorized user is successfully logged out |
| 7 | Log in with authorized administrator credentials | Administrator successfully logs in with full system access |
| 8 | Navigate to the audit logs module | Audit logs interface loads successfully displaying existing log entries |
| 9 | Select an existing audit log entry | Audit log entry details are displayed in read-only format |
| 10 | Attempt to edit or modify any field in the audit log entry through the UI | All fields are read-only and cannot be modified; no edit buttons or options are available |
| 11 | Attempt to delete the audit log entry through the UI | No delete option is available; entry cannot be removed |
| 12 | Attempt to modify audit log entry via API using PUT or PATCH request | API returns 405 Method Not Allowed or 403 Forbidden status code; modification is prevented |
| 13 | Verify that the modification attempt itself is logged in the audit trail | A new audit log entry is created documenting the unauthorized modification attempt with user identity, timestamp, and action details |
| 14 | Verify the original audit log entry remains unchanged | Original audit log entry retains all original values with no modifications |

**Postconditions:**
- Unauthorized user access attempts are blocked and logged
- All audit log entries remain immutable and unchanged
- Modification attempts are recorded in the audit trail
- System security integrity is maintained
- No unauthorized access to sensitive audit data occurred

---

### Test Case: Test export of audit reports
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Administrator is logged into the system with audit log access permissions
- Audit logs contain multiple entries spanning different dates and users
- System supports multiple export formats (CSV, PDF, Excel)
- Administrator has sufficient storage space for downloaded files
- Export functionality is enabled and operational
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit logs module | Audit logs interface loads successfully with search, filter, and export options visible |
| 2 | Apply filters to the audit logs (e.g., date range: last 30 days, user: specific administrator, action type: workflow modifications) | Audit logs are filtered and display only entries matching the specified criteria |
| 3 | Verify the filtered results show the expected number of entries | Result count is displayed and matches the expected number of audit entries for the applied filters |
| 4 | Click on the 'Export' or 'Generate Report' button | Export options dialog appears showing available formats (CSV, PDF, Excel) |
| 5 | Select CSV format from the export options | CSV format is selected and highlighted |
| 6 | Click 'Generate Report' or 'Download' button | System begins generating the report; progress indicator or loading message is displayed |
| 7 | Wait for report generation to complete | Report is generated within 5 seconds; download dialog appears or file automatically downloads |
| 8 | Save the downloaded CSV file to local storage | File is successfully saved with appropriate filename including timestamp (e.g., audit_report_2024-01-15.csv) |
| 9 | Open the downloaded CSV file using spreadsheet application | CSV file opens successfully and is properly formatted with headers and data |
| 10 | Verify the CSV contains all expected columns (e.g., Timestamp, User, Action, Workflow ID, Details, IP Address) | All required audit log fields are present as columns in the CSV |
| 11 | Verify the CSV contains only the filtered audit log entries | Number of rows in CSV matches the filtered result count; all entries match the applied filters |
| 12 | Return to audit logs interface and repeat export process selecting PDF format | PDF export is generated within 5 seconds and downloads successfully |
| 13 | Open the downloaded PDF file | PDF opens successfully with properly formatted audit report including headers, company logo (if applicable), and tabular data |
| 14 | Verify PDF contains the same filtered data as CSV export | PDF report contains identical audit log entries with all relevant fields displayed |
| 15 | Return to audit logs interface and repeat export process selecting Excel format | Excel export is generated within 5 seconds and downloads successfully |
| 16 | Open the downloaded Excel file | Excel file opens successfully with data in structured worksheet format with proper column headers |
| 17 | Verify Excel contains the same filtered data with proper formatting | Excel report contains identical audit log entries with formatted cells, headers, and data types |

**Postconditions:**
- Audit reports are successfully exported in all requested formats
- Exported files contain accurate and complete filtered audit data
- Files are properly formatted and readable
- Export operation is logged in the audit trail
- No data corruption or loss occurred during export
- System performance remains stable after export operations

---

