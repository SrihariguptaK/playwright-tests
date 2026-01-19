# Manual Test Cases

## Story: As System Administrator, I want to audit schedule change approvals to achieve compliance and traceability
**Story ID:** story-16

### Test Case: Verify audit log records approval actions accurately
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Administrator account with audit log access permissions is available
- At least one approver account exists in the system
- At least one pending schedule change request exists
- Audit logging service is enabled and operational
- ApprovalActions audit table is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as an approver user with valid credentials | Approver is successfully authenticated and redirected to the dashboard |
| 2 | Navigate to the schedule change requests list and select a pending request | Schedule change request details are displayed with approval options |
| 3 | Add approval comments in the comments field (e.g., 'Approved for operational requirements') | Comments are entered successfully in the text field |
| 4 | Click the 'Approve' button to perform the approval action | Approval action is processed successfully, request status changes to 'Approved', and confirmation message is displayed |
| 5 | Note the exact timestamp of the approval action | Current timestamp is recorded for verification purposes |
| 6 | Log out from the approver account | User is successfully logged out and redirected to login page |
| 7 | Log in as an administrator user with audit log access permissions | Administrator is successfully authenticated and redirected to the admin dashboard |
| 8 | Navigate to the audit portal/audit logs section | Audit logs interface is displayed with search and filter options |
| 9 | Search for the approval action using the approver username and timestamp | Search results display the audit log entry for the approval action performed in previous steps |
| 10 | Click on the audit log entry to view detailed information | Audit entry details are displayed including: approver username, exact timestamp, action type (Approval), schedule change request ID, and approval comments |
| 11 | Verify all metadata fields are complete and accurate (user, timestamp, comments, action type) | All metadata fields match the approval action performed: correct approver name, accurate timestamp, complete comments text, and correct action type |
| 12 | Click on 'Export' or 'Generate Report' button and select CSV format | Export dialog appears with CSV format selected |
| 13 | Confirm the CSV export and download the file | CSV file is generated and downloaded successfully to local system |
| 14 | Open the downloaded CSV file and verify the audit log entry is present with all metadata | CSV file contains the audit entry with all fields correctly formatted: user, timestamp, action type, request ID, and comments |
| 15 | Return to audit logs interface and click 'Export' button, this time selecting PDF format | Export dialog appears with PDF format selected |
| 16 | Confirm the PDF export and download the file | PDF file is generated and downloaded successfully to local system |
| 17 | Open the downloaded PDF file and verify the audit log entry is present with all metadata in readable format | PDF file contains the audit entry with all fields properly formatted and readable, including user, timestamp, action type, request ID, and comments |

**Postconditions:**
- Audit log entry exists in the ApprovalActions audit table
- Audit log entry contains complete and accurate metadata
- CSV and PDF export files are generated and contain the audit entry
- No data integrity issues are present in audit logs
- Administrator remains logged in to the system

---

### Test Case: Restrict audit log access to administrators
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Administrator account with audit log access permissions exists
- Non-administrator user account exists (e.g., regular employee or approver without admin rights)
- Audit logging system is operational
- Role-based access control (RBAC) is configured and enforced
- Audit logs contain at least one entry for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as a non-administrator user (regular employee or approver without admin privileges) | Non-admin user is successfully authenticated and redirected to their standard dashboard |
| 2 | Attempt to navigate to the audit logs section by entering the audit portal URL directly (e.g., /admin/audit-logs) | Access is denied with error message 'Access Denied: You do not have permission to view audit logs' or similar, user is redirected to unauthorized access page or their dashboard |
| 3 | Check the main navigation menu for any audit log or audit portal links | No audit log links or menu items are visible in the navigation for non-admin users |
| 4 | Attempt to access audit logs via API endpoint directly (GET /api/audit-logs) using the non-admin user's authentication token | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 5 | Log out from the non-administrator account | User is successfully logged out and redirected to login page |
| 6 | Log in as an administrator user with proper audit log access permissions | Administrator is successfully authenticated and redirected to the admin dashboard |
| 7 | Check the main navigation menu for audit log or audit portal links | Audit log links or menu items are visible and accessible in the administrator's navigation menu |
| 8 | Click on the audit logs link to navigate to the audit portal | Audit logs interface is displayed successfully with full functionality including search, filter, and export options |
| 9 | Verify all audit log features are accessible: search functionality, filter options, and view details | All audit log features are fully functional and accessible to the administrator |
| 10 | Perform a search operation on audit logs using date filter | Search executes successfully and returns filtered audit log entries matching the date criteria |
| 11 | Click on an audit log entry to view detailed information | Detailed audit log information is displayed including all metadata fields |
| 12 | Test export functionality by clicking 'Export' button and selecting CSV format | Export dialog appears and CSV file is generated and downloaded successfully |
| 13 | Verify administrator can access audit logs via API endpoint (GET /api/audit-logs) using admin authentication token | API returns 200 OK status code with audit log data in JSON format |

**Postconditions:**
- Non-administrator users cannot access audit logs through any method
- Administrator retains full access to audit log functionality
- Access control policies are enforced correctly
- Security audit trail records the access attempts
- No unauthorized data exposure has occurred

---

## Story: As System Administrator, I want to generate reports on schedule change approvals to achieve operational insights
**Story ID:** story-20

### Test Case: Generate approval summary report with filters
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Administrator account with reporting access permissions exists
- Multiple schedule change requests with various statuses exist in the system
- Approval actions have been recorded across different dates, departments, and approvers
- Reporting service is operational and connected to ScheduleChangeRequests and ApprovalActions data sources
- At least 10 approval records exist spanning multiple departments and date ranges

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as an administrator user with reporting access permissions | Administrator is successfully authenticated and redirected to the admin dashboard |
| 2 | Navigate to the reporting portal or reports section from the main menu | Reporting interface is displayed with available report types and filter options |
| 3 | Select 'Approval Summary Report' from the report type dropdown menu | Approval Summary Report is selected and relevant filter options are displayed (date range, department, approver) |
| 4 | Set the date range filter to cover the last 30 days by selecting start and end dates | Date range filter is applied showing start date as 30 days ago and end date as today |
| 5 | Select a specific department from the department filter dropdown (e.g., 'Engineering') | Department filter is applied with 'Engineering' selected |
| 6 | Select a specific approver from the approver filter dropdown | Approver filter is applied with the selected approver name displayed |
| 7 | Click the 'Generate Report' button to create the filtered report | Report generation process initiates with loading indicator displayed |
| 8 | Wait for report generation to complete (should be within 10 seconds per SLA) | Report is generated successfully within 10 seconds and displays filtered approval data including approval volumes, average approval times, and outcomes |
| 9 | Verify the report data matches the applied filters (date range, department, approver) | All displayed records fall within the specified date range, belong to the Engineering department, and are associated with the selected approver |
| 10 | Scroll down to view the visual dashboard section with charts and statistics | Visual dashboard is displayed showing charts such as approval volume trends, approval time distribution, and approval outcome pie chart |
| 11 | Verify the bar chart showing approval volumes over time reflects the filtered data accurately | Bar chart displays approval volumes for each day/week within the selected date range, with values matching the filtered dataset |
| 12 | Verify the pie chart showing approval outcomes (approved, rejected, pending) reflects accurate percentages | Pie chart displays correct percentages for each outcome category based on the filtered data, with percentages summing to 100% |
| 13 | Verify the average approval time statistic is calculated correctly | Average approval time displayed matches the calculated average from the filtered approval records |
| 14 | Click the 'Export' button and select 'CSV' format from the export options | Export dialog appears with CSV format selected and file name suggestion displayed |
| 15 | Confirm the CSV export and download the file | CSV file is generated and downloaded successfully to local system with filename indicating report type and date |
| 16 | Open the downloaded CSV file in a spreadsheet application | CSV file opens successfully and contains all report data in tabular format with proper column headers (Request ID, Date, Department, Approver, Outcome, Approval Time) |
| 17 | Verify CSV file contains complete data matching the filtered report results | All rows in CSV match the filtered report data, with no missing records or truncated data |
| 18 | Return to the reporting interface and click 'Export' button again, this time selecting 'PDF' format | Export dialog appears with PDF format selected |
| 19 | Confirm the PDF export and download the file | PDF file is generated and downloaded successfully to local system |
| 20 | Open the downloaded PDF file in a PDF reader | PDF file opens successfully and displays the report with professional formatting including header, filters applied, data table, and visual charts |
| 21 | Verify PDF contains all report elements: summary statistics, data table, and visual charts | PDF includes complete report with all sections properly formatted: filter criteria summary, approval statistics, detailed data table, and embedded chart visualizations |
| 22 | Verify the visual charts in the PDF match the charts displayed in the web interface | Charts in PDF are identical to web interface charts with same data values and visual representation |

**Postconditions:**
- Approval summary report is generated with accurate filtered data
- Visual charts and statistics correctly reflect the filtered dataset
- CSV export file contains complete and correctly formatted data
- PDF export file contains complete report with visualizations
- Report generation completed within 10-second SLA
- Administrator remains logged in to the reporting portal

---

### Test Case: Restrict report access to administrators
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Administrator account with reporting access permissions exists
- Non-administrator user account exists (e.g., regular employee or approver without admin rights)
- Reporting system is operational with available reports
- Role-based access control (RBAC) is configured for reporting features
- At least one report type is available in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as a non-administrator user (regular employee or approver without admin privileges) | Non-admin user is successfully authenticated and redirected to their standard dashboard |
| 2 | Attempt to navigate to the reporting portal by entering the reports URL directly (e.g., /admin/reports) | Access is denied with error message 'Access Denied: You do not have permission to access reporting features' or similar, user is redirected to unauthorized access page or their dashboard |
| 3 | Check the main navigation menu for any reporting or reports links | No reporting links or menu items are visible in the navigation for non-admin users |
| 4 | Attempt to access the approval summary report API endpoint directly (GET /api/reports/approval-summary) using the non-admin user's authentication token | API returns 403 Forbidden status code with error message indicating insufficient permissions to access reporting data |
| 5 | Attempt to access report export functionality via API (GET /api/reports/export) using the non-admin user's authentication token | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 6 | Log out from the non-administrator account | User is successfully logged out and redirected to login page |
| 7 | Log in as an administrator user with proper reporting access permissions | Administrator is successfully authenticated and redirected to the admin dashboard |
| 8 | Check the main navigation menu for reporting or reports links | Reporting links or menu items are visible and accessible in the administrator's navigation menu |
| 9 | Click on the reports link to navigate to the reporting portal | Reporting interface is displayed successfully with full functionality including report type selection, filters, and export options |
| 10 | Verify all reporting features are accessible: report type dropdown, filter options, generate button, and export functionality | All reporting features are fully functional and accessible to the administrator |
| 11 | Select 'Approval Summary Report' from the report type dropdown | Report type is selected successfully and filter options are displayed |
| 12 | Apply a date range filter and click 'Generate Report' button | Report is generated successfully with filtered data and visual charts displayed |
| 13 | Test export functionality by clicking 'Export' and selecting CSV format | CSV file is generated and downloaded successfully |
| 14 | Verify administrator can access reporting API endpoint (GET /api/reports/approval-summary) using admin authentication token | API returns 200 OK status code with report data in JSON format |
| 15 | Verify administrator can access export API endpoint (GET /api/reports/export) using admin authentication token | API returns 200 OK status code and generates export file successfully |

**Postconditions:**
- Non-administrator users cannot access reporting features through any method
- Administrator retains full access to all reporting functionality
- Access control policies are enforced correctly for reporting features
- Security audit trail records the access attempts
- No unauthorized access to report data has occurred

---

