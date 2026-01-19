# Manual Test Cases

## Story: As Administrator, I want to generate audit reports for schedule change approvals to achieve compliance and transparency
**Story ID:** story-7

### Test Case: Generate audit report with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Administrator is logged into the system with valid credentials
- Administrator has admin-level access permissions
- Audit reporting module is accessible
- Approval audit logs contain data for the selected date range
- At least one approver exists in the system with approval history

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit reporting module from the admin dashboard | Audit reporting module page loads successfully with report generation options visible |
| 2 | Select a date range filter by choosing start date and end date from the date picker | Selected date range is displayed correctly in the date range field |
| 3 | Select one or more approvers from the approver dropdown filter | Selected approver names are displayed in the approver filter field |
| 4 | Verify that the filters are applied correctly by reviewing the filter summary section | Filter summary displays the selected date range and approver names accurately |
| 5 | Click the 'Generate Report' button | System processes the request and displays a loading indicator |
| 6 | Wait for report generation to complete | Report displays filtered approval actions including action type, timestamp, approver name, status, and comments for the selected criteria |
| 7 | Verify that only approval actions matching the selected filters are displayed in the report | All displayed records match the date range and approver filters applied, with no unrelated records shown |

**Postconditions:**
- Audit report is generated and displayed on screen
- Report contains only filtered data matching the selected criteria
- Report is available for export or further actions
- Audit log records the report generation activity

---

### Test Case: Export audit report in PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Administrator is logged into the system with valid credentials
- Administrator has admin-level access permissions
- An audit report has been generated and is displayed on screen
- Browser allows file downloads
- System has PDF and Excel export functionality enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the export options section on the generated audit report page | Export options are visible with PDF and Excel format buttons available |
| 2 | Click the 'Export as PDF' button | System initiates PDF generation and displays a processing indicator |
| 3 | Wait for PDF file to be generated and downloaded | PDF file downloads successfully to the default download location with a filename containing 'audit_report' and timestamp |
| 4 | Open the downloaded PDF file using a PDF reader | PDF file opens successfully and displays the audit report with all approval actions, timestamps, approver names, statuses, and comments in a properly formatted layout |
| 5 | Verify that the PDF contains correct data matching the on-screen report | All data in the PDF matches the generated report exactly, including headers, filters applied, and record details |
| 6 | Return to the audit report page and click the 'Export as Excel' button | System initiates Excel generation and displays a processing indicator |
| 7 | Wait for Excel file to be generated and downloaded | Excel file downloads successfully to the default download location with a filename containing 'audit_report' and timestamp |
| 8 | Open the downloaded Excel file using a spreadsheet application | Excel file opens successfully and displays the audit report data in a structured spreadsheet format with proper column headers |
| 9 | Verify that the Excel file contains correct data matching the on-screen report | All data in the Excel file matches the generated report exactly, with each approval action in a separate row and all fields in appropriate columns |

**Postconditions:**
- PDF file is successfully downloaded and contains accurate audit report data
- Excel file is successfully downloaded and contains accurate audit report data
- Both exported files are accessible and readable
- Export activities are logged in the system audit trail

---

### Test Case: Schedule automated audit report delivery
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Administrator is logged into the system with valid credentials
- Administrator has admin-level access permissions
- Audit reporting module is accessible
- Email service is configured and operational
- At least one valid recipient email address is available
- System scheduler service is running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit reporting module and locate the 'Schedule Report' option | Schedule Report button or link is visible and clickable |
| 2 | Click on the 'Schedule Report' button | Schedule configuration dialog or page opens with fields for schedule settings and recipient configuration |
| 3 | Configure report schedule by selecting frequency (daily, weekly, monthly) and specific time for report generation | Selected frequency and time are displayed correctly in the schedule configuration fields |
| 4 | Select report format (PDF, Excel, or both) for the scheduled delivery | Selected format options are highlighted and confirmed in the configuration |
| 5 | Enter recipient email addresses in the recipients field, separating multiple addresses with commas or semicolons | All entered email addresses are displayed and validated as properly formatted |
| 6 | Configure optional filters for the scheduled report (date range, approver, status) | Selected filters are applied and displayed in the schedule configuration summary |
| 7 | Review the schedule configuration summary showing all settings | Summary displays frequency, time, format, recipients, and filters accurately |
| 8 | Click the 'Save Schedule' button | System displays a success message confirming that the schedule has been saved successfully |
| 9 | Verify that the scheduled report appears in the list of active scheduled reports | Newly created schedule is listed with correct configuration details including next scheduled run time |
| 10 | Wait for the configured scheduled time to arrive (or manually trigger the schedule for testing purposes) | System automatically generates the audit report at the configured time |
| 11 | Check that the system sends the scheduled report via email to all configured recipients | All recipients receive an email with the audit report attached in the specified format(s) within 5 minutes of the scheduled time |
| 12 | Verify email content by opening the received email | Email contains appropriate subject line, body text explaining the scheduled report, and correct attachment(s) with accurate audit data |

**Postconditions:**
- Scheduled report configuration is saved in the system
- Schedule appears in the active schedules list
- Recipients receive the audit report via email at the configured time
- Email delivery is logged in the system
- Schedule remains active for future executions unless disabled

---

