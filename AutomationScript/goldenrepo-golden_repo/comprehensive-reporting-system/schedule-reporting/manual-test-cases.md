# Manual Test Cases

## Story: As Operations Manager, I want to generate schedule reports filtered by date and team to achieve optimized resource allocation
**Story ID:** story-1

### Test Case: Generate schedule report with valid filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Operations Manager role
- User has authorization to access schedule reporting module
- Schedule database contains test data for multiple teams and date ranges
- At least one scheduling conflict exists in the test data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule reporting module from the main dashboard | Schedule report UI is displayed with filter options including date range picker, team dropdown, and generate report button |
| 2 | Select a valid start date from the date range picker | Start date is populated in the date range field without validation errors |
| 3 | Select a valid end date that is after the start date | End date is populated in the date range field and date range is validated successfully |
| 4 | Select one or more teams from the team filter dropdown | Selected teams are displayed in the filter section and filters are accepted without errors |
| 5 | Click the 'Generate Report' button to submit the report generation request | System processes the request and displays a loading indicator |
| 6 | Wait for report generation to complete | Report is generated within 5 seconds displaying schedule data for the selected date range and teams |
| 7 | Review the generated report content for accuracy | Report displays accurate schedule information including team members, dates, activities, and any scheduling conflicts are clearly highlighted with visual indicators |

**Postconditions:**
- Schedule report is displayed on screen with accurate data
- Scheduling conflicts are visibly highlighted in the report
- Report generation time is logged and within 5 seconds
- User remains on the report viewing page

---

### Test Case: Export schedule report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Operations Manager role
- User has authorization to export reports
- Schedule report has been successfully generated and is displayed on screen
- Browser allows file downloads
- PDF and Excel export functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate schedule report with valid date range and team filters | Report is successfully generated and displayed on screen with complete schedule data |
| 2 | Locate and click the 'Export to PDF' button in the report toolbar | System initiates PDF export process and displays export progress indicator |
| 3 | Wait for PDF export to complete | PDF file is generated and automatically downloads to the default download location with filename format 'Schedule_Report_[date].pdf' |
| 4 | Open the downloaded PDF file using a PDF reader | PDF opens successfully displaying the report with correct layout, formatting, data integrity maintained, and conflicts highlighted |
| 5 | Return to the schedule report page in the application | Report is still displayed on screen with all data intact |
| 6 | Locate and click the 'Export to Excel' button in the report toolbar | System initiates Excel export process and displays export progress indicator |
| 7 | Wait for Excel export to complete | Excel file is generated and automatically downloads to the default download location with filename format 'Schedule_Report_[date].xlsx' |
| 8 | Open the downloaded Excel file using spreadsheet software | Excel file opens successfully with correct data structure, all columns properly formatted, data matches the original report, and no data loss occurred |

**Postconditions:**
- Two files are downloaded: one PDF and one Excel file
- Both exported files contain accurate and complete report data
- Original report remains displayed in the application
- Export actions are logged in the system audit trail

---

### Test Case: Schedule automated report generation and email delivery
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Operations Manager role
- User has authorization to schedule automated reports
- Email service is configured and operational
- Valid recipient email addresses are available
- Schedule report module is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule reporting module and click on 'Schedule Automated Reports' option | Scheduling UI is displayed showing options for report frequency, date range, team filters, format selection, and recipient email fields |
| 2 | Select report frequency (daily, weekly, or monthly) from the dropdown | Frequency is selected and additional time/day options are displayed based on selection |
| 3 | Set the specific time for report generation | Time is accepted and displayed in the scheduling configuration |
| 4 | Configure date range parameters for the automated report (e.g., last 7 days, current week) | Date range parameters are accepted and validated successfully |
| 5 | Select team filters to be applied to the automated report | Team filters are selected and displayed in the configuration |
| 6 | Enter valid recipient email addresses in the email field (comma-separated for multiple recipients) | Email addresses are validated and accepted without errors |
| 7 | Select export format for the automated report (PDF, Excel, or both) | Format selection is accepted and displayed in the configuration summary |
| 8 | Click 'Save Schedule' button to save the automated report configuration | Configuration is saved successfully, confirmation message is displayed, and scheduled report appears in the list of active schedules |
| 9 | Wait for the scheduled time to arrive or trigger a test execution of the scheduled report | System automatically generates the report at the scheduled time with the configured parameters |
| 10 | Check the recipient email inbox at the scheduled delivery time | Email is received with subject line containing report name and date, email body contains report summary, and correct report file(s) are attached in the specified format(s) |
| 11 | Download and open the attached report file(s) from the email | Attached files open successfully with accurate report data matching the configured filters and parameters |

**Postconditions:**
- Automated report schedule is saved and active in the system
- Scheduled report appears in the list of active automated reports
- Email with correct report attachment is successfully delivered to all recipients
- Report generation and email delivery are logged in the system
- Schedule remains active for future executions unless disabled

---

## Story: As Operations Manager, I want to export schedule reports in multiple formats to facilitate sharing and analysis
**Story ID:** story-5

### Test Case: Export schedule report to PDF
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Operations Manager role
- User has authorization to export reports
- Schedule report has been generated with valid filters
- Report contains data to be exported
- Browser allows file downloads
- PDF export functionality is enabled in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule reporting module and generate a schedule report with selected date range and team filters | Schedule report is successfully generated and displayed on screen with complete data including headers, schedule details, and any conflicts |
| 2 | Verify the report content is accurate and complete before exporting | Report displays all expected data fields, formatting is correct, and data matches the applied filters |
| 3 | Locate the export options toolbar and click on 'Export to PDF' button | System initiates PDF export process, displays processing indicator, and export request is submitted to the server |
| 4 | Monitor the export processing time | Export is processed within 10 seconds and PDF file download begins automatically |
| 5 | Check the browser's download location for the exported PDF file | PDF file is successfully downloaded with appropriate filename (e.g., Schedule_Report_YYYY-MM-DD.pdf) and file size is reasonable |
| 6 | Open the downloaded PDF file using a PDF reader application | PDF file opens without errors and is not corrupted |
| 7 | Verify the PDF content matches the original report displayed on screen | All report data is correctly rendered in the PDF including headers, schedule entries, team information, dates, and conflict highlights |
| 8 | Check the PDF layout and formatting quality | Layout is preserved with proper page breaks, fonts are readable, tables are properly formatted, and visual elements like conflict highlights are clearly visible |
| 9 | Verify PDF metadata and properties | PDF contains appropriate metadata including creation date, title, and is not password protected unless required |

**Postconditions:**
- PDF file is successfully downloaded to local system
- PDF contains accurate and complete report data
- Original report remains displayed in the application
- Export action is logged in system audit trail with timestamp and user information
- PDF file can be shared and opened on other systems

---

### Test Case: Export schedule report to Excel
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Operations Manager role
- User has authorization to export reports
- Schedule report has been generated with valid filters
- Report contains data to be exported
- Browser allows file downloads
- Excel export functionality is enabled in the system
- Excel-compatible software is available to open the file

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule reporting module and generate a schedule report with selected date range and team filters | Schedule report is successfully generated and displayed on screen with complete tabular data |
| 2 | Review the report to ensure all data columns and rows are present | Report displays all expected columns (e.g., Date, Team, Employee, Activity, Time) and data rows match the filter criteria |
| 3 | Locate the export options toolbar and click on 'Export to Excel' button | System initiates Excel export process, displays processing indicator, and export request is submitted to the server |
| 4 | Monitor the export processing time | Export is processed within 10 seconds and Excel file download begins automatically |
| 5 | Check the browser's download location for the exported Excel file | Excel file is successfully downloaded with appropriate filename (e.g., Schedule_Report_YYYY-MM-DD.xlsx) in XLSX format |
| 6 | Open the downloaded Excel file using spreadsheet software (Microsoft Excel, Google Sheets, or LibreOffice Calc) | Excel file opens without errors, no corruption warnings are displayed, and file structure is intact |
| 7 | Verify the Excel file contains all data from the original report | All rows and columns from the report are present in the Excel file with no data loss or truncation |
| 8 | Check the data structure and formatting in the Excel file | Data is correctly structured with proper column headers in the first row, data types are preserved (dates as dates, numbers as numbers), and cells are properly formatted |
| 9 | Verify special elements like scheduling conflicts are represented in the Excel file | Conflicts are indicated through cell formatting (e.g., highlighting, color coding) or additional columns, making them easily identifiable |
| 10 | Test data manipulation capabilities in the Excel file | Data can be sorted, filtered, and analyzed using standard Excel functions without errors |

**Postconditions:**
- Excel file is successfully downloaded to local system
- Excel file contains accurate and complete report data with correct structure
- Data types and formatting are preserved appropriately
- Original report remains displayed in the application
- Export action is logged in system audit trail with timestamp and user information
- Excel file can be shared, edited, and analyzed using spreadsheet software

---

## Story: As Operations Manager, I want to filter schedule reports by project to focus on relevant activities
**Story ID:** story-10

### Test Case: Filter schedule report by project
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Operations Manager with valid credentials
- User has authorization to access schedule reporting module
- At least one project exists in the system with associated schedule data
- Scheduling database contains schedule entries for multiple projects
- User has network connectivity to access the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule reporting module from the main dashboard | Schedule reporting module is displayed with all available filter options and an empty or default report view |
| 2 | Click on the project filter dropdown and select a specific project from the list | Selected project is displayed in the project filter field and filter is marked as active |
| 3 | Optionally select additional filters such as date range and team filters | All selected filters are displayed as active and accepted by the system |
| 4 | Click the 'Generate Report' or 'Apply Filters' button | System processes the request and displays a loading indicator |
| 5 | Wait for report generation to complete | Report is generated within 5 seconds and displays schedule data filtered by the selected project, showing only activities and schedules associated with that project |
| 6 | Review the filtered report data for accuracy | All displayed schedule entries belong to the selected project and no entries from other projects are shown |

**Postconditions:**
- Schedule report displays only data for the selected project
- Filter selections remain active in the UI
- Report is available for export if needed
- System logs the report generation activity
- User session maintains the current filter state

---

### Test Case: Persist filter selections during session
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Operations Manager with valid credentials
- User has authorization to access schedule reporting module
- Schedule reporting module is accessible
- Multiple projects and teams exist in the system for filter selection
- User session is active and valid

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule reporting module | Schedule reporting module is displayed with default or empty filter settings |
| 2 | Select a specific project from the project filter dropdown | Selected project is displayed in the project filter field |
| 3 | Select a date range filter by choosing start and end dates | Selected date range is displayed in the date filter field |
| 4 | Select a team from the team filter dropdown | Selected team is displayed in the team filter field |
| 5 | Click 'Generate Report' or 'Apply Filters' button to apply all filters | Filtered report is generated and displayed showing schedule data matching all applied filters (project, date range, and team) |
| 6 | Navigate away from the schedule reporting module to another section of the application (e.g., dashboard, settings, or another module) | User successfully navigates to the different section and the new page is displayed |
| 7 | Navigate back to the schedule reporting module using the navigation menu | Schedule reporting module is displayed again |
| 8 | Verify the filter selections in the project, date, and team filter fields | All previously selected filters (project, date range, and team) are retained and displayed exactly as they were before navigating away |
| 9 | Verify the report data displayed | The filtered report automatically displays the same filtered schedule data without requiring the user to regenerate the report |

**Postconditions:**
- Filter selections persist throughout the user session
- Report data remains consistent with the persisted filters
- User can continue working with the same filter context
- Session state is maintained in the system
- No data loss occurs during navigation

---

