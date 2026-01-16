# Manual Test Cases

## Story: As HR Specialist, I want to generate attendance reports to track employee presence and absences
**Story ID:** story-2

### Test Case: Validate attendance report generation with valid filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with HR Specialist role credentials
- Attendance tracking system database contains test data for multiple employees
- Test data includes attendance records for at least the last 30 days
- User has active network connection to the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance reporting module from the main dashboard | Attendance report UI is displayed with filter options including date range, employee selector, and department selector visible |
| 2 | Select a valid date range (e.g., last 7 days) using the date picker | Date range is accepted and displayed in the filter field without validation errors |
| 3 | Select a specific department from the department dropdown filter | Department filter is applied and displayed correctly in the filter section |
| 4 | Click the 'Generate Report' button to request report generation | System processes the request and displays a loading indicator while generating the report |
| 5 | Wait for report generation to complete | Attendance report is generated within 15 seconds and displayed on screen with correct data including employee names, dates, presence status, absences, and late arrivals matching the selected filters |
| 6 | Verify the report data matches the applied filters | All displayed records fall within the selected date range and department, with accurate attendance data for each employee |

**Postconditions:**
- Attendance report remains displayed on screen for review
- Filter selections remain active for subsequent report generations
- System logs the report generation activity

---

### Test Case: Verify export functionality for attendance reports
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with HR Specialist role credentials
- Attendance reporting module is accessible
- Test data exists in the attendance database
- Browser download settings allow automatic file downloads
- User has write permissions to the default download folder

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance reporting module | Attendance report UI is displayed with filter options |
| 2 | Select a date range of last 30 days and a specific department filter | Filters are applied successfully without errors |
| 3 | Click 'Generate Report' button to generate attendance report with the applied filters | Report is generated and displayed on screen with attendance data including employee names, dates, presence, absences, and tardiness information |
| 4 | Click the 'Export to CSV' button | CSV file is downloaded to the default download folder with a filename containing timestamp and report type |
| 5 | Open the downloaded CSV file using a spreadsheet application | CSV file opens successfully and contains all report data with correct column headers, employee information, dates, and attendance status matching the on-screen report |
| 6 | Return to the attendance report screen and click the 'Export to PDF' button | PDF file is downloaded to the default download folder with a filename containing timestamp and report type |
| 7 | Open the downloaded PDF file using a PDF reader | PDF file opens successfully with correct formatting including company header, report title, filter parameters, table structure, and all attendance data matching the on-screen report |

**Postconditions:**
- Two files (CSV and PDF) are saved in the download folder
- Original report remains displayed on screen
- Export activity is logged in the system audit trail

---

### Test Case: Ensure unauthorized users cannot access attendance reports
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Test user account exists with non-HR role (e.g., Employee or Manager role)
- Attendance reporting module exists in the system
- API endpoint /api/reports/attendance is configured with role-based access control
- User is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page and enter credentials for a non-HR user (e.g., regular employee account) | User is successfully authenticated and logged into the system with non-HR role |
| 2 | Attempt to navigate to the attendance reporting module via the main menu or navigation | Attendance reporting module option is not visible in the navigation menu, or access is denied with an appropriate error message stating insufficient permissions |
| 3 | Attempt to access the attendance reporting module directly by entering the URL in the browser | System redirects to an access denied page or displays an error message indicating the user does not have permission to access this resource |
| 4 | Open browser developer tools and attempt to access the API endpoint directly by sending a GET request to /api/reports/attendance | API returns HTTP 403 Forbidden status code with an error message indicating access is restricted to authorized HR specialist roles only |
| 5 | Verify the response body contains appropriate security error message | Response body contains error message such as 'Access denied: Insufficient permissions' or 'Unauthorized access to attendance reports' |

**Postconditions:**
- Non-HR user remains logged in but cannot access attendance reports
- Security violation attempt is logged in the system audit trail
- No attendance data is exposed to the unauthorized user

---

## Story: As HR Specialist, I want attendance reports to highlight tardiness for compliance monitoring
**Story ID:** story-6

### Test Case: Validate tardiness detection in attendance reports
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with HR Specialist role credentials
- Attendance database contains test records with tardiness data (employees who arrived late)
- Tardiness threshold is configured in the system (e.g., 15 minutes after scheduled start time)
- Test data includes at least 5 employees with tardiness occurrences in the last 30 days
- Attendance reporting module is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance reporting module from the main dashboard | Attendance report UI is displayed with filter options and report generation controls |
| 2 | Select a date range that includes known tardiness occurrences (e.g., last 30 days) | Date range filter is applied successfully without validation errors |
| 3 | Click 'Generate Report' button to generate attendance report with tardiness data | System processes the request and generates the attendance report within 15 seconds |
| 4 | Review the generated report for tardiness highlights | Report is displayed with tardiness occurrences clearly highlighted using visual indicators such as color coding (e.g., yellow or orange), icons, or bold text for late arrivals |
| 5 | Verify the accuracy of tardiness detection by comparing highlighted entries with actual arrival timestamps | All employees who arrived after the tardiness threshold are correctly flagged and highlighted, and employees who arrived on time are not flagged |
| 6 | Select a specific employee from the employee filter dropdown who has known tardiness records | Employee filter is applied successfully |
| 7 | Click 'Generate Report' to filter the report by the selected employee with tardiness | Filtered report is generated showing only attendance records for the selected employee |
| 8 | Verify the filtered report displays tardiness information for the selected employee | Filtered report shows all tardiness occurrences for the selected employee with correct dates, arrival times, and tardiness highlights matching the employee's actual attendance records |

**Postconditions:**
- Attendance report with tardiness highlights remains displayed on screen
- Filter selections remain active for subsequent operations
- Report generation activity is logged in the system

---

### Test Case: Verify export of attendance reports with tardiness highlights
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with HR Specialist role credentials
- Attendance database contains records with tardiness occurrences
- Attendance reporting module is accessible
- Browser download settings allow automatic file downloads
- PDF reader application is installed on the test machine

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance reporting module | Attendance report UI is displayed with available filter options |
| 2 | Select a date range that includes employees with tardiness records (e.g., last 14 days) | Date range filter is applied successfully |
| 3 | Click 'Generate Report' button to generate attendance report with tardiness highlights | Report is generated and displayed on screen with tardiness occurrences visually highlighted using color coding or special formatting |
| 4 | Review the on-screen report to identify tardiness highlights and note specific examples | Report displays with clear visual indicators for tardiness including highlighted rows or cells for late arrivals |
| 5 | Click the 'Export to PDF' button to export the report | PDF file is generated and downloaded to the default download folder with a descriptive filename including timestamp |
| 6 | Open the downloaded PDF file using a PDF reader application | PDF file opens successfully displaying the attendance report with professional formatting |
| 7 | Verify that tardiness highlights are preserved in the PDF export | PDF includes tardiness highlights using visual indicators such as colored text, highlighted cells, or special symbols/icons that clearly distinguish late arrivals from on-time attendance |
| 8 | Compare the PDF content with the on-screen report to ensure data accuracy | All tardiness occurrences shown in the on-screen report are accurately represented in the PDF with consistent highlighting, and all employee names, dates, and attendance data match exactly |

**Postconditions:**
- PDF file with tardiness highlights is saved in the download folder
- Original report remains displayed on screen
- Export activity is logged in the system audit trail
- PDF file is ready for compliance monitoring and archival purposes

---

## Story: As HR Specialist, I want to export attendance reports in multiple formats to support diverse analysis needs
**Story ID:** story-10

### Test Case: Validate export of attendance reports in CSV format
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Specialist with valid credentials
- User has permission to access attendance reports
- Attendance data exists in the system for the selected period
- Browser allows file downloads
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance reports section from the main dashboard | Attendance reports page loads successfully with report generation options visible |
| 2 | Select date range for the attendance report (e.g., last 30 days) | Date range is selected and displayed in the date picker fields |
| 3 | Select department or employee filters if applicable | Filters are applied and displayed in the filter section |
| 4 | Click on 'Generate Report' button | Attendance report is generated and displayed on screen with employee names, dates, attendance status, and other relevant columns |
| 5 | Locate and click on the 'Export' button or dropdown menu | Export options menu appears showing CSV, PDF, and Excel format options |
| 6 | Select 'CSV' format from the export options | CSV export process initiates and file download begins within 10 seconds |
| 7 | Open the downloaded CSV file using a spreadsheet application or text editor | CSV file opens successfully with all attendance data correctly formatted, including headers, employee information, dates, and attendance status matching the displayed report |
| 8 | Verify data integrity by comparing sample records from the CSV with the on-screen report | All data points match exactly between the CSV file and the displayed report with no missing or corrupted data |

**Postconditions:**
- CSV file is successfully downloaded to the user's default download location
- File contains complete and accurate attendance data
- Original report remains displayed on screen
- System logs the export activity
- User can perform additional exports if needed

---

### Test Case: Validate export of attendance reports in PDF format
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as HR Specialist with valid credentials
- User has permission to access and export attendance reports
- Attendance data exists in the system for the selected period
- Browser allows file downloads and has PDF viewing capability
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance reports section from the main dashboard | Attendance reports page loads successfully with report generation options visible |
| 2 | Select date range for the attendance report (e.g., current month) | Date range is selected and displayed in the date picker fields |
| 3 | Apply any necessary filters such as department, team, or specific employees | Filters are applied and reflected in the filter summary section |
| 4 | Click on 'Generate Report' button | Attendance report is generated and displayed on screen with proper formatting, including tables with employee data, attendance records, and summary statistics |
| 5 | Locate and click on the 'Export' button or dropdown menu | Export options menu appears displaying CSV, PDF, and Excel format options |
| 6 | Select 'PDF' format from the export options | PDF export process initiates and file download begins within 10 seconds |
| 7 | Open the downloaded PDF file using a PDF reader application | PDF file opens successfully with professional formatting, proper page layout, headers, footers, and company branding if applicable |
| 8 | Verify the PDF contains all report data including tables, charts, and summary information | All attendance data is present with correct formatting, readable fonts, proper alignment, and no truncated text or overlapping elements |
| 9 | Check that the PDF maintains data integrity by comparing sample records with the on-screen report | All data points match exactly between the PDF file and the displayed report with consistent formatting |

**Postconditions:**
- PDF file is successfully downloaded to the user's default download location
- File is properly formatted and readable
- All data is accurately represented in the PDF
- Original report remains displayed on screen
- System logs the export activity with timestamp and user information

---

### Test Case: Validate export of attendance reports in Excel format
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as HR Specialist with valid credentials
- User has permission to access and export attendance reports
- Attendance data exists in the system for the selected period
- Browser allows file downloads
- Microsoft Excel or compatible spreadsheet application is available to open the file
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance reports section from the main dashboard | Attendance reports page loads successfully with all report generation controls visible |
| 2 | Select date range for the attendance report (e.g., quarterly report) | Date range is selected and displayed correctly in the date picker fields |
| 3 | Configure any additional filters such as department, location, or employee status | Filters are applied and displayed in the active filters section |
| 4 | Click on 'Generate Report' button | Attendance report is generated and displayed on screen with complete data including employee details, attendance records, leave information, and summary statistics |
| 5 | Locate and click on the 'Export' button or dropdown menu | Export options menu appears showing CSV, PDF, and Excel format options clearly labeled |
| 6 | Select 'Excel' format from the export options | Excel export process initiates and file download begins within 10 seconds |
| 7 | Open the downloaded Excel file using Microsoft Excel or compatible application | Excel file opens successfully without errors or corruption warnings |
| 8 | Verify the Excel file structure including worksheets, headers, and data organization | Excel file contains properly formatted worksheets with clear headers, appropriate column widths, and organized data structure |
| 9 | Check data accuracy by comparing sample records from the Excel file with the on-screen report | All data points including employee names, dates, attendance status, hours worked, and leave records match exactly between the Excel file and the displayed report |
| 10 | Verify that Excel-specific features are functional such as sortable columns, filterable data, and formula compatibility | Excel file supports standard spreadsheet operations including sorting, filtering, and calculations without errors |

**Postconditions:**
- Excel file is successfully downloaded to the user's default download location
- File contains complete and accurate attendance data in proper Excel format
- Data is structured for easy analysis and manipulation
- Original report remains displayed on screen
- System logs the export activity with user details and timestamp
- File can be opened and edited in Excel or compatible applications

---

