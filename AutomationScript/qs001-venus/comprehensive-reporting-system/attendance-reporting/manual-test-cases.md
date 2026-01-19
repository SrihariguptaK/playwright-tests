# Manual Test Cases

## Story: As HR Manager, I want to generate attendance reports to achieve accurate tracking of employee presence and absences
**Story ID:** story-2

### Test Case: Generate attendance report with valid filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has role-based access to Attendance Reporting module
- Attendance data exists in the system for the selected date range
- Time-tracking system is integrated and operational
- At least one department exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Attendance Reporting section from the main dashboard | Attendance report UI is displayed with filter options including date range, department, and employee selectors |
| 2 | Select a valid date range (e.g., last 30 days) using the date picker | Date range is selected and displayed in the filter field without validation errors |
| 3 | Select a department from the department dropdown filter | Department is selected and displayed in the filter field without errors |
| 4 | Click the 'Generate Report' button to submit the report generation request | Attendance report is generated and displayed on screen within 5 seconds showing employee names, timestamps, attendance status, and summary statistics |

**Postconditions:**
- Attendance report is displayed with accurate data matching the applied filters
- Report generation is logged in the system audit trail
- User remains on the Attendance Reporting page with filters intact

---

### Test Case: Export attendance report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has role-based access to Attendance Reporting module
- Attendance report has been successfully generated with valid filters
- Report data is displayed on screen
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate attendance report by selecting date range and department filters, then clicking 'Generate Report' | Report is displayed on screen with complete attendance data including timestamps, employee details, and attendance status |
| 2 | Click the 'Export to PDF' button | PDF file is downloaded to the default download location with filename format 'Attendance_Report_[DateRange].pdf' containing all report data with proper formatting, headers, and absenteeism highlights |
| 3 | Open the downloaded PDF file | PDF opens successfully and displays all report data accurately matching the on-screen report |
| 4 | Return to the attendance report screen and click the 'Export to Excel' button | Excel file is downloaded to the default download location with filename format 'Attendance_Report_[DateRange].xlsx' containing all report data in spreadsheet format |
| 5 | Open the downloaded Excel file | Excel file opens successfully with properly formatted columns, headers, and all attendance data matching the on-screen report |

**Postconditions:**
- Both PDF and Excel files are successfully downloaded and saved
- Export actions are logged in the system audit trail
- User remains on the Attendance Reporting page
- Original report remains displayed on screen

---

### Test Case: Verify absenteeism highlights in attendance report
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has role-based access to Attendance Reporting module
- Attendance data exists with known absenteeism and punctuality issues
- Time-tracking system is integrated and contains source data
- Test department has employees with documented absences and late arrivals

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Attendance Reporting section and select a department known to have absenteeism issues | Attendance report UI is displayed with filter options |
| 2 | Select date range covering the period with known absenteeism and click 'Generate Report' | Report is displayed with complete attendance data including employee names, dates, timestamps, and attendance status |
| 3 | Review the report for visual indicators of absenteeism trends such as color coding, icons, or highlighted rows | Absenteeism trends are clearly indicated with visual highlights (e.g., red indicators for absences, yellow for late arrivals) and summary statistics showing absenteeism patterns |
| 4 | Review the report for punctuality issue indicators | Punctuality issues are clearly marked with distinct visual indicators showing late arrivals and their frequency |
| 5 | Cross-reference report data with source data from the time-tracking system | Report data matches source data with 98% accuracy including timestamps, attendance status, and employee records |
| 6 | Verify that absenteeism percentage calculations are correct | Absenteeism percentages and statistics are calculated correctly based on the attendance data |

**Postconditions:**
- Absenteeism and punctuality issues are accurately identified and highlighted
- Report data accuracy is verified against source system
- User has confidence in report reliability
- Report remains available for export or further analysis

---

## Story: As HR Manager, I want to highlight absenteeism trends in attendance reports to achieve proactive workforce management
**Story ID:** story-6

### Test Case: Verify absenteeism trend highlighting in attendance report
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has role-based access to Attendance Reporting module with trend analysis
- Attendance data exists with identifiable absenteeism patterns
- Trend analysis algorithm is configured and operational
- Test data includes multiple employees with varying absenteeism patterns

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Attendance Reporting section from the main dashboard | Attendance report UI is displayed with filter options and trend analysis features enabled |
| 2 | Select a time period filter (e.g., last 3 months) using the date range picker | Time period is selected and displayed in the filter field without validation errors |
| 3 | Select a department from the department dropdown filter | Department is selected and filter is applied successfully |
| 4 | Click 'Generate Report' button to request report with trend analysis | Report is generated within 5 seconds and displayed with attendance data and absenteeism trend analysis |
| 5 | Review the report for visual absenteeism trend highlights such as graphs, charts, color-coded patterns, or trend indicators | Absenteeism trends are clearly indicated visually with graphical representations (e.g., trend lines, heat maps, or highlighted patterns) showing patterns over the selected time period |
| 6 | Verify that trend highlights include metrics such as increasing/decreasing absenteeism, peak absence periods, and repeat offenders | Trend analysis displays comprehensive metrics including absenteeism rate changes, peak absence days/periods, and employees with recurring absences |
| 7 | Click 'Export to PDF' button | PDF file is downloaded containing the report with all absenteeism trend highlights, graphs, and visual indicators intact |
| 8 | Open the downloaded PDF and verify trend highlights are preserved | PDF displays all absenteeism trend highlights including charts, color coding, and visual indicators exactly as shown in the on-screen report |
| 9 | Return to report screen and click 'Export to Excel' button | Excel file is downloaded containing the report data with absenteeism trend indicators and supporting data |
| 10 | Open the downloaded Excel file and verify trend data is included | Excel file contains all trend data, calculations, and conditional formatting to represent absenteeism highlights |

**Postconditions:**
- Absenteeism trends are accurately detected and highlighted with 90% accuracy
- Exported reports (PDF and Excel) contain all trend highlights
- Export actions are logged in the system audit trail
- User can take proactive workforce management actions based on identified trends
- Report data is available for further analysis

---

## Story: As HR Manager, I want to export attendance reports in PDF format to achieve easy sharing and printing
**Story ID:** story-10

### Test Case: Export attendance report to PDF
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with HR Manager role
- User has authorization to access attendance reports
- Attendance data exists in the system for the selected period
- Browser supports PDF file downloads
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance reports section from the main dashboard | Attendance reports page is displayed with report generation options |
| 2 | Select the desired date range for the attendance report (e.g., current month) | Date range is selected and highlighted in the date picker |
| 3 | Select department or employee filters if needed | Selected filters are applied and displayed |
| 4 | Click on 'Generate Report' button | Attendance report is generated and displayed on screen with all attendance data including employee names, dates, check-in/check-out times, and status |
| 5 | Verify the report data is accurate and complete on screen | Report displays correct attendance information matching the selected criteria |
| 6 | Click on 'Export to PDF' button | PDF export process initiates, loading indicator appears, and export completes within 5 seconds |
| 7 | Observe the browser download notification or downloads folder | PDF file is successfully downloaded with a meaningful filename (e.g., 'Attendance_Report_YYYY-MM-DD.pdf') |
| 8 | Navigate to the downloads folder and locate the downloaded PDF file | PDF file is present in the downloads folder with correct file size (not 0 KB) |
| 9 | Open the PDF file using a PDF reader application | PDF file opens successfully without errors |
| 10 | Verify the PDF contains all attendance data from the generated report | PDF displays complete attendance data including all employee records, dates, times, and status information |
| 11 | Check the formatting and readability of the PDF document | PDF maintains proper formatting with clear headers, aligned columns, readable fonts, proper spacing, and professional layout |
| 12 | Verify PDF includes report metadata (generation date, date range, filters applied) | PDF header or footer contains report generation timestamp and selected criteria |
| 13 | Test PDF printability by sending to printer or print preview | PDF is print-ready with proper page breaks and margins |

**Postconditions:**
- PDF file is successfully downloaded and saved to local system
- PDF file contains accurate and complete attendance data
- PDF maintains formatting and is readable
- Original report remains displayed on screen
- User session remains active
- Export action is logged in system audit trail

---

