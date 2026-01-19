# Manual Test Cases

## Story: As HR Manager, I want to generate attendance reports to achieve accurate tracking of employee presence and absences
**Story ID:** story-2

### Test Case: Generate attendance report with valid filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has role-based access to Attendance Reporting module
- Attendance data exists in the system for the selected date range
- Time-tracking system is operational and integrated
- At least one department exists in the system with employee attendance records

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Attendance Reporting section from the main dashboard | Attendance report UI is displayed with filter options including date range picker, department dropdown, and employee selector |
| 2 | Select a valid date range (e.g., last 30 days) using the date picker | Date range is selected and displayed in the filter field without validation errors |
| 3 | Select a department from the department dropdown filter | Department is selected and filters are accepted without errors |
| 4 | Click the 'Generate Report' button to submit report generation request | System processes the request and attendance report is generated and displayed within 5 seconds showing employee names, timestamps, attendance status, and summary statistics |
| 5 | Verify the report contains accurate attendance data with timestamps | Report displays complete attendance records with check-in/check-out timestamps, total hours, and attendance status for all employees in the selected department and date range |

**Postconditions:**
- Attendance report is successfully generated and displayed on screen
- Report data matches the applied filters
- System logs the report generation activity
- Report is available for export or further analysis

---

### Test Case: Export attendance report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has role-based access to Attendance Reporting module
- Attendance report has been successfully generated with valid filters
- Report is currently displayed on screen
- Browser allows file downloads
- User has sufficient storage space for downloaded files

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate attendance report by selecting date range and department filters, then clicking 'Generate Report' | Attendance report is displayed on screen with complete data including employee attendance records, timestamps, and summary information |
| 2 | Locate and click the 'Export to PDF' button in the report toolbar | PDF file is generated and automatically downloaded to the default download location with filename format 'Attendance_Report_[Department]_[DateRange].pdf' |
| 3 | Open the downloaded PDF file using a PDF reader | PDF opens successfully and displays the complete attendance report with correct formatting, all data fields, timestamps, headers, footers, and matches the on-screen report data |
| 4 | Return to the attendance report screen and click the 'Export to Excel' button | Excel file is generated and automatically downloaded to the default download location with filename format 'Attendance_Report_[Department]_[DateRange].xlsx' |
| 5 | Open the downloaded Excel file using spreadsheet software | Excel file opens successfully with properly formatted data in columns, including headers, all attendance records, timestamps, formulas for calculations, and data matches the on-screen report |
| 6 | Verify data integrity by comparing a sample of records between PDF, Excel, and on-screen report | All three formats contain identical data with no discrepancies in employee names, dates, timestamps, or attendance status |

**Postconditions:**
- PDF file is successfully downloaded and contains accurate report data
- Excel file is successfully downloaded and contains accurate report data
- Both exported files are accessible and readable
- Export activity is logged in the system
- Original report remains displayed on screen unchanged

---

### Test Case: Verify absenteeism highlights in attendance report
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has role-based access to Attendance Reporting module
- Attendance data exists with known absenteeism and punctuality issues
- Time-tracking system is operational and accessible for verification
- Test data includes employees with various attendance patterns (present, absent, late arrivals)
- Department has at least 5 employees with mixed attendance records

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Attendance Reporting section and select a department with known absenteeism cases | Attendance report UI is displayed with filter options |
| 2 | Select a date range that includes days with absenteeism and punctuality issues, then click 'Generate Report' | Attendance report is generated and displayed within 5 seconds showing complete attendance data for the selected department and date range |
| 3 | Review the report for visual indicators of absenteeism (e.g., highlighted rows, color coding, icons, or special markers) | Absenteeism cases are clearly indicated with visual highlights such as red color coding or warning icons, making them easily distinguishable from normal attendance |
| 4 | Review the report for punctuality issue indicators (e.g., late arrivals, early departures) | Punctuality issues are clearly indicated with visual highlights such as yellow/orange color coding or clock icons, showing late check-ins or early check-outs with time differences |
| 5 | Identify the absenteeism trends section or summary statistics in the report | Report displays absenteeism trends including total absent days, percentage of absenteeism, patterns by day of week, and comparison to previous periods |
| 6 | Access the time-tracking system independently and retrieve raw attendance data for the same department and date range | Time-tracking system provides source attendance data including timestamps, attendance status, and employee records |
| 7 | Compare the attendance report data with the time-tracking system source data for accuracy | Report data matches source data with 98% or higher accuracy including employee names, dates, timestamps, attendance status, and absenteeism counts |
| 8 | Verify that all highlighted absenteeism cases in the report correspond to actual absences in the source system | 100% of highlighted absenteeism cases are verified as accurate against the time-tracking system with no false positives |

**Postconditions:**
- Absenteeism and punctuality issues are accurately identified and highlighted in the report
- Report data accuracy is verified at 98% or higher against source system
- Visual indicators are clear and easily interpretable
- Report is ready for management review and decision-making
- Data integrity is confirmed between reporting system and time-tracking system

---

## Story: As HR Manager, I want to highlight absenteeism trends in attendance reports to achieve proactive workforce management
**Story ID:** story-6

### Test Case: Verify absenteeism trend highlighting in attendance report
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- User has role-based access to Attendance Reporting module with trend analysis features
- Attendance data exists spanning multiple weeks/months to establish trends
- System has sufficient historical data to perform trend analysis (minimum 30 days)
- Test data includes departments with varying absenteeism patterns
- Trend analysis algorithm is configured and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Attendance Reporting section from the main dashboard | Attendance report UI is displayed with filter options including date range, department selector, and trend analysis toggle |
| 2 | Select a time period filter of at least 30 days to enable trend analysis | Time period is selected and accepted without validation errors |
| 3 | Select a department from the department dropdown filter | Department is selected successfully and filter is applied |
| 4 | Enable the absenteeism trend analysis option if available as a separate toggle | Trend analysis option is enabled and system prepares to include trend data in the report |
| 5 | Click 'Generate Report' button to request report generation with trend analysis | System processes the request and generates attendance report with absenteeism trend analysis within 5 seconds |
| 6 | Review the report for visual absenteeism trend indicators such as graphs, charts, trend lines, or heat maps | Absenteeism trends are clearly indicated visually using charts (line graphs showing trends over time, bar charts comparing periods, or heat maps showing high-absence days) with color coding and clear legends |
| 7 | Examine specific trend highlights including increasing/decreasing patterns, peak absence days, and recurring patterns | Report displays specific trend insights such as 'Absenteeism increased by X% in the last 2 weeks', 'Highest absence rate on Mondays', or 'Recurring pattern detected' with visual emphasis |
| 8 | Verify that individual employees with concerning absenteeism trends are highlighted or flagged | Employees with absenteeism rates above threshold are highlighted with visual indicators and trend statistics showing their absence frequency and pattern |
| 9 | Check the accuracy of trend detection by comparing identified trends with actual attendance data patterns | Trend analysis achieves 90% or higher accuracy in detecting actual absenteeism patterns with minimal false positives |
| 10 | Click 'Export to PDF' button to export the report with trend highlights | PDF file is generated and downloaded successfully with filename format 'Attendance_Trends_Report_[Department]_[DateRange].pdf' |
| 11 | Open the exported PDF file and verify that all absenteeism trend visualizations are included | PDF contains all trend charts, graphs, visual highlights, color coding, and trend analysis data exactly as displayed in the on-screen report with proper formatting |
| 12 | Return to report screen and click 'Export to Excel' button | Excel file is generated and downloaded successfully with filename format 'Attendance_Trends_Report_[Department]_[DateRange].xlsx' |
| 13 | Open the exported Excel file and verify that trend data and highlights are preserved | Excel file includes trend data in tabular format, conditional formatting for highlights, embedded charts if supported, and all trend analysis metrics are intact and readable |

**Postconditions:**
- Attendance report with absenteeism trends is successfully generated and displayed
- Trend analysis is accurate at 90% or higher
- Visual trend highlights are clear and actionable for HR management
- Report is exported successfully in both PDF and Excel formats with trends intact
- HR Manager can identify absenteeism patterns for proactive workforce management
- Export activity is logged in the system

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
| 3 | Select department or employee filters if applicable | Filters are applied and displayed in the filter section |
| 4 | Click on 'Generate Report' button | Attendance report is generated and displayed on screen with all attendance data including employee names, dates, check-in/check-out times, and status |
| 5 | Verify the displayed report contains accurate attendance data | Report shows correct attendance information matching the selected filters and date range |
| 6 | Locate and click on 'Export to PDF' button | Export process initiates and a loading indicator appears |
| 7 | Wait for the PDF export to complete | PDF file is generated and automatically downloaded to the default downloads folder within 5 seconds |
| 8 | Navigate to the downloads folder and locate the downloaded PDF file | PDF file is present with a meaningful filename (e.g., 'Attendance_Report_YYYY-MM-DD.pdf') |
| 9 | Open the downloaded PDF file using a PDF reader application | PDF file opens successfully without errors |
| 10 | Verify the PDF contains all attendance data from the generated report | PDF displays complete attendance data including all employee records, dates, times, and status information |
| 11 | Check the formatting and readability of the PDF document | PDF maintains proper formatting with clear headers, aligned columns, readable fonts, proper spacing, and professional layout |
| 12 | Verify all table columns are visible and not cut off | All data columns fit within the page boundaries and are fully visible |
| 13 | Check if company logo, report title, and date range are displayed in the PDF header | PDF header contains company branding, report title 'Attendance Report', and the selected date range |
| 14 | Scroll through multiple pages if applicable to verify pagination | Page numbers are displayed correctly and data flows properly across pages without data loss |

**Postconditions:**
- PDF file is successfully downloaded and saved in the downloads folder
- PDF file is readable and printable
- Original attendance report remains displayed on screen
- User session remains active
- No data corruption or loss occurred during export
- System logs the export activity for audit purposes

---

