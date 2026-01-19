# Manual Test Cases

## Story: As Department Manager, I want to generate performance reports to achieve insights into team productivity and quality metrics
**Story ID:** story-4

### Test Case: Generate performance report with selected KPIs
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Department Manager
- User has access to Performance Reporting module
- At least one team exists in the system
- Task and attendance data is available for the selected time period
- Performance database is accessible and populated

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Performance Reporting section from the main dashboard | Performance report UI is displayed with KPI options, filter controls, and report generation button visible |
| 2 | Select desired KPIs from the available options (e.g., task completion rate, attendance percentage, quality metrics) | Selected KPIs are highlighted and added to the report configuration |
| 3 | Apply filters for team by selecting a specific team from the dropdown | Team filter is applied and displayed in the active filters section |
| 4 | Apply time period filter by selecting start and end dates | Time period filter is applied and displayed in the active filters section without validation errors |
| 5 | Click the 'Generate Report' button to submit report generation request | Performance report is generated and visualized within 5 seconds showing selected KPIs with charts, graphs, and data tables |

**Postconditions:**
- Performance report is displayed on screen
- Report contains all selected KPIs
- Applied filters are reflected in the report data
- Report generation is logged in system audit trail

---

### Test Case: Export performance report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Department Manager
- User has access to Performance Reporting module
- Performance report has been successfully generated with KPIs
- Browser allows file downloads
- User has write permissions to download folder

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate performance report by selecting KPIs, team filter, and time period, then clicking 'Generate Report' | Report is displayed with visualizations including charts, graphs, and data tables showing selected KPIs |
| 2 | Locate and click the 'Export to PDF' button | PDF file is generated and downloaded to the default download location with filename containing report name and timestamp |
| 3 | Open the downloaded PDF file | PDF opens successfully and contains all report data including visualizations, KPIs, filters applied, and data tables matching the on-screen report |
| 4 | Return to the performance report screen and click the 'Export to Excel' button | Excel file is generated and downloaded to the default download location with filename containing report name and timestamp |
| 5 | Open the downloaded Excel file | Excel file opens successfully and contains all report data in structured format with separate sheets for different KPIs, data tables, and chart representations |

**Postconditions:**
- PDF file is saved in download folder with correct data
- Excel file is saved in download folder with correct data
- Both exported files contain accurate report information
- Export actions are logged in system audit trail
- Original report remains displayed on screen

---

### Test Case: Verify integration of task and attendance data in performance report
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Department Manager
- User has access to Performance Reporting module
- Task database contains task completion data for the selected team
- Attendance database contains attendance records for the selected team
- User has access to view source task and attendance data for verification
- Test team with known task and attendance data exists

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Performance Reporting section and select a specific team from the team filter dropdown | Team is selected and filter is applied |
| 2 | Select KPIs that include both task-related metrics (e.g., task completion rate) and attendance-related metrics (e.g., attendance percentage) | Both task and attendance KPIs are selected and displayed in the configuration |
| 3 | Select a time period and click 'Generate Report' | Report is displayed with integrated data showing both task and attendance metrics in a unified view with visualizations |
| 4 | Access the task database directly or through task management module and retrieve task completion data for the same team and time period | Task source data is retrieved showing number of completed tasks, pending tasks, and completion rates |
| 5 | Compare task metrics in the performance report against the source task data | Report data matches source data with 100% accuracy for task completion rates, total tasks, and other task-related KPIs |
| 6 | Access the attendance database directly or through attendance module and retrieve attendance records for the same team and time period | Attendance source data is retrieved showing attendance percentages, absences, and attendance patterns |
| 7 | Compare attendance metrics in the performance report against the source attendance data | Report data matches source data with 100% accuracy for attendance percentages, total days, and other attendance-related KPIs |
| 8 | Review the visualized trends in the report including line charts, bar graphs, and trend indicators | Trends accurately reflect performance over time showing increases, decreases, or stability in both task and attendance metrics consistent with the underlying data |

**Postconditions:**
- Data integrity is confirmed between report and source systems
- Task and attendance data integration is verified
- Report accuracy is validated at 95% or higher
- Visualizations correctly represent the integrated data
- Verification results are documented

---

## Story: As Department Manager, I want to visualize performance trends over time to achieve better understanding of productivity changes
**Story ID:** story-8

### Test Case: View performance trend visualization for selected time period
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Department Manager
- User has access to Performance Reporting module
- Performance database contains historical data for multiple time periods
- At least one team has performance data spanning the selected time period
- Visualization library is loaded and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Performance Reporting section from the main dashboard | Performance report UI is displayed with KPI selection options, time period selectors, and visualization area |
| 2 | Select performance KPIs from the available options (e.g., productivity score, task completion rate, quality metrics) | Selected KPIs are highlighted and added to the visualization configuration |
| 3 | Select a time period by choosing start date and end date from the date pickers (e.g., last 3 months) | Time period selections are accepted, validated, and displayed in the active filters section without errors |
| 4 | Click 'View Trends' or 'Generate Visualization' button | Trend visualization renders within 5 seconds displaying line charts or area graphs showing selected KPIs over the chosen time period |
| 5 | Examine the trend visualization for data points, trend lines, and axis labels | Visualization displays accurate performance trends with clear data points for each time interval, properly labeled axes, legend showing KPIs, and trend indicators (upward/downward) |
| 6 | Hover over data points on the visualization | Tooltips appear showing exact values, dates, and KPI names for each data point |

**Postconditions:**
- Performance trend visualization is displayed on screen
- Visualization accurately represents data for selected time period
- All selected KPIs are visible in the trend chart
- Visualization is interactive and responsive
- User can interpret productivity changes from the trends

---

### Test Case: Export performance report with visualizations
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Department Manager
- User has access to Performance Reporting module
- Performance report with trend visualizations has been generated
- Visualizations are fully rendered on screen
- Browser allows file downloads
- User has write permissions to download folder

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate performance report by selecting KPIs and time period, then viewing trend visualizations | Report is displayed with trend visualizations including line charts, graphs showing performance over time, and data tables |
| 2 | Verify that all visualizations are fully loaded and displayed correctly on screen | All charts, graphs, and visual elements are rendered completely with no missing components |
| 3 | Locate and click the 'Export to PDF' button | PDF generation process initiates and PDF file is downloaded to the default download location with filename containing report name and timestamp |
| 4 | Open the downloaded PDF file using a PDF reader | PDF opens successfully and contains all report content including trend visualizations rendered as images, charts are clear and readable, data tables are formatted properly, and all KPIs and time period information are included |
| 5 | Verify that visualizations in the PDF match the on-screen visualizations | Visualizations in PDF are identical to on-screen versions with same data points, trend lines, colors, labels, and formatting intact |

**Postconditions:**
- PDF file is saved in download folder
- PDF contains complete report with visualizations intact
- Visualizations in exported PDF are accurate and readable
- Export action is logged in system audit trail
- Original report remains displayed on screen for further use

---

## Story: As Department Manager, I want to export performance reports in PDF format to achieve standardized reporting
**Story ID:** story-12

### Test Case: Export performance report to PDF
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Department Manager with valid credentials
- User has authorization to access performance reports
- Performance report data is available in the system
- Browser supports PDF file downloads
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the performance reports section from the main dashboard | Performance reports page loads successfully and displays available report options |
| 2 | Select the desired date range and filters for the performance report | Filter options are applied and system acknowledges the selection |
| 3 | Click the 'Generate Report' button | Performance report is generated and displayed on screen with all relevant data, charts, and visualizations |
| 4 | Verify that the report contains expected data including metrics, graphs, and tables | Report displays complete performance data with proper formatting and all visualizations are rendered correctly |
| 5 | Locate and click the 'Export to PDF' button | Export process initiates and a loading indicator appears |
| 6 | Wait for the PDF export to complete | PDF file is generated and downloaded to the default download location within 5 seconds, and a success notification is displayed |
| 7 | Navigate to the download location and locate the downloaded PDF file | PDF file is present with a meaningful filename including report name and timestamp |
| 8 | Open the downloaded PDF file using a PDF reader application | PDF file opens successfully without errors |
| 9 | Verify that the PDF contains all performance data from the original report | All data points, metrics, and text content match the original report displayed on screen |
| 10 | Verify that all charts and visualizations are properly rendered in the PDF | All graphs, charts, and visual elements are clearly visible, properly formatted, and maintain their original appearance |
| 11 | Check the overall formatting and layout of the PDF document | PDF maintains professional formatting with proper headers, footers, page breaks, and consistent styling throughout the document |

**Postconditions:**
- PDF file is successfully saved in the download directory
- Original performance report remains accessible in the application
- Export action is logged in the system audit trail
- User can perform additional exports if needed
- No data corruption or loss occurs during export process

---

