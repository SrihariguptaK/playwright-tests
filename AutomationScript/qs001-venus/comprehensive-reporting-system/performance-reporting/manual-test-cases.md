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
- User has valid role-based access permissions for performance reporting
- At least one team exists in the system with performance data
- Task and attendance data is available in the database
- Performance Reporting module is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Performance Reporting section from the main dashboard | Performance report UI is displayed with KPI options including productivity metrics, quality metrics, task completion rates, and attendance statistics |
| 2 | Select desired KPIs from the available options (e.g., task completion rate, quality score) | Selected KPIs are highlighted and marked as chosen without any errors |
| 3 | Apply filters for team selection by choosing a specific team from the dropdown | Team filter is applied and displayed in the filter summary section |
| 4 | Apply time period filter by selecting start and end dates | Time period filter is accepted and displayed in the filter summary section without validation errors |
| 5 | Click the 'Generate Report' button to submit the report generation request | Performance report is generated and visualized within 5 seconds showing selected KPIs with charts and graphs |
| 6 | Review the generated report for completeness and accuracy | Report displays all selected KPIs with corresponding data visualizations and numerical values |

**Postconditions:**
- Performance report is successfully generated and displayed
- Report data is cached for quick access
- User remains on the Performance Reporting page
- Export options are available for the generated report

---

### Test Case: Export performance report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Department Manager
- User has valid role-based access permissions for performance reporting
- Performance report has been generated with selected KPIs
- Report is currently displayed on screen with visualizations
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate performance report by selecting KPIs, team filter, and time period, then clicking 'Generate Report' | Report is displayed with visualizations including charts, graphs, and data tables showing selected KPIs |
| 2 | Locate and click the 'Export to PDF' button in the report toolbar | PDF file download is initiated and file is saved to the default download location |
| 3 | Open the downloaded PDF file using a PDF reader | PDF file opens successfully and contains all report data including visualizations, KPIs, filters applied, and data tables with correct formatting |
| 4 | Return to the performance report page and click the 'Export to Excel' button | Excel file download is initiated and file is saved to the default download location |
| 5 | Open the downloaded Excel file using spreadsheet software | Excel file opens successfully and contains all report data in structured format with separate sheets for different KPIs, proper column headers, and accurate data values |
| 6 | Verify data integrity by comparing exported files with on-screen report | Both PDF and Excel exports contain identical data to the displayed report with no data loss or corruption |

**Postconditions:**
- PDF file is successfully downloaded and contains complete report data
- Excel file is successfully downloaded and contains complete report data
- User remains on the Performance Reporting page
- Original report remains displayed on screen
- Export action is logged in system audit trail

---

### Test Case: Verify integration of task and attendance data in performance report
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Department Manager
- User has valid role-based access permissions for performance reporting
- Test team exists with known task completion data
- Test team has recorded attendance data for the selected time period
- Access to source task and attendance databases for verification
- Expected data values are documented for comparison

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Performance Reporting section and select KPIs that include both task metrics and attendance metrics | KPI selection interface displays both task-related and attendance-related metrics |
| 2 | Select a specific team from the team filter dropdown | Team filter is applied successfully |
| 3 | Select a time period for which test data is available and click 'Generate Report' | Report is generated and displayed with integrated data showing both task completion metrics and attendance statistics |
| 4 | Review the report to identify task-related data points (e.g., tasks completed, task quality scores) | Task data is displayed in the report with specific numerical values and visualizations |
| 5 | Review the report to identify attendance-related data points (e.g., attendance rate, hours worked) | Attendance data is displayed in the report with specific numerical values and visualizations |
| 6 | Cross-reference task data in the report against the source task database records | Report data matches source task database with 95% or higher accuracy for all task metrics |
| 7 | Cross-reference attendance data in the report against the source attendance database records | Report data matches source attendance database with 95% or higher accuracy for all attendance metrics |
| 8 | Review visualized trends (charts and graphs) for task and attendance correlation | Trends accurately reflect performance over time showing correlation between task completion and attendance patterns with correct data plotting |
| 9 | Verify that integrated metrics (combining task and attendance) are calculated correctly | Calculated metrics such as productivity rate (tasks per attendance hour) are mathematically correct based on source data |

**Postconditions:**
- Data integration accuracy is verified at 95% or higher
- Report demonstrates successful integration of multiple data sources
- Visualizations accurately represent integrated data
- User has confidence in report accuracy
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
- User has valid role-based access permissions for performance reporting
- Performance data exists for multiple time periods to show trends
- Performance Reporting module is accessible
- Browser supports interactive visualizations

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Performance Reporting section from the main dashboard | Performance report UI is displayed with options for KPI selection, time period selection, and visualization controls |
| 2 | Select performance KPIs for trend analysis (e.g., productivity rate, quality score, task completion rate) | Selected KPIs are highlighted and accepted by the system without errors |
| 3 | Select a time period by choosing start date and end date that spans multiple weeks or months | Time period selections are accepted and validated successfully, displaying the selected date range |
| 4 | Click 'View Trends' or 'Generate Visualization' button to request trend visualization | System processes the request and renders the visualization within 5 seconds |
| 5 | Review the trend visualization displayed on screen | Visualization displays accurate performance trends with line graphs or area charts showing KPI values over the selected time period with proper axis labels, legends, and data points |
| 6 | Hover over data points in the visualization to view detailed values | Tooltips appear showing exact KPI values, dates, and percentage changes for each data point |
| 7 | Verify trend direction (increasing, decreasing, or stable) matches expected performance changes | Trend lines accurately reflect actual performance changes over time based on underlying data |
| 8 | Change the time period selection to a different date range | Visualization updates dynamically to reflect the new time period with accurate trend data |

**Postconditions:**
- Performance trend visualization is successfully displayed
- Visualization accurately represents data over the selected time period
- User can interact with the visualization
- Visualization renders within performance requirements (5 seconds)
- User remains on the Performance Reporting page

---

### Test Case: Export performance report with visualizations
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Department Manager
- User has valid role-based access permissions for performance reporting
- Performance report with trend visualizations has been generated
- Visualizations are currently displayed on screen
- Browser allows file downloads
- PDF generation service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate performance report by selecting KPIs and time period, then viewing trend visualizations | Report is displayed with interactive trend visualizations showing performance KPIs over time with charts and graphs |
| 2 | Verify that all desired visualizations are visible on screen before export | All trend charts, graphs, and data visualizations are fully rendered and visible |
| 3 | Locate and click the 'Export to PDF' button in the report toolbar | PDF export process is initiated and a loading indicator appears |
| 4 | Wait for the PDF file download to complete | PDF file is successfully downloaded to the default download location within reasonable time |
| 5 | Open the downloaded PDF file using a PDF reader application | PDF file opens successfully without errors or corruption |
| 6 | Verify that all trend visualizations are included in the PDF export | PDF contains all charts, graphs, and visualizations that were displayed on screen with proper formatting and resolution |
| 7 | Check the quality and readability of visualizations in the PDF | Visualizations are clear, properly sized, maintain color coding, include legends and axis labels, and are readable |
| 8 | Verify that data values in the PDF match the on-screen report | All KPI values, trend data, and time period information in the PDF are identical to the displayed report |
| 9 | Check PDF metadata and formatting | PDF includes report title, generation date, selected filters, and proper page layout with headers and footers |

**Postconditions:**
- PDF file is successfully downloaded with complete visualizations
- Exported PDF maintains visual fidelity of on-screen report
- All trend visualizations are intact and readable in the PDF
- User remains on the Performance Reporting page
- Export action is logged in system audit trail
- Original report remains displayed on screen

---

