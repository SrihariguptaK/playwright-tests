# Manual Test Cases

## Story: As Manager, I want to view real-time attendance dashboards to achieve immediate insight into team attendance status
**Story ID:** story-3

### Test Case: Validate real-time dashboard data display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager has valid credentials with dashboard access permissions
- Attendance database contains current day attendance records
- Dashboard portal is accessible and operational
- Manager has access to at least one team/department
- Browser is supported (Chrome, Firefox, Safari, Edge latest versions)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard portal URL | Dashboard login page is displayed |
| 2 | Enter valid manager credentials (username and password) and click Login button | Manager is authenticated and dashboard loads displaying current attendance metrics including present, absent, and late arrivals counts |
| 3 | Verify dashboard displays real-time data with timestamp showing last update within 30 seconds | Dashboard shows current attendance status with timestamp indicating data freshness within 30 seconds |
| 4 | Select a specific team from the team filter dropdown | Team filter is applied and dropdown shows selected team |
| 5 | Select a date range using the date range picker (e.g., last 7 days) | Date range is applied and dashboard updates to reflect attendance data for the selected team and date range |
| 6 | Verify that attendance metrics (present, absent, late) are updated to match the filtered criteria | Dashboard displays accurate attendance metrics filtered by selected team and date range with trend charts showing data for the specified period |
| 7 | Click on a specific employee name or record in the dashboard to drill down | Detailed attendance information panel opens showing individual employee's attendance history including dates, check-in/check-out times, status, and any notes |
| 8 | Verify all detailed information is displayed correctly for the selected employee | Employee attendance details are complete, accurate, and match the aggregated data shown in the dashboard |

**Postconditions:**
- Manager remains logged into the dashboard
- Dashboard displays filtered data based on last applied filters
- Employee detail panel can be closed to return to main dashboard view
- Session is active and data continues to refresh every 30 seconds

---

### Test Case: Verify dashboard export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager is logged into the attendance dashboard portal
- Dashboard is displaying attendance data (with or without filters applied)
- Manager has export permissions enabled
- Browser allows file downloads
- PDF and Excel export functionality is enabled on the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate and click the Export button on the dashboard toolbar | Export dialog box appears displaying available format options (PDF and Excel) |
| 2 | Note the current on-screen data including metrics, team name, date range, and attendance counts for verification | On-screen data is documented for comparison with exported reports |
| 3 | Select PDF format option from the export dialog and click Export/Download button | PDF file download initiates and file is saved to the downloads folder |
| 4 | Open the downloaded PDF file and verify it contains the same data displayed on the dashboard | PDF report matches on-screen data including all metrics, filters applied, date range, team information, and attendance counts. Report is properly formatted and readable |
| 5 | Return to the dashboard and click the Export button again | Export dialog appears with format options |
| 6 | Select Excel format option from the export dialog and click Export/Download button | Excel file download initiates and file is saved to the downloads folder |
| 7 | Open the downloaded Excel file and verify it contains the correct data and formatting | Excel file matches on-screen data with proper column headers, data rows, formatting, and formulas if applicable. All attendance metrics are accurate and match the dashboard display |
| 8 | Verify Excel file contains all expected sheets and data is properly structured for further analysis | Excel file is well-structured with clear headers, properly formatted cells, and data that can be manipulated for additional analysis |

**Postconditions:**
- Two export files (PDF and Excel) are saved in the downloads folder
- Both exported files contain accurate data matching the dashboard display
- Manager remains logged into the dashboard
- Dashboard state is unchanged after export operations
- Export dialog is closed

---

### Test Case: Ensure dashboard performance under load
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Performance testing environment is set up with load testing tools
- Multiple manager test accounts are created and configured
- Attendance database is populated with realistic data volume
- Dashboard application is deployed and operational
- Network conditions are stable and monitored
- Performance monitoring tools are in place to measure load times

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure load testing tool to simulate 20 concurrent manager users accessing the dashboard portal simultaneously | Load testing tool is configured with 20 virtual users with valid manager credentials |
| 2 | Initiate the load test to have all 20 users log in and access the dashboard at the same time | All 20 virtual users successfully authenticate and request dashboard data concurrently |
| 3 | Measure and record the dashboard load time for each of the 20 concurrent users | Dashboard loads within 5 seconds for all 20 users. Performance monitoring shows load times are consistently under the 5-second threshold |
| 4 | Verify that all users receive the dashboard without errors or timeouts | All 20 users successfully view the dashboard with no error messages, timeouts, or failed requests |
| 5 | Compare the attendance data displayed to each concurrent user at the same timestamp | All users see consistent and identical attendance metrics for the same teams and time periods |
| 6 | Verify data accuracy by comparing displayed metrics against the source attendance database | All users see up-to-date data that matches the current state of the attendance database with timestamps within 30 seconds of current time |
| 7 | Have all concurrent users apply different filters and verify response times | Dashboard updates with filtered data within 3 seconds for all concurrent users without performance degradation |
| 8 | Monitor server resources (CPU, memory, database connections) during the load test | Server resources remain within acceptable limits with no crashes, memory leaks, or database connection exhaustion |

**Postconditions:**
- All 20 concurrent user sessions can be terminated cleanly
- Dashboard performance meets the 5-second load time requirement under concurrent load
- Data consistency is maintained across all concurrent sessions
- System resources return to normal levels after load test completion
- No errors or warnings are logged during the load test
- Performance test results are documented for future reference

---

## Story: As Manager, I want to filter attendance dashboard data by department and date to achieve focused attendance insights
**Story ID:** story-6

### Test Case: Validate dashboard filtering by department and date
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager is logged into the attendance dashboard portal
- Dashboard is loaded and displaying default attendance data
- Manager has access to multiple departments
- Attendance database contains records for multiple departments and date ranges
- Filter controls are visible and enabled on the dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the department filter dropdown on the dashboard | Department filter dropdown is visible and displays available departments the manager has access to |
| 2 | Click on the department filter dropdown and select a specific department (e.g., 'Engineering') | Department is selected and displayed in the dropdown |
| 3 | Locate the date range filter and click on the date picker control | Date picker calendar interface opens allowing date range selection |
| 4 | Select a start date and end date for the desired range (e.g., last 30 days) | Date range is selected and displayed in the date filter field |
| 5 | Click Apply or wait for auto-refresh after filter selection | Dashboard updates within 3 seconds displaying attendance data filtered by the selected department and date range |
| 6 | Verify that the displayed attendance metrics reflect only the selected department and date range | Dashboard shows attendance data exclusively for the selected department within the specified date range. Metrics, charts, and employee lists are updated accordingly |
| 7 | Locate and click the 'Save Filter Preset' or 'Save Filter' button | Save filter dialog appears prompting for a preset name |
| 8 | Enter a descriptive name for the filter preset (e.g., 'Engineering Last 30 Days') and click Save | Filter preset is saved successfully and confirmation message is displayed. Preset appears in the saved presets list or dropdown |
| 9 | Apply different filters or navigate away from the current view, then select the saved preset from the presets dropdown | Dashboard immediately applies the saved filter preset and displays data for Engineering department for the last 30 days as originally configured |
| 10 | Locate and click the 'Clear Filters' or 'Reset' button | All applied filters are removed and dashboard resets to default view showing all departments and default date range |
| 11 | Verify that the dashboard displays unfiltered data after clearing filters | Dashboard shows attendance data for all accessible departments with default date range. Filter controls are reset to default state |

**Postconditions:**
- Filter preset is saved and available for future use
- Dashboard is in default unfiltered state after clearing filters
- Manager remains logged into the dashboard
- All filter controls are functional and ready for new filter applications
- Saved preset can be edited or deleted if needed

---

### Test Case: Verify access control on filtered data
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager is logged into the attendance dashboard portal
- Manager has restricted access to specific departments only (e.g., only Engineering and Marketing)
- System has departments that the manager does not have access to (e.g., Finance, HR)
- Role-based access control is properly configured in the system
- Dashboard filter controls are visible and enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Click on the department filter dropdown to view available departments | Dropdown displays only departments the manager has access to (Engineering and Marketing). Unauthorized departments (Finance, HR) are not visible in the list |
| 2 | Verify that unauthorized departments are not present in the filter options | Only authorized departments appear in the dropdown. Finance and HR departments are not listed |
| 3 | Attempt to manually construct a URL or API request to access attendance data for an unauthorized department (e.g., Finance) by modifying query parameters | System detects unauthorized access attempt and prevents data retrieval |
| 4 | Observe the system response to the unauthorized access attempt | System displays an error message such as 'Access Denied: You do not have permission to view this department's data' or 'Unauthorized access to department'. HTTP 403 Forbidden status is returned |
| 5 | Verify that no attendance data for the unauthorized department is displayed on the dashboard | Dashboard does not display any attendance metrics, employee names, or other data from the unauthorized department. Error message is clearly visible to the user |
| 6 | Check application logs or security audit logs for the unauthorized access attempt | Security event is logged with details including manager ID, attempted department access, timestamp, and denial reason |
| 7 | Return to normal dashboard operation by selecting an authorized department from the filter | Dashboard functions normally and displays attendance data for the authorized department without any issues |

**Postconditions:**
- Manager's access remains restricted to authorized departments only
- No unauthorized data was exposed or displayed
- Security event is logged in the audit trail
- Dashboard continues to function normally for authorized access
- Manager can continue using the dashboard with proper access controls enforced
- Error message is dismissed and dashboard is in usable state

---

## Story: As Manager, I want to drill down from summary metrics to individual employee attendance to achieve detailed attendance analysis
**Story ID:** story-7

### Test Case: Validate drill-down from summary to employee attendance
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager is logged into the attendance dashboard with valid credentials
- Manager has appropriate role-based permissions to view employee attendance details
- Attendance data is available in the system for the current period
- Summary metrics are displayed on the dashboard showing absent count
- At least one employee has an absence record in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard and verify summary metrics are visible | Dashboard loads successfully and displays summary metrics including absent count, present count, and other attendance statistics |
| 2 | Click on the absent count metric displayed on the dashboard | Dashboard transitions to drill-down view and displays a list of all absent employees with columns showing employee name, employee ID, date of absence, and absence type. Response time is under 3 seconds |
| 3 | Verify the number of employees in the drill-down list matches the absent count from the summary metric | The count of employees displayed in the list exactly matches the absent count number shown in the summary metric, confirming data consistency |
| 4 | Select an employee from the displayed list by clicking on their name or row | Detailed attendance record view opens for the selected employee showing complete attendance history, including dates, attendance status, leave types, anomalies, and any relevant notes |
| 5 | Review the detailed attendance information displayed for accuracy and completeness | All attendance details are displayed correctly with proper formatting, dates are in chronological order, and attendance patterns/anomalies are highlighted if present |
| 6 | Click on the 'Back' or 'Return to Summary' navigation button | Dashboard navigates back to the summary view displaying the original summary metrics without loss of any previously applied filters or settings |
| 7 | Verify the summary dashboard is displayed in its original state | Summary dashboard is fully visible with all metrics displayed correctly, maintaining the same state as before the drill-down operation |

**Postconditions:**
- Manager is returned to the summary dashboard view
- No data has been modified during the drill-down operation
- Session remains active and authenticated
- All navigation history is preserved for potential back/forward navigation

---

## Story: As Manager, I want to export attendance dashboard reports to achieve offline analysis and sharing
**Story ID:** story-8

### Test Case: Validate export of dashboard reports
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Manager is logged into the attendance dashboard with valid credentials
- Manager has appropriate permissions to export attendance reports
- Attendance data is available and displayed on the dashboard
- Browser allows file downloads and pop-ups are not blocked
- Export functionality is enabled in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard and verify data is displayed | Dashboard loads successfully showing attendance summary metrics and data for the current period |
| 2 | Apply filters to the dashboard by selecting a specific date range (e.g., last 30 days) and department | Dashboard refreshes and displays filtered attendance data matching the selected date range and department criteria. Filter tags are visible showing active filters |
| 3 | Perform a drill-down operation by clicking on a specific metric (e.g., late arrivals count) | Drill-down view displays showing detailed list of employees matching the late arrivals criteria with the applied filters still active |
| 4 | Locate and click on the 'Export' button or menu option on the dashboard | Export options dialog or menu appears displaying available export formats including PDF and Excel options |
| 5 | Select 'Export as PDF' option from the export menu | System initiates PDF report generation. Progress indicator or loading message is displayed. PDF file is generated and download begins within 30 seconds |
| 6 | Open the downloaded PDF file and verify its contents | PDF opens successfully and contains all dashboard data matching the on-screen view including applied filters (date range, department), drill-down data (late arrivals list), employee details, and summary metrics. Report header shows filter criteria and generation timestamp |
| 7 | Return to the dashboard and click on the 'Export' button again | Export options dialog appears again showing PDF and Excel format options |
| 8 | Select 'Export as Excel' option from the export menu | System initiates Excel report generation. Progress indicator is displayed. Excel file (.xlsx) is generated and download begins within 30 seconds |
| 9 | Open the downloaded Excel file and verify its contents | Excel file opens successfully with properly formatted spreadsheet containing all dashboard data. Data includes applied filters, drill-down details, employee information in separate columns, and summary statistics. All data matches the on-screen dashboard view exactly |
| 10 | Verify that both exported files contain identical data in their respective formats | PDF and Excel exports contain the same data values, employee counts, metrics, and filter criteria, confirming consistency across export formats |

**Postconditions:**
- Two report files (PDF and Excel) are successfully downloaded to the manager's device
- Dashboard remains in the same state with filters and drill-downs still applied
- No data has been modified during the export process
- Export activity is logged in the system audit trail
- Manager session remains active

---

### Test Case: Verify export error handling
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager is logged into the attendance dashboard with valid credentials
- Manager has appropriate permissions to export reports
- Test environment allows simulation of export failures
- Dashboard is displaying attendance data
- System administrator or test setup can trigger report generation failure

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard and verify data is displayed | Dashboard loads successfully with attendance data visible |
| 2 | Configure the test environment to simulate a report generation failure (e.g., disable report service, simulate database timeout, or trigger server error) | Test environment is configured to force export failure on next export attempt |
| 3 | Click on the 'Export' button and select 'Export as PDF' option | System attempts to generate the PDF report. Progress indicator is displayed showing export is in progress |
| 4 | Wait for the system to detect and respond to the simulated failure | System detects the report generation failure and stops the export process gracefully without crashing or freezing the dashboard |
| 5 | Observe the error notification displayed to the manager | Clear and user-friendly error message is displayed stating 'Report generation failed. Please try again later or contact support if the issue persists.' Error message includes an error reference ID or timestamp for troubleshooting |
| 6 | Verify the dashboard remains functional after the error | Dashboard is still fully functional, all data is visible, filters work correctly, and navigation is not impaired. No data loss or corruption occurred |
| 7 | Click the 'Close' or 'OK' button on the error message | Error message closes and manager can continue using the dashboard normally |
| 8 | Attempt to export again using 'Export as Excel' option while failure condition is still active | System again attempts export, detects failure, and displays the same type of clear error message without system instability |
| 9 | Restore the test environment to normal operation (remove failure simulation) | Test environment is restored and export functionality should work normally |
| 10 | Attempt to export as PDF again with normal system operation | Export completes successfully and PDF file downloads, confirming system has recovered from error state |

**Postconditions:**
- Dashboard remains stable and functional despite export failures
- Error messages have been displayed appropriately to the manager
- No partial or corrupted files were downloaded
- Export errors are logged in the system error logs for administrator review
- System has recovered and can successfully export reports after failure condition is removed
- Manager session remains active and authenticated

---

