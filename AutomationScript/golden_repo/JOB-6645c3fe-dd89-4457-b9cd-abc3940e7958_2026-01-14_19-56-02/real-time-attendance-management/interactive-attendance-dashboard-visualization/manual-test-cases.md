# Manual Test Cases

## Story: As Manager, I want to view real-time attendance status on dashboard to achieve immediate workforce visibility
**Story ID:** story-13

### Test Case: Validate real-time attendance data display on dashboard
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has valid Manager credentials
- Attendance database contains current day employee check-in/out records
- Dashboard application is accessible and running
- Network connectivity is stable
- Browser is compatible (Chrome, Firefox, Edge latest versions)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid Manager credentials | Manager is successfully authenticated and redirected to the main dashboard |
| 2 | Click on the attendance dashboard menu option | Attendance dashboard loads displaying current attendance data including employee check-in/out status, department-wise summary, and visual indicators for absent/late employees |
| 3 | Verify the timestamp of the data displayed on the dashboard | Dashboard shows current timestamp indicating data freshness and real-time status |
| 4 | Note the current attendance count and wait for 60 seconds without any user interaction | Dashboard automatically refreshes after 60 seconds, timestamp updates to current time, and any new check-in/out data is reflected in the display |
| 5 | Select a specific department from the department filter dropdown | Dashboard updates immediately to display only attendance data for the selected department, showing filtered employee records and department-specific summary |
| 6 | Verify that the filtered data matches the selected department criteria | All displayed employee records belong to the selected department and summary statistics reflect only that department's data |

**Postconditions:**
- Dashboard remains in filtered view with selected department
- Auto-refresh continues to function every 60 seconds
- Manager session remains active
- No data corruption or system errors logged

---

### Test Case: Verify export of attendance dashboard reports
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Manager is logged into the system
- Attendance dashboard is loaded with current data
- Export functionality is enabled for Manager role
- Browser allows file downloads
- Sufficient disk space available for downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate and click the 'Export' button on the attendance dashboard | Export options menu appears showing PDF and Excel format options |
| 2 | Select 'Export as PDF' option from the export menu | PDF report generation process initiates, progress indicator is displayed |
| 3 | Wait for PDF generation to complete and verify the download | PDF file is successfully downloaded to the default download location with filename containing 'Attendance_Dashboard' and current date |
| 4 | Open the downloaded PDF file and verify its contents | PDF contains all visible dashboard data including attendance summary, employee status, department breakdown, and timestamp matching the dashboard view |
| 5 | Return to the dashboard and click the 'Export' button again | Export options menu appears again |
| 6 | Select 'Export as Excel' option from the export menu | Excel report generation process initiates, progress indicator is displayed |
| 7 | Wait for Excel generation to complete and verify the download | Excel file (.xlsx) is successfully downloaded to the default download location with filename containing 'Attendance_Dashboard' and current date |
| 8 | Open the downloaded Excel file and verify its contents | Excel file contains all dashboard data in structured format with proper columns for employee name, department, check-in time, check-out time, status, and summary sheets matching the dashboard view |

**Postconditions:**
- Two report files (PDF and Excel) are saved in download location
- Dashboard remains in current state without data loss
- Export functionality remains available for subsequent use
- No temporary files left in system cache

---

### Test Case: Test dashboard load performance
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager has valid login credentials
- System is under normal load conditions (baseline user activity)
- Network latency is within acceptable range (<100ms)
- Database contains representative attendance data
- Performance monitoring tools are available to measure load time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Clear browser cache and cookies to ensure clean test environment | Browser cache and cookies are cleared successfully |
| 2 | Open browser developer tools and navigate to the Network tab to monitor page load metrics | Developer tools are open and ready to capture performance metrics |
| 3 | Navigate to the login page and enter valid Manager credentials | Manager is authenticated successfully |
| 4 | Start the performance timer and click on the attendance dashboard menu option | Dashboard loading process begins, loading indicator is displayed |
| 5 | Monitor the dashboard loading process until all elements are fully rendered | Dashboard completes loading with all components visible including charts, tables, summary cards, and filter controls |
| 6 | Check the Network tab in developer tools and note the total page load time from initial request to DOM content loaded | Total dashboard load time is 3 seconds or less, all API calls return successfully with status 200 |
| 7 | Verify that all dashboard elements are interactive and data is fully populated | All attendance data is displayed correctly, filters are functional, and no loading spinners or placeholders remain visible |
| 8 | Repeat steps 1-7 two more times to ensure consistent performance | Dashboard loads within 3 seconds in all three test iterations under normal load conditions |

**Postconditions:**
- Dashboard is fully loaded and functional
- Performance metrics are documented
- System remains stable with no memory leaks
- All API endpoints responded within acceptable time limits

---

## Story: As Manager, I want to filter attendance dashboard by department and date to achieve focused insights
**Story ID:** story-14

### Test Case: Validate filtering by department and date range
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager is logged into the system with appropriate permissions
- Attendance dashboard is loaded and displaying full data set
- Multiple departments exist in the system with attendance records
- Attendance data exists for multiple dates
- Filter controls are visible and enabled on the dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the department filter dropdown on the attendance dashboard | Department dropdown is visible and displays placeholder text 'Select Department' or shows 'All Departments' |
| 2 | Click on the department dropdown to expand the list of available departments | Dropdown expands showing a complete list of all departments in the organization |
| 3 | Select a valid department (e.g., 'Engineering') from the dropdown list | Selected department is highlighted and displayed in the dropdown field |
| 4 | Locate the date range picker control on the dashboard | Date range picker is visible with 'From Date' and 'To Date' fields or a calendar icon |
| 5 | Click on the date range picker and select a valid date range (e.g., last 7 days) | Calendar interface opens, selected date range is highlighted and displayed in the date fields |
| 6 | Click 'Apply' or wait for auto-apply of filters | Dashboard updates within 2 seconds showing loading indicator, then displays filtered attendance data for the selected department and date range |
| 7 | Examine the employee records displayed in the dashboard table | All displayed employee records belong to the selected department (Engineering) only |
| 8 | Verify the dates of all attendance records shown in the dashboard | All attendance records fall within the selected date range, no records outside the range are displayed |
| 9 | Check the summary statistics and visualizations on the dashboard | Summary cards, charts, and graphs reflect only the filtered data (selected department and date range), totals and percentages are recalculated accordingly |
| 10 | Locate and click the 'Reset Filters' or 'Clear All' button | Reset button is clicked successfully |
| 11 | Observe the dashboard behavior after clicking reset | All filter selections are cleared (department shows 'All Departments', date range resets to default), dashboard reloads and displays the full attendance data set for all departments and default date range |
| 12 | Verify the record count and summary statistics after reset | Dashboard shows complete unfiltered data with total record count matching the original state before filtering |

**Postconditions:**
- Dashboard displays full unfiltered data set
- All filter controls are reset to default state
- No filter criteria are applied
- Dashboard performance remains optimal
- Filter state is ready for next filtering operation

---

### Test Case: Verify filter input validation
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Manager is logged into the system
- Attendance dashboard is loaded and accessible
- Filter controls are enabled and visible
- Validation rules are configured for department and date inputs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the department filter dropdown on the dashboard | Department dropdown is visible and accessible |
| 2 | Attempt to manually enter an invalid or non-existent department name in the department filter (if text input is allowed) or use browser console to inject invalid department value | System detects invalid department input |
| 3 | Observe the system response to invalid department input | Validation error message is displayed (e.g., 'Invalid department selected' or 'Department does not exist'), error message is shown in red or with warning icon, filter is not applied, dashboard data remains unchanged |
| 4 | Clear the invalid department input and locate the date range picker | Error message clears, date range picker is accessible |
| 5 | Enter an invalid date format in the 'From Date' field (e.g., '99/99/9999' or 'invalid-date') | Date field accepts the input or shows inline validation |
| 6 | Attempt to apply the filter with invalid date format | Validation error message is displayed (e.g., 'Invalid date format. Please use MM/DD/YYYY'), error is highlighted on the date field, filter query is prevented from executing, dashboard data remains unchanged |
| 7 | Clear the invalid date and enter a valid 'From Date' but enter a 'To Date' that is earlier than 'From Date' (e.g., From: 01/15/2024, To: 01/10/2024) | Both dates are entered in the fields |
| 8 | Attempt to apply the filter with invalid date range (To Date before From Date) | Validation error message is displayed (e.g., 'End date must be after start date' or 'Invalid date range'), error is highlighted on the date range picker, filter query is prevented from executing, dashboard data remains unchanged |
| 9 | Enter a future date in the date range picker (e.g., a date 30 days from today) | Future date is entered in the field |
| 10 | Attempt to apply the filter with future date | System either displays validation warning (e.g., 'Future dates selected - no data available') or allows the query but returns empty results with appropriate message, no system error occurs, dashboard handles the scenario gracefully |
| 11 | Verify that no database query was executed for any of the invalid input scenarios | Network tab in browser developer tools shows no API calls were made for invalid filter attempts, system prevented unnecessary database queries |

**Postconditions:**
- Dashboard remains in stable state with original data displayed
- No invalid data was queried from the database
- All validation error messages are cleared when valid inputs are provided
- Filter controls are ready for valid input
- No system errors or exceptions are logged

---

## Story: As Manager, I want to export attendance dashboard reports to achieve offline analysis and sharing
**Story ID:** story-17

### Test Case: Validate export of filtered dashboard data to PDF and Excel
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Attendance dashboard is accessible and loaded
- Attendance data exists in the system for the selected time period
- Browser has download permissions enabled
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard page | Dashboard loads successfully displaying attendance data with available filter options |
| 2 | Apply date range filter by selecting start date and end date from the filter panel | Dashboard updates and displays attendance data only for the selected date range |
| 3 | Apply department filter by selecting a specific department from the dropdown | Dashboard refreshes and shows attendance data filtered by the selected department |
| 4 | Verify that charts and tabular data reflect the applied filters | All visible charts and tables display data matching the applied filter criteria |
| 5 | Click on the 'Export' button located on the dashboard toolbar | Export format selection dialog appears with PDF and Excel options |
| 6 | Select 'PDF' format from the export options | System initiates PDF generation process and shows loading indicator |
| 7 | Wait for the PDF file to be generated and downloaded | PDF file downloads successfully to the default download location within 10 seconds |
| 8 | Open the downloaded PDF file and verify its contents | PDF contains all visible charts, tabular data, and reflects the applied filters with proper formatting and readability |
| 9 | Return to the dashboard and click the 'Export' button again | Export format selection dialog appears again |
| 10 | Select 'Excel' format from the export options | System initiates Excel generation process and shows loading indicator |
| 11 | Wait for the Excel file to be generated and downloaded | Excel file downloads successfully to the default download location within 10 seconds |
| 12 | Open the downloaded Excel file and verify its contents | Excel file contains all tabular data in structured format with proper column headers, reflects applied filters, and data is accurate and readable |

**Postconditions:**
- Two export files (PDF and Excel) are saved in the download folder
- Dashboard remains in the same filtered state
- User session remains active
- No errors are logged in the system

---

### Test Case: Verify export generation time and confirmation
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Attendance dashboard is loaded with data
- System is under normal load conditions
- Browser has download permissions enabled
- Timer or stopwatch is available to measure export time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard | Dashboard loads successfully with attendance data displayed |
| 2 | Apply any filter to the dashboard (e.g., select a date range) | Dashboard updates with filtered data |
| 3 | Click on the 'Export' button and note the current time | Export format selection dialog appears |
| 4 | Select 'PDF' format and start timing the export process | System begins generating the PDF export and displays a loading indicator |
| 5 | Monitor the export generation process and measure the time taken | Export generation completes within 10 seconds from the moment of format selection |
| 6 | Observe the system response after export completion | System displays a confirmation message such as 'Export successful' or 'Report downloaded successfully' |
| 7 | Verify the confirmation message contains relevant information | Confirmation message includes file name, format, and success status |
| 8 | Check the download folder for the exported file | Exported PDF file is present in the download folder with correct naming convention and timestamp |
| 9 | Repeat the export process with Excel format and measure the time | Excel export completes within 10 seconds and confirmation message is displayed |
| 10 | Verify the Excel file is downloaded successfully | Excel file is present in the download folder and confirmation message was displayed |

**Postconditions:**
- Export files are successfully downloaded
- Confirmation messages were displayed for both exports
- Export generation time was within acceptable limits (under 10 seconds)
- Dashboard remains functional and responsive
- No error messages or system issues occurred

---

## Story: As Manager, I want to view employee punctuality trends to achieve better attendance insights
**Story ID:** story-19

### Test Case: Validate punctuality trend chart display and filtering
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Dashboard is accessible and loaded
- Attendance data with timestamps exists in the system
- Multiple employees and departments have attendance records
- Punctuality trend feature is enabled for the manager role

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard page | Dashboard loads successfully and displays punctuality trend charts section |
| 2 | Verify that punctuality trend charts are visible on the dashboard | Punctuality trend charts are displayed showing data over time with proper axis labels and legends |
| 3 | Locate the employee filter dropdown in the punctuality section | Employee filter dropdown is visible and contains a list of employees |
| 4 | Select a specific employee from the employee filter dropdown | Punctuality trend chart updates within 3 seconds to display data only for the selected employee |
| 5 | Verify the chart data matches the selected employee's attendance records | Chart displays accurate punctuality data including on-time arrivals, late arrivals, and timestamps for the selected employee |
| 6 | Locate the department filter dropdown in the punctuality section | Department filter dropdown is visible and contains a list of departments |
| 7 | Select a specific department from the department filter dropdown | Punctuality trend chart updates within 3 seconds to display aggregated data for all employees in the selected department |
| 8 | Verify the chart reflects department-level punctuality trends | Chart shows punctuality trends for the selected department with accurate data aggregation |
| 9 | Locate and review the summary statistics section on the dashboard | Summary statistics are displayed including metrics such as average late arrivals, total late days, punctuality percentage, and on-time percentage |
| 10 | Manually calculate or cross-reference summary statistics with raw attendance data | Summary statistics match the actual attendance data with 95% or higher accuracy |
| 11 | Verify that statistics update when filters are changed | Summary statistics dynamically update to reflect the currently applied employee or department filter |
| 12 | Click on the 'Export' button in the punctuality trend section | Export format selection dialog appears with PDF and Excel options |
| 13 | Select 'PDF' format and initiate the export | PDF trend report is generated and downloaded successfully within 10 seconds |
| 14 | Open the downloaded PDF report and verify its contents | PDF contains punctuality trend charts, summary statistics, and reflects the currently applied filters with proper formatting |
| 15 | Return to dashboard and export the trend report in Excel format | Excel trend report is generated and downloaded successfully with tabular punctuality data |
| 16 | Open the Excel file and verify data accuracy | Excel file contains detailed punctuality data in structured format matching the dashboard display and applied filters |

**Postconditions:**
- Punctuality trend charts are displayed with accurate filtered data
- Summary statistics reflect the applied filters
- Export files (PDF and Excel) are saved successfully
- Dashboard remains in filtered state
- No errors occurred during filtering or export operations

---

### Test Case: Test real-time update of punctuality data
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Dashboard is loaded and displaying punctuality trend charts
- System has real-time data refresh capability enabled
- Test environment allows simulation of new attendance entries
- Access to create or simulate attendance data entries is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard and locate the punctuality trend charts | Dashboard loads successfully with punctuality trend charts visible showing current data |
| 2 | Note the current data displayed in the punctuality trend chart including the latest timestamp and data points | Current punctuality data is visible and documented for comparison |
| 3 | Open a separate browser tab or use admin interface to access attendance data entry | Attendance data entry interface is accessible |
| 4 | Create a new attendance entry for an employee with a timestamp indicating late arrival (e.g., 15 minutes after scheduled start time) | New attendance record is successfully created and saved in the system |
| 5 | Return to the dashboard tab with punctuality trend charts | Dashboard is still active and displaying the previous data state |
| 6 | Wait and observe the punctuality trend chart for automatic updates (monitor for up to 60 seconds) | Punctuality trend chart automatically refreshes and updates to include the newly entered attendance data within 60 seconds |
| 7 | Verify that the new data point appears on the trend chart | New late arrival is reflected in the chart with correct timestamp and punctuality status |
| 8 | Check if summary statistics have updated to reflect the new attendance entry | Summary statistics such as average late arrivals and punctuality percentage are recalculated and updated to include the new data |
| 9 | Simulate another attendance entry with on-time arrival | Second attendance record is successfully created in the system |
| 10 | Monitor the dashboard for the second real-time update | Dashboard updates within 60 seconds to reflect the second attendance entry with accurate punctuality status |
| 11 | Verify data consistency across all chart elements and statistics | All charts, graphs, and summary statistics consistently reflect the updated attendance data with no discrepancies |

**Postconditions:**
- Punctuality trend charts display the most recent attendance data
- Summary statistics are updated and accurate
- Real-time refresh functionality is confirmed working
- New attendance entries are visible on the dashboard
- System performance remains stable during real-time updates

---

## Story: As Manager, I want to view employee presence heatmaps to achieve spatial attendance insights
**Story ID:** story-20

### Test Case: Validate heatmap display and filtering
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Dashboard is accessible and loaded
- Attendance location data exists for multiple dates and departments
- Browser supports PNG image downloads
- User has role-based access to view heatmaps

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the dashboard page | Dashboard loads successfully and heatmap visualization section is visible |
| 2 | Locate the date filter dropdown on the heatmap section | Date filter dropdown is displayed with available date options |
| 3 | Select a specific date from the date filter dropdown | Selected date is highlighted and heatmap begins to update |
| 4 | Locate the department filter dropdown on the heatmap section | Department filter dropdown is displayed with available department options |
| 5 | Select a specific department from the department filter dropdown | Selected department is highlighted and heatmap updates to reflect filtered data with color-coded presence intensity for the selected date and department |
| 6 | Verify the heatmap displays color-coded presence data matching the applied filters | Heatmap shows accurate employee presence intensity with appropriate color gradients representing different presence levels for the filtered date and department |
| 7 | Use mouse scroll or zoom controls to zoom into a specific area of the heatmap | Heatmap zooms in smoothly, showing more detailed view of the selected area with maintained visual clarity |
| 8 | Hover mouse cursor over a specific location on the heatmap | Tooltip or popup appears displaying detailed presence information including location name, number of employees present, department, and timestamp |
| 9 | Move cursor to different locations on the heatmap | Hover details update dynamically showing relevant information for each hovered location |
| 10 | Locate and click the 'Export' or 'Download' button for the heatmap | Export dialog appears or download process initiates |
| 11 | Confirm the export action if prompted and wait for download to complete | PNG image file downloads successfully to the default download location |
| 12 | Open the downloaded PNG file | PNG image opens correctly displaying the heatmap visualization with all applied filters and current zoom level preserved |

**Postconditions:**
- Heatmap remains displayed with applied filters
- PNG image file is saved in downloads folder
- User session remains active
- No errors are logged in the system

---

### Test Case: Test heatmap load performance
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role credentials
- System is under normal load conditions (not peak hours)
- Network connection is stable with normal bandwidth
- Attendance location data is available in the database
- Browser cache is cleared to ensure accurate load time measurement
- Performance monitoring tools are ready (browser developer tools or stopwatch)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab to monitor load times | Developer tools open successfully and Network tab is active with recording enabled |
| 2 | Start timer or note the current timestamp | Timer is started and ready to measure load time |
| 3 | Navigate to the dashboard page containing the heatmap visualization | Dashboard page begins loading and API call to GET /api/dashboard/heatmap is initiated |
| 4 | Wait for the heatmap visualization to fully render with all visual elements displayed | Heatmap visualization loads completely with color-coded presence data, all interactive elements are functional, and loading indicators disappear |
| 5 | Stop timer and record the total load time from navigation to full render | Total load time is recorded and is 4 seconds or less |
| 6 | Verify in Network tab that GET /api/dashboard/heatmap API call completed successfully with 200 status code | API call shows successful response (200 OK) and response time contributes to overall load time under 4 seconds |
| 7 | Interact with the heatmap by hovering over a location to confirm full functionality | Heatmap responds immediately to interaction showing that all data and interactive features are fully loaded |

**Postconditions:**
- Heatmap is fully loaded and functional
- Load time is documented and meets performance requirement of under 4 seconds
- System remains stable under normal load
- No performance errors are logged

---

