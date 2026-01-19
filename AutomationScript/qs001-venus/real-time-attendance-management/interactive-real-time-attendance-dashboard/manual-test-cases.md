# Manual Test Cases

## Story: As Manager, I want to view real-time attendance status to achieve timely workforce monitoring
**Story ID:** story-15

### Test Case: Validate real-time attendance data display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Manager account exists with valid credentials and role-based access
- Attendance database contains current employee attendance records
- Dashboard application is accessible and operational
- Network connection is stable
- At least one department with active employees exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the dashboard login page and enter valid manager credentials (username and password), then click Login button | Manager is successfully authenticated and redirected to the dashboard home page. Dashboard loads with real-time attendance data displaying employee names, status indicators, timestamps, and department information within 3 seconds |
| 2 | Check the timestamp of the most recent attendance record displayed on the dashboard and compare it with the current system time | The data latency is under 30 seconds. Timestamp shows data is fresh and up-to-date. Real-time status indicators (present, absent, late) are accurately displayed |
| 3 | Locate the department filter dropdown, click on it, and select a specific department from the available options | Dashboard immediately updates to display only attendance data for the selected department. Employee count reflects the filtered department. All displayed records belong to the selected department. Filter selection is visually indicated |

**Postconditions:**
- Manager remains logged into the dashboard
- Filtered attendance data is displayed on screen
- Dashboard is ready for additional filtering or export operations
- Session remains active for further testing

---

### Test Case: Verify export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Manager is logged into the dashboard with valid credentials
- Attendance data is loaded and displayed on the dashboard
- Export functionality is enabled for the manager role
- Browser has permission to download files
- Sufficient storage space available on local machine

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the export options on the dashboard interface and click on the 'Export to PDF' button or option | System processes the export request. A PDF file is generated containing the current attendance data with proper formatting, headers, and company branding. Download dialog appears or file is automatically downloaded to the default downloads folder. PDF file is named with a timestamp (e.g., Attendance_Report_YYYY-MM-DD.pdf) |
| 2 | Open the downloaded PDF file and verify its contents, then return to the dashboard and click on the 'Export to Excel' button or option | System processes the Excel export request. An Excel file (.xlsx format) is generated containing the attendance data in a structured spreadsheet format with appropriate columns (Employee Name, Department, Location, Status, Time). Download dialog appears or file is automatically downloaded. Excel file is named with a timestamp (e.g., Attendance_Report_YYYY-MM-DD.xlsx). File opens successfully in Excel or compatible spreadsheet application |

**Postconditions:**
- Two files (PDF and Excel) are successfully downloaded to the local machine
- Both files contain accurate attendance data matching the dashboard display
- Files are properly formatted and readable
- Manager remains logged into the dashboard
- Dashboard state is unchanged after export operations

---

### Test Case: Test dashboard load performance
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Manager has valid login credentials
- Standard network connection is available (not high-speed or degraded)
- Network bandwidth is typical for business environment (10-100 Mbps)
- Dashboard application is deployed and operational
- Attendance database contains representative data volume
- Browser cache is cleared to simulate realistic load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Clear browser cache and cookies. Open a new browser window and navigate to the dashboard URL. Enter valid manager credentials and click Login. Start a timer immediately after clicking Login | Dashboard authentication completes successfully. Dashboard page fully loads with all attendance data, visual elements, filters, and interactive components rendered and functional. Total load time from login submission to complete dashboard display is 3 seconds or less. All attendance records are visible and status indicators are displayed correctly |

**Postconditions:**
- Dashboard is fully loaded and interactive
- All attendance data is displayed correctly
- Performance benchmark of 3 seconds or less is confirmed
- Manager can immediately interact with dashboard features
- Session is established and active

---

## Story: As Manager, I want to filter attendance data by department and location to achieve focused workforce insights
**Story ID:** story-16

### Test Case: Validate department and location filtering
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager is logged into the dashboard with appropriate permissions
- Dashboard displays unfiltered attendance data for all departments and locations
- Multiple departments exist in the system with attendance records
- Multiple locations exist in the system with attendance records
- Department and location filter dropdowns are visible and enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the department filter dropdown on the dashboard. Click on the dropdown to expand the list of available departments. Select one department from the list by clicking on it | Department dropdown expands showing all available departments. Selected department is highlighted or checked. Dashboard immediately updates within 2 seconds to display only attendance records for employees in the selected department. Employee count updates to reflect filtered results. All displayed records show the selected department name |
| 2 | With the department filter still active, select additional departments from the dropdown using multi-select functionality (Ctrl+Click or checkbox selection) | Multiple departments are selected and visually indicated in the filter. Dashboard updates to show attendance records for all selected departments. Data refreshes within 2 seconds. Employee count reflects the combined total from all selected departments |
| 3 | Locate the location filter dropdown. Click to expand it and select one location from the available options | Location dropdown expands showing all available locations. Selected location is highlighted or checked. Dashboard updates within 2 seconds to show only attendance records matching both the selected departments AND the selected location. Data is filtered by the intersection of department and location criteria. Record count updates accordingly |
| 4 | Select additional locations from the location dropdown using multi-select functionality | Multiple locations are selected and visually indicated. Dashboard updates to show attendance records matching selected departments AND any of the selected locations. Data refreshes within 2 seconds. All displayed records match the combined filter criteria |
| 5 | Locate and click the 'Reset Filters' or 'Clear All' button on the dashboard | All department and location filters are immediately cleared. Filter dropdowns return to default unselected state. Dashboard updates to display all attendance data without any filters applied. Full employee count is restored. Dashboard returns to the original unfiltered view within 2 seconds |

**Postconditions:**
- All filters are cleared and dashboard shows unfiltered data
- Filter dropdowns are reset to default state
- Dashboard is ready for new filter selections
- Manager remains logged in with active session
- No residual filter state remains in the system

---

### Test Case: Verify filter input validation
- **ID:** tc-005
- **Type:** error-case
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- Manager is logged into the dashboard
- Dashboard is fully loaded with attendance data
- Filter dropdowns are accessible and functional
- System has validation rules configured for filter inputs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to manually enter an invalid department name or code directly into the department filter field (if text input is allowed), or try to manipulate the dropdown selection using browser developer tools to inject an invalid value | System detects the invalid input and prevents the selection. A clear validation message is displayed near the filter field (e.g., 'Invalid department selection' or 'Please select a valid department from the list'). Dashboard data does not update with invalid filter. Filter dropdown remains in a valid state or returns to previous valid selection |
| 2 | Attempt to manually enter an invalid location name or code directly into the location filter field (if text input is allowed), or try to manipulate the dropdown selection to inject an invalid value | System detects the invalid input and prevents the selection. A clear validation message is displayed near the filter field (e.g., 'Invalid location selection' or 'Please select a valid location from the list'). Dashboard data does not update with invalid filter. Filter dropdown remains in a valid state or returns to previous valid selection |
| 3 | Try to submit or apply filters without making any selection (if an apply button exists), or attempt to select a disabled or inactive department/location option | System either prevents the action or handles it gracefully. If no selection is made, dashboard shows all data or displays a message prompting for selection. Disabled options cannot be selected and show visual indication of being unavailable. No error occurs and application remains stable |

**Postconditions:**
- Dashboard remains in a stable state with valid data displayed
- No invalid filter values are applied to the data
- Validation messages are cleared when valid selections are made
- Manager can continue to use filters normally
- System integrity is maintained

---

### Test Case: Test filter response time
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Manager is logged into the dashboard
- Attendance database contains a large data set (minimum 1000+ employee records)
- Multiple departments and locations exist with substantial attendance data
- Network connection is stable and standard
- Dashboard is displaying unfiltered data
- Timer or performance monitoring tool is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify the current data set size by checking the total employee count displayed. Start a timer. Select multiple departments (at least 3-5) from the department filter dropdown using multi-select functionality | Multiple departments are selected successfully. Dashboard begins processing the filter request immediately. Filtered attendance data loads and displays completely within 2 seconds. Timer confirms response time is 2 seconds or less. All displayed records accurately match the selected departments. Loading indicator (if present) appears briefly and disappears when data is loaded |
| 2 | With department filters still active, start a new timer. Select multiple locations (at least 3-5) from the location filter dropdown | Multiple locations are selected successfully. Dashboard processes the combined department and location filters. Filtered data updates and displays completely within 2 seconds. Timer confirms response time is 2 seconds or less. All displayed records match both department and location filter criteria. Data accuracy is maintained despite large data set and multiple filter criteria |
| 3 | Start a timer and click the Reset Filters button to clear all filters and return to the full unfiltered data set | All filters are cleared immediately. Dashboard loads the complete unfiltered data set within 2 seconds. Timer confirms response time is 2 seconds or less. Full employee count is restored and displayed. All attendance records are visible without any filter restrictions |

**Postconditions:**
- Dashboard displays unfiltered attendance data
- Performance benchmark of 2 seconds or less is confirmed for all filter operations
- All filters are cleared and reset to default state
- Large data set is handled efficiently without performance degradation
- Manager can continue using the dashboard normally

---

## Story: As Manager, I want to export attendance reports to achieve offline analysis and sharing
**Story ID:** story-20

### Test Case: Validate export to PDF and Excel
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an authorized manager
- Attendance dashboard is accessible and loaded
- Attendance data is available in the system
- Browser supports file downloads
- User has necessary permissions to export reports

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard | Dashboard loads successfully with attendance data displayed |
| 2 | Apply filters on dashboard (e.g., select specific date range, department, or location) | Filtered data is displayed on the dashboard according to selected criteria |
| 3 | Locate and click the 'Export' button or menu option | Export options menu appears showing available formats (PDF and Excel) |
| 4 | Select 'Export to PDF' option from the menu | System initiates PDF report generation with a loading indicator |
| 5 | Wait for PDF generation to complete | PDF report is generated successfully and download dialog appears or file is automatically downloaded |
| 6 | Open the downloaded PDF file | PDF opens correctly, displays filtered attendance data with applied filters, proper formatting, and all relevant information |
| 7 | Return to the dashboard and click the 'Export' button again | Export options menu appears again |
| 8 | Select 'Export to Excel' option from the menu | System initiates Excel report generation with a loading indicator |
| 9 | Wait for Excel generation to complete | Excel report is generated successfully and download dialog appears or file is automatically downloaded |
| 10 | Open the downloaded Excel file | Excel file opens correctly, displays filtered attendance data with applied filters in proper spreadsheet format with headers and data rows |

**Postconditions:**
- Both PDF and Excel reports are successfully downloaded to the user's device
- Reports contain accurate filtered attendance data
- Dashboard remains in the same filtered state
- No errors are logged in the system

---

### Test Case: Verify report generation time
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as an authorized manager
- Attendance dashboard is accessible
- Large dataset of attendance records is available (minimum 1000+ records)
- Timer or stopwatch is available to measure generation time
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard | Dashboard loads successfully |
| 2 | Apply filters to select a large data set (e.g., all departments, 6-12 month date range) | Dashboard displays the large filtered dataset with multiple records visible |
| 3 | Verify the number of records in the filtered view to ensure it represents a large dataset | Record count shows a substantial number of attendance entries (1000+ records) |
| 4 | Start timer and click 'Export' button, then select either PDF or Excel format | Export process begins immediately with loading indicator displayed |
| 5 | Monitor the report generation process and stop timer when report is ready for download | Report generation completes and download is available within 10 seconds |
| 6 | Record the actual generation time | Generation time is 10 seconds or less |
| 7 | Download and verify the report contains all expected data | Report downloads successfully and contains complete dataset matching the filtered criteria |

**Postconditions:**
- Report is generated within the 10-second performance requirement
- Large dataset is successfully exported without data loss
- System performance remains stable
- Generation time is documented for performance tracking

---

### Test Case: Test email delivery of reports
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an authorized manager
- Attendance dashboard is accessible
- Email service is configured and operational
- User has a valid email address registered in the system
- Test email account is accessible for verification
- Attendance data is available for export

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard | Dashboard loads successfully with attendance data |
| 2 | Apply desired filters to the attendance data | Filtered data is displayed on the dashboard |
| 3 | Click the 'Export' button and select a report format (PDF or Excel) | Export options are displayed including download and email delivery options |
| 4 | Select 'Email Report' or 'Send via Email' option | Email dialog or form appears requesting email address and optional message |
| 5 | Enter the specified email address in the recipient field | Email address is accepted and validated (proper format check) |
| 6 | Add optional subject line or message if available | Subject and message fields accept input |
| 7 | Click 'Send' or 'Email Report' button to submit the request | System displays confirmation message that report is being sent, loading indicator appears |
| 8 | Wait for email sending confirmation | Success message appears confirming email has been sent |
| 9 | Access the specified email account inbox | Email client opens successfully |
| 10 | Check inbox for the attendance report email (check within 2-3 minutes) | Email is received with attendance report attached, proper subject line, and sender information |
| 11 | Open the email and verify attachment is present | Email contains the report file as an attachment in the requested format |
| 12 | Download and open the attached report | Report opens successfully and contains the correct filtered attendance data |

**Postconditions:**
- Report is successfully delivered to the specified email address
- Email contains correct attachment in requested format
- Report data matches the filtered dashboard view
- Email delivery is logged in the system
- No errors occurred during the email sending process

---

## Story: As Manager, I want to view historical attendance trends to achieve informed workforce planning
**Story ID:** story-22

### Test Case: Validate historical attendance trend display
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an authorized manager
- Dashboard is accessible and loaded
- Historical attendance data exists in the system for multiple time periods
- Multiple departments and locations have attendance records
- User has permissions to view historical attendance data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard | Dashboard loads successfully with main attendance view displayed |
| 2 | Locate and click on 'Historical Data' or 'Trends' view option | Historical data view is activated and interface changes to show trend analysis options |
| 3 | Select a time period from the date range selector (e.g., Last 3 months, Last 6 months, or custom date range) | Time period is selected and date range is displayed in the selector |
| 4 | Click 'Apply' or 'View Trends' button to load the historical data | Trend charts are displayed showing attendance data for the selected time period with proper axis labels, legends, and data points |
| 5 | Verify the trend charts display relevant attendance metrics (e.g., attendance rates, absences, late arrivals over time) | Charts show clear visual representation of attendance trends with accurate data points, proper scaling, and readable labels |
| 6 | Locate the department filter dropdown or selector | Department filter control is visible and accessible |
| 7 | Select a specific department from the filter options | Department is selected and filter is applied |
| 8 | Observe the trend charts update | Charts update immediately to display attendance trends filtered by the selected department, showing only relevant department data |
| 9 | Locate the location filter dropdown or selector | Location filter control is visible and accessible |
| 10 | Select a specific location from the filter options | Location is selected and filter is applied |
| 11 | Observe the trend charts update again | Charts update to display attendance trends filtered by both department and location, showing data specific to the selected criteria |
| 12 | Verify chart interactivity by hovering over data points or clicking on chart elements | Interactive tooltips appear showing detailed data values, dates, and percentages for specific data points |

**Postconditions:**
- Historical trend charts are displayed with accurate filtered data
- Filters are applied and reflected in the chart display
- Charts remain interactive and responsive
- System maintains the selected filters for subsequent actions
- No errors are displayed or logged

---

### Test Case: Verify export of historical trend reports
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an authorized manager
- Historical attendance trend view is accessible
- Historical data is loaded and displayed in trend charts
- Export functionality is enabled for the user role
- Browser supports file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the historical attendance trends view | Historical trends dashboard loads with trend charts displayed |
| 2 | Select desired time period and apply any filters (department, location) for the trend report | Trend charts update to show filtered historical data |
| 3 | Locate and click the 'Export' button on the historical trends view | Export options menu appears showing available formats (PDF and Excel) |
| 4 | Select 'Export to PDF' option | System initiates PDF report generation with loading indicator displayed |
| 5 | Wait for PDF generation to complete | PDF trend report is generated successfully and download dialog appears or file downloads automatically |
| 6 | Open the downloaded PDF file | PDF opens correctly displaying historical trend charts, graphs, applied filters, time period, and relevant attendance statistics in a formatted report layout |
| 7 | Verify PDF content includes charts, legends, and data summaries | PDF contains all visual trend charts, proper labels, time period information, and data is readable and properly formatted |
| 8 | Return to the historical trends view and click 'Export' button again | Export options menu appears |
| 9 | Select 'Export to Excel' option | System initiates Excel report generation with loading indicator |
| 10 | Wait for Excel generation to complete | Excel trend report is generated successfully and download dialog appears or file downloads automatically |
| 11 | Open the downloaded Excel file | Excel file opens correctly with multiple sheets or organized data sections |
| 12 | Verify Excel content includes raw trend data, charts, and summaries | Excel file contains historical attendance data in tabular format, embedded charts if applicable, proper headers, time period information, and applied filters are documented |

**Postconditions:**
- Both PDF and Excel historical trend reports are successfully downloaded
- Reports contain accurate historical attendance trend data
- Charts and data visualizations are properly rendered in exports
- Applied filters and time periods are reflected in exported reports
- Dashboard remains in the same state with filters intact

---

### Test Case: Test chart rendering performance
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an authorized manager
- Standard device is being used (meeting minimum system requirements)
- Historical attendance data is available in the system
- Network connection is stable
- Timer or browser developer tools are available to measure rendering time
- Browser cache is cleared for accurate performance measurement

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to Performance or Network tab to monitor page load metrics | Developer tools are open and ready to record performance metrics |
| 2 | Navigate to the attendance dashboard | Dashboard begins loading |
| 3 | Start performance recording or timer | Performance monitoring is active |
| 4 | Click on 'Historical Data' or 'Trends' view to load trend charts | System begins loading historical trend charts with loading indicator displayed |
| 5 | Monitor the chart rendering process and observe visual feedback | Charts begin rendering with progressive display of data points and visual elements |
| 6 | Stop timer when all trend charts are fully rendered and interactive | All charts are completely loaded, data points are visible, legends are displayed, and charts are interactive |
| 7 | Record the total rendering time from the performance tools or timer | Rendering time is captured and is 5 seconds or less |
| 8 | Verify all chart elements are properly displayed (axes, labels, data points, legends, tooltips) | All chart components are rendered correctly with no missing elements or visual glitches |
| 9 | Test chart interactivity by hovering over data points | Charts respond immediately to user interactions with smooth tooltip displays and no lag |
| 10 | Apply a filter and measure the chart re-rendering time | Charts update and re-render within 5 seconds with new filtered data |

**Postconditions:**
- Trend charts render within the 5-second performance requirement
- All chart elements are fully functional and interactive
- Performance metrics are documented
- System remains responsive after chart rendering
- No performance degradation or memory leaks are observed

---

