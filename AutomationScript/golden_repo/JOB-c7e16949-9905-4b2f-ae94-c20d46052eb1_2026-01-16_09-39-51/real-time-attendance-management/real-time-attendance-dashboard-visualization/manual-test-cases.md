# Manual Test Cases

## Story: As Manager, I want to view real-time attendance status on a dashboard to achieve immediate workforce visibility
**Story ID:** story-3

### Test Case: Validate real-time attendance data display on dashboard
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Manager has valid login credentials with dashboard access permissions
- Attendance database contains current employee attendance records
- Network connection is stable
- Browser is compatible (Chrome, Firefox, Safari, or Edge latest versions)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard login page | Login page is displayed with username and password fields |
| 2 | Enter valid manager credentials and click Login button | Manager is authenticated and redirected to the attendance dashboard |
| 3 | Observe the dashboard upon initial load | Dashboard loads with current attendance data showing employee presence indicators, summary metrics (total present, absent, late), and timestamp of last update |
| 4 | Note the current timestamp displayed on the dashboard | Timestamp shows the current date and time of data refresh |
| 5 | Wait and observe the dashboard for 30 seconds without any interaction | Dashboard automatically refreshes and updates the timestamp to reflect new data at the 30-second mark |
| 6 | Continue observing the dashboard for an additional 30 seconds | Dashboard refreshes again automatically at the next 30-second interval with updated attendance data and timestamp |
| 7 | Locate and click on the team filter dropdown menu | Team filter dropdown expands showing list of available teams |
| 8 | Select a specific team from the dropdown list | Dashboard updates immediately to display attendance data only for the selected team, with summary metrics recalculated for filtered data |
| 9 | Verify the filtered data matches the selected team | All displayed employee records belong to the selected team, and no records from other teams are visible |
| 10 | Observe the dashboard for 30 seconds after filtering | Filtered data continues to refresh automatically every 30 seconds maintaining the applied filter |

**Postconditions:**
- Manager remains logged into the dashboard
- Team filter remains applied
- Dashboard continues auto-refresh cycle
- No errors or warnings are displayed

---

### Test Case: Verify drill-down to individual employee attendance details
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 2 mins

**Preconditions:**
- Manager is logged into the attendance dashboard
- Dashboard is displaying current attendance data with multiple employee records
- At least one employee presence indicator is visible on the dashboard
- Employee detail view functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify an employee presence indicator on the dashboard (e.g., employee name or status icon) | Employee presence indicators are clearly visible and clickable on the dashboard |
| 2 | Click on a specific employee presence indicator | Detailed attendance view opens displaying comprehensive information for the selected employee |
| 3 | Review the detailed attendance information displayed | Detail view shows employee name, current status (present/absent/late), check-in time, check-out time (if applicable), location, and any relevant attendance notes |
| 4 | Verify that the detail view is clearly distinguishable from the summary view | Detail view is displayed in a modal, overlay, or separate panel with clear visual distinction from the main dashboard |
| 5 | Locate the close button or back navigation option in the detail view | Close button (X icon) or back button is visible and accessible in the detail view |
| 6 | Click the close button to exit the detail view | Detail view closes and dashboard returns to the summary view showing all employee attendance data |
| 7 | Verify the summary view is restored correctly | Dashboard displays the same summary view as before drill-down, with all filters and settings preserved |

**Postconditions:**
- Dashboard is in summary view mode
- No detail views are open
- All previous filter settings remain intact
- Dashboard continues normal auto-refresh functionality

---

### Test Case: Test dashboard load performance
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Manager has valid login credentials
- Standard network connection is available (minimum 10 Mbps)
- Browser cache is cleared to simulate realistic load conditions
- Attendance database contains representative data volume
- Performance measurement tool or browser developer tools are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab | Developer tools are open with Network tab active and ready to record |
| 2 | Clear browser cache and cookies | Cache and cookies are cleared successfully |
| 3 | Start network recording in developer tools | Network activity recording is active |
| 4 | Navigate to the attendance dashboard login page | Login page loads successfully |
| 5 | Enter valid manager credentials and click Login button, simultaneously start timer | Authentication process begins |
| 6 | Observe the dashboard loading process until fully rendered | Dashboard completes loading with all attendance data, summary metrics, and UI elements fully visible and interactive |
| 7 | Stop timer when dashboard is fully loaded and check the elapsed time | Total load time from login submission to fully rendered dashboard is 3 seconds or less |
| 8 | Review network tab in developer tools to verify API response times | API endpoint /api/dashboard/attendance responds within acceptable time contributing to overall 3-second load target |
| 9 | Verify all dashboard elements are functional immediately after load | All buttons, filters, and interactive elements are responsive and functional without delay |

**Postconditions:**
- Dashboard is fully loaded and operational
- Manager is logged in and viewing attendance data
- Performance metrics are recorded and meet the 3-second requirement
- All dashboard features are accessible

---

## Story: As Manager, I want to filter attendance data by team and location to achieve focused workforce insights
**Story ID:** story-4

### Test Case: Validate filtering by team
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Manager is logged into the attendance dashboard
- Dashboard is displaying attendance data for multiple teams
- Team filter dropdown is visible and accessible
- Attendance database contains records for at least 2 different teams
- No filters are currently applied

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Observe the initial dashboard state and note the total number of employees displayed | Dashboard shows attendance data for all teams with total employee count visible in summary metrics |
| 2 | Locate the team filter dropdown on the dashboard | Team filter dropdown is visible with a label such as 'Filter by Team' or 'Team' |
| 3 | Click on the team filter dropdown | Dropdown expands showing a list of all available teams with team names clearly displayed |
| 4 | Select a specific team from the dropdown list (e.g., 'Engineering Team') | Selected team is highlighted and dropdown closes automatically |
| 5 | Observe the dashboard update after team selection | Dashboard refreshes and displays attendance data only for the selected team within 2 seconds |
| 6 | Verify that all displayed employee records belong to the selected team | All visible employee records show team affiliation matching the selected team, and no employees from other teams are displayed |
| 7 | Check the summary metrics (total present, absent, late) | Summary metrics are recalculated and display counts only for the filtered team |
| 8 | Verify the team filter indicator shows the active filter | Team filter dropdown or a filter tag displays the currently selected team name |
| 9 | Locate and click the clear filter button or option (e.g., 'Clear', 'X' icon, or 'All Teams' option) | Clear filter option is clicked successfully |
| 10 | Observe the dashboard after clearing the team filter | Dashboard updates to show attendance data for all teams, returning to the initial unfiltered state with all employee records visible |
| 11 | Verify the employee count matches the original total before filtering | Total employee count in summary metrics matches the count observed in step 1 |

**Postconditions:**
- Team filter is cleared and set to show all teams
- Dashboard displays complete attendance data for all teams
- No filters are active
- Dashboard continues auto-refresh functionality

---

### Test Case: Validate filtering by location
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Manager is logged into the attendance dashboard
- Dashboard is displaying attendance data for multiple locations
- Location filter dropdown is visible and accessible
- Attendance database contains records for at least 2 different locations
- No filters are currently applied

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Observe the initial dashboard state and note the total number of employees displayed across all locations | Dashboard shows attendance data for all locations with total employee count visible in summary metrics |
| 2 | Locate the location filter dropdown on the dashboard | Location filter dropdown is visible with a label such as 'Filter by Location' or 'Location' |
| 3 | Click on the location filter dropdown | Dropdown expands showing a list of all available locations with location names clearly displayed |
| 4 | Select a specific location from the dropdown list (e.g., 'New York Office') | Selected location is highlighted and dropdown closes automatically |
| 5 | Observe the dashboard update after location selection | Dashboard refreshes and displays attendance data only for the selected location within 2 seconds |
| 6 | Verify that all displayed employee records belong to the selected location | All visible employee records show location affiliation matching the selected location, and no employees from other locations are displayed |
| 7 | Check the summary metrics (total present, absent, late) | Summary metrics are recalculated and display counts only for the filtered location |
| 8 | Verify the location filter indicator shows the active filter | Location filter dropdown or a filter tag displays the currently selected location name |
| 9 | Locate and click the clear filter button or option (e.g., 'Clear', 'X' icon, or 'All Locations' option) | Clear filter option is clicked successfully |
| 10 | Observe the dashboard after clearing the location filter | Dashboard updates to show attendance data for all locations, returning to the initial unfiltered state with all employee records visible |
| 11 | Verify the employee count matches the original total before filtering | Total employee count in summary metrics matches the count observed in step 1 |

**Postconditions:**
- Location filter is cleared and set to show all locations
- Dashboard displays complete attendance data for all locations
- No filters are active
- Dashboard continues auto-refresh functionality

---

### Test Case: Validate combined filtering by team and location
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Manager is logged into the attendance dashboard
- Dashboard is displaying attendance data for multiple teams and locations
- Both team and location filter dropdowns are visible and accessible
- Attendance database contains records with various team and location combinations
- At least one employee exists matching a specific team-location combination
- No filters are currently applied

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Observe the initial dashboard state and note the total number of employees displayed | Dashboard shows attendance data for all teams and locations with complete employee count in summary metrics |
| 2 | Click on the team filter dropdown | Team filter dropdown expands showing list of available teams |
| 3 | Select a specific team from the dropdown (e.g., 'Sales Team') | Selected team is applied and dashboard updates to show only employees from the Sales Team |
| 4 | Note the number of employees displayed after team filter is applied | Dashboard shows reduced employee count reflecting only the selected team members |
| 5 | Click on the location filter dropdown while team filter is active | Location filter dropdown expands showing list of available locations |
| 6 | Select a specific location from the dropdown (e.g., 'London Office') | Selected location is applied and dropdown closes |
| 7 | Observe the dashboard update after applying both filters | Dashboard refreshes within 2 seconds and displays attendance data only for employees matching both the selected team AND selected location |
| 8 | Verify each displayed employee record matches both filter criteria | All visible employees belong to 'Sales Team' AND are located in 'London Office', with no records violating either filter condition |
| 9 | Check the summary metrics with combined filters applied | Summary metrics (total present, absent, late) reflect only the employees matching both filter criteria |
| 10 | Verify both filter indicators show active filters | Both team and location filter displays show the currently selected values ('Sales Team' and 'London Office') |
| 11 | Locate and click the clear all filters button or clear each filter individually | Clear filters option is activated successfully |
| 12 | Observe the dashboard after clearing all filters | Dashboard updates to show attendance data for all teams and all locations, returning to the initial unfiltered state |
| 13 | Verify the employee count matches the original total before any filtering | Total employee count in summary metrics matches the count observed in step 1, confirming all data is visible again |

**Postconditions:**
- All filters are cleared
- Dashboard displays complete attendance data for all teams and locations
- No active filters are shown
- Dashboard maintains normal functionality and auto-refresh

---

## Story: As Manager, I want to view attendance trend graphs to achieve insights into workforce attendance patterns
**Story ID:** story-5

### Test Case: Validate attendance trend graph display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has role-based access to attendance dashboard
- Historical attendance data exists in the system for the selected date range
- Network connection is stable
- Browser is compatible with the dashboard application

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard from the main menu | Attendance dashboard page loads successfully and displays the trend visualization section |
| 2 | Locate the date range selector in the trend visualization section | Date range selector is visible with start date and end date fields |
| 3 | Select a start date from the date picker (e.g., first day of current month) | Start date is populated in the date range selector field |
| 4 | Select an end date from the date picker (e.g., last day of current month) | End date is populated in the date range selector field |
| 5 | Click the 'Apply' or 'Update' button to apply the selected date range | Trend graphs update dynamically to display attendance data for the selected date range with line and bar charts visible |
| 6 | Verify that absenteeism rates trend graph is displayed on the dashboard | Absenteeism rates graph is visible showing data points for the selected date range with appropriate labels and legends |
| 7 | Verify that late arrival trends graph is displayed on the dashboard | Late arrival trends graph is visible showing data points for the selected date range with appropriate labels and legends |
| 8 | Cross-verify the displayed attendance metrics with source data records | Graphs accurately reflect attendance metrics with 95% or higher accuracy compared to source data |

**Postconditions:**
- Attendance trend graphs are displayed for the selected date range
- Dashboard remains in active state for further interactions
- Selected date range is retained in the session

---

### Test Case: Validate graph export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Attendance trend graphs are already displayed on the dashboard
- A valid date range has been selected and graphs are rendered
- Browser has download permissions enabled
- Sufficient storage space is available on the local machine

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the export button on the trend graph section (typically represented by a download icon or 'Export' button) | Export button is visible and enabled on the trend graph interface |
| 2 | Click the export button to open export options | Export options menu appears displaying available formats (Image and PDF) |
| 3 | Select 'Export as Image' option from the menu | Graph is downloaded as an image file (PNG or JPG format) to the default download location |
| 4 | Navigate to the download location and open the downloaded image file | Image file opens successfully and displays the trend graph with all data points, labels, and legends clearly visible |
| 5 | Return to the dashboard and click the export button again | Export options menu appears again |
| 6 | Select 'Export as PDF' option from the menu | Graph is downloaded as a PDF file to the default download location |
| 7 | Navigate to the download location and open the downloaded PDF file | PDF file opens successfully and displays the trend graph with all data points, labels, and legends clearly visible in proper formatting |

**Postconditions:**
- Trend graph files (image and PDF) are successfully downloaded to local machine
- Dashboard remains active and functional
- Downloaded files are accessible and readable

---

### Test Case: Test graph rendering performance
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Standard network connection is established (not high-speed or low-speed)
- Historical attendance data exists in the system
- Browser cache is cleared to ensure accurate performance measurement
- Performance monitoring tools or browser developer tools are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab to monitor loading times | Developer tools are open and Network tab is active with recording enabled |
| 2 | Navigate to the attendance dashboard from the main menu | Dashboard page begins loading |
| 3 | Start timer when the trend visualization section begins to load | Timer is started and API call to /api/dashboard/attendance/trends is visible in Network tab |
| 4 | Observe the trend graphs as they render on the screen | Trend graphs (line and bar charts) begin rendering with data points appearing progressively |
| 5 | Stop timer when all trend graphs are fully rendered and interactive | All graphs are completely loaded with all data points, labels, legends, and interactive elements visible |
| 6 | Record the total rendering time from the Network tab or timer | Total rendering time is recorded and is within 3 seconds or less |
| 7 | Verify that graphs are interactive (hover over data points, zoom if applicable) | Graphs respond to user interactions immediately without lag |
| 8 | Repeat the test by selecting a different date range and measure rendering time again | Graphs update and render within 3 seconds for the new date range |

**Postconditions:**
- Graph rendering performance meets the 3-second requirement
- Dashboard is fully functional and responsive
- Performance metrics are documented for reporting

---

## Story: As Manager, I want to customize dashboard views to achieve personalized attendance monitoring
**Story ID:** story-7

### Test Case: Validate adding and removing dashboard widgets
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has authorization to access dashboard customization features
- Dashboard is loaded with default widget configuration
- Available widgets are defined in the system
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard from the main menu | Dashboard loads successfully displaying current widget layout |
| 2 | Locate and click the 'Customize Dashboard' or 'Edit Layout' button | Dashboard enters customization mode and customization UI is displayed with options to add, remove, and rearrange widgets |
| 3 | Verify that existing widgets show edit controls (remove buttons, drag handles) | All current widgets display edit controls indicating they can be modified or removed |
| 4 | Click the 'Add Widget' or '+' button to view available widgets | A widget gallery or menu appears showing all available widgets that can be added to the dashboard |
| 5 | Select a new widget from the available options (e.g., 'Attendance Summary' widget) | Selected widget is added to the dashboard layout and appears in a default position |
| 6 | Verify the newly added widget displays correctly with appropriate content | New widget is visible on the dashboard with proper formatting and displays relevant data |
| 7 | Locate an existing widget that you want to remove | Widget is visible with a remove button (typically an 'X' or trash icon) |
| 8 | Click the remove button on the selected widget | A confirmation dialog appears asking to confirm widget removal |
| 9 | Confirm the removal action | Widget is removed from the dashboard layout and remaining widgets adjust positioning accordingly |
| 10 | Verify the widget is no longer visible on the dashboard | Removed widget is not displayed and dashboard layout is updated without the widget |

**Postconditions:**
- Dashboard is in customization mode with modified widget layout
- Added widgets are visible and functional
- Removed widgets are no longer displayed
- Dashboard remains responsive and functional

---

### Test Case: Validate saving and loading custom layouts
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Dashboard is in customization mode with modified widget layout
- At least one widget has been added or removed from default layout
- User preferences database is accessible
- API endpoint /api/dashboard/customization is functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | After customizing the dashboard layout, locate the 'Save Layout' or 'Save Changes' button | Save button is visible and enabled in the customization interface |
| 2 | Click the 'Save Layout' button | A confirmation message appears indicating the layout is being saved |
| 3 | Wait for the save operation to complete | Success notification appears confirming 'Layout saved successfully' and dashboard exits customization mode |
| 4 | Verify the current dashboard displays the customized layout | Dashboard shows the saved custom layout with all added/removed widgets in their configured positions |
| 5 | Note the specific widget arrangement and configuration for verification | Current layout details are documented (widget types, positions, configurations) |
| 6 | Click the browser refresh button or press F5 to reload the dashboard page | Dashboard page reloads completely |
| 7 | Observe the dashboard as it loads after refresh | Dashboard loads and displays the previously saved custom layout automatically |
| 8 | Verify that all customized widgets are present in their saved positions | All widgets from the saved layout are displayed in the exact same arrangement as before the reload |
| 9 | Log out of the system completely | User is logged out and redirected to the login page |
| 10 | Log back into the system with the same manager credentials | Login is successful and user is redirected to the dashboard |
| 11 | Observe the dashboard upon login | Dashboard automatically loads the saved custom layout with all widgets in their configured positions |
| 12 | Verify that the layout persists across sessions | Custom layout is identical to the saved configuration, confirming preferences are persisted securely in the database |

**Postconditions:**
- Custom dashboard layout is saved in user preferences database
- Layout persists across page refreshes and login sessions
- Dashboard displays the saved custom layout automatically
- User customization preferences are securely stored

---

### Test Case: Test configuration of data refresh intervals
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Dashboard is loaded and displaying attendance data
- Dashboard customization or settings menu is accessible
- System supports configurable data refresh intervals
- Real-time or near real-time data updates are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to dashboard settings or customization options | Settings menu or customization panel is displayed |
| 2 | Locate the 'Data Refresh Interval' or 'Auto-Refresh' configuration option | Data refresh interval setting is visible with current value displayed (e.g., default 30 seconds or manual) |
| 3 | Click on the data refresh interval dropdown or input field | Available refresh interval options are displayed (e.g., 30 seconds, 60 seconds, 2 minutes, 5 minutes, manual) |
| 4 | Select '60 seconds' from the available refresh interval options | 60 seconds option is selected and highlighted in the configuration |
| 5 | Click 'Save' or 'Apply' button to confirm the refresh interval setting | Confirmation message appears indicating 'Refresh interval updated successfully' and settings are saved |
| 6 | Exit the settings menu and return to the main dashboard view | Dashboard is displayed with active widgets showing current attendance data |
| 7 | Note the current timestamp and data values displayed on the dashboard widgets | Current data values and timestamp are documented for comparison |
| 8 | Wait for 60 seconds without interacting with the dashboard | Time elapses with no manual interaction |
| 9 | Observe the dashboard after 60 seconds have elapsed | Dashboard automatically refreshes and updates data without manual intervention |
| 10 | Verify that the timestamp or data values have been updated | Dashboard displays updated data with new timestamp indicating automatic refresh occurred at the 60-second interval |
| 11 | Continue observing for another 60-second interval | Dashboard refreshes again after another 60 seconds, confirming consistent refresh behavior |
| 12 | Check browser network activity or console for refresh API calls | Network logs show periodic API calls to refresh data occurring every 60 seconds |

**Postconditions:**
- Data refresh interval is set to 60 seconds
- Dashboard automatically refreshes data every 60 seconds
- Refresh interval setting is persisted in user preferences
- Dashboard continues to function normally with automatic refresh enabled

---

## Story: As Manager, I want to export attendance reports from the dashboard to achieve offline analysis and sharing
**Story ID:** story-8

### Test Case: Validate export of attendance reports in CSV format
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Manager role credentials
- User has access to the attendance dashboard
- Attendance data exists in the system for the selected period
- Browser allows file downloads
- User has appropriate permissions to export attendance reports

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard | Dashboard loads successfully and displays attendance data with available filter options |
| 2 | Apply filters on dashboard (e.g., date range, department, employee status) | Filtered data is displayed on the dashboard reflecting the selected filter criteria |
| 3 | Verify the filtered data matches the applied filter criteria | Dashboard shows only the records matching the filter parameters |
| 4 | Click on the Export button on the dashboard | Export options dialog or dropdown appears showing available export formats (CSV, Excel, PDF) |
| 5 | Select CSV format from the export options | CSV format is selected and export process is initiated |
| 6 | Wait for the export process to complete | CSV file is generated and automatically downloaded to the default download location |
| 7 | Navigate to the download location and locate the exported CSV file | CSV file is present with appropriate naming convention (e.g., attendance_report_YYYYMMDD.csv) |
| 8 | Open the CSV file using a spreadsheet application (Excel, Google Sheets, etc.) | CSV file opens successfully without errors |
| 9 | Verify the CSV file contains the filtered attendance data with all relevant columns (employee name, date, time in, time out, status, etc.) | File contains accurate filtered attendance data matching the dashboard display with proper column headers and data formatting |
| 10 | Verify the data count in CSV matches the filtered record count on dashboard | Number of records in CSV file matches the count displayed on the dashboard |

**Postconditions:**
- CSV file is successfully downloaded and saved
- Dashboard remains in the same filtered state
- User session remains active
- Export action is logged in the system audit trail

---

### Test Case: Validate export completion notification
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role credentials
- User has access to the attendance dashboard
- Attendance data exists in the system
- System notifications are enabled
- User has appropriate permissions to export attendance reports

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard | Dashboard loads successfully with attendance data displayed |
| 2 | Click on the Export button | Export options dialog appears with available formats |
| 3 | Select any export format (CSV, Excel, or PDF) and initiate the export | Export process begins and export progress indicator is displayed (progress bar, spinner, or percentage) |
| 4 | Observe the export progress indicator during the export process | Progress indicator shows real-time status of the export operation (e.g., 'Generating report...', 'Processing data...') |
| 5 | Wait for the export process to complete | Export completes successfully within the expected timeframe |
| 6 | Observe the notification area or message displayed after export completion | System displays a success notification message (e.g., 'Export completed successfully', 'Your report is ready for download') with appropriate visual indicator (green checkmark, success icon) |
| 7 | Verify the notification contains relevant information about the export | Notification includes details such as file name, format, and download link or confirmation that file has been downloaded |
| 8 | Verify the exported file is available in the download location | Exported file is successfully saved and accessible |

**Postconditions:**
- Export completion notification is displayed to the manager
- Exported file is available for access
- Dashboard remains functional and responsive
- Export event is logged with timestamp and user details

---

### Test Case: Test export performance
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Manager role credentials
- User has access to the attendance dashboard
- Large dataset of attendance records exists in the system (minimum 1000+ records)
- System performance monitoring tools are available or timer is ready
- User has appropriate permissions to export attendance reports

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard | Dashboard loads successfully |
| 2 | Apply filters to select a large dataset (e.g., all departments, 6-12 months date range, all employees) | Dashboard displays the large filtered dataset with record count visible |
| 3 | Note the total number of records to be exported | Record count is displayed showing a large number of attendance records (1000+ records) |
| 4 | Start a timer or note the current timestamp | Timer is started and ready to measure export duration |
| 5 | Click on the Export button and select any format (CSV, Excel, or PDF) | Export process is initiated and progress indicator appears |
| 6 | Monitor the export progress and wait for completion | Export process shows progress and continues without errors or timeouts |
| 7 | Stop the timer when the export completes and file download begins or completion notification appears | Export completes successfully and elapsed time is recorded |
| 8 | Verify the total export time from initiation to completion | Export completes within 30 seconds as per the performance requirement |
| 9 | Verify the exported file is complete and not corrupted | Exported file opens successfully and contains all the expected records |
| 10 | Verify the record count in the exported file matches the dashboard count | All records from the large dataset are present in the exported file without data loss |

**Postconditions:**
- Large attendance report is successfully exported within 30 seconds
- Exported file contains complete and accurate data
- System performance remains stable after export
- No memory leaks or system degradation observed
- Export performance metrics are logged for monitoring

---

