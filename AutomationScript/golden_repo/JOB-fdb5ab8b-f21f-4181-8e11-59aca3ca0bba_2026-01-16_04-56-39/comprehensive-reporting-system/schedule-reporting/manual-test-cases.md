# Manual Test Cases

## Story: As Manager, I want to generate schedule reports to monitor team shift adherence
**Story ID:** story-1

### Test Case: Validate successful schedule report generation with valid filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Scheduling database contains test data with employee shifts for the selected date range
- Schedule reporting module is accessible and operational
- At least one employee, team, and department exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule reporting module from the main dashboard or menu | Schedule report UI is displayed with date range selector, filter options (employee, team, department), and generate report button visible |
| 2 | Select a valid date range (e.g., current week) using the date picker | Date range is populated in the date fields without validation errors |
| 3 | Select specific filters: choose an employee from the employee dropdown, select a team from the team dropdown, and select a department from the department dropdown | All selected filters are displayed in the filter section without errors, and filter values are properly highlighted or shown as selected |
| 4 | Click the 'Generate Report' button to request report generation | System displays a loading indicator and processes the request within 10 seconds |
| 5 | Review the generated schedule report displayed on screen | Schedule report is generated and displayed with correct data including: employee names, shift times, dates within selected range, team assignments, department information, and all data matches the applied filters. Report shows accurate shift details for the selected criteria |

**Postconditions:**
- Schedule report is displayed on screen with filtered data
- Report data matches the selected filters and date range
- System logs the report generation activity
- User remains on the schedule reporting page

---

### Test Case: Verify export functionality for schedule reports
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Schedule reporting module is accessible
- Test data exists in the scheduling database
- Browser allows file downloads
- User has necessary permissions to export reports

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule reporting module | Schedule report UI is displayed with all filter options and export buttons visible |
| 2 | Select a valid date range and apply filters (employee, team, or department) | Filters are accepted and displayed without errors |
| 3 | Click the 'Generate Report' button to generate the schedule report | Report is generated and displayed on screen with filtered data matching the selected criteria, including all shift details, employee names, and schedule information |
| 4 | Click the 'Export to PDF' button | PDF file is downloaded to the default download location with filename format 'ScheduleReport_[DateRange].pdf'. File opens successfully and displays correct formatting including headers, columns, shift data, and applied filters. All data from the screen report is present in the PDF |
| 5 | Return to the displayed report and click the 'Export to Excel' button | Excel file is downloaded to the default download location with filename format 'ScheduleReport_[DateRange].xlsx'. File opens successfully in Excel or compatible application. All data is accurate and matches the screen report including employee names, shift times, dates, teams, and departments. Data is properly formatted in columns with headers |

**Postconditions:**
- PDF file is saved in the download folder with correct data
- Excel file is saved in the download folder with accurate data
- Both exported files contain the same data as displayed in the screen report
- User remains on the schedule reporting page
- Export activity is logged in the system

---

### Test Case: Ensure unauthorized users cannot access schedule reports
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Test user account exists with non-manager role (e.g., Employee, Viewer, or Guest role)
- Schedule reporting module exists and is protected by role-based access control
- API endpoint /api/reports/schedules is secured with authentication and authorization
- User is not logged in or logged in with non-manager credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the application using non-manager user credentials (e.g., Employee role) | User successfully logs in and is redirected to the appropriate dashboard for their role |
| 2 | Attempt to navigate to the schedule reporting module by clicking on the menu or entering the URL directly | Access to schedule reporting module is denied. User sees an error message such as 'Access Denied' or 'You do not have permission to view this page'. User is either redirected to their home page or shown an authorization error page. Schedule reporting module is not visible in the navigation menu |
| 3 | Open browser developer tools and attempt to access the API endpoint directly by sending a GET request to /api/reports/schedules with authentication token | API returns HTTP 403 Forbidden response with error message indicating insufficient permissions. No schedule data is returned in the response body |
| 4 | Attempt to access the API endpoint without authentication token | API returns HTTP 401 Unauthorized response indicating authentication is required |

**Postconditions:**
- Non-manager user remains unable to access schedule reports
- No schedule data is exposed to unauthorized user
- Security logs record the unauthorized access attempts
- User session remains active but restricted to authorized features only

---

## Story: As Manager, I want to filter schedule reports by department to analyze scheduling patterns
**Story ID:** story-5

### Test Case: Validate department filter in schedule reports
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Schedule reporting module is accessible and operational
- Multiple departments exist in the system with associated employee schedules
- Test data includes employees assigned to different departments with scheduled shifts
- At least one department has scheduled shifts within the test date range

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule reporting module from the main dashboard or menu | Schedule report UI is displayed with date range selector and all filter options including the department filter dropdown visible and enabled |
| 2 | Select a valid date range (e.g., current month) using the date picker | Date range is populated in the date fields without validation errors |
| 3 | Click on the department filter dropdown and select a specific department (e.g., 'Sales Department') | Selected department is displayed in the filter section and highlighted as active. No validation errors are shown |
| 4 | Optionally select additional filters such as team or employee if needed for the test scenario | All selected filters are accepted and displayed without errors |
| 5 | Click the 'Generate Report' button to generate the schedule report | System processes the request within 10 seconds and displays a loading indicator during processing |
| 6 | Review the generated schedule report displayed on screen | Report displays data only for the selected department. All employees shown in the report belong to the selected department. No employees from other departments are included. Report includes accurate shift details, dates, times, and employee information. Department name is clearly indicated in the report header or filter summary |
| 7 | Verify each employee record in the report to confirm department association | All employee records in the report are confirmed to belong to the selected department only |

**Postconditions:**
- Schedule report displays only data for the selected department
- No data from other departments is visible in the report
- Report generation is completed within the 10-second SLA
- System logs the filtered report generation activity
- User remains on the schedule reporting page with the report displayed

---

### Test Case: Verify export of department filtered schedule reports
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Schedule reporting module is accessible
- Multiple departments exist with scheduled shifts in the system
- Test data includes employees from different departments
- Browser allows file downloads
- User has permissions to export reports

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule reporting module | Schedule report UI is displayed with all filter options including department filter visible |
| 2 | Select a valid date range using the date picker | Date range is populated without errors |
| 3 | Select a specific department from the department filter dropdown (e.g., 'Engineering Department') | Department filter is applied and displayed as selected |
| 4 | Click the 'Generate Report' button to generate the schedule report with department filter applied | Filtered report is generated within 10 seconds and displayed on screen showing only employees and shifts from the selected department. Report data is accurate and complete for the selected department |
| 5 | Click the 'Export to PDF' button to export the filtered report | PDF file is downloaded to the default download location with filename indicating the report type and date range (e.g., 'ScheduleReport_Engineering_[DateRange].pdf') |
| 6 | Open the downloaded PDF file | PDF opens successfully and contains data filtered by the selected department only. All employees and shifts shown belong to the selected department. No data from other departments is present. PDF includes proper formatting with headers, columns, department name clearly indicated, and all shift details are accurate and readable. Applied department filter is visible in the report header or summary section |
| 7 | Verify the PDF content matches the on-screen report data | PDF content exactly matches the filtered data displayed on screen with no discrepancies in employee names, shift times, dates, or department information |

**Postconditions:**
- PDF file is saved in the download folder containing department-filtered data only
- Exported PDF maintains the applied department filter
- PDF formatting is correct and data is readable
- No data from other departments is included in the export
- Export activity is logged in the system
- User remains on the schedule reporting page

---

## Story: As Manager, I want schedule reports to update automatically after schedule changes to ensure data freshness
**Story ID:** story-9

### Test Case: Validate automatic schedule report refresh after schedule changes
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Manager role credentials
- User has access to schedule reports module
- Scheduling database is operational and accessible
- At least one schedule report exists with current data
- System change tracking mechanism is enabled
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule reports section from the main dashboard | Schedule reports page loads successfully and displays available reports |
| 2 | Select and open a specific schedule report to view | Report is displayed with current schedule data including timestamps, employee assignments, and shift details |
| 3 | Note the current data values in the report (e.g., specific employee shift assignments, dates, times) | Current report data is clearly visible and documented for comparison |
| 4 | Navigate to the scheduling module while keeping the report accessible | Scheduling module opens successfully without closing the report view |
| 5 | Make a schedule change (e.g., reassign an employee to a different shift, modify shift time, or add new schedule entry) | Schedule change is accepted by the system and confirmation message is displayed |
| 6 | Save the schedule changes in the system | Changes are saved successfully with a success confirmation message and timestamp |
| 7 | Return to the schedule report view immediately after saving changes | Report view is still accessible and displays the previous data state |
| 8 | Monitor the report for automatic refresh, waiting up to 5 minutes and noting the exact refresh time | Report automatically refreshes within 5 minutes showing a loading indicator or refresh notification |
| 9 | Verify the report now displays the updated schedule data that was just changed | Report accurately reflects all schedule changes made in step 5, including updated employee assignments, times, and dates |
| 10 | Check the report timestamp or last updated indicator | Report timestamp shows the current date and time, confirming the refresh occurred within the 5-minute window |

**Postconditions:**
- Schedule report displays the most current data
- Report timestamp reflects the recent refresh time
- Schedule changes are permanently saved in the database
- System remains stable and responsive
- No data inconsistencies exist between scheduling module and reports

---

### Test Case: Verify user notification of report refresh completion
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Manager role credentials
- User has access to schedule reports and scheduling modules
- Notification system is enabled and configured for the user
- User notification preferences are set to receive report refresh alerts
- At least one schedule report is available in the system
- Scheduling database is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule reports section and open a specific schedule report | Schedule report opens and displays current schedule data |
| 2 | Navigate to the scheduling module to make changes | Scheduling module loads successfully with editable schedule interface |
| 3 | Trigger a schedule change by modifying an existing schedule entry (e.g., change employee shift assignment or modify shift timing) | Schedule modification interface accepts the changes and displays them in the edit view |
| 4 | Save the schedule changes to trigger the report refresh process | System saves changes successfully and displays a confirmation message with timestamp |
| 5 | Monitor the notification area (notification bell, banner, or notification center) for refresh status updates | System displays an initial notification indicating that report refresh has been initiated |
| 6 | Wait for the automatic report refresh process to complete (up to 5 minutes) | System processes the schedule changes and refreshes the associated reports |
| 7 | Check for a completion notification in the notification area | User receives a clear notification message indicating report refresh completion with details such as report name and completion timestamp |
| 8 | Click on the notification to verify it links back to the refreshed report | Notification is clickable and navigates user directly to the updated schedule report |
| 9 | Verify the refreshed report contains the schedule changes made in step 3 | Report displays accurate updated data matching the schedule changes, confirming successful refresh |
| 10 | Check notification history or log to confirm the notification was recorded | Notification appears in the user's notification history with correct timestamp and status |

**Postconditions:**
- User has received and acknowledged the report refresh completion notification
- Schedule report contains the latest updated data
- Notification is logged in the user's notification history
- System is ready for subsequent schedule changes and refreshes
- No pending refresh processes remain in the queue

---

