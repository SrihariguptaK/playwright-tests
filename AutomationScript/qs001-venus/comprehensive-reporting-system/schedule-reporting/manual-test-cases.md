# Manual Test Cases

## Story: As Project Manager, I want to generate schedule reports to achieve visibility into planned activities and timelines
**Story ID:** story-1

### Test Case: Generate schedule report with valid filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Project Manager with valid credentials
- User has authorization to access schedule reporting functionality
- Schedule database contains test data with multiple projects, teams, and date ranges
- Reporting system is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Schedule Reporting section from the main dashboard | Schedule report UI is displayed with filter options including date range, team, and project dropdowns |
| 2 | Select valid date range using the date picker (e.g., start date: 01/01/2024, end date: 31/01/2024) | Date range is populated in the filter fields without validation errors |
| 3 | Select a valid team from the team filter dropdown | Team filter displays selected team name and is accepted without errors |
| 4 | Select a valid project from the project filter dropdown | Project filter displays selected project name and filters are accepted without errors |
| 5 | Click the 'Generate Report' button to submit report generation request | Schedule report is generated and displayed within 5 seconds showing timelines, resource assignments, and activities matching the selected filters |
| 6 | Verify report contains accurate data including project name, team name, date range, activities, and resource assignments | Report displays all expected data fields with correct values matching the applied filters |

**Postconditions:**
- Schedule report is successfully generated and displayed on screen
- Report data matches the selected filter criteria
- System logs the report generation activity
- User remains on the schedule reporting page

---

### Test Case: Export schedule report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Project Manager with valid credentials
- User has authorization to export schedule reports
- Schedule report has been successfully generated and is displayed on screen
- Browser allows file downloads
- User has write permissions to the download directory

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate schedule report with valid filters (date range, team, and project) | Report is displayed on screen with complete schedule data including timelines and resource assignments |
| 2 | Click the 'Export to PDF' button | PDF file is downloaded to the default download location with filename format 'ScheduleReport_YYYYMMDD_HHMMSS.pdf' |
| 3 | Open the downloaded PDF file | PDF opens successfully and contains correct report data matching the on-screen report including all filters, timelines, and resource assignments with proper formatting |
| 4 | Return to the schedule report page and click the 'Export to Excel' button | Excel file is downloaded to the default download location with filename format 'ScheduleReport_YYYYMMDD_HHMMSS.xlsx' |
| 5 | Open the downloaded Excel file | Excel file opens successfully and contains correct report data matching the on-screen report with proper column headers, data rows, and formatting |
| 6 | Verify both exported files contain identical data to the on-screen report | Both PDF and Excel exports contain accurate and complete schedule information matching the displayed report |

**Postconditions:**
- PDF file is successfully downloaded and contains accurate report data
- Excel file is successfully downloaded and contains accurate report data
- Export operations are logged in the system
- User remains on the schedule reporting page
- Original report remains displayed on screen

---

### Test Case: Verify real-time update of schedule report
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Project Manager with valid credentials
- Schedule report is generated and displayed for a specific project
- User has access to backend system or test data modification interface
- Real-time update mechanism is enabled and functional
- WebSocket or polling mechanism is active for live updates

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open schedule report for a specific project with current schedule data visible | Report is displayed showing current schedule information including activities, timelines, and resource assignments |
| 2 | Note the current values displayed in the report (e.g., activity dates, resource names, timeline milestones) | Current report data is documented for comparison after update |
| 3 | Update schedule data in backend system (e.g., modify activity date, change resource assignment, or update timeline) | Backend data is successfully updated and saved in the schedule database |
| 4 | Monitor the report UI without refreshing the page | Report UI updates automatically within 10 seconds showing a visual indicator of data refresh |
| 5 | Verify updated data is reflected in the report by comparing with the noted original values | Report shows latest schedule information with all modified fields displaying the new values accurately |
| 6 | Verify timestamp or last updated indicator shows recent update time | Report displays current timestamp indicating the real-time update occurred |

**Postconditions:**
- Schedule report displays the most current data from the database
- Real-time update mechanism is confirmed functional
- Updated data is accurately reflected in the report
- System maintains connection for future real-time updates
- Update activity is logged in the system

---

## Story: As Project Manager, I want to filter schedule reports by team to achieve focused insights on team-specific schedules
**Story ID:** story-5

### Test Case: Filter schedule report by valid team
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Project Manager with valid credentials
- User has authorization to access schedule reporting functionality
- Schedule database contains data for multiple teams
- At least one team has associated schedule data available
- Team filter dropdown is populated with valid team options

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Schedule Reporting section from the main dashboard | Schedule report UI is displayed with all filter options including team filter dropdown |
| 2 | Click on the team filter dropdown to view available teams | Dropdown expands showing a list of valid teams with team names and identifiers |
| 3 | Select a valid team from the filter dropdown (e.g., 'Development Team A') | Team filter is applied and displays the selected team name in the filter field |
| 4 | Click the 'Generate Report' button to generate the filtered report | Report is generated within 5 seconds and displays schedule data only for the selected team |
| 5 | Verify all displayed activities, resources, and timelines belong to the selected team | Report contains only schedule entries associated with the selected team, with no data from other teams visible |
| 6 | Check report header or filter summary section | Report clearly indicates the team filter is active and shows the selected team name |

**Postconditions:**
- Schedule report displays only team-specific data
- Team filter remains applied and visible
- Report is ready for export if needed
- Filter selection is logged in the system
- User remains on the schedule reporting page

---

### Test Case: Handle invalid team filter input
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Project Manager with valid credentials
- User has access to schedule reporting functionality
- Schedule reporting page is loaded and accessible
- Team filter field accepts manual input or can be manipulated

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Schedule Reporting section | Schedule report UI is displayed with team filter field available |
| 2 | Enter an invalid team identifier in the team filter field (e.g., 'INVALID_TEAM_999' or special characters like '@#$%') | System displays a validation error message such as 'Invalid team selection. Please select a valid team from the list.' |
| 3 | Verify the error message is clearly visible and user-friendly | Error message is displayed in red text near the team filter field with clear instructions |
| 4 | Attempt to click the 'Generate Report' button with invalid team filter | Report generation is blocked and system prevents submission, displaying message 'Please correct the errors before generating the report.' |
| 5 | Clear the invalid input and select a valid team from the dropdown | Validation error disappears and team filter accepts the valid selection |
| 6 | Click 'Generate Report' button with valid team filter | Report is successfully generated with the valid team filter applied |

**Postconditions:**
- Invalid team input is rejected by the system
- Validation error message is displayed to the user
- Report generation is prevented until valid input is provided
- System maintains data integrity by blocking invalid filters
- Error handling is logged for monitoring purposes

---

## Story: As Project Manager, I want to export schedule reports in Excel format to achieve flexible data analysis
**Story ID:** story-9

### Test Case: Export schedule report to Excel
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Project Manager role
- User has authorization to export schedule reports
- Schedule data exists in the system
- Browser supports file downloads
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule reports section | Schedule reports page is displayed with available report options |
| 2 | Select the desired schedule parameters (date range, project, resources) | Schedule parameters are selected and highlighted in the interface |
| 3 | Click the 'Generate Report' button | Schedule report is generated and displayed on screen with all selected data including tasks, dates, resources, and dependencies |
| 4 | Verify the report contains expected schedule data | Report displays accurate schedule information matching the selected parameters |
| 5 | Click the 'Export to Excel' button | Export process initiates and Excel file download begins within 5 seconds |
| 6 | Wait for the download to complete | Excel file is successfully downloaded to the default downloads folder with naming convention 'ScheduleReport_YYYY-MM-DD.xlsx' |
| 7 | Navigate to the downloads folder and locate the exported Excel file | Excel file is present in the downloads folder with correct filename and non-zero file size |
| 8 | Open the Excel file using Microsoft Excel or compatible spreadsheet application | Excel file opens without errors or corruption warnings |
| 9 | Verify the Excel file contains all schedule data from the generated report | All tasks, dates, resources, dependencies, and other schedule information are present and match the original report |
| 10 | Verify data formatting is maintained (dates, numbers, text alignment, headers) | Data is properly formatted with correct date formats, numerical values, column headers are bold, and cells are appropriately aligned |
| 11 | Verify data integrity by comparing sample data points between the web report and Excel file | All compared data points match exactly between the web report and Excel export with no data loss or corruption |

**Postconditions:**
- Excel file remains in downloads folder
- Original schedule report remains displayed in the browser
- User session remains active
- Export action is logged in system audit trail
- No data is modified in the source system

---

