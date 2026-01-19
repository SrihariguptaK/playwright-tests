# Manual Test Cases

## Story: As Project Manager, I want to generate schedule reports to achieve visibility into planned activities and timelines
**Story ID:** story-1

### Test Case: Generate schedule report with valid filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Project Manager with valid credentials
- User has authorization to access schedule reporting functionality
- Schedule database contains test data with multiple projects, teams, and date ranges
- Reporting system is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Schedule Reporting section from the main dashboard | Schedule report UI is displayed with filter options including date range, team, and project dropdowns |
| 2 | Select a valid start date and end date from the date range picker (e.g., current month) | Date range is populated in the filter fields without validation errors |
| 3 | Select a valid team from the team filter dropdown | Team filter displays the selected team name and is accepted without errors |
| 4 | Select a valid project from the project filter dropdown | Project filter displays the selected project name and is accepted without errors |
| 5 | Click the 'Generate Report' button to submit the report generation request | System processes the request and displays a loading indicator |
| 6 | Wait for report generation to complete | Schedule report is generated and displayed within 5 seconds showing timelines, activities, and resource assignments matching the selected filters |
| 7 | Verify the report contains accurate data for the selected date range, team, and project | Report displays only activities within the specified date range, assigned to the selected team and project with correct timelines and resource information |

**Postconditions:**
- Schedule report is displayed on screen with filtered data
- Report data matches the applied filters
- System remains in ready state for additional operations (export, filter changes)
- No errors are logged in the system

---

### Test Case: Export schedule report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as a Project Manager with valid credentials
- User has authorization to access schedule reporting functionality
- Schedule report has been successfully generated with valid filters
- Report is currently displayed on screen
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate schedule report by selecting valid date range, team, and project filters and clicking 'Generate Report' | Report is displayed on screen with complete schedule data including timelines and resource assignments |
| 2 | Locate and click the 'Export to PDF' button in the report toolbar | System initiates PDF export process and displays export progress indicator |
| 3 | Wait for PDF download to complete and open the downloaded PDF file | PDF file is downloaded successfully with filename containing report name and timestamp, file opens correctly and contains all report data with proper formatting, headers, and footers |
| 4 | Verify PDF content matches the on-screen report data | PDF displays identical schedule information, timelines, resource assignments, and filter criteria as shown in the UI report |
| 5 | Return to the displayed report and click the 'Export to Excel' button in the report toolbar | System initiates Excel export process and displays export progress indicator |
| 6 | Wait for Excel download to complete and open the downloaded Excel file | Excel file is downloaded successfully with filename containing report name and timestamp, file opens correctly in spreadsheet application |
| 7 | Verify Excel content matches the on-screen report data and contains proper column headers | Excel file displays identical schedule information in tabular format with proper column headers (Activity, Timeline, Resources, etc.) and all data matches the UI report |
| 8 | Verify Excel file is editable and data can be manipulated | Excel file allows data manipulation, sorting, and filtering as expected from a standard Excel workbook |

**Postconditions:**
- PDF file is saved to downloads folder with correct data
- Excel file is saved to downloads folder with correct data
- Both exported files contain accurate schedule report information
- Original report remains displayed on screen
- Export operations are logged successfully in the system

---

### Test Case: Verify real-time update of schedule report
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as a Project Manager with valid credentials
- User has authorization to access schedule reporting functionality
- Schedule report is currently displayed for a specific project
- User has access to backend system or test tools to modify schedule data
- Real-time update mechanism is enabled in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Schedule Reporting section and generate a report for a specific project with current date range | Report is displayed showing current schedule data including activities, timelines, and resource assignments for the selected project |
| 2 | Note the current values displayed in the report (e.g., activity dates, resource names, timeline milestones) | Current schedule data is clearly visible and documented for comparison |
| 3 | Using backend access or test tools, update schedule data for the displayed project (e.g., change an activity date, modify resource assignment, or update timeline) | Backend schedule data is successfully updated and saved in the schedule database |
| 4 | Return to the displayed report UI and observe for automatic updates without manual refresh | Report UI automatically detects the backend change and displays an update indicator or notification |
| 5 | Wait up to 10 seconds and monitor the report display | Report UI updates automatically within 10 seconds showing the modified schedule data without requiring manual page refresh |
| 6 | Verify the updated data is accurately reflected in the report by comparing with the backend changes made | Report shows the latest schedule information matching exactly with the backend updates (updated activity dates, modified resource assignments, or changed timelines) |
| 7 | Verify that only the changed data is updated while other report elements remain unchanged | Only the modified schedule elements are updated in the report; all other data remains consistent and unchanged |

**Postconditions:**
- Report displays the most current schedule information
- Real-time update mechanism is functioning correctly
- Updated data matches backend schedule database
- No data inconsistencies or display errors are present
- System logs show successful real-time synchronization

---

## Story: As Project Manager, I want to filter schedule reports by team to achieve focused insights on team-specific schedules
**Story ID:** story-5

### Test Case: Filter schedule report by valid team
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Project Manager with valid credentials
- User has authorization to access schedule reporting functionality
- Schedule database contains data for multiple teams with assigned activities
- At least one team has schedule data available for reporting
- Team filter dropdown is populated with valid team options

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Schedule Reporting section from the main dashboard | Schedule report UI is displayed with all available filter options including team filter dropdown |
| 2 | Click on the team filter dropdown to view available teams | Team filter dropdown expands and displays a list of all available teams with their names |
| 3 | Select a valid team from the filter dropdown (e.g., 'Development Team A') | Team filter displays the selected team name, dropdown closes, and the filter is visually indicated as applied |
| 4 | Click the 'Generate Report' button to create the filtered report | System processes the request with team filter applied and displays a loading indicator |
| 5 | Wait for report generation to complete (within 5 seconds) | Report is generated and displayed showing schedule data exclusively for the selected team |
| 6 | Verify that all activities and schedules displayed belong only to the selected team | Report displays schedule data only for the selected team with no activities from other teams visible |
| 7 | Check that resource assignments shown in the report are members of the selected team | All resource assignments and team members listed in the report belong to the selected team |
| 8 | Verify the report header or filter summary indicates the team filter is active | Report header or filter summary section clearly shows that the report is filtered by the selected team name |

**Postconditions:**
- Schedule report displays only team-specific data
- Team filter remains applied and visible
- Report is ready for export or further filtering
- No data from other teams is visible in the report
- System logs successful team-filtered report generation

---

### Test Case: Handle invalid team filter input
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as a Project Manager with valid credentials
- User has authorization to access schedule reporting functionality
- Schedule reporting UI is accessible
- Team filter accepts manual input or can be manipulated to test invalid values

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Schedule Reporting section from the main dashboard | Schedule report UI is displayed with team filter input field or dropdown |
| 2 | Enter an invalid team identifier in the team filter field (e.g., 'INVALID_TEAM_999', special characters, or non-existent team ID) | Invalid team identifier is entered in the filter field |
| 3 | Tab out of the field or trigger validation by clicking elsewhere | System displays a validation error message such as 'Invalid team selected' or 'Please select a valid team from the list' near the team filter field |
| 4 | Verify the error message is clearly visible and describes the validation issue | Error message is displayed in red or highlighted color, clearly indicating that the team filter input is invalid |
| 5 | Attempt to click the 'Generate Report' button with the invalid team filter | Report generation is blocked and the 'Generate Report' button is either disabled or clicking it triggers a validation error message |
| 6 | Verify that no report is generated with invalid team filter | No report is displayed, and the system prevents report generation until valid input is provided |
| 7 | Clear the invalid team filter input and select a valid team from the dropdown | Validation error message disappears, valid team is selected, and the 'Generate Report' button becomes enabled |
| 8 | Click 'Generate Report' with the valid team filter | Report is successfully generated and displayed with data for the valid team selected |

**Postconditions:**
- Invalid team filter input is rejected by the system
- Validation error messages are cleared after valid input is provided
- Report generation only proceeds with valid team filter
- System maintains data integrity by preventing invalid queries
- Error handling is logged appropriately in the system

---

