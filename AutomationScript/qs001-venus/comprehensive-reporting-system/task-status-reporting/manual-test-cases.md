# Manual Test Cases

## Story: As Team Lead, I want to view task status reports to achieve real-time monitoring of task progress and completion
**Story ID:** story-3

### Test Case: Generate task status report with valid filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has authorization to access task status reporting
- Task management database contains task data with various statuses
- At least one project exists with tasks in pending, in-progress, and completed statuses
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Task Status Reporting section from the main dashboard | Task status report UI is displayed with filter options including project, team, and priority dropdowns |
| 2 | Select a valid project from the project filter dropdown | Selected project is highlighted and displayed in the filter field without errors |
| 3 | Select a valid priority level from the priority filter dropdown | Selected priority is highlighted and displayed in the filter field without errors |
| 4 | Click the 'Generate Report' button to submit report generation request | Task status report is generated and displayed within 5 seconds showing tasks categorized by pending, in-progress, and completed statuses matching the selected filters |
| 5 | Verify the report displays task count for each status category | Report shows accurate count of tasks in pending, in-progress, and completed categories |
| 6 | Verify the report contains only tasks matching the applied filters | All displayed tasks belong to the selected project and priority level |

**Postconditions:**
- Task status report is displayed on screen
- Report data matches the applied filters
- User remains logged in
- System is ready for additional filter changes or export actions

---

### Test Case: Export task status report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has authorization to access task status reporting
- Task status report has been generated and is displayed on screen
- Browser allows file downloads
- Sufficient disk space available for file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate task status report by selecting project and priority filters and clicking 'Generate Report' | Report is displayed on screen with task data categorized by status |
| 2 | Locate and click the 'Export to PDF' button | PDF file download is initiated and file is downloaded to the default download location |
| 3 | Open the downloaded PDF file | PDF opens successfully and contains the correct report data with all task statuses, filters applied, and proper formatting |
| 4 | Return to the task status report page in the application | Report is still displayed with the same filter settings |
| 5 | Locate and click the 'Export to Excel' button | Excel file download is initiated and file is downloaded to the default download location |
| 6 | Open the downloaded Excel file | Excel file opens successfully and contains the correct report data with all task statuses in structured columns, filters applied, and data is editable |
| 7 | Verify both exported files contain identical data matching the on-screen report | PDF and Excel files contain the same task information, counts, and status categories as displayed in the UI |

**Postconditions:**
- PDF file is successfully downloaded and contains accurate report data
- Excel file is successfully downloaded and contains accurate report data
- Original report remains displayed on screen
- User remains logged in
- No data corruption or loss occurred during export

---

### Test Case: Verify real-time update of task status report
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has authorization to access task status reporting
- At least one project exists with tasks in various statuses
- Real-time update mechanism is enabled and functioning
- Backend task management system is accessible
- WebSocket or polling mechanism for real-time updates is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Task Status Reporting section and select a specific project | Task status report UI is displayed with current task statuses for the selected project |
| 2 | Note the current count of tasks in each status category (pending, in-progress, completed) | Task counts are clearly visible for each status category |
| 3 | Using backend access or another user session, update the status of a task from 'pending' to 'in-progress' in the task management system | Task status is successfully updated in the backend database |
| 4 | Monitor the task status report UI without refreshing the page | Report UI updates automatically within 10 seconds showing the changed task status |
| 5 | Verify the task count in 'pending' category decreased by 1 | Pending task count is reduced by 1 from the previously noted count |
| 6 | Verify the task count in 'in-progress' category increased by 1 | In-progress task count is increased by 1 from the previously noted count |
| 7 | Update another task status from 'in-progress' to 'completed' in the backend | Task status is successfully updated in the backend database |
| 8 | Monitor the report UI for automatic updates | Report shows the latest task status information with in-progress count decreased by 1 and completed count increased by 1 within 10 seconds |
| 9 | Verify all task status changes are accurately reflected in the report | Report displays current and accurate task status information matching the backend data |

**Postconditions:**
- Task status report displays the most recent task status information
- Real-time update mechanism continues to function
- All task status changes are accurately reflected
- User remains logged in
- No manual page refresh was required

---

## Story: As Team Lead, I want to filter task status reports by priority to achieve focused monitoring of critical tasks
**Story ID:** story-7

### Test Case: Filter task status report by valid priority
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has authorization to access task status reporting
- Task database contains tasks with different priority levels (High, Medium, Low)
- At least one task exists for each priority level
- Task Status Reporting section is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Task Status Reporting section from the main dashboard | Task status report UI is displayed with filter options including priority dropdown |
| 2 | Locate the priority filter dropdown and click to expand it | Priority dropdown expands showing available priority options (High, Medium, Low) |
| 3 | Select 'High' priority from the filter dropdown | Priority filter is applied and 'High' is displayed as the selected value in the dropdown |
| 4 | Click the 'Generate Report' button | Report is generated within 5 seconds and displays task status data only for tasks with High priority |
| 5 | Verify all tasks displayed in the report have 'High' priority | All tasks shown in pending, in-progress, and completed categories have High priority designation |
| 6 | Verify no tasks with Medium or Low priority are displayed | Report contains only High priority tasks, excluding all Medium and Low priority tasks |
| 7 | Change the priority filter to 'Medium' and regenerate the report | Report updates to display only Medium priority tasks across all status categories |
| 8 | Verify the filtered report accuracy for Medium priority | All displayed tasks have Medium priority and no High or Low priority tasks are shown |

**Postconditions:**
- Task status report displays only tasks matching the selected priority filter
- Filter selection is retained until changed by user
- User remains logged in
- System is ready for export or additional filter modifications

---

### Test Case: Handle invalid priority filter input
- **ID:** tc-005
- **Type:** error-case
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has authorization to access task status reporting
- Task Status Reporting section is accessible
- Priority filter accepts manual input or has validation mechanism

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Task Status Reporting section | Task status report UI is displayed with priority filter field |
| 2 | Enter an invalid priority value 'InvalidPriority' in the priority filter field | System displays a validation error message indicating 'Invalid priority value. Please select from: High, Medium, Low' |
| 3 | Verify the error message is clearly visible and user-friendly | Error message is displayed in red text near the priority filter field with clear instructions |
| 4 | Click the 'Generate Report' button while invalid priority is entered | Report generation is blocked and system displays error message 'Please correct the priority filter before generating report' |
| 5 | Verify no report is generated with invalid filter | No report data is displayed and the generate button remains inactive or shows validation error |
| 6 | Enter a numeric value '123' in the priority filter field | System displays validation error message indicating invalid priority format |
| 7 | Attempt to generate report with numeric invalid input | Report generation is blocked until valid input is provided |
| 8 | Clear the invalid input and select a valid priority 'High' from the dropdown | Validation error disappears and 'High' priority is accepted |
| 9 | Click 'Generate Report' with valid priority selected | Report is successfully generated displaying High priority tasks within 5 seconds |

**Postconditions:**
- System validates priority filter input before report generation
- Invalid inputs are rejected with clear error messages
- Report generation only proceeds with valid priority values
- User remains logged in
- No corrupted data is processed

---

## Story: As Team Lead, I want to export task status reports in Excel format to achieve detailed offline analysis
**Story ID:** story-11

### Test Case: Export task status report to Excel
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Team Lead with authorized role
- Task status report data is available in the system
- User has permissions to access task status reports
- Browser supports file downloads
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task status reports section | Task status reports page is displayed with available report options |
| 2 | Select desired filters or parameters for the task status report (if applicable) | Selected filters are applied and highlighted in the UI |
| 3 | Click on 'Generate Report' button | Task status report is generated and displayed on screen with all task data including status, assignees, dates, and other relevant fields |
| 4 | Verify the displayed report contains accurate task status information | Report shows correct task data matching the current system state |
| 5 | Locate and click on 'Export to Excel' button | Export process initiates and Excel file download begins within 5 seconds |
| 6 | Wait for the Excel file download to complete | Excel file is successfully downloaded to the default download location with filename format 'TaskStatusReport_YYYY-MM-DD.xlsx' |
| 7 | Navigate to the download location and locate the downloaded Excel file | Excel file is present in the downloads folder with correct filename and non-zero file size |
| 8 | Open the downloaded Excel file using Microsoft Excel or compatible spreadsheet application | Excel file opens without errors and displays the task status report data |
| 9 | Verify all columns are present (Task ID, Task Name, Status, Assignee, Start Date, Due Date, Priority, etc.) | All expected columns are present with proper headers |
| 10 | Verify data integrity by comparing sample records from the Excel file with the original report displayed in the system | Data in Excel file matches exactly with the data shown in the system report |
| 11 | Check formatting of the Excel file including column widths, headers, and data alignment | Excel file maintains proper formatting with readable column widths, bold headers, and appropriate data alignment |
| 12 | Verify that dates are formatted correctly in Excel date format | All date fields are displayed in proper Excel date format (MM/DD/YYYY or system default) |
| 13 | Check that all rows from the report are exported without truncation | Row count in Excel matches the total number of tasks in the generated report |

**Postconditions:**
- Excel file remains in the download folder
- Original report remains displayed in the system
- No data is modified in the system
- Export action is logged in the system audit trail
- User can perform additional exports if needed

---

