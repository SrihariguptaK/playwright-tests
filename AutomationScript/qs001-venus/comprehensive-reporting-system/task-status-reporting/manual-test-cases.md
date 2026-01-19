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
- User has role-based access to Task Status Reporting
- Task management database contains task data with various statuses
- At least one project exists with tasks in pending, in-progress, and completed statuses
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Task Status Reporting section from the main dashboard | Task status report UI is displayed with filter options including project, team, and priority dropdowns |
| 2 | Select a valid project from the project filter dropdown | Selected project is highlighted in the dropdown and filter is applied without errors |
| 3 | Select a valid priority level from the priority filter dropdown | Selected priority is highlighted in the dropdown and filters are accepted without errors |
| 4 | Click the 'Generate Report' button to submit report generation request | Task status report is generated and displayed within 5 seconds showing tasks categorized by pending, in-progress, and completed statuses matching the selected filters |
| 5 | Verify the report displays task count for each status category | Report shows accurate count of tasks in pending, in-progress, and completed categories |

**Postconditions:**
- Task status report is displayed on screen
- Report data matches the applied filters
- User remains on the Task Status Reporting page
- Filters remain selected for subsequent operations

---

### Test Case: Export task status report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has role-based access to Task Status Reporting
- Task status report has been generated with valid filters
- Report data is displayed on screen
- Browser has download permissions enabled
- Sufficient disk space available for file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate task status report by selecting project and priority filters and clicking 'Generate Report' | Report is displayed on screen with task data categorized by status |
| 2 | Click the 'Export to PDF' button | PDF file is downloaded to the default download location with filename containing report name and timestamp |
| 3 | Open the downloaded PDF file | PDF opens successfully and displays correct report data including all task statuses, applied filters, and task details matching the on-screen report |
| 4 | Return to the task status report page and click the 'Export to Excel' button | Excel file is downloaded to the default download location with filename containing report name and timestamp |
| 5 | Open the downloaded Excel file | Excel file opens successfully and displays correct report data in structured format with columns for task details, status categories, and applied filters matching the on-screen report |
| 6 | Verify data integrity in both exported files | Both PDF and Excel files contain identical data matching the on-screen report with 100% accuracy |

**Postconditions:**
- PDF file is saved in downloads folder
- Excel file is saved in downloads folder
- Both files contain accurate report data
- User remains on the Task Status Reporting page
- Report remains displayed on screen

---

### Test Case: Verify real-time update of task status report
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has role-based access to Task Status Reporting
- At least one project exists with tasks in various statuses
- Real-time update mechanism is enabled
- Backend task management system is accessible
- WebSocket or polling mechanism for real-time updates is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Task Status Reporting section and select a specific project filter | Task status report UI is displayed with filter options |
| 2 | Click 'Generate Report' to open task status report for the selected project | Report is displayed showing current task statuses with counts for pending, in-progress, and completed categories |
| 3 | Note the current count of tasks in each status category (pending, in-progress, completed) | Current task counts are visible and documented |
| 4 | Update a task status in the backend system (e.g., move a task from pending to in-progress) | Task status is successfully updated in the backend database |
| 5 | Monitor the report UI for automatic updates without manual refresh | Report UI updates automatically within 10 seconds showing the status change |
| 6 | Verify the updated task statuses are reflected in the report by checking task counts | Report shows latest task status information with updated counts (e.g., pending count decreased by 1, in-progress count increased by 1) |
| 7 | Verify the specific task that was updated now appears in the correct status category | The updated task is displayed in the new status category with accurate details |

**Postconditions:**
- Task status report displays real-time updated data
- Task counts reflect the latest status changes
- No manual page refresh was required
- Report remains functional for further operations
- Backend task status remains updated

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
- User has role-based access to Task Status Reporting
- Task database contains tasks with different priority levels (High, Medium, Low)
- At least one task exists for each priority level
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Task Status Reporting section from the main dashboard | Task status report UI is displayed with filter options including priority dropdown |
| 2 | Click on the priority filter dropdown to view available priority options | Dropdown expands showing all available priority levels (High, Medium, Low) |
| 3 | Select 'High' priority from the filter dropdown | Priority filter is applied and 'High' is displayed as the selected value in the dropdown |
| 4 | Click the 'Generate Report' button | Report is generated within 5 seconds and displays task status data only for tasks with High priority |
| 5 | Verify all displayed tasks have 'High' priority assigned | All tasks in the report show 'High' priority and no Medium or Low priority tasks are displayed |
| 6 | Verify tasks are categorized by status (pending, in-progress, completed) within the priority filter | Report displays High priority tasks grouped by their status categories with accurate counts |
| 7 | Change priority filter to 'Medium' and regenerate the report | Report updates to display only Medium priority tasks across all status categories |

**Postconditions:**
- Filtered task status report is displayed on screen
- Only tasks matching the selected priority are shown
- Report data is accurate with 100% priority filtering accuracy
- Priority filter remains selected for export operations
- User remains on the Task Status Reporting page

---

### Test Case: Handle invalid priority filter input
- **ID:** tc-005
- **Type:** error-case
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has role-based access to Task Status Reporting
- Task Status Reporting page is accessible
- Priority filter validation is enabled
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Task Status Reporting section | Task status report UI is displayed with filter options |
| 2 | Attempt to enter an invalid priority value in the priority filter field (e.g., 'Invalid', special characters, or numeric values) | System displays validation error message indicating 'Invalid priority value. Please select from available options: High, Medium, Low' |
| 3 | Verify the error message is clearly visible near the priority filter field | Error message is displayed in red text below or next to the priority filter with clear instructions |
| 4 | Click the 'Generate Report' button while invalid priority value is entered | Report generation is blocked and system prevents submission with error message 'Please correct the priority filter before generating report' |
| 5 | Verify the Generate Report button remains disabled or shows validation warning | Generate Report button is either disabled or displays a tooltip indicating validation errors must be resolved |
| 6 | Clear the invalid input and select a valid priority value from the dropdown | Error message disappears and valid priority is accepted without errors |
| 7 | Click 'Generate Report' with valid priority filter | Report is generated successfully displaying tasks matching the valid priority selection |

**Postconditions:**
- Invalid priority input is rejected by the system
- Validation error messages are cleared after valid input
- Report generation only proceeds with valid priority filter
- System maintains data integrity by preventing invalid filter values
- User remains on the Task Status Reporting page

---

