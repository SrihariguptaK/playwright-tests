# Manual Test Cases

## Story: As Project Manager, I want to generate task status reports to monitor project progress
**Story ID:** story-3

### Test Case: Validate task status report generation with valid filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Project Manager role
- At least one project exists in the system with tasks
- Task data is available in the project management database
- User has appropriate permissions to access task status reporting module

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task status reporting module from the main dashboard | Task status report UI is displayed with filter options, report generation button, and empty report area |
| 2 | Select a valid project from the project dropdown filter | Project is selected and displayed in the filter section without any validation errors |
| 3 | Select a valid date range using the date range picker | Date range is accepted and displayed in the filter section |
| 4 | Click the 'Generate Report' button to request report generation | System processes the request and displays a loading indicator |
| 5 | Wait for report generation to complete | Task status report is generated within 15 seconds and displayed with correct data including progress percentages, completion status, and overdue tasks for the selected project and date range |
| 6 | Verify report contains task names, assignees, status, progress percentage, and due dates | All task details are accurately displayed in the report matching the database records |

**Postconditions:**
- Task status report is displayed on screen
- Report data matches the selected filters
- User remains on the task status reporting page
- Report is available for export

---

### Test Case: Verify export functionality for task status reports
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Project Manager role
- Task status reporting module is accessible
- At least one project with tasks exists in the system
- Browser allows file downloads
- User has permissions to export reports

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task status reporting module | Task status report UI is displayed with filter options |
| 2 | Select a valid project and date range filters | Filters are applied successfully |
| 3 | Click 'Generate Report' button to generate task status report with filters | Report is generated and displayed on screen with task data including progress, status, and overdue information |
| 4 | Locate and click the 'Export to Excel' button | System initiates Excel file download |
| 5 | Open the downloaded Excel file and verify contents | Excel file is downloaded successfully with accurate data matching the on-screen report, including all columns, task details, and formatting |
| 6 | Return to the task status report page and click 'Export to PDF' button | System initiates PDF file download |
| 7 | Open the downloaded PDF file and verify contents | PDF file is downloaded with correct formatting, all task data is readable, and layout matches the report structure |

**Postconditions:**
- Excel file is saved to downloads folder with accurate report data
- PDF file is saved to downloads folder with proper formatting
- Original report remains displayed on screen
- No data corruption or loss during export

---

### Test Case: Ensure unauthorized users cannot access task status reports
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Test user account exists without Project Manager role
- Task status reporting module exists in the system
- Role-based access control is configured
- API endpoint /api/reports/taskstatus is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the application as a non-project manager user (e.g., Developer or Viewer role) | User is successfully logged in and redirected to their default dashboard |
| 2 | Attempt to navigate to the task status reporting module via the main menu or direct URL | Access to task status reporting module is denied with an appropriate error message such as 'Access Denied' or 'Insufficient Permissions', and user is redirected to an error page or their dashboard |
| 3 | Verify that the task status reporting menu option is not visible in the navigation | Task status reporting module link is not displayed in the user's navigation menu |
| 4 | Open browser developer tools and attempt to access the API endpoint directly by sending a GET request to /api/reports/taskstatus | API returns HTTP 403 Forbidden response with an error message indicating insufficient permissions |
| 5 | Verify the response body contains appropriate error details | Response includes error code and message such as 'Access forbidden: Project Manager role required' |

**Postconditions:**
- Unauthorized user cannot access task status reports
- Security logs record the unauthorized access attempt
- User session remains active but restricted to authorized features
- No sensitive report data is exposed to unauthorized user

---

## Story: As Project Manager, I want task status reports to identify overdue tasks to prioritize work
**Story ID:** story-7

### Test Case: Validate overdue task detection in task status reports
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Project Manager role
- At least one project exists with tasks that have passed their due dates
- System clock is accurate and synchronized
- Task status reporting module is accessible
- Overdue task detection logic is configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task status reporting module | Task status report UI is displayed with filter options and report generation controls |
| 2 | Select a project that contains tasks with overdue dates from the project filter dropdown | Project is selected successfully |
| 3 | Click 'Generate Report' button to generate task status report with overdue tasks | System processes the request and generates the report within 15 seconds |
| 4 | Review the generated report and identify tasks marked as overdue | Report highlights overdue tasks correctly with visual indicators such as red text, warning icons, or highlighted rows. Overdue tasks show due dates that are earlier than the current date |
| 5 | Verify that all tasks with due dates in the past are flagged as overdue | 100% accuracy in overdue task detection - all tasks past their due date are marked as overdue, and no false positives exist |
| 6 | Apply additional filter to show only overdue tasks by project | Report refreshes and displays only overdue tasks for the selected project |
| 7 | Filter report by a specific assignee who has overdue tasks | Filtered report shows overdue tasks assigned only to the selected assignee within the chosen project |
| 8 | Verify overdue task count matches the filtered results | Summary statistics show correct count of overdue tasks matching the displayed results |

**Postconditions:**
- Report accurately displays all overdue tasks with proper highlighting
- Filtered views show correct subset of overdue tasks
- No tasks are incorrectly flagged as overdue
- Report remains available for further filtering or export

---

### Test Case: Verify export of task status reports with overdue task highlights
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Project Manager role
- At least one project exists with overdue tasks
- Task status reporting module is accessible
- Browser allows file downloads
- Export functionality supports overdue task highlighting

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task status reporting module | Task status report UI is displayed |
| 2 | Select a project with overdue tasks and apply relevant filters | Filters are applied successfully |
| 3 | Click 'Generate Report' button to generate task status report with overdue highlights | Report is generated and displayed on screen with overdue tasks clearly highlighted using visual indicators |
| 4 | Verify that overdue tasks are visually distinguished in the on-screen report | Overdue tasks are highlighted with distinct formatting such as red text, bold font, or colored background |
| 5 | Click 'Export to Excel' button to export the report | System initiates Excel file download |
| 6 | Open the downloaded Excel file and locate overdue tasks | Excel file includes overdue task highlights with formatting preserved - overdue tasks are marked with cell colors, conditional formatting, or special indicators that distinguish them from on-time tasks |
| 7 | Verify all overdue tasks in the Excel file match those shown in the on-screen report | All overdue tasks are present in the Excel export with accurate data and consistent highlighting |
| 8 | Return to the report page and click 'Export to PDF' button | System initiates PDF file download |
| 9 | Open the downloaded PDF file and verify overdue task highlights are preserved | PDF file displays overdue tasks with visual highlights maintained, formatting is clear and readable |

**Postconditions:**
- Excel file contains all overdue tasks with proper highlighting
- PDF file contains all overdue tasks with visual indicators
- Exported files accurately reflect the on-screen report
- Overdue task formatting is preserved across all export formats

---

