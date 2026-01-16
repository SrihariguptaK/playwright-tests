# Manual Test Cases

## Story: As HR Manager, I want to generate reports on shift template usage to analyze scheduling efficiency
**Story ID:** story-8

### Test Case: Generate shift template usage report with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- Shift template usage data exists in the system for multiple departments
- At least 30 days of historical scheduling data is available
- User has 'Report Generation' permission enabled
- Reporting module is accessible and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module from the main dashboard | Reporting module page loads successfully and displays available reporting options including 'Shift Template Usage Report' |
| 2 | Select 'Shift Template Usage Report' from the list of available reports | Report configuration screen is displayed with filter options for date range and department |
| 3 | Set the date range filter to the last 30 days using the date picker | Date range is selected and displayed correctly in the filter field |
| 4 | Select a specific department from the department dropdown filter | Department is selected and displayed in the filter field |
| 5 | Click the 'Generate Report' button | Report is generated and displayed on screen within 5 seconds showing template usage data filtered by selected date range and department with usage frequency, adoption metrics, and scheduling outcomes |
| 6 | Click the 'Export to PDF' button | PDF file is downloaded to the default download location containing the complete filtered report data with proper formatting, headers, and all visible data from the screen report |
| 7 | Open the downloaded PDF file | PDF opens successfully and displays all report data accurately matching the on-screen report with correct date range and department filters applied |

**Postconditions:**
- Report data remains displayed on screen
- PDF file is saved in the downloads folder
- Audit log records the report generation activity
- User session remains active
- No data is modified in the system

---

### Test Case: Restrict report access to authorized users
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with non-HR Manager role (e.g., Employee or Scheduler)
- User does not have 'Report Generation' permission
- Reporting module URL is known
- Role-based access control is configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to navigate to the reporting module by entering the URL directly or clicking on a reporting link | Access is denied and an appropriate error message is displayed stating 'Access Denied: You do not have permission to view reports. Please contact your administrator.' or similar message |
| 2 | Verify that the user is redirected to an appropriate page (dashboard or error page) | User is redirected to their dashboard or a 403 Forbidden error page without accessing any report data |
| 3 | Attempt to access the report API endpoint directly using GET /api/reports/shifttemplateusage | API returns 403 Forbidden status code with error message indicating insufficient permissions |

**Postconditions:**
- No report data is exposed to unauthorized user
- Access attempt is logged in security audit trail
- User remains on authorized pages only
- System security remains intact

---

### Test Case: Verify report generation performance
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as HR Manager with valid credentials
- Large dataset exists with at least 10,000 shift template usage records
- Database contains data spanning multiple years across all departments
- System performance monitoring tools are available
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module | Reporting module loads successfully |
| 2 | Select 'Shift Template Usage Report' option | Report configuration screen is displayed |
| 3 | Set date range filter to maximum range (e.g., last 12 months or all available data) | Date range is set to maximum available period |
| 4 | Select 'All Departments' option to include all departments in the report | All departments filter is applied |
| 5 | Start a timer and click 'Generate Report' button | Report generation begins and loading indicator is displayed |
| 6 | Monitor the time taken for the report to fully load and display on screen | Report is completely generated and displayed within 5 seconds showing all data for the large dataset with proper pagination or scrolling functionality |
| 7 | Verify that all data is rendered correctly and the report is fully interactive | Report displays complete data with all charts, tables, and metrics properly rendered and responsive to user interactions |

**Postconditions:**
- Report is fully loaded and functional
- System performance remains stable
- No timeout errors occurred
- Database connections are properly closed
- Memory usage returns to normal levels

---

## Story: As Manager, I want to view audit trails of schedule changes to ensure compliance
**Story ID:** story-9

### Test Case: Verify audit logging of schedule changes
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Two user accounts are available: one with Scheduler role and one with Manager role
- Scheduler user is logged in and has permission to modify schedules
- At least one employee schedule exists in the system
- Audit logging functionality is enabled in the system
- Manager user has access to audit trail module

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | As Scheduler user, navigate to the schedule management page | Schedule management page loads successfully displaying existing schedules |
| 2 | Select an existing employee schedule and modify the shift time from 9:00 AM to 10:00 AM | Schedule modification interface allows the change and displays updated time |
| 3 | Click 'Save' button to save the schedule change | Success message is displayed confirming 'Schedule updated successfully' and the new shift time is reflected in the schedule |
| 4 | Note the current timestamp and log out from the Scheduler account | User is successfully logged out and redirected to login page |
| 5 | Log in as Manager user with valid credentials | Manager successfully logs in and is redirected to the manager dashboard |
| 6 | Navigate to the audit trail module from the main menu | Audit trail interface loads successfully displaying search and filter options |
| 7 | Query the audit trail for the employee whose schedule was modified in the previous steps | Audit trail displays change entries showing the schedule modification with details including: previous shift time (9:00 AM), new shift time (10:00 AM), username of the Scheduler who made the change, timestamp of the change, and change type (Schedule Edit) |
| 8 | Click on the audit entry to view detailed change information | Detailed view displays complete change information including all modified fields, before and after values, and full audit metadata |

**Postconditions:**
- Schedule change remains saved in the system
- Audit log entry is permanently recorded in AuditLogs table
- Manager remains logged in to audit trail module
- No data integrity issues exist
- Audit trail is available for future queries

---

### Test Case: Search and filter audit logs
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Manager with audit trail access permissions
- Multiple audit log entries exist in the system for different employees
- Audit logs span multiple dates and include changes by different users
- At least 20 audit log entries are available for testing filter functionality
- Audit trail module is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit trail module | Audit trail interface loads displaying all recent audit logs with filter options visible including employee filter, date range filter, and user filter |
| 2 | Note the total number of audit entries currently displayed | Total count of audit entries is visible (e.g., 'Showing 50 entries') |
| 3 | Select a specific employee from the employee filter dropdown | Employee is selected and displayed in the filter field |
| 4 | Set the date range filter to show only entries from the last 7 days | Date range is set and displayed in the filter field showing start and end dates |
| 5 | Click 'Apply Filters' or observe auto-filtering if enabled | Audit logs table updates immediately to display only entries matching the selected employee and date range. The total count updates to reflect filtered results (e.g., 'Showing 8 entries') |
| 6 | Verify that all displayed entries match the applied filters by checking employee name and date on each entry | All visible audit log entries show the selected employee name and have timestamps within the last 7 days. No entries outside the filter criteria are displayed |
| 7 | Clear the employee filter and add a user filter to show changes made by a specific scheduler | Filter updates and audit logs display only entries where the specified user made the changes, regardless of which employee was affected |
| 8 | Click 'Clear All Filters' button | All filters are removed and the audit trail returns to showing all available entries with the original total count restored |

**Postconditions:**
- Filters can be reapplied as needed
- Audit log data remains unchanged
- Filter state is cleared for next use
- User session remains active
- System performance remains stable

---

### Test Case: Restrict audit trail access to authorized users
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with a non-Manager role (e.g., Employee or Scheduler without audit access)
- User does not have 'Audit Trail Access' permission
- Audit trail module URL is known
- Role-based access control is properly configured
- Audit log data exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to navigate to the audit trail module by clicking on audit trail link or entering the URL directly | Access is denied and system displays an appropriate error message such as 'Access Denied: You do not have permission to view audit trails. This feature is restricted to authorized managers only.' |
| 2 | Verify the page content to ensure no audit log data is visible | No audit trail data, filters, or sensitive information is displayed. User sees only the access denied message |
| 3 | Check if user is redirected to an appropriate page | User is automatically redirected to their authorized dashboard or remains on an error page without access to audit functionality |
| 4 | Attempt to access the audit logs API endpoint directly using GET /api/auditlogs | API returns 403 Forbidden status code with JSON error response indicating insufficient permissions and no audit data in the response body |
| 5 | Verify that the unauthorized access attempt is logged | Security audit log records the unauthorized access attempt with user details, timestamp, and attempted resource |

**Postconditions:**
- No audit trail data is exposed to unauthorized user
- Unauthorized access attempt is logged in security audit
- User remains restricted to authorized areas only
- System security and data integrity remain intact
- No session or authentication issues occur

---

