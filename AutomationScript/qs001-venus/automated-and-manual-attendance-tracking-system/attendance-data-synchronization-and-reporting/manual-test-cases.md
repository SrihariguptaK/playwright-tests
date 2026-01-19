# Manual Test Cases

## Story: As Attendance Manager, I want to generate consolidated attendance reports combining biometric and manual data to achieve accurate workforce insights
**Story ID:** story-7

### Test Case: Validate generation of consolidated attendance reports
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Attendance Manager with valid credentials
- Attendance database contains both biometric and manual attendance data
- Reporting module is accessible and functional
- User has necessary permissions to access reporting features

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to reporting module from the main dashboard | Reporting interface is displayed with available report types, filter options, and generation controls |
| 2 | Select 'Consolidated Attendance Report' as report type and apply desired filters (date range, department, etc.), then click 'Generate Report' button | Consolidated attendance report is displayed showing combined biometric and manual attendance data with accurate employee records, timestamps, and attendance status |
| 3 | Click 'Export' button and select 'PDF' format from the export options | PDF file downloads successfully with correct data matching the displayed report, including all columns, formatting, and consolidated attendance information |

**Postconditions:**
- Consolidated report is generated and viewable
- PDF export file is saved to local downloads folder
- Report generation action is logged in system audit trail

---

### Test Case: Verify report filtering and export options
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Attendance Manager
- Reporting module is accessible
- Attendance database contains multiple employees with varied attendance records
- Test data includes specific employee records for the selected date range

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to reporting module and select specific employee from employee filter dropdown and set date range using date picker controls | Filters are applied successfully and report displays only attendance data for the selected employee within the specified date range, excluding all other employee records |
| 2 | Click 'Export' button and select 'Excel' format from the export options | Excel file downloads successfully with correct filtered data matching the displayed report, maintaining all data integrity, formulas, and formatting in spreadsheet format |

**Postconditions:**
- Filtered report displays accurate subset of attendance data
- Excel export file is saved to local downloads folder
- Export action is logged in system

---

### Test Case: Ensure access control for reporting features
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- System has role-based access control configured
- Test user accounts exist: one unauthorized user and one attendance manager
- Reporting module requires specific permissions to access

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using credentials of an unauthorized user (without attendance manager role) | Access to reporting module is denied with appropriate error message or the reporting module option is not visible in the navigation menu |
| 2 | Logout from unauthorized user account and login using attendance manager credentials with proper permissions | Access to reporting module is granted and the reporting interface is displayed with all available features and options visible |

**Postconditions:**
- Unauthorized access attempt is logged in security audit trail
- Attendance manager has full access to reporting features
- Role-based access control is validated and functioning correctly

---

## Story: As Attendance Manager, I want to resolve conflicts between biometric and manual attendance data to ensure data consistency
**Story ID:** story-8

### Test Case: Validate automatic conflict detection
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Attendance Manager
- Conflict detection service is running and scheduled hourly
- Attendance database is accessible and contains test data
- Conflict resolution dashboard is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create overlapping biometric and manual attendance entries for the same employee at the same time period (e.g., biometric check-in at 9:00 AM and manual entry at 9:05 AM for same date) | System automatically detects the conflict during the next scheduled conflict detection run and lists it in the conflict resolution dashboard with conflict type, employee details, and timestamp information |
| 2 | Navigate to conflict resolution interface and locate the newly detected conflict in the conflicts list | Conflict details are displayed correctly showing both conflicting entries (biometric and manual), employee information, date/time of entries, conflict type, and available resolution actions |

**Postconditions:**
- Conflict is detected and logged in the system
- Conflict appears in manager's dashboard awaiting resolution
- Notification is sent to attendance manager about detected conflict

---

### Test Case: Verify conflict resolution actions
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Attendance Manager
- Multiple conflicts exist in the conflict resolution dashboard
- Test conflicts include various scenarios (overlapping entries, duplicates)
- Attendance records are in editable state

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select a conflicting entry from the conflict list and click 'Accept' button to accept the selected entry as the correct record | Attendance record is updated with the accepted entry, conflict is removed from the dashboard, and the conflicting alternative entry is discarded or marked as resolved |
| 2 | Select another conflicting entry and click 'Reject' button to reject the selected entry | Entry is marked as rejected with appropriate status flag, excluded from all attendance reports and calculations, and conflict is removed from active conflicts list |
| 3 | Select a third conflicting entry, click 'Modify' button, make changes to the attendance time or status, and save the modifications | Changes are saved successfully to the attendance record, modified entry replaces the original conflicting entries, conflict is resolved and removed from dashboard, and updated record appears in attendance reports |

**Postconditions:**
- All three conflicts are resolved and removed from pending list
- Attendance records are updated according to resolution actions
- Reports reflect the resolved attendance data
- All resolution actions are logged in audit trail

---

### Test Case: Ensure audit logging of conflict resolutions
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Attendance Manager
- Audit logging system is enabled and functional
- At least one conflict exists in the system
- User has permissions to view audit logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select a conflict from the conflict resolution dashboard, choose a resolution action (accept, reject, or modify), complete the resolution process, then navigate to audit logs section | Resolution action is logged in audit trail with complete details including user ID/name who performed the action, timestamp of resolution, conflict ID, action taken (accept/reject/modify), original conflicting values, final resolved value, and employee affected |

**Postconditions:**
- Audit log entry is permanently stored in the system
- Log entry is retrievable and viewable by authorized users
- Audit trail maintains data integrity and compliance requirements

---

## Story: As Attendance Manager, I want to audit attendance data synchronization processes to ensure data integrity
**Story ID:** story-12

### Test Case: Validate logging of synchronization events
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Attendance Manager role
- Biometric attendance system is connected and operational
- Manual attendance data is available for synchronization
- Synchronization logs database is accessible
- User has permissions to access synchronization audit interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance data synchronization module | Synchronization module interface is displayed with available data sources |
| 2 | Select biometric and manual attendance data sources for synchronization | Data sources are selected and synchronization options are displayed |
| 3 | Initiate attendance data synchronization by clicking 'Synchronize' button | Synchronization process starts and progress indicator is displayed |
| 4 | Wait for synchronization process to complete | Synchronization completes successfully with status message displayed |
| 5 | Verify that synchronization event is logged with status and timestamp in the system | Synchronization event is recorded in logs with 'Success' status, timestamp, data source details, and number of records synchronized |
| 6 | Navigate to synchronization audit interface from the main menu | Synchronization audit interface loads displaying list of synchronization events |
| 7 | Locate the most recent synchronization event in the audit logs | The synchronization event performed in previous steps appears in audit logs with correct timestamp, status, and event details |
| 8 | Verify the event appears within 1 minute of synchronization completion | Event timestamp confirms log entry was created within 1 minute of synchronization event occurrence |

**Postconditions:**
- Synchronization event is permanently logged in the database
- Audit trail is available for future review
- Attendance data is synchronized between biometric and manual systems
- System remains in operational state

---

### Test Case: Verify filtering and export of synchronization audit logs
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Attendance Manager role
- Multiple synchronization events exist in the system with different dates and statuses
- At least 5 successful synchronization events are logged
- At least 2 failed synchronization events are logged
- User has permissions to view and export audit logs
- Synchronization audit interface is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to synchronization audit interface | Audit interface loads displaying all synchronization events in chronological order |
| 2 | Verify that filter options are available (date range, status, data source) | Filter panel is displayed with date range picker, status dropdown (Success/Failed/In Progress), and data source options |
| 3 | Select a specific date range using the date filter (e.g., last 7 days) | Date range is selected and applied to the filter |
| 4 | Select 'Success' status from the status filter dropdown | Status filter is applied showing only successful synchronization events |
| 5 | Click 'Apply Filters' button | Audit logs are filtered and display only successful synchronization events within the selected date range |
| 6 | Verify filtered results show correct data matching filter criteria | All displayed events have 'Success' status and timestamps within the selected date range |
| 7 | Change status filter to 'Failed' and apply | Audit logs update to display only failed synchronization events within the date range |
| 8 | Click 'Export' button and select CSV format | Export dialog appears with CSV format selected and file name suggestion displayed |
| 9 | Confirm export by clicking 'Download' button | CSV file downloads successfully to local system within 5 seconds |
| 10 | Open the downloaded CSV file | CSV file opens correctly with columns: Event ID, Timestamp, Status, Data Source, Records Synchronized, Duration, User |
| 11 | Verify CSV data matches the filtered audit logs displayed on screen | All rows in CSV match the filtered results with correct data in all columns |

**Postconditions:**
- Filtered audit logs remain displayed in the interface
- CSV file is saved in downloads folder
- Audit logs database remains unchanged
- Filter settings can be cleared or modified for subsequent queries

---

### Test Case: Ensure alert generation for synchronization failures
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Attendance Manager role
- Synchronization system is operational
- Alert notification system is configured and enabled
- User has permissions to receive synchronization alerts
- Test environment allows simulation of synchronization failures
- Email/notification channels are configured for alerts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to synchronization audit interface | Audit interface is displayed with current synchronization status |
| 2 | Access synchronization test/simulation module or disconnect biometric data source to simulate failure | Test mode is activated or data source connection is interrupted |
| 3 | Initiate attendance data synchronization process | Synchronization process starts and attempts to connect to data sources |
| 4 | Wait for synchronization process to fail due to simulated error | Synchronization process fails with error message displayed on screen |
| 5 | Verify that system generates an alert notification for the synchronization failure | Alert notification appears in the system notification panel with failure details including timestamp, error type, and affected data source |
| 6 | Check email or configured notification channel for alert message | Alert email/notification is received with subject 'Synchronization Failure Alert' containing failure details and timestamp |
| 7 | Navigate to synchronization audit logs | Audit logs interface displays the list of synchronization events |
| 8 | Locate the failed synchronization event in the audit logs | Failed synchronization event appears in logs with 'Failed' status, timestamp, error message, and failure reason |
| 9 | Verify the failure event was logged within 1 minute of occurrence | Event timestamp confirms log entry was created within 1 minute of synchronization failure |
| 10 | Click on the failed event to view detailed error information | Detailed view opens showing complete error stack trace, affected records count, and recommended resolution steps |
| 11 | Verify alert contains actionable information for troubleshooting | Alert includes error code, description, affected system components, and suggested corrective actions |

**Postconditions:**
- Synchronization failure is logged in audit database
- Alert notification is recorded in notification history
- System remains operational for other functions
- Failed synchronization can be retried after resolving the issue
- Alert recipients are notified of the failure

---

