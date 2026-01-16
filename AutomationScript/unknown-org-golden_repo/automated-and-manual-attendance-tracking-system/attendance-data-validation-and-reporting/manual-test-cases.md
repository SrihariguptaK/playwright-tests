# Manual Test Cases

## Story: As System Auditor, I want to review audit trails of attendance data changes to ensure compliance
**Story ID:** story-8

### Test Case: Review audit logs for attendance data changes
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- System auditor account exists with valid credentials
- Audit log database contains attendance data change records
- Audit portal is accessible and operational
- Test data includes attendance changes by multiple users across different dates
- Export functionality is configured and enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit portal login page | Audit portal login page is displayed with username and password fields |
| 2 | Enter valid system auditor credentials and click Login button | Access granted to audit log interface, auditor dashboard is displayed with search and filter options |
| 3 | Verify audit log interface displays available search criteria including user, date, action type, and timestamp | Search interface shows all filter options with appropriate input fields and date pickers |
| 4 | Enter specific user name in the user filter field | User filter accepts the input and displays matching suggestions if available |
| 5 | Select a date range using the date filter (e.g., last 7 days) | Date range is selected and displayed in the filter criteria |
| 6 | Click Search or Apply Filters button | Relevant audit records are displayed in a table format showing user identity, timestamp, action type (create/update/delete), and change details |
| 7 | Review the displayed audit records for completeness including all required fields | Each audit record contains user name, exact timestamp, action performed, before/after values, and affected attendance record ID |
| 8 | Click on Export button and select export format (CSV or PDF) | Export format selection dialog appears with available format options |
| 9 | Select CSV format and confirm export | Audit logs are exported successfully, download begins, and file contains all filtered records with proper formatting |
| 10 | Open the exported file and verify data integrity | Exported file opens correctly and contains all audit log data matching the displayed records |

**Postconditions:**
- Auditor remains logged into the audit portal
- Audit logs remain unchanged and intact
- Exported file is saved to local system
- Audit trail of the export action is recorded in the system

---

### Test Case: Prevent unauthorized access to audit logs
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Non-auditor user account exists with valid credentials (e.g., regular employee or attendance manager)
- Audit log system is operational
- Role-based access control is configured and enforced
- Audit portal URL is known and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit portal login page | Audit portal login page is displayed |
| 2 | Enter valid non-auditor user credentials (e.g., regular employee username and password) | Credentials are accepted for authentication |
| 3 | Click Login button | Access to audit logs is denied with appropriate error message such as 'Access Denied: Insufficient Permissions' or 'You do not have authorization to view audit logs' |
| 4 | Verify user is not redirected to audit log interface | User remains on login page or is redirected to an error page, audit log interface is not accessible |
| 5 | Attempt to access audit log URL directly by typing the endpoint URL in browser | Access is blocked with 403 Forbidden error or redirect to unauthorized access page |
| 6 | Verify no audit log data is visible or accessible through any interface | No audit records, search functionality, or export options are displayed to the unauthorized user |

**Postconditions:**
- Non-auditor user remains unauthorized to access audit logs
- Audit log security remains intact
- Failed access attempt is logged in security audit trail
- No audit data has been exposed or compromised

---

## Story: As Attendance Manager, I want to view real-time attendance status to monitor workforce presence
**Story ID:** story-10

### Test Case: View real-time attendance status with filtering
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Attendance manager account exists with valid credentials and appropriate role permissions
- Real-time attendance dashboard is deployed and operational
- Real-time attendance database contains current employee attendance data
- Multiple employees have checked in using biometric and manual methods
- Employees belong to different departments and shifts
- Auto-refresh functionality is configured to update every minute

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance management system login page | Login page is displayed with username and password fields |
| 2 | Enter valid attendance manager credentials and click Login button | Access granted to real-time dashboard, dashboard loads displaying current attendance status for all employees |
| 3 | Verify dashboard displays employee list with attendance status including employee name, check-in time, status (present/absent/late), and attendance source (biometric/manual) | Dashboard shows comprehensive attendance information in a clear table or card layout with all required fields visible |
| 4 | Observe the visual indicators for absent and late employees | Absent employees are highlighted with distinct color (e.g., red) and late employees are highlighted with another color (e.g., yellow or orange) |
| 5 | Verify biometric and manual attendance entries are differentiated with icons or labels | Each attendance entry clearly shows the source with appropriate icon or text label (e.g., fingerprint icon for biometric, manual entry icon for manual) |
| 6 | Locate and click on the department filter dropdown | Department filter dropdown expands showing list of all available departments |
| 7 | Select a specific department from the dropdown (e.g., 'IT Department') | Dashboard updates immediately to show only employees from the selected department, employee count reflects filtered results |
| 8 | Verify filtered results display only employees from the selected department | All displayed employees belong to the selected department, other department employees are hidden |
| 9 | Clear department filter and apply shift filter by selecting a specific shift (e.g., 'Morning Shift') | Dashboard updates to show only employees assigned to the selected shift |
| 10 | Note the current timestamp displayed on the dashboard | Dashboard shows last refresh timestamp clearly visible |
| 11 | Wait for 60 seconds without any user interaction | Dashboard automatically refreshes after 1 minute, last refresh timestamp updates to current time |
| 12 | Verify attendance status data has been updated with any new check-ins or status changes | Attendance status reflects the most current data, any new check-ins appear in the list, status indicators update if employees arrived late |
| 13 | Observe the refresh indicator or animation during auto-refresh | Visual feedback is provided during refresh (e.g., loading spinner or refresh icon animation) |

**Postconditions:**
- Manager remains logged into the attendance dashboard
- Dashboard continues to auto-refresh every minute
- Applied filters remain active unless cleared by user
- Real-time attendance data remains accurate and up-to-date
- Manager's dashboard access is logged in the system

---

### Test Case: Verify access restriction to real-time dashboard
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Unauthorized user account exists with valid credentials but without attendance manager role (e.g., regular employee or contractor)
- Real-time attendance dashboard is operational
- Role-based access control is properly configured
- Dashboard URL endpoint is known

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance management system login page | Login page is displayed |
| 2 | Enter valid credentials for an unauthorized user (non-manager role) | Credentials are accepted for authentication |
| 3 | Click Login button | Access to real-time attendance dashboard is denied, error message is displayed such as 'Access Denied: You do not have permission to view the attendance dashboard' or 'Unauthorized Access' |
| 4 | Verify user is not redirected to the real-time dashboard interface | User is either kept on login page with error message or redirected to their appropriate home page without dashboard access |
| 5 | Attempt to access the dashboard directly by entering the dashboard URL in the browser address bar | Access is blocked with HTTP 403 Forbidden error or redirect to unauthorized access page |
| 6 | Verify no attendance data, filters, or dashboard features are visible | No employee attendance information, department filters, shift filters, or real-time status data is displayed to the unauthorized user |
| 7 | Check if any API endpoints can be accessed directly through browser developer tools or API testing tools | API endpoint GET /api/attendance/real-time returns 403 Forbidden or 401 Unauthorized error when accessed without proper authorization |

**Postconditions:**
- Unauthorized user remains blocked from accessing the dashboard
- No attendance data has been exposed to unauthorized user
- Failed access attempt is logged in security audit trail
- Dashboard security and access controls remain intact
- User can only access features appropriate to their assigned role

---

