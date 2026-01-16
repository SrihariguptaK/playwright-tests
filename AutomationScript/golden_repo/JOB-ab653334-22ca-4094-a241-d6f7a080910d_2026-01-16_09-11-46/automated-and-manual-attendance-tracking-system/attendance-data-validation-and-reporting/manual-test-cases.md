# Manual Test Cases

## Story: As Attendance Auditor, I want to review attendance data validation reports to achieve data accuracy
**Story ID:** story-25

### Test Case: Validate generation of attendance validation reports
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has valid Attendance Auditor credentials
- User is logged into the system
- Attendance data exists in the system for the selected date range
- Validation rules are configured in the system
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the validation reports module from the main dashboard | Report generation interface is displayed with options for date range selection, employee filter, department filter, and generate button |
| 2 | Select a date range (e.g., last 30 days) using the date picker | Date range is selected and displayed correctly in the date fields |
| 3 | Select specific department from the department dropdown filter | Department filter is applied and selected department is displayed in the dropdown |
| 4 | Select specific employee from the employee filter (optional) | Employee filter is applied without errors and selected employee is displayed |
| 5 | Click the 'Generate Report' button | System processes the request and displays a loading indicator |
| 6 | Wait for report generation to complete | Report is generated within 10 seconds displaying a comprehensive list of attendance anomalies including missing punches, duplicate entries, and validation errors with employee names, dates, and anomaly types |
| 7 | Review the generated report for anomalies and recommendations | Report displays anomalies in a structured table format with columns for date, employee, anomaly type, description, and recommended actions |

**Postconditions:**
- Validation report is successfully generated and displayed on screen
- Report generation time is logged in system metrics
- User remains on the validation reports page
- Report data is cached for export functionality

---

### Test Case: Test report export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User has valid Attendance Auditor credentials
- User is logged into the system
- User has already generated a validation report
- Report is displayed on screen with anomaly data
- Browser allows file downloads
- User has write permissions to download folder

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to validation reports module and generate a validation report with date range and filters | Report is displayed on screen showing attendance anomalies with complete data including employee details, dates, anomaly types, and recommendations |
| 2 | Locate and click the 'Export as PDF' button on the report interface | System initiates PDF generation and displays a download progress indicator |
| 3 | Wait for PDF download to complete | PDF file downloads successfully to the default download location with filename format 'Attendance_Validation_Report_YYYY-MM-DD.pdf' |
| 4 | Open the downloaded PDF file | PDF opens successfully and contains all report data including header with report title, date range, filters applied, anomaly details in tabular format, and recommendations section |
| 5 | Return to the validation report on screen and click the 'Export as CSV' button | System initiates CSV generation and displays a download progress indicator |
| 6 | Wait for CSV download to complete | CSV file downloads successfully to the default download location with filename format 'Attendance_Validation_Report_YYYY-MM-DD.csv' |
| 7 | Open the downloaded CSV file in a spreadsheet application | CSV opens successfully with properly formatted columns including Date, Employee ID, Employee Name, Department, Anomaly Type, Description, and Recommendations. All data from the report is present and readable |

**Postconditions:**
- Both PDF and CSV files are successfully downloaded
- Export activities are logged in the audit trail
- User remains on the validation reports page
- Downloaded files contain accurate and complete report data

---

### Test Case: Ensure access control for validation reports
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- System has role-based access control configured
- Test user accounts exist: one unauthorized user (e.g., regular employee) and one authorized auditor
- Validation reports module is active and accessible
- Both user credentials are valid and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the application login page | Login page is displayed with username and password fields |
| 2 | Enter credentials for an unauthorized user (e.g., regular employee without auditor role) | Credentials are accepted and user is authenticated |
| 3 | Navigate to the main dashboard after successful login | User dashboard is displayed showing only modules accessible to the user's role |
| 4 | Attempt to access the validation reports module by clicking on it or navigating directly via URL | Access to validation reports is denied with an error message 'Access Denied: You do not have permission to view this page' or the module is not visible in the navigation menu |
| 5 | Verify that no validation report data or interface is displayed | User is either redirected to the dashboard or shown an access denied page. No sensitive validation report data is exposed |
| 6 | Log out from the unauthorized user account | User is successfully logged out and redirected to the login page |
| 7 | Enter credentials for an authorized auditor user | Credentials are accepted and auditor is authenticated successfully |
| 8 | Navigate to the main dashboard after successful login | Auditor dashboard is displayed with validation reports module visible in the navigation menu |
| 9 | Click on the validation reports module | Access to validation reports is granted and the report generation interface is displayed with all functionality including filters, generate button, and export options |
| 10 | Verify full access to all validation report features | Auditor can view, generate, filter, and export validation reports without any access restrictions |

**Postconditions:**
- Unauthorized access attempts are logged in security audit trail
- Authorized auditor has full access to validation reports module
- No data breach or unauthorized data exposure occurred
- System maintains proper role-based access control

---

## Story: As Attendance Manager, I want to receive alerts for attendance anomalies to achieve proactive issue resolution
**Story ID:** story-27

### Test Case: Validate anomaly detection and alert generation
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has valid Attendance Manager credentials
- Anomaly detection business rules are configured in the system
- Email notification service is configured and operational
- Test attendance data with known anomalies is prepared (missing punches, duplicate entries)
- Manager email address is registered in the system
- Daily anomaly detection job is scheduled and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Inject test attendance data containing known anomalies into the system (e.g., employee with missing clock-out punch, duplicate clock-in entries, attendance on holiday) | Test data is successfully inserted into the attendance records database without errors |
| 2 | Trigger the anomaly detection process manually or wait for the scheduled daily run | Anomaly detection process executes successfully and completes within the expected timeframe |
| 3 | Verify that the system detects all injected anomalies | System identifies and flags all known anomalies including missing punches, duplicate entries, and other rule violations. Alerts are generated for each detected anomaly |
| 4 | Login to the system as an Attendance Manager | Manager successfully logs in and is directed to the dashboard |
| 5 | Navigate to the alert dashboard or notifications section | Alert dashboard is displayed showing a list of all generated alerts |
| 6 | Verify that alerts appear in the manager dashboard with complete details | Alerts are visible in the dashboard with correct details including employee name, employee ID, date of anomaly, anomaly type (e.g., 'Missing Clock-Out', 'Duplicate Entry'), description, severity level, and timestamp of detection |
| 7 | Check the manager's email inbox for alert notifications | Email notifications are received for each alert containing accurate information including subject line with anomaly type, employee details, date, anomaly description, link to the alert dashboard, and recommended actions |
| 8 | Click on an alert in the dashboard to view detailed information | Alert detail page opens showing comprehensive information including full employee details, attendance records related to the anomaly, timeline of events, and actionable recommendations for resolution |

**Postconditions:**
- All anomalies are detected and alerts are generated
- Alerts are visible in the manager dashboard
- Email notifications are successfully delivered
- Alert generation is logged in the system
- Alerts remain in 'New' or 'Unacknowledged' status

---

### Test Case: Test alert acknowledgment and resolution
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has valid Attendance Manager credentials
- User is logged into the system
- At least one unacknowledged alert exists in the system
- Alert dashboard is accessible
- Audit logging is enabled and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alert dashboard from the main menu | Alert dashboard is displayed showing a list of alerts with their current status (New, Acknowledged, Resolved) |
| 2 | Select an alert with 'New' status from the list | Alert is selected and highlighted. Alert details are displayed including employee information, anomaly type, date, and description |
| 3 | Click the 'Acknowledge' button on the alert | System displays a confirmation dialog asking to confirm acknowledgment |
| 4 | Confirm the acknowledgment action | Alert status changes from 'New' to 'Acknowledged'. Status update timestamp is recorded. Acknowledgment confirmation message is displayed. Alert remains in the dashboard with updated status |
| 5 | Review the alert details and take necessary corrective action (e.g., correct attendance record, contact employee) | Manager can view all relevant information needed to resolve the issue |
| 6 | After corrective action is completed, click the 'Mark as Resolved' button on the alert | System displays a resolution dialog with optional fields for resolution notes or comments |
| 7 | Enter resolution notes describing the corrective action taken and click 'Confirm' | Alert status changes from 'Acknowledged' to 'Resolved'. Resolution timestamp is recorded. Resolution notes are saved. Success message is displayed confirming resolution |
| 8 | Navigate to the audit log section or reports module | Audit log interface is displayed with search and filter options |
| 9 | Search for audit log entries related to the resolved alert using alert ID or employee name | Audit log displays all activities related to the alert including: alert generation timestamp and details, acknowledgment timestamp and user who acknowledged, resolution timestamp and user who resolved, resolution notes, and complete audit trail of all status changes |
| 10 | Verify the completeness and accuracy of audit log entries | Audit log contains complete and accurate information for all alert activities with proper timestamps, user information, and action details |

**Postconditions:**
- Alert status is updated to 'Resolved'
- All alert activities are logged in the audit trail
- Resolution notes are saved and associated with the alert
- Alert is moved to resolved alerts section or archived
- Audit log is complete and accurate

---

### Test Case: Ensure access control for alert management
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System has role-based access control configured for alert management
- Test user accounts exist: one unauthorized user (e.g., regular employee) and one authorized attendance manager
- Alert dashboard and notification system are active
- At least one active alert exists in the system
- Both user credentials are valid and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the application login page | Login page is displayed with username and password fields |
| 2 | Enter credentials for an unauthorized user (e.g., regular employee without attendance manager role) | Credentials are accepted and user is authenticated successfully |
| 3 | Navigate to the main dashboard after successful login | User dashboard is displayed showing only modules and features accessible to the user's role |
| 4 | Attempt to access the alert dashboard by clicking on alerts menu or navigating directly via URL | Access to alert dashboard is denied. System displays an error message such as 'Access Denied: You do not have permission to view alerts' or the alerts menu item is not visible in the navigation |
| 5 | Attempt to access alert notifications or email alerts | Unauthorized user does not receive any alert notifications via email or system notifications. No alert data is exposed |
| 6 | Verify that no alert-related functionality is accessible | User cannot view, acknowledge, or resolve any alerts. All alert management features are restricted |
| 7 | Log out from the unauthorized user account | User is successfully logged out and redirected to the login page |
| 8 | Enter credentials for an authorized attendance manager user | Credentials are accepted and attendance manager is authenticated successfully |
| 9 | Navigate to the main dashboard after successful login | Attendance manager dashboard is displayed with alert dashboard and notifications menu visible and accessible |
| 10 | Click on the alert dashboard menu item | Access to alert dashboard is granted. Dashboard displays all active alerts with full details including employee information, anomaly types, dates, and status |
| 11 | Verify that email notifications are received for new alerts | Attendance manager receives email notifications for all new alerts with complete information and links to the dashboard |
| 12 | Verify full access to all alert management features | Attendance manager can view alert details, acknowledge alerts, mark alerts as resolved, add resolution notes, and access all alert-related functionality without any restrictions |

**Postconditions:**
- Unauthorized access attempts are logged in security audit trail
- Authorized attendance manager has full access to alert dashboard and notifications
- No sensitive alert data is exposed to unauthorized users
- System maintains proper role-based access control for alert management
- Security policies are enforced correctly

---

## Story: As Attendance Manager, I want to generate attendance summary reports to achieve workforce insights
**Story ID:** story-29

### Test Case: Validate attendance summary report generation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an authorized Attendance Manager
- Attendance database contains valid attendance records for multiple employees and departments
- System is connected to the attendance database
- Browser supports PDF and Excel file downloads
- User has appropriate role-based permissions to access attendance reports module

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance reports module from the main dashboard | Report interface is displayed with options to select parameters including employee, department, date range, and report type |
| 2 | Select a specific department from the department dropdown | Department is selected and displayed in the parameter selection area |
| 3 | Select a date range using the date picker (e.g., last 30 days) | Date range is selected and displayed correctly in the parameter fields |
| 4 | Click the 'Generate Report' button | System processes the request and generates the report within 10 seconds. Report displays accurate data including total hours, absences, and late arrivals for the selected parameters |
| 5 | Review the generated report data and verify metrics accuracy | Report shows correct attendance metrics with accurate calculations for total hours worked, number of absences, and late arrival counts |
| 6 | Review the graphical visualizations in the report | Graphical visualizations (charts/graphs) are displayed correctly showing attendance trends, patterns, and distributions |
| 7 | Click the 'Export as PDF' button | PDF file downloads successfully to the default download location with correct filename and contains all report data and visualizations |
| 8 | Open the downloaded PDF file | PDF opens correctly with properly formatted content, readable text, and clear visualizations matching the on-screen report |
| 9 | Return to the report interface and click the 'Export as Excel' button | Excel file downloads successfully to the default download location with correct filename |
| 10 | Open the downloaded Excel file | Excel file opens correctly with all report data in structured format, proper column headers, and accurate data values that match the generated report |

**Postconditions:**
- Attendance summary report is successfully generated and displayed
- PDF and Excel files are downloaded and saved to local system
- Report data remains accessible in the system for future reference
- No errors or warnings are displayed in the system
- User session remains active

---

### Test Case: Ensure access control for attendance reports
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- System has role-based access control configured
- Test user accounts exist: one unauthorized user (non-manager role) and one authorized manager
- Attendance reports module is accessible via direct URL or navigation menu
- Security policies are properly configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using credentials of an unauthorized user (e.g., regular employee without manager privileges) | User successfully logs into the system and is redirected to their default dashboard |
| 2 | Attempt to navigate to the attendance reports module from the main menu | Attendance reports module option is not visible in the navigation menu for unauthorized user |
| 3 | Attempt to access the attendance reports module by entering the direct URL (e.g., /attendance/reports) | Access is denied with an appropriate error message such as 'Access Denied: You do not have permission to view this page' or user is redirected to an unauthorized access page |
| 4 | Verify that no attendance report data or interface elements are displayed | No sensitive attendance data is exposed and user cannot view or generate any reports |
| 5 | Logout from the unauthorized user account | User is successfully logged out and redirected to the login page |
| 6 | Login to the system using credentials of an authorized manager with attendance report access permissions | Manager successfully logs into the system and is redirected to their manager dashboard |
| 7 | Navigate to the attendance reports module from the main menu | Attendance reports module option is visible in the navigation menu and is clickable |
| 8 | Click on the attendance reports module link | Access is granted and the attendance reports interface is displayed with all report generation options and parameters available |
| 9 | Verify that all report functionalities are accessible (parameter selection, report generation, export options) | All report features are fully functional and accessible to the authorized manager |

**Postconditions:**
- Unauthorized user remains blocked from accessing attendance reports
- Authorized manager has full access to attendance reports module
- Security audit logs record both access attempts (denied and granted)
- No security vulnerabilities are exposed
- System maintains proper role-based access control integrity

---

