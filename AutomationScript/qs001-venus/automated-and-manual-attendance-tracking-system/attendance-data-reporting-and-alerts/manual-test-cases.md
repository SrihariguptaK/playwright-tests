# Manual Test Cases

## Story: As Attendance Manager, I want to generate attendance reports combining biometric and manual data to achieve comprehensive attendance insights
**Story ID:** story-20

### Test Case: Validate generation of attendance report with combined data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager has valid credentials with Attendance Manager role
- Manager is logged into the system
- Biometric attendance data exists in the database for the selected period
- Manual attendance data exists in the database for the selected period
- Reporting module is accessible and functional
- At least one attendance anomaly exists in the data (absence or late arrival)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module from the main dashboard | Reporting module page loads successfully with report type options and filter controls visible |
| 2 | Select report type as 'Daily Attendance Report' from the dropdown | Report type is selected and additional filter options become available |
| 3 | Apply filters: Select specific department, date range (last 7 days), and employee group | Filters are applied successfully, filter tags are displayed showing selected criteria |
| 4 | Click on 'Generate Report' button | System processes the request, loading indicator appears, and report generation completes within 5 seconds |
| 5 | Review the generated report on screen | Report displays with combined biometric and manual attendance data including employee names, check-in/check-out times, attendance status, and data source indicators |
| 6 | Verify the report summary section | Summary shows total employees, present count, absent count, late arrivals, and early departures with accurate calculations |
| 7 | Scroll through the detailed attendance records section | All attendance records are displayed with clear distinction between biometric entries (marked with biometric icon) and manual entries (marked with manual icon) |
| 8 | Locate and review highlighted anomalies in the report | Attendance anomalies such as absences and late arrivals are highlighted in red or with warning icons, making them easily identifiable |
| 9 | Verify data accuracy by cross-checking sample records with source data | Report data matches the source biometric and manual attendance records with 100% accuracy |

**Postconditions:**
- Report remains displayed on screen for further actions
- Report data is temporarily cached for export operations
- System logs the report generation activity with timestamp and user details
- Manager remains logged in and can generate additional reports

---

### Test Case: Verify report export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager has valid credentials with Attendance Manager role
- Manager is logged into the system
- Attendance data exists in the database for the selected period
- Reporting module is accessible
- Browser has download permissions enabled
- Sufficient storage space available on local machine

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module and select 'Weekly Attendance Report' type | Report type selection is successful and filter options are displayed |
| 2 | Apply filters: Select date range for current week and specific department | Filters are applied and displayed correctly |
| 3 | Click 'Generate Report' button | Report is generated within 5 seconds and displayed on screen with all attendance data visible |
| 4 | Verify the report is fully loaded and displays complete data | Report shows summary statistics, detailed records, and highlighted anomalies without any loading errors |
| 5 | Click on 'Export' button and select 'CSV' format from the dropdown | Export dialog appears with CSV format selected, file name suggestion is displayed |
| 6 | Confirm the CSV export by clicking 'Download' button | CSV file download initiates immediately, download progress is shown, and file is saved to default download location |
| 7 | Open the downloaded CSV file using spreadsheet application | CSV file opens successfully with proper column headers, all attendance data is present, data is properly formatted in columns, and special characters are correctly encoded |
| 8 | Verify CSV data accuracy by comparing with on-screen report | CSV file contains identical data to the displayed report including all records, summary statistics, and anomaly indicators |
| 9 | Return to the report screen and click 'Export' button, then select 'PDF' format | Export dialog appears with PDF format selected and file name suggestion is displayed |
| 10 | Confirm the PDF export by clicking 'Download' button | PDF file download initiates immediately, download completes successfully, and file is saved to default download location |
| 11 | Open the downloaded PDF file using PDF reader application | PDF file opens successfully with professional formatting, company header/logo, report title, filter criteria, summary section, and detailed attendance table with proper pagination |
| 12 | Verify PDF formatting and data completeness | PDF displays all data with proper alignment, highlighted anomalies are visible in color or bold, page numbers are present, and data matches the on-screen report exactly |

**Postconditions:**
- CSV and PDF files are successfully downloaded to local machine
- Downloaded files contain accurate and complete attendance data
- System logs the export activities with timestamps and file formats
- Original report remains displayed on screen
- Manager can perform additional export operations if needed

---

### Test Case: Ensure access control for attendance reports
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- System has role-based access control configured
- Test user account exists without Attendance Manager role (e.g., regular employee role)
- Valid Attendance Manager account exists in the system
- Attendance data exists in the database
- Reporting module is functional and accessible to authorized users

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using unauthorized user credentials (regular employee account) | User successfully logs into the system and is redirected to their role-appropriate dashboard |
| 2 | Attempt to navigate to the reporting module by entering the URL directly or clicking on reports menu (if visible) | System denies access and displays 'Access Denied' or '403 Forbidden' message stating 'You do not have permission to access attendance reports' |
| 3 | Verify that reporting module link is not visible in the navigation menu for unauthorized user | Reporting module option is hidden or grayed out in the navigation menu for users without appropriate permissions |
| 4 | Attempt to access report generation API endpoint directly using browser developer tools or API client | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 5 | Log out from the unauthorized user account | User is successfully logged out and redirected to login page |
| 6 | Log into the system using authorized Attendance Manager credentials | Manager successfully logs in and is redirected to the dashboard with reporting module visible in navigation |
| 7 | Navigate to the reporting module by clicking on the reports menu option | Reporting module page loads successfully with all report types, filters, and controls accessible |
| 8 | Select 'Monthly Attendance Report' type and apply filters for current month and all departments | Report type and filters are applied successfully without any access restrictions |
| 9 | Click 'Generate Report' button | Report is generated successfully within 5 seconds and displays complete attendance data with summary and details |
| 10 | Click 'Export' button and select CSV format | Export functionality is accessible and CSV file downloads successfully with correct data |
| 11 | Return to report screen and export the same report as PDF | PDF export completes successfully with proper formatting and complete data |
| 12 | Verify all report operations complete without any errors or access restrictions | All operations (generation, viewing, exporting) succeed without errors, and system logs show successful activities |

**Postconditions:**
- Unauthorized user access attempt is logged in security audit trail
- Authorized manager successfully accessed and used all reporting features
- Report generation and export activities are logged with manager's user ID
- System maintains security integrity with proper access control enforcement
- No unauthorized data access occurred during the test

---

## Story: As Attendance Manager, I want to receive alerts for attendance anomalies to achieve timely intervention
**Story ID:** story-21

### Test Case: Validate detection and alerting of attendance anomalies
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager has valid credentials with Attendance Manager role
- Manager is logged into the system
- Anomaly detection rules are configured (absence, late arrival thresholds)
- Manager's email address is configured in the system
- System notification service is active and functional
- Email service is configured and operational
- Real-time attendance monitoring is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate an attendance anomaly by creating an absence record for an employee who was scheduled to work | Absence record is created in the attendance database with current timestamp |
| 2 | Wait for the system to process the attendance data and detect the anomaly | System's real-time monitoring service detects the absence anomaly within 1 minute based on predefined rules |
| 3 | Verify that an alert notification is generated in the system | Alert is created in the alerts database with details including employee name, anomaly type (absence), timestamp, and status (pending acknowledgment) |
| 4 | Check the manager's email inbox for alert notification | Email alert is received within 1 minute containing subject line 'Attendance Anomaly Alert', employee details, anomaly type, date/time, and link to view in system |
| 5 | Check the system notifications panel in the manager's dashboard | System notification appears in the notifications panel with red badge indicator, showing alert summary and timestamp |
| 6 | Click on the system notification to view alert details | Alert detail modal opens displaying complete information: employee name, department, anomaly type, detection time, attendance record details, and 'Acknowledge' button |
| 7 | Review the alert details for accuracy | All alert information matches the simulated absence anomaly including correct employee, date, time, and anomaly classification |
| 8 | Click the 'Acknowledge' button in the alert detail modal | Acknowledgment confirmation dialog appears asking for optional comments |
| 9 | Enter acknowledgment comment 'Reviewed and will follow up with employee' and confirm | Alert status updates to 'Acknowledged', acknowledgment timestamp is recorded, manager's user ID is logged, and comment is saved |
| 10 | Navigate to the alerts history page | Alerts history page displays the acknowledged alert with status 'Acknowledged', acknowledgment time, acknowledging manager name, and comment |
| 11 | Verify the alert log entry in the system | Alert log contains complete audit trail: creation timestamp, detection time, notification sent time, acknowledgment time, manager ID, and all status changes |

**Postconditions:**
- Alert is successfully acknowledged and status updated in database
- Complete audit trail exists for the alert lifecycle
- Email notification was delivered successfully
- System notification was displayed and acknowledged
- Alert remains in history for future reference
- Manager can view alert details from history at any time

---

### Test Case: Verify alert access control
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System has role-based access control configured for alerts
- Test user account exists without alert access permissions (regular employee role)
- Valid Attendance Manager account exists with alert access
- At least one active alert exists in the system
- Alert module is functional and accessible to authorized users

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using unauthorized user credentials (regular employee account) | User successfully logs into the system and is redirected to their role-appropriate dashboard |
| 2 | Check if alerts or notifications panel is visible in the unauthorized user's dashboard | Alerts panel is either not visible or shows only user's personal notifications, not attendance anomaly alerts |
| 3 | Attempt to navigate to the alerts module by entering the URL directly in browser | System denies access and displays 'Access Denied' message stating 'You do not have permission to view attendance alerts' |
| 4 | Attempt to access alerts API endpoint directly using browser developer tools | API returns 403 Forbidden status code with error message 'Insufficient permissions to access alerts' |
| 5 | Verify that no attendance alert emails were sent to unauthorized user | Unauthorized user's email inbox does not contain any attendance anomaly alert emails |
| 6 | Log out from the unauthorized user account | User is successfully logged out and redirected to login page |
| 7 | Log into the system using authorized Attendance Manager credentials | Manager successfully logs in and dashboard loads with alerts panel visible showing notification badge with alert count |
| 8 | Click on the alerts/notifications icon in the dashboard | Alerts panel expands showing list of active attendance anomaly alerts with details: employee name, anomaly type, time, and status |
| 9 | Verify that all alerts are accessible and actionable | Manager can view all alert details, filter alerts by type/status, and access acknowledgment functionality |
| 10 | Select an unacknowledged alert from the list | Alert detail view opens showing complete information with 'Acknowledge' button enabled |
| 11 | Click 'Acknowledge' button and add comment 'Investigating the issue' | Acknowledgment is processed successfully, alert status changes to 'Acknowledged', and confirmation message is displayed |
| 12 | Verify the acknowledgment is recorded in the system | Alert shows 'Acknowledged' status with manager's name, acknowledgment timestamp, and comment visible in alert history |

**Postconditions:**
- Unauthorized access attempts are logged in security audit trail
- Authorized manager successfully accessed and managed alerts
- Alert acknowledgment is recorded with complete audit information
- System maintains security integrity with proper access control
- No unauthorized alert access occurred during the test

---

### Test Case: Ensure alert delivery latency within SLA
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager has valid credentials with Attendance Manager role
- Manager is logged into the system
- Anomaly detection rules are configured and active
- Manager's email address is configured correctly
- System notification service is running
- Email service is operational with no delays
- Real-time monitoring is enabled
- System clock is synchronized with accurate time source

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current system time before triggering the anomaly | Current timestamp is recorded as baseline (T0) for latency measurement |
| 2 | Trigger an attendance anomaly event by creating a late arrival record (employee check-in 30 minutes after scheduled time) | Late arrival record is created in the attendance database with exact timestamp (T1) |
| 3 | Monitor the system's anomaly detection process in real-time | System's monitoring service picks up the new attendance record and begins anomaly evaluation |
| 4 | Wait and observe when the alert is generated in the alerts database | Alert is generated and recorded in the database with creation timestamp (T2), where T2 - T1 is less than 60 seconds |
| 5 | Check the manager's email inbox and note the time when alert email is received | Alert email is received with timestamp (T3), where T3 - T1 is less than or equal to 60 seconds, meeting the 1-minute SLA |
| 6 | Verify the email content includes accurate timestamp information | Email displays anomaly detection time, employee check-in time, scheduled time, and delay duration (30 minutes late) |
| 7 | Check the system notifications panel for the alert | System notification appears with timestamp (T4), where T4 - T1 is less than or equal to 60 seconds |
| 8 | Click on the system notification to view alert details | Alert detail opens showing late arrival anomaly with employee name, scheduled time, actual check-in time, and delay calculation |
| 9 | Navigate to the alerts log/history section | Alerts log page displays the new alert entry with complete timestamp trail |
| 10 | Verify the alert log entry contains all required timestamps | Log entry shows: anomaly occurrence time (T1), alert generation time (T2), email sent time (T3), notification displayed time (T4), and all timestamps are within 1-minute window from T1 |
| 11 | Calculate and verify the total latency from anomaly occurrence to alert delivery | Total latency (T3 - T1 or T4 - T1) is less than or equal to 60 seconds, confirming SLA compliance |
| 12 | Review system performance logs for alert processing time | Performance logs confirm alert generation and delivery completed within the 1-minute SLA requirement with no errors or delays |

**Postconditions:**
- Alert was delivered within the 1-minute SLA requirement
- Complete timestamp audit trail exists in the system logs
- Email and system notifications were delivered successfully
- Alert remains in the system for manager acknowledgment
- Performance metrics are logged for SLA monitoring
- System continues to monitor for additional anomalies

---

