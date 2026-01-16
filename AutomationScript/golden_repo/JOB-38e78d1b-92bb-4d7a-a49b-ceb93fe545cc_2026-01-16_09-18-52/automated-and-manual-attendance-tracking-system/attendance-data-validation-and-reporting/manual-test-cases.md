# Manual Test Cases

## Story: As Attendance Auditor, I want to review attendance data validation reports to achieve data accuracy
**Story ID:** story-25

### Test Case: Validate generation of attendance validation reports
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as an authorized Attendance Auditor
- Attendance data exists in the system for the selected date range
- Validation rules are configured in the system
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the validation reports module from the main dashboard | Report generation interface is displayed with filter options including date range, employee, and department fields |
| 2 | Select a date range using the date picker (e.g., last 30 days) | Date range is selected and displayed in the date fields without errors |
| 3 | Select specific department from the department dropdown filter | Department filter is applied and displayed correctly |
| 4 | Click the 'Generate Report' button | System processes the request and generates the validation report within 10 seconds, displaying a list of anomalies including missing punches, duplicate entries, and validation errors with employee details |
| 5 | Review the generated report for anomalies and recommendations | Report displays all detected anomalies with clear descriptions, affected employees, dates, and actionable recommendations for corrections |

**Postconditions:**
- Validation report is successfully generated and displayed
- Report generation time is logged in system metrics
- User remains on the validation reports page

---

### Test Case: Test report export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as an authorized Attendance Auditor
- A validation report has been generated and is displayed on screen
- Browser allows file downloads
- Sufficient storage space available for downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate a validation report by selecting date range and clicking 'Generate Report' | Validation report is displayed on screen with anomalies, employee details, and recommendations |
| 2 | Click the 'Export as PDF' button | PDF file is generated and downloaded successfully to the default download location with filename format 'Validation_Report_YYYY-MM-DD.pdf' |
| 3 | Open the downloaded PDF file | PDF opens correctly displaying all report data including headers, anomalies, employee information, and recommendations in a readable format |
| 4 | Return to the validation report screen and click the 'Export as CSV' button | CSV file is generated and downloaded successfully to the default download location with filename format 'Validation_Report_YYYY-MM-DD.csv' |
| 5 | Open the downloaded CSV file in a spreadsheet application | CSV opens correctly with all report data in structured columns including employee ID, name, date, anomaly type, description, and recommendations |

**Postconditions:**
- PDF and CSV files are successfully downloaded
- Export actions are logged in the audit trail
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
- Test user accounts exist: one unauthorized user and one authorized auditor
- Validation reports module is accessible via the application
- User is logged out initially

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using credentials of an unauthorized user (e.g., regular employee without auditor role) | User successfully logs into the system and is redirected to their default dashboard |
| 2 | Attempt to navigate to the validation reports module by entering the URL or searching for the module | Access to validation reports is denied with an error message 'Access Denied: You do not have permission to view this page' or the module is not visible in the navigation menu |
| 3 | Logout from the unauthorized user account | User is successfully logged out and redirected to the login page |
| 4 | Login to the system using credentials of an authorized auditor | Auditor successfully logs into the system and is redirected to their dashboard |
| 5 | Navigate to the validation reports module from the main menu or dashboard | Access to validation reports is granted and the report generation interface is displayed with all filter options and functionality available |
| 6 | Verify that all report features are accessible including generation, filtering, and export options | All validation report features are fully accessible and functional for the authorized auditor |

**Postconditions:**
- Access control is enforced correctly for both authorized and unauthorized users
- All access attempts are logged in the security audit trail
- Authorized auditor has full access to validation reports functionality
- System security remains intact

---

## Story: As Attendance Manager, I want to receive alerts for attendance anomalies to achieve proactive issue resolution
**Story ID:** story-27

### Test Case: Validate anomaly detection and alert generation
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an Attendance Manager
- Anomaly detection business rules are configured in the system
- Email notification service is configured and operational
- Test attendance data with known anomalies is prepared for injection
- Manager's email address is registered in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Inject attendance data containing known anomalies (e.g., missing punch-out, duplicate entries, irregular hours) into the system | Test data is successfully inserted into the attendance database |
| 2 | Trigger the automated anomaly detection process or wait for the scheduled daily run | System runs anomaly detection algorithms and processes the attendance data within 1 hour |
| 3 | Verify that alerts are generated for each detected anomaly | System generates alerts for all injected anomalies with unique alert IDs and timestamps |
| 4 | Navigate to the manager dashboard and check the alerts section | Alerts are visible in the dashboard with correct details including employee name, date, anomaly type, description, and severity level |
| 5 | Click on an individual alert to view detailed information | Alert details page displays comprehensive information including affected employee, date/time of anomaly, specific issue description, and recommended corrective actions |
| 6 | Check the email inbox of the attendance manager | Email notifications are received containing accurate alert information including employee details, anomaly type, date, and a link to view the alert in the system |
| 7 | Verify the content and formatting of the email notification | Email is properly formatted with clear subject line, alert details, and actionable information matching the dashboard alert |

**Postconditions:**
- All anomalies are detected and alerts are generated
- Alerts are visible in the manager dashboard
- Email notifications are successfully delivered
- Alert generation is logged in the system
- Alerts remain in 'New' status awaiting manager action

---

### Test Case: Test alert acknowledgment and resolution
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an Attendance Manager
- At least one unacknowledged alert exists in the system
- Audit logging is enabled and functional
- Manager has permissions to acknowledge and resolve alerts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alert dashboard and locate an unacknowledged alert | Alert dashboard displays the list of alerts with status indicators showing 'New' or 'Unacknowledged' |
| 2 | Click on the alert to open the alert details page | Alert details page opens displaying full information about the anomaly and available actions |
| 3 | Click the 'Acknowledge' button on the alert | Alert status changes to 'Acknowledged', timestamp is recorded, and a confirmation message is displayed |
| 4 | Verify the alert status in the dashboard list view | Alert now shows 'Acknowledged' status with the manager's name and acknowledgment timestamp |
| 5 | Return to the alert details and review the recommended corrective actions | Corrective action recommendations are clearly displayed with steps to resolve the anomaly |
| 6 | After taking corrective action (simulated or actual), click the 'Mark as Resolved' button | Alert status changes to 'Resolved', resolution timestamp is recorded, and a confirmation message is displayed |
| 7 | Add resolution notes in the comments field and save | Resolution notes are saved and associated with the alert record |
| 8 | Navigate to the audit log section and search for the alert ID | Audit log displays entries for alert creation, acknowledgment, and resolution with timestamps, manager name, and actions taken |
| 9 | Verify that all alert activities are properly logged | Audit log contains complete trail including: alert generation time, acknowledgment time and user, resolution time and user, and any comments or notes added |

**Postconditions:**
- Alert status is updated to 'Resolved'
- All alert activities are logged in the audit trail
- Resolution notes are saved and retrievable
- Alert is moved to resolved alerts section
- Audit log is complete and accurate

---

### Test Case: Ensure access control for alert management
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System has role-based access control configured for alert management
- Test user accounts exist: one unauthorized user and one attendance manager
- Active alerts exist in the system
- User is logged out initially

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using credentials of an unauthorized user (e.g., regular employee or auditor without manager role) | User successfully logs into the system and is redirected to their role-appropriate dashboard |
| 2 | Attempt to navigate to the alert dashboard by entering the URL directly or searching for the module | Access to alert dashboard is denied with an error message 'Access Denied: You do not have permission to view alerts' or the alert module is not visible in the navigation |
| 3 | Attempt to access alert notifications or email links as an unauthorized user | System prevents access and displays appropriate authorization error message |
| 4 | Logout from the unauthorized user account | User is successfully logged out and redirected to the login page |
| 5 | Login to the system using credentials of an authorized attendance manager | Attendance manager successfully logs into the system and is redirected to their dashboard |
| 6 | Navigate to the alert dashboard from the main menu | Access to alert dashboard is granted and the interface displays all active alerts with full details |
| 7 | Verify that alert notifications are visible in the dashboard notification area | Alert notifications are displayed with count badge and recent alerts summary |
| 8 | Verify access to all alert management features including acknowledge, resolve, and comment functions | All alert management features are fully accessible and functional for the authorized attendance manager |
| 9 | Check that email notifications are being received by the manager's registered email | Email notifications are successfully delivered to the attendance manager's inbox |

**Postconditions:**
- Access control is properly enforced for both authorized and unauthorized users
- All access attempts are logged in the security audit trail
- Authorized attendance manager has full access to alert dashboard and notifications
- Unauthorized users cannot view or manipulate alerts
- System security and data integrity remain intact

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
| 1 | Navigate to the attendance reports module from the main dashboard | Report interface is displayed with options to select report parameters including employee, department, and date range filters |
| 2 | Select a specific department from the department dropdown | Department is selected and displayed in the filter section |
| 3 | Select a date range (e.g., last 30 days) using the date picker | Date range is selected and displayed in the filter section |
| 4 | Click the 'Generate Report' button | System processes the request and generates the report within 10 seconds. Report displays accurate data including total hours, absences, and late arrivals with graphical visualizations such as charts and graphs |
| 5 | Review the generated report data and verify metrics accuracy against source data | All metrics (total hours, absences, late arrivals) match the attendance database records. Graphical visualizations accurately represent the data |
| 6 | Click the 'Export as PDF' button | PDF file downloads successfully to the default download location. File opens correctly and contains all report data, metrics, and visualizations with proper formatting |
| 7 | Click the 'Export as Excel' button | Excel file downloads successfully to the default download location. File opens correctly in Excel with all report data in structured format, including separate sheets for data and visualizations if applicable |

**Postconditions:**
- Attendance summary report is successfully generated and displayed
- PDF and Excel files are downloaded and saved to local system
- Report generation is logged in system audit trail
- User remains on the reports interface for further actions

---

### Test Case: Ensure access control for attendance reports
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- System has role-based access control configured
- Test user accounts exist: one unauthorized user (e.g., regular employee) and one authorized manager
- Attendance reports module requires manager-level permissions
- Both user accounts have valid credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page and enter credentials for an unauthorized user (regular employee without manager role) | User is successfully authenticated and logged into the system |
| 2 | Attempt to navigate to the attendance reports module by entering the URL directly or clicking on reports menu if visible | Access to the attendance reports module is denied. System displays an error message such as 'Access Denied: You do not have permission to view this page' or redirects to unauthorized access page |
| 3 | Verify that the attendance reports menu option is not visible in the navigation for unauthorized user | Attendance reports module link is not displayed in the navigation menu for unauthorized user |
| 4 | Logout from the unauthorized user account | User is successfully logged out and redirected to the login page |
| 5 | Navigate to the login page and enter credentials for an authorized manager account | Manager is successfully authenticated and logged into the system |
| 6 | Navigate to the attendance reports module from the main dashboard or navigation menu | Access to the attendance reports module is granted. Report interface is displayed with all available options including parameter selection, report generation, and export functionality |
| 7 | Verify that all report features are accessible including filters, generate button, and export options | All attendance report features are fully accessible and functional for the authorized manager |

**Postconditions:**
- Unauthorized user access attempt is logged in security audit trail
- Authorized manager has full access to attendance reports module
- Role-based access control is validated and functioning correctly
- No unauthorized data access occurred during testing

---

