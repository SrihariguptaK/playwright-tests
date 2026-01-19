# Manual Test Cases

## Story: As Biometric System Administrator, I want to configure biometric devices to achieve seamless attendance data capture
**Story ID:** story-1

### Test Case: Validate successful biometric device registration
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has valid Biometric System Administrator credentials
- User is logged into the configuration portal
- Device registry database is accessible and operational
- Network connectivity is stable
- At least one biometric device is available for registration with valid configuration parameters

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to device configuration page from the main menu | Device registration form is displayed with all required fields: Device ID, Device Name, IP Address, Communication Protocol, and Location |
| 2 | Enter valid device details - Device ID: 'BIO-001', Device Name: 'Main Entrance Scanner', IP Address: '192.168.1.100', Protocol: 'TCP/IP', Location: 'Building A - Floor 1' | All fields accept the input without validation errors |
| 3 | Click the 'Submit' or 'Register Device' button | System validates device connectivity and displays confirmation message 'Device registered successfully' with device ID |
| 4 | Navigate to device status dashboard | Device status dashboard loads successfully |
| 5 | Check device status dashboard for the newly registered device 'BIO-001' | New device 'BIO-001' appears in the device list with status 'Connected' and timestamp of registration |

**Postconditions:**
- Device 'BIO-001' is successfully registered in the device registry database
- Device appears on the status dashboard with 'Connected' status
- Configuration change is logged with timestamp and administrator username
- Device is ready to capture biometric attendance data

---

### Test Case: Verify error handling for invalid device configuration
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User has valid Biometric System Administrator credentials
- User is logged into the configuration portal
- Device registration form is accessible
- Input validation rules are configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to device configuration page from the main menu | Device registration form is displayed with all required fields and validation indicators |
| 2 | Enter invalid IP address '999.999.999.999' in the IP Address field | Field is highlighted with red border indicating validation error |
| 3 | Click the 'Submit' or 'Register Device' button | Inline error message 'Invalid IP address format' is displayed below the IP Address field and submission is blocked |
| 4 | Clear the IP Address field and correct it to '192.168.1.101', then clear the required Device ID field | IP Address field validation error is cleared |
| 5 | Attempt to submit the form with missing Device ID field | Submission is blocked and error message 'Device ID is required' is displayed below the Device ID field |
| 6 | Leave Device Name field empty and attempt to submit | Submission is blocked with error message 'Device Name is required' and all missing required fields are highlighted with appropriate error messages |

**Postconditions:**
- No device is registered in the system
- Device registry database remains unchanged
- User remains on the device configuration page with error messages displayed
- Form retains valid input data for correction

---

### Test Case: Ensure only authorized users can access device configuration
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Two user accounts are available: one with non-administrator role and one with Biometric System Administrator role
- Role-based access control is configured and active
- Configuration portal is accessible
- User is logged out of the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the configuration portal using non-administrator user credentials (username: 'employee001', password: valid password) | User is successfully authenticated and redirected to the default dashboard for their role |
| 2 | Attempt to navigate to device configuration page by entering the URL directly or through menu navigation | Access to device configuration page is denied with error message 'Access Denied: Insufficient permissions' or '403 Forbidden' and user is redirected to unauthorized access page |
| 3 | Logout from the non-administrator account | User is successfully logged out and redirected to login page |
| 4 | Login to the configuration portal using Biometric System Administrator credentials (username: 'admin001', password: valid password) | Administrator is successfully authenticated and redirected to the administrator dashboard |
| 5 | Navigate to device configuration page from the main menu | Access to device configuration page is granted and device registration form is displayed with full functionality |

**Postconditions:**
- Access control is verified and functioning correctly
- Non-administrator users cannot access device configuration features
- Administrator users have full access to device configuration features
- All access attempts are logged in the system audit log

---

## Story: As Attendance Manager, I want to view real-time biometric attendance logs to achieve timely monitoring
**Story ID:** story-2

### Test Case: Validate real-time attendance log updates
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has valid Attendance Manager credentials
- User is logged into the attendance management system
- At least one biometric device is configured and operational
- Attendance logs database contains existing attendance records
- Auto-refresh functionality is enabled with 30-second interval
- Test biometric device is ready to capture new attendance data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to attendance dashboard from the main menu | Dashboard displays attendance logs with columns: Employee ID, Employee Name, Date, Time, Device ID, Status, and timestamp of last refresh |
| 2 | Note the current timestamp and total number of attendance entries displayed | Current timestamp and entry count are recorded for comparison |
| 3 | Trigger a new biometric attendance capture on a test device (simulate employee punch-in) | Biometric device successfully captures attendance data and sends to the system |
| 4 | Wait for 30 seconds and observe the dashboard | Dashboard automatically refreshes and displays the new attendance entry with correct Employee ID, timestamp, and device information within 30 seconds of data capture |
| 5 | Click on the filter dropdown and select specific employee 'EMP-12345' from the employee filter | Employee filter dropdown displays list of employees and selected employee is highlighted |
| 6 | Select today's date from the date filter and click 'Apply Filters' | Dashboard refreshes and displays only attendance logs for employee 'EMP-12345' for today's date, with all other entries filtered out |
| 7 | Verify the filtered results show correct employee name, date, and time entries | Filtered attendance logs display correctly with accurate employee information, timestamps, and device details matching the applied filters |

**Postconditions:**
- Dashboard displays real-time attendance data with 30-second refresh interval
- Filters are applied and working correctly
- New attendance entries are visible in the system
- Dashboard remains responsive and functional
- All displayed data matches the attendance logs database

---

### Test Case: Verify anomaly highlighting in attendance logs
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has valid Attendance Manager credentials
- User is logged into the attendance management system
- Attendance logs database contains entries with anomalies (missing punch-out, duplicate entries)
- Anomaly detection rules are configured and active
- Export functionality is enabled for the user role

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to attendance dashboard from the main menu | Dashboard displays attendance logs with all entries including normal and anomalous records |
| 2 | Scan the attendance log entries for visual indicators of anomalies | Entries with missing punches are highlighted with distinct visual indicators (e.g., yellow background or warning icon) |
| 3 | Identify and click on an entry with missing punch-out for employee 'EMP-67890' | Anomaly details are displayed showing 'Missing Punch-Out' with timestamp of punch-in and no corresponding punch-out time |
| 4 | Locate duplicate attendance entries for the same employee at similar timestamps | Duplicate entries are highlighted visually with a different color indicator (e.g., orange background or duplicate icon) and marked as 'Duplicate Entry' |
| 5 | Apply filter to show only anomalous entries by selecting 'Show Anomalies Only' checkbox | Dashboard refreshes to display only entries with anomalies, filtering out normal attendance records |
| 6 | Click the 'Export' button to download filtered logs | Export dialog appears with format options (CSV selected by default) |
| 7 | Confirm export by clicking 'Download CSV' | CSV file downloads successfully with filename format 'attendance_logs_YYYYMMDD_HHMMSS.csv' |
| 8 | Open the downloaded CSV file and verify contents | CSV file contains all filtered anomalous entries with correct data: Employee ID, Employee Name, Date, Time, Device ID, Status, and Anomaly Type columns with accurate data matching dashboard display |

**Postconditions:**
- Anomalies are correctly identified and highlighted in the dashboard
- Filtered logs are exported successfully in CSV format
- CSV file contains accurate and complete data
- Dashboard remains in filtered state until filters are cleared
- Export action is logged in the system audit log

---

### Test Case: Ensure access control for attendance dashboard
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Two user accounts are available: one unauthorized user without attendance management permissions and one with Attendance Manager role
- Role-based access control is configured and active
- Attendance management system is accessible
- User is logged out of the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the attendance management system using unauthorized user credentials (username: 'employee002', password: valid password) | User is successfully authenticated and redirected to their default dashboard based on assigned role |
| 2 | Attempt to navigate to attendance dashboard by entering the URL directly '/attendance/dashboard' or searching for it in the menu | Access to attendance dashboard is denied with error message 'Access Denied: You do not have permission to view attendance logs' or '403 Forbidden' and user is redirected to unauthorized access page or their default dashboard |
| 3 | Verify that attendance dashboard menu option is not visible in the navigation menu | Attendance dashboard link is not displayed in the navigation menu for unauthorized user |
| 4 | Logout from the unauthorized user account | User is successfully logged out and redirected to login page with session terminated |
| 5 | Login to the attendance management system using Attendance Manager credentials (username: 'manager001', password: valid password) | Attendance Manager is successfully authenticated and redirected to the manager dashboard |
| 6 | Verify that attendance dashboard menu option is visible in the navigation menu | Attendance dashboard link is displayed in the navigation menu under 'Attendance Management' section |
| 7 | Navigate to attendance dashboard by clicking the menu link | Access to attendance dashboard is granted and dashboard loads successfully displaying biometric attendance logs with full functionality including filters, search, and export options |

**Postconditions:**
- Access control is verified and functioning correctly for attendance dashboard
- Unauthorized users cannot access attendance logs
- Attendance Manager users have full access to attendance dashboard features
- All access attempts (successful and denied) are logged in the system audit log with timestamps and user details
- User sessions are properly managed and terminated on logout

---

## Story: As System Administrator, I want to monitor biometric device connectivity to ensure continuous attendance data capture
**Story ID:** story-6

### Test Case: Validate real-time device connectivity status display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- System administrator account is created and active
- Administrator has valid login credentials
- At least 3 biometric devices are registered in the system
- All biometric devices are currently connected and operational
- Device monitoring dashboard is accessible
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open web browser and navigate to the system login page | Login page is displayed with username and password fields |
| 2 | Enter valid system administrator credentials and click Login button | Administrator is successfully authenticated and redirected to the main dashboard |
| 3 | Navigate to the device monitoring dashboard from the main menu | Device monitoring dashboard loads and displays all registered biometric devices with their current connectivity status (Connected/Disconnected), device ID, location, and last sync time |
| 4 | Verify the status refresh interval by observing the timestamp updates | Device status updates automatically every 30 seconds as indicated by the timestamp refresh |
| 5 | Simulate device disconnection by physically disconnecting one biometric device from the network or using the test simulation tool | Within 30 seconds, the disconnected device status changes from 'Connected' to 'Disconnected' with a red indicator, and an alert notification appears on the dashboard |
| 6 | Verify the alert details by clicking on the generated alert | Alert details are displayed showing device ID, disconnection timestamp, alert severity level, and an 'Acknowledge' button |
| 7 | Click the 'Acknowledge' button on the alert | Alert status changes to 'Acknowledged', the acknowledgment timestamp is recorded, and the administrator's name is logged as the acknowledger |
| 8 | Verify the acknowledged alert appears in the alerts history section | The acknowledged alert is moved to the alerts history with status 'Acknowledged' and displays the administrator who acknowledged it |

**Postconditions:**
- Device connectivity status is accurately displayed on the dashboard
- Alert is generated and acknowledged in the system
- Alert acknowledgment is logged with timestamp and administrator details
- One device remains in 'Disconnected' status
- Administrator remains logged into the system

---

### Test Case: Verify alert generation and notification
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- System administrator is logged into the monitoring dashboard
- At least one biometric device is connected and operational
- Alert notification system is configured and enabled
- Administrator has permissions to view and manage alerts
- Email notification service is configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the device monitoring dashboard, identify a currently connected biometric device | Device is displayed with 'Connected' status and green indicator |
| 2 | Disconnect the selected biometric device from the network by unplugging the network cable or disabling network connectivity | Device loses network connectivity |
| 3 | Monitor the dashboard for alert generation | Within 30 seconds, system generates an alert notification, device status changes to 'Disconnected', and a visual alert banner appears on the dashboard with device details and disconnection time |
| 4 | Check the alerts panel for the new alert entry | New alert is listed in the alerts panel showing device ID, alert type 'Device Disconnection', severity level 'High', timestamp, and status 'Unacknowledged' |
| 5 | Verify that administrators are notified through configured notification channels | Alert notification is visible on the dashboard and system administrators receive notification according to configured settings |
| 6 | Resolve the device issue by reconnecting the biometric device to the network | Device network connectivity is restored |
| 7 | Monitor the dashboard for device status update | Within 30 seconds, device status automatically updates to 'Connected' with green indicator, and the alert is automatically cleared or marked as 'Resolved' |
| 8 | Verify the alert history shows the complete lifecycle of the alert | Alert history displays the disconnection event, duration of disconnection, reconnection event, and resolution timestamp |

**Postconditions:**
- Device is reconnected and showing 'Connected' status
- Alert is cleared or marked as resolved in the system
- Complete alert lifecycle is logged in the system
- Device is operational and capturing attendance data
- Alert history is updated with resolution details

---

### Test Case: Ensure access control for monitoring dashboard
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- System has role-based access control configured
- At least one unauthorized user account exists (non-administrator role)
- At least one system administrator account exists
- Both user accounts have valid credentials
- Monitoring dashboard access is restricted to system administrators only

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open web browser and navigate to the system login page | Login page is displayed with username and password fields |
| 2 | Enter credentials for an unauthorized user (e.g., regular employee or attendance user without admin privileges) and click Login | User is successfully authenticated and redirected to their authorized dashboard |
| 3 | Attempt to navigate to the device monitoring dashboard by entering the URL directly or clicking on the monitoring menu option if visible | Access is denied with an error message 'Access Denied: You do not have permission to view this page' or 'Unauthorized Access - Administrator privileges required', and user is redirected to their default dashboard |
| 4 | Verify that the device monitoring menu option is not visible in the navigation menu for unauthorized users | Device monitoring dashboard link is not displayed in the navigation menu for non-administrator users |
| 5 | Log out from the unauthorized user account | User is successfully logged out and redirected to the login page |
| 6 | Enter valid system administrator credentials and click Login | System administrator is successfully authenticated and redirected to the administrator dashboard |
| 7 | Verify that the device monitoring option is visible in the navigation menu | Device monitoring dashboard link is visible and accessible in the navigation menu |
| 8 | Click on the device monitoring dashboard link | Access is granted and the device monitoring dashboard loads successfully, displaying all biometric devices with their connectivity status, alerts panel, and administrative controls |
| 9 | Verify all monitoring features are accessible including device status, alerts, and historical logs | All monitoring dashboard features are fully accessible and functional for the system administrator |

**Postconditions:**
- Access control is verified and functioning correctly
- Unauthorized users cannot access the monitoring dashboard
- System administrator has full access to monitoring features
- Security logs record both denied and granted access attempts
- System administrator remains logged in

---

## Story: As Attendance Manager, I want to receive notifications for biometric device failures to minimize attendance data gaps
**Story ID:** story-10

### Test Case: Validate notification delivery on device failure
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Attendance manager account is created and active
- Attendance manager email address is configured in the system
- Email notification service is configured and operational
- At least one biometric device is connected and operational
- Attendance manager is logged into the attendance management dashboard
- Device failure detection system is enabled
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify the current status of biometric devices on the attendance management dashboard | Dashboard displays all biometric devices with 'Connected' status and green indicators |
| 2 | Note the current time and simulate a biometric device failure by disconnecting the device, powering it off, or using the failure simulation tool | Biometric device is disconnected or powered off successfully |
| 3 | Monitor the system for failure detection | Within 1 minute, the system detects the device failure and the device status changes to 'Failed' or 'Disconnected' on the dashboard |
| 4 | Wait for email notification delivery and check the attendance manager's email inbox | Within 1 minute of failure detection, an email notification is received in the attendance manager's inbox with subject line indicating device failure, device ID, location, failure timestamp, and recommended actions |
| 5 | Verify the email notification content | Email contains complete details including device name, device ID, location, failure type, timestamp, severity level, and a link to the dashboard for acknowledgment |
| 6 | Return to the attendance management dashboard and check the alerts section | Dashboard displays a new alert for the device failure immediately after detection, showing device details, failure type, timestamp, severity level 'High', and status 'Unacknowledged' |
| 7 | Verify the alert notification banner appears on the dashboard | A prominent alert banner is displayed at the top of the dashboard with device failure information and an option to view details or acknowledge |
| 8 | Click on the alert to view full details | Alert details panel opens showing comprehensive information including device ID, location, failure timestamp, failure type, impact assessment, and acknowledgment options |

**Postconditions:**
- Device failure is detected and logged in the system
- Email notification is successfully delivered to attendance manager
- Dashboard alert is displayed and accessible
- Alert remains in 'Unacknowledged' status
- Notification delivery is logged in the system
- Device remains in failed status

---

### Test Case: Verify alert acknowledgment functionality
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Attendance manager is logged into the attendance management dashboard
- At least one unacknowledged device failure alert exists on the dashboard
- Alert acknowledgment feature is enabled
- Attendance manager has permissions to acknowledge alerts
- System logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alerts section on the attendance management dashboard | Alerts section displays all active alerts including at least one unacknowledged device failure alert with status 'Unacknowledged' |
| 2 | Identify the unacknowledged device failure alert and click on it to view details | Alert details panel opens displaying device information, failure timestamp, severity, current status 'Unacknowledged', and an 'Acknowledge' button |
| 3 | Click the 'Acknowledge' button on the alert | A confirmation dialog appears asking to confirm the acknowledgment with an optional comment field |
| 4 | Enter an optional comment (e.g., 'Investigating device failure') and click 'Confirm' | Acknowledgment is processed successfully and a success message 'Alert acknowledged successfully' is displayed |
| 5 | Verify the alert status has changed on the dashboard | Alert status changes from 'Unacknowledged' to 'Acknowledged', the alert indicator color changes from red to yellow or orange, and the acknowledgment timestamp is displayed |
| 6 | Check the alert details to verify acknowledgment information | Alert details show 'Acknowledged by: [Attendance Manager Name]', acknowledgment timestamp, and the comment entered during acknowledgment |
| 7 | Navigate to the system logs or audit trail section | System logs display a new entry recording the alert acknowledgment with details including alert ID, device ID, acknowledging user, timestamp, and comment |
| 8 | Verify the acknowledged alert is moved to the appropriate section or filtered view | Acknowledged alert appears in the 'Acknowledged Alerts' section or can be filtered separately from unacknowledged alerts |
| 9 | Attempt to acknowledge the same alert again | The 'Acknowledge' button is disabled or not visible, and a message indicates 'Alert already acknowledged' with details of who acknowledged it and when |

**Postconditions:**
- Alert status is changed to 'Acknowledged' in the system
- Acknowledgment is logged with timestamp, user details, and comment
- Alert remains visible in acknowledged alerts section
- Audit trail contains complete acknowledgment record
- Alert cannot be acknowledged again
- Attendance manager remains logged in

---

### Test Case: Ensure notification access control
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- System has role-based access control configured
- At least one unauthorized user account exists (without attendance manager privileges)
- At least one device failure alert exists in the system
- Unauthorized user has valid login credentials
- Alert viewing is restricted to authorized attendance managers only

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open web browser and navigate to the system login page | Login page is displayed with username and password fields |
| 2 | Enter credentials for an unauthorized user (e.g., regular employee without attendance manager role) and click Login | User is successfully authenticated and redirected to their authorized dashboard |
| 3 | Attempt to navigate to the alerts section by clicking on alerts menu or entering the alerts URL directly | Access denied message is displayed: 'Access Denied: You do not have permission to view device failure alerts' or 'Unauthorized Access - Attendance Manager privileges required' |
| 4 | Verify that the alerts menu option is not visible in the navigation for unauthorized users | Alerts or device failure notifications menu is not displayed in the navigation menu for non-attendance manager users |
| 5 | Attempt to access the alerts API endpoint directly using browser developer tools or API testing tool | API returns 403 Forbidden error with message 'Insufficient permissions to access this resource' |
| 6 | Verify that no email notifications for device failures were sent to the unauthorized user's email | Unauthorized user's email inbox does not contain any device failure notification emails |
| 7 | Log out from the unauthorized user account | User is successfully logged out and redirected to the login page |
| 8 | Log in with valid attendance manager credentials | Attendance manager is successfully authenticated and redirected to the attendance management dashboard |
| 9 | Navigate to the alerts section | Access is granted and alerts section loads successfully, displaying all device failure alerts with full details and acknowledgment options |
| 10 | Verify all alert management features are accessible | Attendance manager can view alert details, acknowledge alerts, add comments, and access alert history without any restrictions |

**Postconditions:**
- Access control is verified and functioning correctly
- Unauthorized users cannot view or access device failure alerts
- Attendance manager has full access to alerts and notifications
- Security logs record both denied and granted access attempts
- No sensitive alert information is exposed to unauthorized users
- Attendance manager remains logged in with full access

---

