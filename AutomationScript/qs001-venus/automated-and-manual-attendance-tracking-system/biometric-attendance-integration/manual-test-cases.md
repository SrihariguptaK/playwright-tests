# Manual Test Cases

## Story: As Biometric System Administrator, I want to configure biometric device integration to achieve seamless automatic attendance capture
**Story ID:** story-17

### Test Case: Validate successful biometric device configuration
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as administrator with device configuration permissions
- Biometric device is powered on and connected to the network
- Device API credentials are available
- System is accessible and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to biometric device configuration page from admin dashboard | Configuration form is displayed with fields for device name, IP address, port, device type, unique identifier, and API credentials |
| 2 | Enter valid device name (e.g., 'Main Entrance Device 01') | Device name is accepted and displayed in the input field |
| 3 | Enter valid IP address (e.g., '192.168.1.100'), port number (e.g., '8080'), and unique device identifier | All connection parameters are accepted without validation errors |
| 4 | Select device type from dropdown (e.g., 'Fingerprint Scanner') | Device type is selected and displayed |
| 5 | Enter valid API credentials (username and password/token) | Credentials are accepted and masked appropriately |
| 6 | Click 'Test Connection' button | System initiates connectivity test and displays 'Testing connection...' message |
| 7 | Wait for connection test to complete | System displays 'Connection successful' message with green indicator within 5 seconds |
| 8 | Click 'Save Configuration' button | System validates all fields and displays 'Device registered successfully' confirmation message |
| 9 | Navigate to device status dashboard | Device status dashboard is displayed showing all registered devices |
| 10 | Locate the newly configured device in the dashboard | Device is listed with status showing as 'Connected' and 'Active' with green status indicator and current timestamp |

**Postconditions:**
- Biometric device is successfully registered in the system
- Device status shows as connected and active
- Device is ready to capture attendance data
- Configuration is saved in the database
- Device appears in the monitoring dashboard

---

### Test Case: Verify error handling for invalid device configuration
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as administrator with device configuration permissions
- System is accessible and responsive
- No biometric device is connected at the specified invalid address

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to biometric device configuration page from admin dashboard | Configuration form is displayed with all required input fields |
| 2 | Enter invalid IP address (e.g., '999.999.999.999') | Field accepts the input temporarily |
| 3 | Enter invalid port number (e.g., '99999') | Field accepts the input temporarily |
| 4 | Enter device name and select device type | Valid fields are accepted normally |
| 5 | Enter incorrect API credentials | Credentials are accepted in the form |
| 6 | Click 'Test Connection' button | System attempts to connect and displays 'Testing connection...' message |
| 7 | Wait for connection test to complete | System displays descriptive error message 'Connection failed: Invalid IP address format' or 'Unable to reach device at specified address' with red indicator |
| 8 | Click 'Save Configuration' button without fixing errors | System prevents saving and displays error message 'Cannot save device configuration: Connection test must pass before saving' |
| 9 | Navigate to device status dashboard | Dashboard does not show the invalid device configuration |
| 10 | Attempt to manually trigger attendance data capture from non-existent device | No data is captured and system shows 'No active devices available' message |

**Postconditions:**
- Invalid device configuration is not saved in the system
- No device entry is created in the database
- Device does not appear in monitoring dashboard
- System remains stable with no data corruption
- Error messages are logged in system audit trail

---

### Test Case: Ensure only authorized admins can configure devices
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System has both admin and non-admin user accounts configured
- Non-admin user credentials are available (e.g., regular employee account)
- Admin user credentials are available
- Biometric device is available for configuration
- All users are logged out initially

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using non-admin user credentials (e.g., employee username and password) | User is successfully logged in and redirected to employee dashboard |
| 2 | Attempt to navigate to biometric device configuration page by entering the URL directly or through menu | System displays 'Access Denied: You do not have permission to access this page' message with 403 error code |
| 3 | Verify that device configuration menu option is not visible in navigation | Device configuration option is hidden or disabled in the user interface |
| 4 | Logout from non-admin account | User is successfully logged out and redirected to login page |
| 5 | Login to the system using admin user credentials | Admin is successfully logged in and redirected to admin dashboard |
| 6 | Navigate to biometric device configuration page from admin menu | Configuration page is accessible and displays the device configuration form with all fields |
| 7 | Enter valid device details: name 'Reception Device 01', IP '192.168.1.101', port '8080', device type 'Fingerprint Scanner', and valid API credentials | All fields accept the input without errors |
| 8 | Click 'Test Connection' button | Connection test completes successfully with 'Connection successful' message |
| 9 | Click 'Save Configuration' button | System saves the configuration and displays 'Device registered successfully' confirmation message |
| 10 | Verify device appears in device status dashboard with 'Connected' and 'Active' status | Device is listed in dashboard with green status indicators showing it is registered and active |

**Postconditions:**
- Non-admin users cannot access device configuration functionality
- Admin users have full access to device configuration
- Device is successfully registered by admin user
- Access control is enforced and logged
- Security permissions are validated correctly

---

## Story: As Employee, I want my attendance to be recorded automatically via biometric authentication to achieve accurate and timely attendance tracking
**Story ID:** story-18

### Test Case: Validate successful attendance recording via biometric authentication
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee biometric data is registered in the system
- Biometric device is configured, connected, and active
- Employee profile exists in the database with valid employee ID
- System time is synchronized correctly
- Attendance recording service is running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee approaches the biometric device and places finger on fingerprint scanner or looks at facial recognition camera | Biometric device activates and begins scanning, displaying 'Scanning...' or similar indicator |
| 2 | Biometric device captures and sends biometric data to the system | System receives biometric data and initiates validation process within 1 second |
| 3 | System validates biometric data against registered employee profiles | System successfully matches biometric data to employee profile and identifies employee (e.g., 'John Doe, EMP001') |
| 4 | System records attendance timestamp automatically | Attendance record is created in database with employee ID, date, timestamp (e.g., '2024-01-15 09:00:23'), and device location |
| 5 | System processes the attendance record | Attendance status is updated to 'Present' for the employee for current date |
| 6 | System displays confirmation message on biometric device screen | Device displays 'Attendance Recorded Successfully' with employee name and timestamp within 2 seconds of authentication |
| 7 | Verify attendance record in employee attendance dashboard | Attendance record appears in employee's attendance history with correct date, time, and status |
| 8 | Check system logs for the attendance event | System audit log contains entry for successful biometric authentication and attendance recording |

**Postconditions:**
- Attendance record is permanently stored in the database
- Employee attendance status is updated for the current day
- Confirmation message was displayed to employee
- Attendance data is available for reporting
- System logs contain successful authentication event

---

### Test Case: Verify rejection of invalid biometric authentication
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Biometric device is configured, connected, and active
- System has registered employee biometric data
- Unregistered person is available to test (or use invalid biometric sample)
- Attendance recording service is running
- Audit logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Unregistered person approaches biometric device and attempts authentication using fingerprint or facial recognition | Biometric device activates and begins scanning process |
| 2 | Biometric device captures and sends unregistered biometric data to system | System receives biometric data and attempts to match against registered profiles |
| 3 | System attempts to validate unregistered biometric data | System fails to match biometric data to any registered employee profile within 2 seconds |
| 4 | System rejects the authentication attempt | Device displays 'Authentication Failed: Biometric data not recognized' or 'Please try again' message with red indicator or error sound |
| 5 | Verify no attendance record is created in the database | No new attendance record exists for the failed authentication attempt |
| 6 | Same person or registered employee retries authentication with valid registered biometric data | Biometric device re-activates and scans the valid biometric data |
| 7 | System validates the correct biometric data | System successfully matches biometric data to registered employee profile |
| 8 | System records attendance for valid authentication | Attendance record is created with accurate timestamp and employee details, and confirmation message is displayed |
| 9 | Check system audit logs for both authentication attempts | Audit log contains entry for failed authentication attempt with timestamp, device ID, and rejection reason, followed by successful authentication entry |

**Postconditions:**
- Invalid authentication attempt is logged in audit trail
- No attendance record created for invalid authentication
- Valid authentication creates proper attendance record
- System security is maintained
- Retry mechanism works correctly

---

### Test Case: Ensure attendance timestamp accuracy
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee biometric data is registered in the system
- Biometric device is configured and active
- System time is synchronized with NTP server or accurate time source
- Database access is available for verification
- Attendance reporting module is functional
- Reference clock or time source is available for comparison

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current accurate time from reference clock (e.g., 09:30:00 AM on 2024-01-15) | Reference time is recorded for comparison |
| 2 | Employee authenticates using biometric device at the noted time | Biometric device scans and system validates employee identity successfully |
| 3 | Observe the timestamp displayed on confirmation message | Confirmation message shows timestamp matching the authentication time (e.g., '09:30:01 AM' - within 2 seconds of reference time) |
| 4 | Immediately access the database and query the attendance record for the employee using SQL: SELECT * FROM attendance WHERE employee_id = 'EMP001' AND date = '2024-01-15' ORDER BY timestamp DESC LIMIT 1 | Database returns the most recent attendance record with timestamp field |
| 5 | Compare database timestamp with reference authentication time | Database timestamp matches actual authentication time within 2 seconds tolerance (e.g., reference: 09:30:00, database: 09:30:01) |
| 6 | Verify all timestamp components: date, hours, minutes, seconds | All timestamp components are accurate: correct date (2024-01-15), correct hour (09), correct minute (30), seconds within acceptable range |
| 7 | Navigate to attendance reporting module and generate attendance report for the employee for current date | Report generation completes successfully and displays attendance records |
| 8 | Locate the attendance entry in the generated report | Report shows the attendance record with employee name, date, and timestamp |
| 9 | Verify timestamp accuracy in the report matches database and actual authentication time | Report displays timestamp as '09:30:01 AM' or equivalent format, matching database record and within 2 seconds of actual authentication time |
| 10 | Perform second authentication test at different known time (e.g., 02:15:00 PM) and repeat timestamp verification | Second attendance record also shows accurate timestamp within 2 seconds of actual authentication time, confirming consistent accuracy |

**Postconditions:**
- All attendance timestamps are accurate within 2-second tolerance
- Database records match actual authentication times
- Reports reflect accurate attendance timestamps
- System time synchronization is verified
- Timestamp accuracy is consistent across multiple authentications

---

## Story: As System Administrator, I want to monitor biometric device connectivity to achieve system reliability
**Story ID:** story-24

### Test Case: Validate real-time device connectivity status display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- System administrator account is created and active
- At least one biometric device is registered in the system
- Monitoring dashboard is deployed and accessible
- Device status API endpoint (GET /api/biometric/devices/status) is operational
- Administrator has valid authentication credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid administrator credentials | Administrator is successfully authenticated and redirected to the main dashboard |
| 2 | Click on the 'Monitoring Dashboard' or 'Device Monitoring' menu option | Monitoring dashboard page loads successfully |
| 3 | Observe the dashboard display showing all registered biometric devices | Dashboard displays a list of all biometric devices with columns showing device ID, device name, location, current status (connected/disconnected), last heartbeat timestamp, and status indicator (green for connected, red for disconnected) |
| 4 | Verify the current status of all devices shows 'Connected' with green indicators | All devices display 'Connected' status with green visual indicators and recent heartbeat timestamps (within last 30 seconds) |
| 5 | Simulate device disconnection by physically disconnecting a biometric device or using test simulation tool | Device disconnection is initiated successfully |
| 6 | Wait and observe the dashboard for up to 30 seconds | Within 30 seconds, the disconnected device's status changes from 'Connected' (green) to 'Disconnected' (red), and the status indicator updates accordingly |
| 7 | Click on the disconnected device row to view detailed information | Device detail panel opens showing comprehensive device information including current status, last known connection time, and link to view logs |
| 8 | Click on 'View Logs' or 'Device Logs' button for the disconnected device | Device connectivity logs page opens displaying historical connectivity data |
| 9 | Review the logs for the disconnection event | Logs show complete connectivity history with timestamps, including the recent disconnection event with exact time, previous connection status, and any error messages or diagnostic information |
| 10 | Verify log entries include connection state changes, heartbeat signals, and disconnection timestamp | All relevant log entries are present and accurately reflect the device's connectivity timeline |

**Postconditions:**
- Dashboard accurately reflects current device connectivity status
- Disconnection event is logged in the system
- Device status can be monitored in real-time
- Administrator remains logged in to the system

---

### Test Case: Verify alert generation on device connectivity loss
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System administrator account is created and active
- Administrator is logged into the monitoring dashboard
- At least one biometric device is connected and operational
- Alert notification system is configured and enabled
- Alert channels (email, SMS, in-app notifications) are properly configured
- Device heartbeat monitoring is active with 30-second intervals

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify that all biometric devices are currently showing 'Connected' status on the monitoring dashboard | All devices display 'Connected' status with green indicators |
| 2 | Note the current time and simulate device connectivity loss by disconnecting a biometric device from the network or using the test simulation tool | Device connectivity is successfully interrupted |
| 3 | Monitor the dashboard and wait for the system to detect the connectivity loss | Within 30 seconds, the device status changes to 'Disconnected' on the dashboard |
| 4 | Check for alert notification generation in the system's alert panel or notification center | System generates an alert notification immediately upon detecting device disconnection, displaying alert message with device name, location, disconnection time, and severity level |
| 5 | Verify the alert delivery time by comparing the disconnection time with alert generation time | Alert is generated and displayed within 1 minute of the actual connectivity loss |
| 6 | Check configured alert channels (email inbox, SMS, in-app notifications) for alert delivery | Administrator receives alert notification via all configured channels (email, SMS, in-app) promptly with complete device disconnection details |
| 7 | Review the alert message content for completeness | Alert message includes device ID, device name, location, disconnection timestamp, alert severity, and recommended actions |
| 8 | Click on the alert notification in the dashboard or notification panel | Alert details page opens showing full alert information and options to acknowledge or take action |
| 9 | Click the 'Acknowledge' button on the alert | Alert acknowledgment confirmation dialog appears |
| 10 | Confirm the acknowledgment action | Alert status changes to 'Acknowledged', acknowledgment timestamp is recorded, administrator name is logged, and alert is moved to acknowledged alerts section |
| 11 | Navigate to the alert logs or alert history section | Alert history page displays the acknowledged alert with complete audit trail including generation time, delivery time, acknowledgment time, and administrator who acknowledged it |

**Postconditions:**
- Alert is generated and logged in the system
- Alert is delivered to all configured channels
- Alert status is updated to 'Acknowledged'
- Complete alert audit trail is maintained in logs
- Device remains in disconnected state until reconnected

---

### Test Case: Ensure access control for monitoring dashboard
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- System has role-based access control (RBAC) implemented
- At least one administrator account exists with monitoring dashboard access
- At least one non-admin user account exists (e.g., regular employee, HR staff without admin privileges)
- Monitoring dashboard URL is known and accessible
- Authentication system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log out from any existing session and navigate to the system login page | Login page is displayed with username and password fields |
| 2 | Enter credentials for a non-admin user account (regular employee or HR staff without admin privileges) | User is successfully authenticated and redirected to their authorized dashboard or home page |
| 3 | Attempt to access the monitoring dashboard by clicking on the monitoring menu option (if visible) or by directly entering the monitoring dashboard URL | Access is denied with an error message displayed: 'Access Denied - You do not have permission to access this resource' or 'Unauthorized Access - Administrator privileges required' |
| 4 | Verify that the monitoring dashboard menu option is not visible in the navigation menu for non-admin users | Monitoring dashboard link is hidden or not displayed in the navigation menu for non-admin users |
| 5 | Verify that the user is redirected to an error page or remains on the current authorized page | User is either shown an access denied page or remains on their current authorized page without accessing the monitoring dashboard |
| 6 | Check the system logs for the unauthorized access attempt | Security log records the unauthorized access attempt with timestamp, user ID, attempted resource, and access denial reason |
| 7 | Log out from the non-admin user account | User is successfully logged out and redirected to the login page |
| 8 | Enter credentials for a valid administrator account | Administrator is successfully authenticated and redirected to the admin dashboard |
| 9 | Click on the 'Monitoring Dashboard' menu option in the navigation | Monitoring dashboard menu option is visible and accessible to the administrator |
| 10 | Access the monitoring dashboard | Monitoring dashboard loads successfully, displaying all biometric devices with their connectivity status, health indicators, and full dashboard functionality |
| 11 | Verify all dashboard features are accessible including device list, status indicators, logs, and alert management | All monitoring dashboard features are fully functional and accessible to the administrator, including viewing device status, accessing logs, managing alerts, and viewing device health metrics |
| 12 | Navigate through different sections of the monitoring dashboard (device list, logs, alerts, settings) | Administrator can successfully navigate and interact with all sections of the monitoring dashboard without any access restrictions |

**Postconditions:**
- Non-admin users are prevented from accessing the monitoring dashboard
- Unauthorized access attempts are logged in security logs
- Administrator successfully accesses and uses the monitoring dashboard
- Access control policies are enforced correctly
- System maintains security integrity

---

