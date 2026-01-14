# Manual Test Cases

## Story: As Biometric System Administrator, I want to configure biometric device connections to achieve real-time attendance data capture
**Story ID:** story-12

### Test Case: Validate successful biometric device addition and connectivity test
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as System Administrator with device configuration permissions
- Biometric device is powered on and connected to the network
- Device IP address, port, and credentials are available
- System has network connectivity to the biometric device
- Device configuration page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the device configuration page from the admin dashboard | Device configuration page loads successfully and displays the device configuration form with fields for device name, IP address, port, device type, location, and credentials |
| 2 | Enter valid device details: Device Name='Main Entrance Scanner', IP Address='192.168.1.100', Port='4370', Device Type='Fingerprint', Location='Building A - Main Entrance', Username='admin', Password='devicepass123' | All input fields accept the entered values without validation errors |
| 3 | Click the 'Test Connection' button | System displays a loading indicator and initiates connection test to the biometric device |
| 4 | Observe the connection test result within 5 seconds | System displays 'Connection Successful' message with green indicator, showing device model and firmware version |
| 5 | Click the 'Save Configuration' button | System saves the device configuration, displays success notification 'Device added successfully', and the new device appears in the device list with 'Online' status |
| 6 | Verify the device entry in the device list | Device list shows the newly added device with all entered details, current status as 'Online', and timestamp of configuration |

**Postconditions:**
- Biometric device is successfully configured and connected to the system
- Device appears in the active devices list with 'Online' status
- Device configuration change is logged in the system audit log with administrator username and timestamp
- System begins receiving real-time attendance data from the configured device

---

### Test Case: Verify rejection of invalid device parameters
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as System Administrator with device configuration permissions
- Device configuration page is accessible
- No devices are currently being configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the device configuration page from the admin dashboard | Device configuration page loads successfully and displays an empty device configuration form |
| 2 | Enter invalid IP address '999.999.999.999' in the IP Address field | IP Address field accepts the input temporarily |
| 3 | Enter valid values for other fields: Device Name='Test Device', Port='4370', Device Type='Fingerprint', Location='Test Location', Username='admin', Password='pass123' | All other fields accept the entered values |
| 4 | Click the 'Test Connection' or 'Save Configuration' button | System displays validation error message 'Invalid IP address format. Please enter a valid IPv4 address (e.g., 192.168.1.100)' in red text below the IP Address field and prevents form submission |
| 5 | Correct the IP address to valid format '192.168.1.150' | Validation error message disappears and the IP Address field shows valid state with green border or checkmark |
| 6 | Click the 'Test Connection' button | System accepts the corrected input and initiates connection test to the device, displaying loading indicator |
| 7 | Observe the connection test result | System either displays 'Connection Successful' if device is reachable, or 'Connection Failed' with appropriate error message if device is not reachable, but no validation errors are shown |

**Postconditions:**
- Invalid device parameters are rejected and not saved to the system
- User is informed of validation errors with clear error messages
- System maintains data integrity by preventing invalid configurations
- After correction, valid parameters can be submitted successfully

---

### Test Case: Ensure unauthorized users cannot access device configuration
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Test user account with non-administrator role (e.g., 'Employee' or 'Attendance Manager') exists in the system
- User credentials for non-administrator account are available: Username='testuser', Password='testpass123'
- Device configuration page URL is known: '/admin/device-configuration'
- Device configuration API endpoint is known: 'POST /api/devices'
- User is currently logged out of the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page and enter non-administrator credentials: Username='testuser', Password='testpass123' | System authenticates the user successfully and redirects to the appropriate dashboard for their role (not admin dashboard) |
| 2 | Verify the main navigation menu options available to the logged-in user | Navigation menu does not display 'Device Configuration' or 'System Administration' options |
| 3 | Manually enter the device configuration page URL '/admin/device-configuration' in the browser address bar and press Enter | System denies access and displays 'Access Denied' or '403 Forbidden' error page with message 'You do not have permission to access this page. Please contact your administrator.' |
| 4 | Open browser developer tools and attempt to make a POST request to '/api/devices' endpoint with sample device data: {"deviceName":"Test","ipAddress":"192.168.1.100","port":"4370"} | API returns HTTP 403 Forbidden status code with JSON response: {"error":"Authorization failed","message":"Insufficient permissions to perform this action"} |
| 5 | Attempt to make a GET request to '/api/devices/status' endpoint | API returns HTTP 403 Forbidden status code with authorization error message |
| 6 | Check system audit logs for unauthorized access attempts | System logs the unauthorized access attempts with username, timestamp, attempted resource, and 'Access Denied' status |

**Postconditions:**
- Non-administrator user remains unable to access device configuration functionality
- No device configurations are created or modified
- All unauthorized access attempts are logged in the security audit log
- System security and role-based access control remain intact

---

## Story: As Attendance Manager, I want to review biometric attendance logs to verify employee check-ins
**Story ID:** story-13

### Test Case: Validate attendance log retrieval with filters
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Attendance Manager with log access permissions
- Biometric attendance data exists in the system for multiple employees across different dates and devices
- At least 50 attendance records exist for testing filter and export functionality
- Sample data includes: Employee 'John Smith' with attendance records from '2024-01-01' to '2024-01-31' on Device 'Main Entrance Scanner'
- Attendance logs page is accessible from the manager dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance logs page from the manager dashboard by clicking on 'Attendance Logs' menu item | Attendance logs page loads successfully and displays the attendance logs UI with filter panel on the left, data grid in the center showing all recent attendance records with columns: Employee Name, Employee ID, Check-in Time, Check-out Time, Device Name, Location, Status |
| 2 | Verify the initial display of attendance logs without any filters applied | System displays all attendance logs sorted by most recent timestamp first, showing at least 20 records per page with pagination controls at the bottom |
| 3 | In the filter panel, enter 'John Smith' in the Employee Name field | Employee Name field accepts the input and displays autocomplete suggestions if available |
| 4 | Select date range filter: Start Date='2024-01-01', End Date='2024-01-15' | Date picker controls accept the selected dates and display them in the filter panel |
| 5 | Click the 'Apply Filters' button | System processes the filters within 3 seconds and displays only attendance logs for employee 'John Smith' between '2024-01-01' and '2024-01-15', showing filtered record count (e.g., 'Showing 28 records') |
| 6 | Verify the accuracy of filtered results by checking employee names and dates in the displayed records | All displayed records show 'John Smith' as the employee and dates fall within the specified range '2024-01-01' to '2024-01-15', with accurate timestamps and device information |
| 7 | Click the 'Export' button and select 'CSV' format from the dropdown menu | System generates CSV file within 5 seconds and initiates download with filename format 'attendance_logs_YYYYMMDD_HHMMSS.csv' |
| 8 | Open the downloaded CSV file and verify its contents | CSV file contains all filtered attendance records with proper headers (Employee Name, Employee ID, Check-in Time, Check-out Time, Device Name, Location, Status) and data matches the on-screen filtered results |
| 9 | Return to the attendance logs page and click the 'Export' button, then select 'PDF' format | System generates PDF file within 5 seconds and initiates download with filename format 'attendance_logs_YYYYMMDD_HHMMSS.pdf' |
| 10 | Open the downloaded PDF file and verify its contents | PDF file contains all filtered attendance records in a formatted table with company header, filter criteria summary, and data matches the on-screen filtered results with proper pagination |

**Postconditions:**
- Filtered attendance logs are displayed accurately on screen
- CSV and PDF export files are successfully generated and downloaded
- Export files contain accurate data matching the applied filters
- User can continue to apply different filters or export additional reports
- System performance remains within 3 seconds for log retrieval

---

### Test Case: Verify access restriction for unauthorized users
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Test user account with non-attendance manager role (e.g., 'Employee' or 'HR Staff') exists in the system
- User credentials for non-attendance manager account are available: Username='employee01', Password='emppass123'
- Attendance logs page URL is known: '/manager/attendance-logs'
- Attendance logs API endpoint is known: 'GET /api/attendance/logs'
- User is currently logged out of the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page and enter non-attendance manager credentials: Username='employee01', Password='emppass123' | System authenticates the user successfully and redirects to the employee dashboard appropriate for their role |
| 2 | Verify the main navigation menu options available to the logged-in user | Navigation menu does not display 'Attendance Logs' or 'Attendance Management' options that are specific to Attendance Manager role |
| 3 | Manually enter the attendance logs page URL '/manager/attendance-logs' in the browser address bar and press Enter | System denies access and displays 'Access Denied' or '403 Forbidden' error page with message 'You do not have permission to access attendance logs. This feature is restricted to Attendance Managers only.' |
| 4 | Verify that the user is not redirected to the attendance logs page and remains on the error page | User remains on the access denied error page and cannot view any attendance log data |
| 5 | Open browser developer tools and attempt to make a GET request to '/api/attendance/logs' endpoint | API returns HTTP 403 Forbidden status code with JSON response: {"error":"Authorization failed","message":"Insufficient permissions to access attendance logs"} |
| 6 | Attempt to make a GET request to '/api/attendance/logs' with query parameters: '?employeeName=John Smith&startDate=2024-01-01&endDate=2024-01-31' | API returns HTTP 403 Forbidden status code regardless of query parameters, preventing any data access |
| 7 | Check system security audit logs for the unauthorized access attempts | System logs all unauthorized access attempts with username 'employee01', timestamp, attempted resource '/manager/attendance-logs' and '/api/attendance/logs', and 'Access Denied' status |

**Postconditions:**
- Non-attendance manager user remains unable to access attendance logs functionality
- No attendance log data is exposed or accessible to unauthorized users
- All unauthorized access attempts are logged in the security audit log
- System maintains 100% role-based access control enforcement
- User session remains active but restricted to authorized features only

---

