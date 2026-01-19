# Manual Test Cases

## Story: As Biometric System Administrator, I want to configure biometric device connections to achieve seamless data integration
**Story ID:** story-22

### Test Case: Validate successful device configuration addition
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Biometric System Administrator
- User has valid administrator credentials and permissions
- Biometric device configuration module is accessible
- Test biometric device is available with known valid IP, port, and credentials
- Database is accessible and configuration table is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to biometric device configuration page from the main menu or dashboard | Configuration form is displayed with fields for device IP, port, and credentials. Form is empty and ready for input |
| 2 | Enter valid device IP address (e.g., 192.168.1.100) in the IP field | IP address is accepted and displayed in the field without validation errors |
| 3 | Enter valid port number (e.g., 4370) in the port field | Port number is accepted and displayed in the field without validation errors |
| 4 | Enter valid device credentials (username and password) in the respective fields | Credentials are accepted, password field shows masked characters, no validation errors displayed |
| 5 | Click the Submit or Save button to save the configuration | System initiates connectivity test to the device, loading indicator is displayed |
| 6 | Wait for connectivity test to complete | Configuration is saved successfully to the database, connectivity test passes, success message is displayed confirming device connection, device appears in the device list with 'Connected' status |

**Postconditions:**
- New biometric device configuration is saved in the database
- Device is listed in the active devices list with connected status
- Configuration change is logged in audit trail with administrator username and timestamp
- Device credentials are encrypted in storage
- Device is ready for attendance data capture

---

### Test Case: Verify rejection of invalid device parameters
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Biometric System Administrator
- User has valid administrator credentials and permissions
- Biometric device configuration module is accessible
- Configuration form validation rules are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to biometric device configuration page from the main menu or dashboard | Configuration form is displayed with empty fields for device IP, port, and credentials |
| 2 | Enter invalid IP address format (e.g., '999.999.999.999' or 'invalid-ip') in the IP field | Inline validation error is displayed below or next to the IP field indicating invalid IP format (e.g., 'Please enter a valid IP address') |
| 3 | Enter invalid port number (e.g., '99999' or '-1' or 'abc') in the port field | Inline validation error is displayed below or next to the port field indicating invalid port range (e.g., 'Port must be between 1 and 65535') |
| 4 | Attempt to click the Submit or Save button with invalid inputs | Form submission is blocked, validation errors remain visible, error summary message is displayed at the top of the form listing all validation failures, no data is sent to the server |
| 5 | Correct the IP address to valid format (e.g., 192.168.1.100) but leave port as invalid | IP field validation error clears, port field validation error remains visible |
| 6 | Attempt to submit the form again | Submission is still blocked due to invalid port, error message for port field remains displayed |

**Postconditions:**
- No invalid configuration is saved to the database
- Form remains on the configuration page with validation errors visible
- No audit log entry is created for failed submission
- User can correct errors and retry submission

---

### Test Case: Ensure access control restricts unauthorized users
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Two user accounts are available: one with non-administrator role and one with administrator role
- Role-based access control is configured and active
- Biometric device configuration module requires administrator privileges
- API endpoints are protected with authentication and authorization

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using non-administrator user credentials (e.g., regular employee or viewer role) | User is successfully authenticated and logged into the system with limited permissions |
| 2 | Attempt to navigate to the biometric device configuration page via menu or direct URL | Access is denied, user is redirected to unauthorized access page or error message is displayed stating 'You do not have permission to access this page', configuration page is not displayed |
| 3 | Attempt to directly access the configuration API endpoint POST /api/biometric/devices using API testing tool or browser console | API returns HTTP 401 Unauthorized or 403 Forbidden error with appropriate error message, no configuration data is accessible or modifiable |
| 4 | Attempt to access the device status API endpoint GET /api/biometric/devices/status | API returns HTTP 401 Unauthorized or 403 Forbidden error, no device status data is returned |
| 5 | Logout from the non-administrator account | User is successfully logged out and returned to login page |
| 6 | Login to the system using administrator credentials | Administrator is successfully authenticated and logged into the system with full permissions |
| 7 | Navigate to the biometric device configuration page | Full access is granted, configuration page is displayed with all features accessible including add, edit, and delete device configurations |
| 8 | Access the configuration API endpoints POST /api/biometric/devices and GET /api/biometric/devices/status | API endpoints are accessible, return HTTP 200 OK status, and provide expected data or accept configuration requests |

**Postconditions:**
- Non-administrator users remain restricted from device configuration features
- Administrator users have full access to all configuration features
- All access attempts are logged in security audit trail
- System security integrity is maintained

---

## Story: As Biometric System Administrator, I want to monitor biometric device status to ensure continuous attendance data capture
**Story ID:** story-25

### Test Case: Validate real-time device status display
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has valid Biometric System Administrator credentials
- At least 2-3 biometric devices are configured and connected to the system
- Monitoring dashboard module is accessible and functional
- Device status polling service is running and updating every minute
- Alert notification system is configured and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using Biometric System Administrator credentials | Administrator is successfully authenticated and logged into the system, main dashboard or home page is displayed |
| 2 | Navigate to the biometric device monitoring dashboard from the main menu | Access is granted, monitoring dashboard page loads successfully within 5 seconds |
| 3 | View the device status panel on the monitoring dashboard | All configured biometric devices are listed with their current status (Online/Offline), device details include IP address, location, last sync time, and connection status indicator (green for online, red for offline), status information is accurate and matches actual device states |
| 4 | Observe the real-time status updates by waiting for the next polling cycle (approximately 1 minute) | Dashboard automatically refreshes and updates device status without manual page reload, timestamp of last update is displayed and current |
| 5 | Simulate a device offline event by disconnecting one of the biometric devices from the network or powering it off | Within the next polling cycle (maximum 1 minute), the device status changes from 'Online' to 'Offline', status indicator changes from green to red |
| 6 | Wait for alert notification to be triggered | Alert notification is triggered and displayed on the dashboard (banner, popup, or notification panel), alert message clearly indicates which device went offline with device name/IP and timestamp, notification appears within 5 seconds of status detection, alert is also logged in the notifications history |
| 7 | Reconnect the device and observe status update | Device status returns to 'Online' within the next polling cycle, alert is cleared or marked as resolved, status indicator returns to green |

**Postconditions:**
- All device status information is accurately displayed on the dashboard
- Alert notifications are properly logged in the system
- Device offline event is recorded in device logs
- Administrator is aware of device connectivity issues
- Dashboard remains accessible for continued monitoring

---

### Test Case: Verify access restriction to monitoring dashboard
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Two user accounts are available: one with non-administrator role and one with administrator role
- Role-based access control is configured and enforced
- Monitoring dashboard requires administrator privileges
- Monitoring API endpoints are protected with authentication and authorization

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using non-administrator user credentials (e.g., regular employee, HR staff, or viewer role) | User is successfully authenticated and logged into the system with limited permissions, user dashboard or home page is displayed |
| 2 | Attempt to navigate to the biometric device monitoring dashboard via menu or direct URL | Access to monitoring dashboard is denied, user is redirected to an unauthorized access page or receives error message 'Access Denied: You do not have permission to view this page', monitoring dashboard is not displayed, menu option for monitoring may be hidden or disabled |
| 3 | Attempt to directly access the monitoring API endpoint GET /api/biometric/devices/status using API testing tool, browser console, or direct HTTP request | API returns HTTP 401 Unauthorized or 403 Forbidden error response, error message indicates insufficient permissions (e.g., 'Unauthorized access' or 'Administrator privileges required'), no device status data is returned in the response |
| 4 | Verify that no monitoring data or device information is accessible through any alternative means for the non-administrator user | All monitoring-related features and data remain inaccessible, system maintains security boundaries |
| 5 | Logout from the non-administrator account | User is successfully logged out and session is terminated, login page is displayed |
| 6 | Login to the system using valid Biometric System Administrator credentials | Administrator is successfully authenticated with full permissions, administrator dashboard is displayed with access to all features |
| 7 | Navigate to the biometric device monitoring dashboard | Full access is granted to the monitoring dashboard, all device status information is visible and accessible, dashboard loads successfully with all monitoring features enabled |
| 8 | Access the monitoring API endpoint GET /api/biometric/devices/status | API endpoint is accessible and returns HTTP 200 OK status, device status data is returned in the response with complete information for all configured devices |

**Postconditions:**
- Non-administrator users remain restricted from monitoring dashboard and related features
- Administrator users have full access to monitoring capabilities
- All unauthorized access attempts are logged in security audit trail
- System access control integrity is verified and maintained
- No sensitive device information is exposed to unauthorized users

---

