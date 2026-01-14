# Manual Test Cases

## Story: As Biometric System Administrator, I want to configure biometric device integration to achieve seamless automatic attendance capture
**Story ID:** story-1

### Test Case: Validate successful biometric device configuration
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Biometric System Administrator role
- Biometric device is powered on and connected to the network
- Valid device IP address, port, and credentials are available
- Employee records exist in the system for user mapping
- Network connectivity between system and device is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to biometric device configuration page from the admin dashboard | Configuration form is displayed with fields for IP address, port, credentials, and user mapping section |
| 2 | Enter valid device IP address in the IP address field | IP address is accepted and no validation error is shown |
| 3 | Enter valid port number in the port field | Port number is accepted and no validation error is shown |
| 4 | Enter valid device credentials (username and password) | Credentials are accepted and masked appropriately |
| 5 | Navigate to user mapping section and select biometric device users from the list | List of device users is displayed for selection |
| 6 | Map each biometric device user to corresponding employee ID from the dropdown | Employee IDs are successfully mapped to device users without validation errors |
| 7 | Click 'Test Connection' button | Connection test initiates and completes within 5 seconds showing 'Connection Successful' message |
| 8 | Click 'Save Configuration' button | Configuration is saved successfully with confirmation message displayed |
| 9 | Verify device appears in the device list with 'Active' status | Device is listed with 'Active' status and data reception indicator shows 'Receiving Data' |

**Postconditions:**
- Biometric device configuration is saved in the system
- Device is actively receiving attendance data
- Device appears on the monitoring dashboard with online status
- User mappings are stored and active

---

### Test Case: Verify error handling for invalid device parameters
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Biometric System Administrator role
- Biometric device configuration page is accessible
- System validation rules are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to biometric device configuration page | Configuration form is displayed with empty fields |
| 2 | Enter invalid IP address format (e.g., '999.999.999.999' or 'invalid-ip') | Validation error message is displayed: 'Invalid IP address format. Please enter a valid IP address.' |
| 3 | Correct the IP address and enter invalid port number (e.g., '99999' or '-1') | Validation error message is displayed: 'Port number must be between 1 and 65535.' |
| 4 | Correct the port number and leave credentials fields empty | Validation error message is displayed: 'Device credentials are required.' |
| 5 | Enter all fields with invalid but properly formatted data (unreachable IP) | Form accepts the input format without client-side validation errors |
| 6 | Click 'Test Connection' button with invalid parameters | Connection test fails within 5 seconds with descriptive error message: 'Connection failed. Unable to reach device at specified IP address. Please verify device is online and parameters are correct.' |
| 7 | Correct all parameters with valid and reachable device information | All fields accept the corrected values without validation errors |
| 8 | Click 'Test Connection' button again | Connection test succeeds within 5 seconds showing 'Connection Successful' message |
| 9 | Click 'Save Configuration' button | Configuration is saved successfully with confirmation message |

**Postconditions:**
- Valid device configuration is saved after corrections
- Invalid configurations are not saved in the system
- Error messages are cleared after successful validation

---

### Test Case: Ensure device status dashboard updates correctly
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Biometric System Administrator role
- At least one biometric device is configured in the system
- Device is currently online and transmitting data
- Dashboard refresh interval is set to 5 minutes or less
- Test environment allows device status simulation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to device status dashboard from the main menu | Dashboard is displayed showing list of all configured biometric devices with current status indicators (online/offline), last sync time, and data transmission status |
| 2 | Verify the current status of the test device | Device shows 'Online' status with green indicator and recent last sync timestamp |
| 3 | Simulate device offline status by disconnecting the device from network or stopping the device service | Device physical connection is interrupted |
| 4 | Wait for dashboard auto-refresh or manually refresh the dashboard (within 5 minutes) | Dashboard updates to show device with 'Offline' status, red indicator, and alert notification appears stating 'Device [Device Name] is offline' |
| 5 | Click on the offline device to view detailed status information | Device detail page displays offline status, last known sync time, and error message indicating connection loss |
| 6 | Restore device connectivity by reconnecting to network or restarting device service | Device is physically reconnected and operational |
| 7 | Wait for dashboard auto-refresh or manually refresh the dashboard (within 5 minutes) | Dashboard reflects device 'Online' status with green indicator, alert is cleared or marked as resolved, and last sync time is updated to current time |
| 8 | Verify alert history shows the offline and online status changes | Alert history log displays timestamps for device offline event and device online restoration event |

**Postconditions:**
- Device status dashboard accurately reflects current device state
- Status change history is logged in the system
- Alerts are properly generated and cleared based on device status
- Device is online and operational

---

## Story: As Biometric Device Technician, I want to monitor biometric device health and connectivity to ensure reliable attendance data capture
**Story ID:** story-6

### Test Case: Display real-time device connectivity status
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Biometric Device Technician user account exists with proper role assignment
- Multiple biometric devices are configured and operational in the system
- Monitoring dashboard is accessible and functional
- Test environment allows device status simulation
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page and enter valid Biometric Device Technician credentials | Login is successful and user is redirected to the technician dashboard |
| 2 | Verify access to monitoring dashboard is granted | Monitoring dashboard is displayed with navigation menu showing device monitoring options |
| 3 | View the list of all biometric devices on the monitoring dashboard | Complete list of biometric devices is displayed with columns showing device name, location, current connectivity status (Online/Offline), last sync time, and health indicator |
| 4 | Verify each device displays current connectivity status with appropriate visual indicators | Online devices show green status indicator, offline devices show red indicator, and status labels are clearly visible |
| 5 | Note the current timestamp and status of a specific test device | Device shows 'Online' status with current timestamp within the last 5 minutes |
| 6 | Simulate device disconnection by disconnecting the test device from network | Device is physically disconnected from the network |
| 7 | Monitor the dashboard and wait for status update (maximum 1 minute) | Within 1 minute, device status updates to 'Offline' with red indicator, and last sync time shows the timestamp before disconnection |
| 8 | Verify alert notification appears for the disconnected device | Alert notification is displayed indicating device disconnection with device name and timestamp |
| 9 | Reconnect the test device to the network | Device is physically reconnected and operational |
| 10 | Monitor the dashboard for status update (maximum 1 minute) | Within 1 minute, device status updates to 'Online' with green indicator, and last sync time is updated to current timestamp |

**Postconditions:**
- Device connectivity status is accurately displayed in real-time
- Status changes are logged in the system
- Test device is back online and operational
- Technician remains logged in with active session

---

### Test Case: Generate alerts for device malfunctions
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Biometric Device Technician
- Monitoring dashboard is accessible
- At least one biometric device is configured and operational
- Alert system is enabled and functional
- Test environment allows error condition simulation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Access the device monitoring dashboard | Dashboard is displayed showing all devices and current alert status panel |
| 2 | Verify the alerts panel shows no active alerts for the test device | Alerts panel shows 'No active alerts' or empty state for the test device |
| 3 | Simulate device error condition (e.g., authentication failure, sensor malfunction, or data transmission error) | Error condition is successfully triggered on the test device |
| 4 | Monitor the dashboard for alert generation (maximum 1 minute) | Within 1 minute, alert is generated and displayed on the dashboard with error details including device name, error type, severity level, and timestamp |
| 5 | Verify alert notification appears in the alerts panel | Alert appears in the alerts panel with 'New' or 'Unacknowledged' status, highlighted for visibility |
| 6 | Click on the alert to view detailed information | Alert detail modal or page opens showing comprehensive error information, affected device details, error logs, and recommended actions |
| 7 | Click 'Acknowledge Alert' button | Acknowledgement confirmation dialog appears |
| 8 | Confirm alert acknowledgement | Alert status updates to 'Acknowledged' with technician name and acknowledgement timestamp displayed |
| 9 | Verify alert remains visible but marked as acknowledged | Alert is still displayed in the alerts panel but with 'Acknowledged' status and different visual indicator (e.g., gray instead of red) |
| 10 | Check alert history log | Alert history shows the complete lifecycle: generation time, acknowledgement time, and technician who acknowledged |

**Postconditions:**
- Alert is generated and logged in the system
- Alert status is updated to acknowledged
- Alert history is maintained for audit purposes
- Technician action is recorded with timestamp

---

### Test Case: Restrict monitoring access to authorized technicians
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Multiple user accounts exist with different roles (Technician, Employee, Manager, etc.)
- Unauthorized user account credentials are available for testing
- Role-based access control is configured and active
- Monitoring dashboard requires technician role authorization
- API endpoints have proper authentication and authorization

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page and enter credentials of an unauthorized user (non-technician role) | Login is successful and user is redirected to their role-appropriate dashboard |
| 2 | Attempt to navigate to the biometric device monitoring dashboard URL directly | Access is denied with error message: 'Access Denied. You do not have permission to view this page. Technician role required.' User is redirected to their home dashboard or access denied page |
| 3 | Verify monitoring dashboard menu option is not visible in navigation | Device monitoring menu option is not displayed in the navigation menu for unauthorized user |
| 4 | Open browser developer tools and attempt to make direct API call to GET /api/biometric/devices/status endpoint using current session | API request returns HTTP 403 Forbidden status code with error response: 'Authorization error: Insufficient permissions. Technician role required.' |
| 5 | Logout from the unauthorized user account | User is successfully logged out and redirected to login page |
| 6 | Login with valid Biometric Device Technician credentials | Login is successful and technician is redirected to monitoring dashboard |
| 7 | Verify monitoring dashboard is accessible and displays device information | Monitoring dashboard is fully accessible showing all biometric devices with status, health metrics, and alerts |
| 8 | Verify device monitoring menu option is visible in navigation | Device monitoring menu option is displayed and accessible in the navigation menu |
| 9 | Make API call to GET /api/biometric/devices/status endpoint using technician session | API request returns HTTP 200 OK status with complete device status data in JSON format |

**Postconditions:**
- Unauthorized access attempts are logged for security audit
- Access control remains enforced for monitoring dashboard
- Authorized technician has full access to monitoring features
- System security is maintained

---

