# Manual Test Cases

## Story: As Biometric System Administrator, I want to configure biometric device connections to achieve reliable data capture
**Story ID:** story-1

### Test Case: Validate adding biometric device with valid parameters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as an administrator with device configuration permissions
- Device configuration database is accessible
- Network connectivity is available
- Test biometric device is powered on and reachable on the network

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to device configuration page from the main menu or dashboard | Configuration form is displayed with fields for IP address, port, device name, and communication protocol. All input fields are empty and enabled |
| 2 | Enter valid IP address (e.g., 192.168.1.100) in the IP address field | IP address is accepted and displayed in the correct format without any validation errors |
| 3 | Enter valid port number (e.g., 4370) in the port field | Port number is accepted and displayed correctly without any validation errors |
| 4 | Enter device name (e.g., Main Entrance Device) in the device name field | Device name is accepted and displayed in the field |
| 5 | Select communication protocol from dropdown (e.g., TCP/IP) | Protocol is selected and displayed in the dropdown field |
| 6 | Click the Submit or Save Configuration button | System displays a loading indicator and initiates connectivity test. Configuration is saved to the database |
| 7 | Wait for connectivity test to complete | System displays success message indicating device configuration saved successfully. Device status shows as 'Connected' or 'Online'. Connectivity test completes within 3 seconds |
| 8 | Verify the newly added device appears in the device list | Device is listed with correct IP address, port, name, and status showing as active/connected |

**Postconditions:**
- Biometric device configuration is saved in the database
- Device status is set to active/connected
- Configuration change is logged with administrator username and timestamp
- Device is ready to capture biometric data

---

### Test Case: Reject invalid IP address during device configuration
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as an administrator with device configuration permissions
- Device configuration page is accessible
- Form validation rules are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to device configuration page from the main menu or dashboard | Configuration form is displayed with all required input fields visible and enabled |
| 2 | Enter invalid IP address format in the IP address field (e.g., 999.999.999.999) | Inline validation error message is displayed below or next to the IP address field indicating 'Invalid IP address format' or similar descriptive error |
| 3 | Enter valid port number (e.g., 4370) in the port field | Port number is accepted without errors |
| 4 | Attempt to click the Submit or Save Configuration button | Submission is blocked. Submit button is either disabled or clicking it displays an error message. Error message clearly states 'Please correct the IP address format before submitting' or similar |
| 5 | Clear the IP address field and enter another invalid format (e.g., 192.168.1) | Inline validation error message is displayed indicating incomplete or invalid IP address format |
| 6 | Attempt to submit the configuration again | Submission is blocked with error message displayed. Configuration is not saved to the database |
| 7 | Enter alphabetic characters in IP address field (e.g., abc.def.ghi.jkl) | Inline validation error message is displayed indicating invalid characters in IP address field |

**Postconditions:**
- No device configuration is saved in the database
- User remains on the device configuration page with error messages visible
- No connectivity test is initiated
- No configuration change is logged

---

### Test Case: Restrict device configuration access to authorized users
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Two user accounts are available: one with non-administrator role and one with administrator role
- Role-based access control is configured and active
- Device configuration page requires administrator privileges

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using non-administrator user credentials (e.g., regular employee or attendance viewer role) | User is successfully logged in and redirected to the appropriate dashboard for their role |
| 2 | Attempt to navigate to device configuration page by clicking menu item or entering URL directly | Access is denied. System displays 'Access Denied' or '403 Forbidden' message. User is either redirected to their dashboard or shown an error page stating insufficient permissions |
| 3 | Verify that device configuration menu item is not visible or is disabled in the navigation menu | Device configuration option is either hidden from the menu or displayed as disabled/grayed out for non-administrator users |
| 4 | Logout from the non-administrator account | User is successfully logged out and redirected to the login page |
| 5 | Login to the system using administrator user credentials | Administrator is successfully logged in and redirected to the administrator dashboard |
| 6 | Navigate to device configuration page from the menu | Access is granted. Device configuration page loads successfully with all configuration options visible and enabled |
| 7 | Verify that all device configuration features are accessible (add, edit, delete, test connectivity) | All configuration features are visible and functional. Administrator can interact with all form fields and action buttons |

**Postconditions:**
- Non-administrator user access attempt is logged in security audit log
- Administrator has full access to device configuration functionality
- Role-based access control is enforced correctly

---

## Story: As Attendance Manager, I want to review biometric attendance logs to ensure data accuracy
**Story ID:** story-2

### Test Case: Filter attendance logs by date and employee
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as an Attendance Manager with log viewing permissions
- Attendance logs database contains test data with multiple employees and date ranges
- At least 50 attendance records exist spanning multiple dates and employees
- Export functionality is enabled and configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to attendance logs page from the main menu or dashboard | Attendance logs page is displayed showing a list of attendance records with columns for timestamp, employee ID, employee name, device information, and status. Filter panel is visible with date range and employee ID filter options |
| 2 | Select start date in the date range filter (e.g., 2024-01-01) | Start date is selected and displayed in the date picker field |
| 3 | Select end date in the date range filter (e.g., 2024-01-31) | End date is selected and displayed in the date picker field |
| 4 | Enter specific employee ID in the employee ID filter field (e.g., EMP12345) | Employee ID is entered and displayed in the filter field |
| 5 | Click Apply Filters or Search button | System displays loading indicator and then shows filtered logs. Only attendance records matching the specified date range and employee ID are displayed. Record count is updated to reflect filtered results |
| 6 | Verify that all displayed records match the filter criteria by checking dates and employee IDs | All displayed records have timestamps within the selected date range (2024-01-01 to 2024-01-31) and employee ID matches EMP12345. No records outside the criteria are shown |
| 7 | Click the Export or Download CSV button | System initiates CSV file download. Browser displays download progress or save dialog |
| 8 | Open the downloaded CSV file in a spreadsheet application | CSV file opens successfully and contains all filtered records with correct data including timestamp, employee ID, employee name, device information, and status. Data matches what was displayed on screen. File includes appropriate headers |
| 9 | Verify the number of records in CSV matches the filtered results count | Record count in CSV file matches the count displayed on the attendance logs page |

**Postconditions:**
- Filtered attendance logs remain displayed on screen
- CSV file is successfully downloaded to user's device
- Filter criteria remain applied for subsequent operations
- User action is logged in system audit trail

---

### Test Case: Search attendance logs by employee name
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as an Attendance Manager with log viewing permissions
- Attendance logs database contains records with various employee names
- At least some attendance records have rejected or error status
- Search functionality is enabled and configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to attendance logs page from the main menu or dashboard | Attendance logs page is displayed with all attendance records visible. Search box is prominently displayed at the top of the page or in the filter panel |
| 2 | Locate the search box for employee name or ID | Search box is clearly labeled (e.g., 'Search by Employee Name or ID') and is enabled for input |
| 3 | Enter a specific employee name in the search box (e.g., 'John Smith') | Employee name is entered and displayed in the search box. System may show auto-suggestions if available |
| 4 | Press Enter or click the Search button | System displays loading indicator briefly and then shows filtered results. Only attendance logs matching the employee name 'John Smith' are displayed. Record count is updated |
| 5 | Verify that all displayed records belong to the searched employee | All displayed records show employee name as 'John Smith' or matching variations. Employee ID is consistent across all records |
| 6 | Scan through the displayed logs to identify any rejected or error entries | Rejected or error entries are visually distinct from normal entries. They are highlighted with different background color (e.g., red or yellow), different text color, or special icon/badge indicating error status |
| 7 | Click on or hover over a rejected entry to view details | Rejected entry displays additional information such as rejection reason, error code, or tooltip explaining why the entry was rejected |
| 8 | Verify the visual distinction is consistent across all rejected entries in the results | All rejected or error entries have the same consistent visual highlighting. Normal/successful entries do not have this highlighting. The distinction is clear and easily identifiable |
| 9 | Clear the search box and verify results reset | When search box is cleared, all attendance logs are displayed again without the employee name filter applied |

**Postconditions:**
- Search results remain displayed until user clears search or applies new filters
- Rejected entries remain visually highlighted
- Search query is logged in system audit trail
- User can perform additional actions on the filtered results

---

## Story: As Biometric System Administrator, I want to handle biometric device disconnections to maintain continuous attendance tracking
**Story ID:** story-9

### Test Case: Detect and retry biometric device disconnection
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Biometric System Administrator
- At least one biometric device is connected and operational
- Device status monitoring service is active and running
- Alert notification system is configured and operational
- System clock is synchronized for accurate timing measurements

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the biometric device management interface and verify the target device shows 'Connected' status | Device status displays as 'Connected' with green indicator and last heartbeat timestamp is current |
| 2 | Simulate device disconnection by unplugging the network cable or disabling the device connection | Device physically disconnects from the network |
| 3 | Monitor the system response and note the time taken to detect the disconnection | System detects the disconnection within 10 seconds and updates device status to 'Disconnected' with red indicator |
| 4 | Observe the system behavior for automatic retry attempts over the next 2 minutes | System automatically attempts to reconnect to the device every 30 seconds (at 30s, 60s, 90s, 120s intervals) |
| 5 | Check the device connection logs to verify retry attempts are being recorded | Connection logs show timestamped entries for each retry attempt with status 'Connection Failed' or 'Retry Attempted' |
| 6 | Continue monitoring the disconnected device for 5 minutes without reconnecting | System continues retry attempts every 30 seconds throughout the 5-minute period |
| 7 | After exactly 5 minutes of disconnection, check administrator notification channels (email, SMS, in-app notifications) | Administrator receives alert notification indicating prolonged disconnection with device details, disconnection duration, and timestamp |
| 8 | Verify the alert contains device name, location, disconnection time, and recommended actions | Alert message includes all required information: device identifier, location, exact disconnection timestamp, duration (5 minutes), and troubleshooting suggestions |
| 9 | Reconnect the device by restoring network connection | Device reconnects successfully on the next retry attempt (within 30 seconds) |
| 10 | Verify the device status updates to 'Connected' and reconnection event is logged | Device status changes to 'Connected' with green indicator, and system logs show reconnection event with timestamp |

**Postconditions:**
- Device is reconnected and operational
- All disconnection and reconnection events are logged in the system
- Administrator has received and acknowledged the alert notification
- Device status dashboard reflects current connected state
- System resumes normal monitoring of the device

---

### Test Case: View real-time device status on dashboard
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Biometric System Administrator
- Multiple biometric devices are registered in the system
- At least one device is currently connected
- Device status monitoring service is running
- Dashboard has real-time update capability enabled
- Browser supports real-time updates (WebSocket or polling enabled)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the main menu, click on 'Device Management' or 'Device Status Dashboard' option | System navigates to the device status dashboard page |
| 2 | Observe the dashboard layout and verify all registered devices are displayed | Dashboard displays a list or grid view of all registered biometric devices with their current status |
| 3 | Check each device entry for status indicators including connection status, device name, location, and last activity timestamp | Each device shows: device name, location, connection status (Connected/Disconnected with color coding), last heartbeat time, and device health indicators |
| 4 | Identify a currently connected device and note its status as 'Connected' with green indicator | Target device displays 'Connected' status with green indicator and recent last activity timestamp |
| 5 | Simulate device disconnection by physically disconnecting the target device or disabling its network connection | Device is physically disconnected from the network |
| 6 | Keep the dashboard open and monitor for automatic status updates without refreshing the page | Within 10 seconds, the dashboard automatically updates the device status to 'Disconnected' with red indicator without manual page refresh |
| 7 | Verify the disconnection timestamp is displayed and updates in real-time | Dashboard shows 'Last seen: [timestamp]' and displays duration of disconnection that updates in real-time |
| 8 | Reconnect the device by restoring its network connection | Device reconnects to the network successfully |
| 9 | Observe the dashboard for automatic status update to reflect reconnection | Within 30 seconds (next retry cycle), dashboard automatically updates device status to 'Connected' with green indicator without manual page refresh |
| 10 | Verify the reconnection timestamp and current heartbeat status are displayed accurately | Dashboard shows updated 'Last seen' timestamp reflecting current time and connection status shows 'Connected' with active heartbeat indicator |
| 11 | Check if dashboard provides additional information such as connection uptime, total disconnection events, and device health metrics | Dashboard displays comprehensive device information including uptime percentage, disconnection count, and overall device health status |

**Postconditions:**
- Device status dashboard accurately reflects current state of all devices
- Real-time updates are functioning correctly
- Device is reconnected and showing connected status
- All status changes are reflected in the dashboard without manual refresh
- Administrator has visibility into current device health and connectivity

---

