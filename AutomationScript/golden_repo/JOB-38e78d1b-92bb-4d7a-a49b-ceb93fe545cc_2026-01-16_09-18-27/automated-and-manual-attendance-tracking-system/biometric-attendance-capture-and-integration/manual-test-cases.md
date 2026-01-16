# Manual Test Cases

## Story: As Biometric System Administrator, I want to configure biometric device connections to achieve seamless attendance data capture
**Story ID:** story-22

### Test Case: Validate successful device configuration with valid inputs
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as System Administrator
- User has permissions to configure biometric devices
- Device configuration page is accessible
- Valid biometric device IP address and credentials are available
- Database is operational and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to device configuration page from the admin dashboard | Device configuration page loads successfully and displays the device configuration form with fields for IP address, device name, credentials, and device type |
| 2 | Enter valid IP address (e.g., 192.168.1.100) in the IP address field | IP address is accepted and no validation error is displayed |
| 3 | Enter device name (e.g., 'Main Entrance Device') in the device name field | Device name is accepted without errors |
| 4 | Enter valid username and password credentials for the biometric device | Credentials are accepted and password field displays masked characters for security |
| 5 | Select device type from the dropdown menu (e.g., 'Fingerprint Scanner') | Device type is selected successfully |
| 6 | Click the 'Submit' or 'Save Configuration' button | System processes the configuration, validates the inputs, and displays a success message 'Device configured successfully'. The new device appears in the device list with status 'Active' |
| 7 | Verify the device configuration is saved in the database | Device configuration is stored with encrypted credentials and displays in the device management list |

**Postconditions:**
- New biometric device configuration is saved in the database
- Device credentials are encrypted and stored securely
- Device appears in the active devices list
- Device status is set to 'Active'
- Configuration timestamp is recorded

---

### Test Case: Verify device connectivity test functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as System Administrator
- At least one biometric device is configured in the system
- Device configuration page is accessible
- Network connectivity is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the device configuration page and locate the configured device in the device list | Device list is displayed showing all configured devices with their current status |
| 2 | Select the configured device and click the 'Test Connection' button | System initiates connection test and displays a loading indicator. Connection test completes within 5 seconds and displays either success or failure message based on device availability |
| 3 | Simulate device offline scenario by disconnecting the device from network or powering it off, then click 'Test Connection' again | System attempts connection and displays error message 'Connection failed: Device is unreachable' or similar error indicating connection failure. Device status updates to 'Offline' |
| 4 | Restore device connectivity by reconnecting to network or powering it on | Device is back online and accessible |
| 5 | Click 'Test Connection' button again to simulate device online scenario | System successfully connects to the device and displays success message 'Connection successful: Device is online and responding'. Device status updates to 'Online'. Last synchronization timestamp is updated |
| 6 | Verify connection test response time is under 5 seconds | Connection test completes and displays result within 5 seconds |

**Postconditions:**
- Device status is accurately reflected in the system
- Last connection test timestamp is recorded
- Connection test logs are stored for audit purposes
- Device synchronization status is updated

---

### Test Case: Ensure unauthorized users cannot access device configuration
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- System has role-based access control implemented
- Non-admin user account exists with limited permissions
- Admin user account exists with full permissions
- Device configuration page and API endpoints are protected

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using non-admin user credentials (e.g., regular employee or manager role) | User successfully logs in and is redirected to their authorized dashboard |
| 2 | Attempt to navigate to the device configuration page by entering the URL directly or through navigation menu | Access is denied. System displays error message 'Access Denied: You do not have permission to access this page' or redirects to unauthorized access page. Device configuration option is not visible in navigation menu |
| 3 | Attempt to access device configuration API endpoint POST /api/biometric-devices using API testing tool or browser | System returns HTTP 403 Forbidden or 401 Unauthorized error with message 'Authorization error: Insufficient permissions' |
| 4 | Attempt to access device status API endpoint GET /api/biometric-devices/status | System returns HTTP 403 Forbidden or 401 Unauthorized error with message 'Authorization error: Insufficient permissions' |
| 5 | Logout from non-admin user account | User is successfully logged out and redirected to login page |
| 6 | Login to the system using admin user credentials | Admin user successfully logs in and is redirected to admin dashboard |
| 7 | Navigate to the device configuration page | Access is granted. Device configuration page loads successfully with full functionality including add, edit, delete, and test connection options |
| 8 | Access device configuration API endpoints POST /api/biometric-devices and GET /api/biometric-devices/status | API endpoints are accessible and return HTTP 200 OK with appropriate data. Admin has full access to all device configuration APIs |

**Postconditions:**
- Non-admin users remain restricted from device configuration access
- Admin users retain full access to device configuration
- Access attempts are logged for security audit
- No unauthorized changes are made to device configurations

---

## Story: As Attendance Manager, I want to view real-time biometric attendance logs to achieve timely monitoring
**Story ID:** story-23

### Test Case: Verify real-time attendance log updates
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Attendance Manager
- Attendance dashboard is accessible
- Biometric devices are configured and operational
- At least one employee has existing attendance records
- Real-time data synchronization is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance dashboard from the main menu | Attendance dashboard loads within 3 seconds and displays the latest attendance logs with columns for employee name, ID, timestamp, device, and status |
| 2 | Note the current timestamp and total number of attendance entries displayed | Dashboard shows current attendance data with accurate count and latest entry timestamp |
| 3 | Simulate or trigger a new biometric entry by having an employee punch in/out at a biometric device | Biometric device captures the attendance entry successfully |
| 4 | Wait for 1 minute and observe the dashboard for automatic updates | New attendance entry appears on the dashboard within 1 minute without manual refresh. Entry count increases by 1 and the new entry is displayed at the top of the list with correct employee details, timestamp, and device information |
| 5 | Click the 'Refresh' or 'Reload' button on the dashboard | Dashboard reloads within 3 seconds and displays all current attendance data including the most recent entries. Data freshness indicator shows current timestamp |
| 6 | Verify data freshness by comparing dashboard timestamp with actual current time | Data freshness is within 1 minute of current time, meeting the 99% freshness requirement |

**Postconditions:**
- Dashboard displays all attendance entries including new ones
- Data freshness is maintained within 1-minute threshold
- No data loss or duplication occurs
- Dashboard performance remains under 3 seconds load time

---

### Test Case: Test filtering and search functionality
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Attendance Manager
- Attendance dashboard is loaded with multiple attendance records
- Multiple employees from different departments have attendance entries
- Multiple biometric devices have recorded attendance
- Date range includes multiple days of attendance data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | On the attendance dashboard, locate the filter section and select a specific department from the department dropdown (e.g., 'Engineering') | Department filter is applied and dashboard displays only attendance records for employees in the selected department. Record count updates to reflect filtered results |
| 2 | Select a specific date or date range from the date filter (e.g., today's date) | Date filter is applied in combination with department filter. Dashboard displays only matching attendance records for the selected department and date. Results are accurate and complete |
| 3 | Apply additional filter by selecting a specific biometric device from the device dropdown | Device filter is applied along with existing filters. Dashboard shows only attendance records matching all three criteria: department, date, and device. Filter combination works correctly |
| 4 | In the search box, enter an employee name (e.g., 'John Smith') and press Enter or click Search | Search is executed and dashboard displays attendance records only for the searched employee 'John Smith'. All entries show correct employee name, ID, and attendance details |
| 5 | Clear the name search and enter an employee ID (e.g., 'EMP001') in the search box | Search by employee ID is executed successfully. Dashboard shows all attendance records for employee with ID 'EMP001'. Search results are accurate and match the employee ID |
| 6 | Click 'Clear Filters' or 'Reset' button to remove all applied filters and search criteria | All filters and search criteria are cleared. Dashboard reloads and displays all attendance records without any filtering. Full dataset is visible again |
| 7 | Verify the total record count matches the unfiltered dataset | Record count shows total number of all attendance entries. Dashboard displays complete attendance data |

**Postconditions:**
- All filters can be applied individually or in combination
- Search functionality works accurately for both name and ID
- Filters and search can be cleared to restore full dataset
- Dashboard performance remains optimal with filtered results

---

### Test Case: Validate anomaly highlighting
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Attendance Manager
- Attendance dashboard is loaded with attendance records
- System has anomaly detection rules configured
- Test data includes attendance records with missing punches or duplicates
- Export functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Review the attendance dashboard and identify attendance records that have missing punch-in or punch-out entries | System automatically highlights attendance records with missing punches using visual indicators such as red background, warning icon, or colored border. Highlighted records are easily distinguishable from normal entries |
| 2 | Hover over or click on a highlighted anomaly record to view details | System displays tooltip or detail panel showing the specific anomaly type (e.g., 'Missing Punch-Out') and relevant information about the incomplete attendance entry |
| 3 | Identify any duplicate attendance entries for the same employee at similar timestamps | System highlights duplicate entries with appropriate visual indicator (e.g., yellow background or duplicate icon). Duplicates are clearly marked |
| 4 | Navigate to attendance correction interface and correct the missing punch entry by adding the missing punch-in or punch-out time | Correction is saved successfully and the attendance record is updated with complete information |
| 5 | Return to the attendance dashboard and locate the previously corrected record | Anomaly highlight is removed from the corrected record. The record now appears as a normal entry without any warning indicators. System accurately reflects the correction |
| 6 | Apply filters to show only current date attendance records, then click 'Export' or 'Download CSV' button | System generates CSV file with filtered attendance data. Download prompt appears within 3 seconds |
| 7 | Save and open the downloaded CSV file | CSV file contains all filtered attendance records with columns for employee ID, name, department, timestamp, device, status, and anomaly indicators. Data is accurate and matches dashboard display. File format is valid and can be opened in spreadsheet applications |
| 8 | Verify that anomaly records are marked or flagged in the exported CSV file | CSV file includes a column or indicator showing anomaly status for records with issues. Exported data maintains integrity and completeness |

**Postconditions:**
- Anomalies are accurately highlighted on the dashboard
- Corrected records no longer show anomaly indicators
- CSV export contains accurate filtered data
- Export file is properly formatted and complete
- Anomaly detection continues to function for new entries

---

