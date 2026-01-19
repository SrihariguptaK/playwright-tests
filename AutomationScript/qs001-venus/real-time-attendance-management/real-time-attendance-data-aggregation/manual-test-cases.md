# Manual Test Cases

## Story: As Attendance System Administrator, I want to integrate biometric devices to achieve real-time attendance data collection
**Story ID:** story-13

### Test Case: Validate successful connection and data reception from biometric devices
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Admin user has valid credentials and access to admin interface
- Biometric device is powered on and network accessible
- Biometric device API credentials are available
- Attendance database is operational and accessible
- System has network connectivity to biometric device

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the admin interface with valid administrator credentials | Admin dashboard is displayed successfully |
| 2 | Navigate to biometric device configuration section | Device configuration page is displayed with connection settings form |
| 3 | Enter biometric device API endpoint, authentication credentials, and device identifier | Configuration fields accept input and display entered values |
| 4 | Click 'Test Connection' button to verify device connectivity | System displays 'Connection Successful' message with device status as 'Connected' |
| 5 | Save the biometric device configuration | Configuration is saved successfully and confirmation message is displayed |
| 6 | Simulate an attendance event on the biometric device by scanning a registered employee fingerprint | Biometric device registers the scan and sends event data to the system |
| 7 | Monitor the admin dashboard real-time data feed for the attendance event | Attendance event appears in the dashboard within 1 minute showing employee ID, timestamp, and device ID |
| 8 | Navigate to attendance database query interface or run database query to retrieve the latest attendance record | Database query returns the attendance record successfully |
| 9 | Compare the database record fields (employee ID, timestamp, device ID, event type) with the original biometric device output | All event data fields match exactly between biometric device output and database record |
| 10 | Verify the timestamp difference between event occurrence and database storage | Time difference is less than 1 minute, confirming real-time data collection |

**Postconditions:**
- Biometric device remains connected and operational
- Valid attendance event is stored in database
- Admin dashboard shows active device status
- System is ready to receive subsequent attendance events

---

### Test Case: Verify system handles corrupted attendance data
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Biometric device is connected and configured in the system
- Admin has access to admin dashboard
- Error logging mechanism is enabled
- Database contains existing valid attendance records for comparison
- Test environment allows simulation of corrupted data transmission

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Access the test data simulation tool or API endpoint for sending attendance events | Test tool or API endpoint is accessible and ready to accept test data |
| 2 | Prepare corrupted attendance event data with missing employee ID field | Corrupted test payload is created with incomplete data structure |
| 3 | Send the corrupted attendance event data to the system via biometric device API endpoint | System receives the corrupted data transmission |
| 4 | Observe system response and check for error response code (e.g., 400 Bad Request) | System rejects the data with appropriate error response code and validation error message |
| 5 | Navigate to system error logs or logging dashboard | Error log interface displays recent error entries |
| 6 | Search for the error entry corresponding to the corrupted data submission with timestamp and error details | Error log contains entry with timestamp, error type 'Data Validation Failed', details about missing employee ID, and source device information |
| 7 | Access the admin dashboard and navigate to error notifications section | Admin dashboard displays error notifications panel |
| 8 | Verify the error notification displays details including timestamp, device ID, error type, and description | Error notification is visible with complete details: 'Corrupted data rejected - Missing employee ID from Device [device-id] at [timestamp]' |
| 9 | Query the attendance database for records matching the timestamp of the corrupted data submission | Database query returns no record for the corrupted event timestamp |
| 10 | Verify database integrity by checking that only valid records exist and record count has not increased | Database contains only valid attendance records with complete required fields, confirming corrupted data was not stored |
| 11 | Send additional corrupted data with invalid timestamp format | System rejects data and logs error with description 'Invalid timestamp format' |
| 12 | Confirm no corrupted records from any test iteration are present in the database | Final database verification shows zero corrupted records and all existing records are valid |

**Postconditions:**
- No corrupted data exists in the attendance database
- All error events are logged with complete details
- Admin dashboard displays all error notifications
- System continues to accept valid attendance events normally
- Data integrity is maintained

---

### Test Case: Test device disconnection and automatic reconnection
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Biometric device is connected and actively sending attendance data
- Admin is logged into the admin dashboard
- System has automatic reconnection feature enabled
- Network connectivity can be controlled for testing
- Alert notification system is configured and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify biometric device status on admin dashboard shows 'Connected' with green indicator | Dashboard displays device status as 'Connected' with last heartbeat timestamp within the last minute |
| 2 | Note the current timestamp and number of attendance events received | Baseline metrics are recorded for comparison after reconnection |
| 3 | Simulate biometric device disconnection by disabling network connection or stopping the device service | Network connection to biometric device is interrupted |
| 4 | Monitor the admin dashboard for device status change | Within 30 seconds, device status changes to 'Disconnected' with red indicator and timestamp of disconnection |
| 5 | Check for admin alert notification regarding device disconnection | Alert notification is displayed on dashboard and/or sent via configured channel (email/SMS) with message 'Biometric Device [device-id] disconnected at [timestamp]' |
| 6 | Verify system logs contain disconnection event entry | System log shows entry with severity 'Warning', message 'Device disconnection detected', device ID, and timestamp |
| 7 | Observe system behavior during disconnection period for 2 minutes | System continues normal operation for other connected devices and displays disconnection status for affected device |
| 8 | Restore the biometric device connection by re-enabling network or restarting device service | Network connection to biometric device is restored |
| 9 | Monitor admin dashboard for automatic reconnection attempt | Within 1 minute, system detects device availability and initiates reconnection automatically without manual intervention |
| 10 | Verify device status changes to 'Connected' on admin dashboard | Device status indicator turns green showing 'Connected' with reconnection timestamp |
| 11 | Check for reconnection success notification on admin dashboard | Notification displays 'Biometric Device [device-id] reconnected successfully at [timestamp]' |
| 12 | Simulate a new attendance event on the reconnected biometric device | Attendance event is captured and transmitted to the system successfully |
| 13 | Verify the new attendance event is received and stored in the database within 1 minute | Database contains the new attendance record confirming data collection has resumed |
| 14 | Review system logs for the disconnection period | Logs contain entries documenting: disconnection timestamp, disconnection duration, reconnection timestamp, and confirmation that no data was received during disconnection period |
| 15 | Verify no data loss by confirming that system properly logged the disconnection period and resumed normal operation | System logs clearly indicate the disconnection window, no corrupted data was stored, and normal operation resumed immediately after reconnection |

**Postconditions:**
- Biometric device is reconnected and operational
- System is actively receiving attendance events
- Disconnection period is logged with start and end timestamps
- Admin dashboard shows current connected status
- No data corruption occurred during disconnection/reconnection cycle
- System is ready to handle future disconnection events

---

## Story: As Attendance System Administrator, I want to integrate badge scan systems to achieve comprehensive attendance data aggregation
**Story ID:** story-14

### Test Case: Validate successful badge scan data ingestion
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Admin user has valid credentials and access to admin interface
- Badge scan system is operational and network accessible
- Badge scan system API credentials are available
- Attendance database is operational
- At least one employee badge is registered in the system
- System supports 5000 events per minute throughput

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the admin interface using valid administrator credentials | Admin dashboard is displayed with navigation menu and system status overview |
| 2 | Navigate to badge scan system integration configuration section | Badge scan system configuration page is displayed with connection settings form |
| 3 | Enter badge scan system API endpoint URL in the configuration field | API endpoint URL is accepted and displayed in the input field |
| 4 | Enter authentication credentials (API key or username/password) for badge scan system | Authentication credentials are accepted and masked appropriately for security |
| 5 | Enter badge scan system identifier and location information | System identifier and location fields are populated correctly |
| 6 | Click 'Test Connection' button to verify connectivity to badge scan system | System establishes connection and displays 'Connection Successful' message with badge scan system status as 'Active' |
| 7 | Save the badge scan system configuration by clicking 'Save' button | Configuration is saved successfully, confirmation message is displayed, and badge scan system appears in the list of connected systems |
| 8 | Navigate to the real-time data monitoring dashboard | Monitoring dashboard displays with badge scan system listed as active data source |
| 9 | Simulate a badge scan event by scanning a registered employee badge at the badge reader | Badge reader registers the scan with visual/audio confirmation and transmits event data to the system |
| 10 | Monitor the real-time data feed on the admin dashboard for the badge scan event | Badge scan event appears in the dashboard within 1 minute displaying employee ID, badge ID, timestamp, location, and scan type (entry/exit) |
| 11 | Record the exact timestamp when the event appears on the dashboard | Timestamp is recorded for latency verification |
| 12 | Calculate the time difference between badge scan occurrence and dashboard display | Time difference is less than 1 minute, confirming real-time ingestion requirement |
| 13 | Open database query interface or execute SQL query to retrieve the badge scan attendance record | Database query interface returns the attendance record successfully |
| 14 | Verify the database record contains all required fields: employee ID, badge ID, timestamp, location, scan type, and system identifier | All required fields are present and populated with data |
| 15 | Compare database record values with the original badge scan event data (employee ID, badge ID, timestamp, location) | All data fields match exactly between badge scan event and database record, confirming data integrity |
| 16 | Verify the record timestamp in database matches the badge scan event timestamp | Timestamps match precisely, confirming accurate data capture |

**Postconditions:**
- Badge scan system remains connected and operational
- Valid badge scan event is stored in attendance database
- Admin dashboard shows active badge scan system status
- System is ready to receive subsequent badge scan events
- Data integrity is maintained between source and database

---

### Test Case: Verify duplicate badge scan event filtering
- **ID:** tc-005
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Badge scan system is connected and configured
- Admin has access to admin dashboard
- Duplicate detection mechanism is enabled
- Database contains existing attendance records
- Test environment allows simulation of duplicate events
- Duplicate detection rules are configured (e.g., same employee, same location, within 5 seconds)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into admin dashboard and navigate to badge scan data monitoring section | Badge scan monitoring interface is displayed with real-time event feed |
| 2 | Query the database to get the current count of attendance records for baseline | Current record count is retrieved and documented |
| 3 | Prepare a badge scan event with specific employee ID, badge ID, timestamp, and location | Test badge scan event data is prepared with all required fields |
| 4 | Send the first badge scan event to the system via badge scan API endpoint | System receives and processes the event successfully, returns HTTP 200 status |
| 5 | Verify the first event is stored in the database by querying for the specific employee ID and timestamp | Database query returns one record matching the event details |
| 6 | Immediately send an identical duplicate badge scan event with the same employee ID, badge ID, timestamp, and location | System receives the duplicate event transmission |
| 7 | Observe system response to the duplicate event submission | System detects duplicate and returns HTTP 200 status with message 'Duplicate event detected and filtered' |
| 8 | Query the database again for records matching the employee ID and timestamp | Database query returns only one record, confirming duplicate was not stored |
| 9 | Verify the total record count in database has increased by only one since baseline | Record count shows increment of 1, confirming only the first event was stored |
| 10 | Send a third duplicate event with the same details | System receives the third duplicate event |
| 11 | Check system logs for duplicate event entries | System logs contain entries for both duplicate events with severity 'Info', message 'Duplicate badge scan event filtered', employee ID, timestamp, and badge ID |
| 12 | Navigate to admin dashboard duplicate event alerts section | Dashboard displays duplicate event alerts panel |
| 13 | Verify duplicate event alerts show the number of duplicates detected and details | Alert displays '2 duplicate events detected for Employee [employee-id] at [timestamp] from Location [location]' |
| 14 | Check the duplicate events report or statistics section on dashboard | Dashboard shows duplicate event statistics including count, affected employees, and time range |
| 15 | Send a valid non-duplicate badge scan event with different timestamp (6 seconds later) for the same employee | System accepts and stores the new event as it falls outside duplicate detection window |
| 16 | Verify the new event is stored in database as a separate record | Database now contains two records for the employee with different timestamps, confirming duplicate filtering only affects true duplicates |

**Postconditions:**
- Only unique badge scan events are stored in database
- All duplicate events are logged with complete details
- Admin dashboard displays duplicate event alerts and statistics
- System continues to accept valid non-duplicate events
- Data integrity is maintained without duplicate records

---

### Test Case: Test automatic reconnection on badge scan system failure
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Badge scan system is connected and actively sending data
- Admin is logged into admin dashboard
- Automatic reconnection feature is enabled with retry configuration
- Network connectivity can be controlled for testing
- Alert notification system is operational
- System has retry interval configured (e.g., retry every 30 seconds)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Access admin dashboard and navigate to badge scan system status monitoring page | Status monitoring page displays badge scan system with 'Connected' status and green indicator |
| 2 | Verify the last successful data transmission timestamp is recent (within last minute) | Dashboard shows last data received timestamp within the last 60 seconds |
| 3 | Document the current connection status, uptime, and number of events received | Baseline metrics are recorded: status 'Connected', uptime duration, event count |
| 4 | Simulate badge scan system disconnection by disabling network connection, stopping the badge scan service, or blocking API endpoint | Network connection to badge scan system is interrupted and system becomes unreachable |
| 5 | Monitor the admin dashboard for system detection of the failure | Within 30-60 seconds, dashboard detects connection failure and updates status |
| 6 | Verify badge scan system status changes to 'Disconnected' or 'Failed' with red indicator | Status indicator turns red, displays 'Disconnected', and shows timestamp of failure detection |
| 7 | Check for admin alert notification regarding badge scan system failure | Alert notification appears on dashboard with message 'Badge Scan System [system-id] at [location] disconnected at [timestamp]' and severity level 'Critical' |
| 8 | Verify alert is sent through configured notification channels (email, SMS, or in-app) | Alert notification is delivered through all configured channels with failure details |
| 9 | Check system logs for failure detection entry | System log contains entry with timestamp, severity 'Error', message 'Badge scan system connection failed', system ID, and error details |
| 10 | Observe dashboard for automatic reconnection attempts indicator | Dashboard shows 'Attempting to reconnect...' message with retry counter or progress indicator |
| 11 | Wait for one retry interval (e.g., 30 seconds) and verify system attempts reconnection | System log shows reconnection attempt with timestamp and attempt number |
| 12 | Allow system to continue retry attempts while badge scan system remains disconnected for 2 minutes | System continues automatic retry attempts at configured intervals without manual intervention |
| 13 | Restore the badge scan system connection by re-enabling network, restarting service, or unblocking API endpoint | Badge scan system becomes reachable and operational again |
| 14 | Monitor dashboard for successful automatic reconnection | Within one retry interval (30-60 seconds), system detects availability and successfully reconnects |
| 15 | Verify badge scan system status changes to 'Connected' with green indicator | Status indicator turns green, displays 'Connected', and shows reconnection timestamp |
| 16 | Check for reconnection success notification on admin dashboard | Success notification displays 'Badge Scan System [system-id] reconnected successfully at [timestamp]' with severity 'Info' |
| 17 | Verify system logs contain reconnection success entry | Log entry shows timestamp, message 'Badge scan system reconnected successfully', system ID, downtime duration, and number of retry attempts |
| 18 | Simulate a new badge scan event by scanning an employee badge | Badge reader captures the scan and transmits event to the system |
| 19 | Verify the new badge scan event is received and displayed on the dashboard within 1 minute | Event appears on dashboard with all details confirming data ingestion has resumed |
| 20 | Query the database to confirm the new event is stored successfully | Database contains the new badge scan record with correct timestamp and details, confirming full operational recovery |
| 21 | Review complete system logs for the entire disconnection and reconnection cycle | Logs provide complete audit trail: failure detection, retry attempts, reconnection success, and resumption of data ingestion |

**Postconditions:**
- Badge scan system is reconnected and fully operational
- System is actively receiving and storing badge scan events
- Disconnection period is logged with start time, end time, and duration
- Admin dashboard shows current connected status
- All reconnection attempts are logged
- System is ready to handle future connection failures with automatic recovery
- No data corruption occurred during failure and recovery cycle

---

## Story: As Attendance System Administrator, I want to monitor data ingestion health to achieve reliable attendance data availability
**Story ID:** story-19

### Test Case: Validate ingestion health dashboard updates
- **ID:** tc-019-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with admin credentials
- Ingestion system is running and processing data
- Dashboard monitoring service is active
- Test environment has access to ingestion health dashboard URL
- At least one data source is configured for ingestion

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the ingestion health dashboard URL (GET /monitoring/ingestion) | Dashboard loads successfully and displays current ingestion status with recent metrics including timestamp, data source status, records processed, and last update time within the last minute |
| 2 | Observe the dashboard for 2 minutes without any interaction | Dashboard automatically refreshes every minute showing updated metrics and timestamps reflecting the refresh cycle |
| 3 | Simulate an ingestion failure by stopping the data ingestion service or disconnecting a data source | Within 1-2 minutes, dashboard status changes to 'Failed' or 'Error' state with red indicator, error message is displayed, and timestamp shows when failure was detected |
| 4 | Check the alerts section or notification panel on the dashboard | Alert is generated and displayed showing failure details including affected data source, failure time, and error type |
| 5 | Navigate to the historical logs section from the dashboard menu | Historical logs page loads displaying a chronological list of ingestion events |
| 6 | Review the historical logs for the simulated failure event | Logs show detailed ingestion events including the failure event with timestamp, data source name, error message, stack trace or error details, and event severity level |
| 7 | Filter logs by date range to view events from the last hour | Logs are filtered correctly showing only events within the specified time range including the recent failure |

**Postconditions:**
- Dashboard continues to display real-time status
- Alert remains visible until acknowledged or issue is resolved
- Historical logs are preserved and accessible
- Simulated failure is documented in the system
- Test data source can be restored to normal operation

---

### Test Case: Verify admin access control
- **ID:** tc-019-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Test environment has both admin and non-admin user accounts configured
- Non-admin user credentials are available (username and password)
- Admin user credentials are available (username and password)
- Ingestion health dashboard URL is accessible
- Authentication system is functioning properly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log out from any existing session and clear browser cache/cookies | User is logged out successfully and session is cleared |
| 2 | Log in to the system using non-admin user credentials | Login is successful and user is redirected to the default landing page for non-admin users |
| 3 | Attempt to access the ingestion health dashboard by navigating to GET /monitoring/ingestion URL | Access is denied with HTTP 403 Forbidden error or user is redirected to an 'Access Denied' page with message indicating insufficient permissions |
| 4 | Verify that no dashboard data or metrics are visible in the response | No sensitive ingestion data, metrics, or dashboard components are displayed or accessible in the page source |
| 5 | Log out from the non-admin account | User is logged out successfully and redirected to login page |
| 6 | Log in to the system using admin user credentials | Login is successful and admin user is authenticated |
| 7 | Navigate to the ingestion health dashboard URL (GET /monitoring/ingestion) | Access is granted and dashboard loads successfully displaying all ingestion health metrics, status indicators, alerts, and navigation options |
| 8 | Verify all dashboard features are accessible including real-time metrics, historical logs, and alert configurations | All admin-level features are visible and functional with no access restrictions |

**Postconditions:**
- Non-admin user remains unable to access monitoring dashboard
- Admin user retains full access to all monitoring features
- Access control logs record both denied and successful access attempts
- No security vulnerabilities are exposed during testing
- User sessions are properly managed

---

## Story: As Attendance System Administrator, I want to validate incoming attendance data to achieve data integrity
**Story ID:** story-21

### Test Case: Validate acceptance of correct attendance data
- **ID:** tc-021-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has admin or system-level access to submit attendance events
- Attendance validation API endpoint (POST /attendance/validate) is accessible
- Database is running and accepting connections
- Valid employee IDs exist in the system database
- System clock is synchronized for accurate timestamp validation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare a valid attendance event JSON payload with all required fields: employee ID (existing in system), timestamp (current date/time in ISO 8601 format), event type (e.g., 'check-in' or 'check-out'), and location | Valid JSON payload is created with proper schema structure and all mandatory fields populated with correct data types |
| 2 | Send POST request to /attendance/validate endpoint with the valid attendance event payload | API accepts the request and returns HTTP 200 OK status code |
| 3 | Review the API response body for validation confirmation | Response contains success message indicating event passed validation with details such as validation_status: 'passed', event_id, and timestamp of validation |
| 4 | Measure and record the response time from request submission to response receipt | Validation process completes in under 500 milliseconds as indicated by response time metrics |
| 5 | Query the attendance database to verify the event was stored | Attendance event is successfully stored in the database with all field values matching the submitted payload including employee ID, timestamp, event type, and location |
| 6 | Check validation logs for the processed event | Validation log entry exists showing successful validation with event details, validation timestamp, and 'accepted' status |

**Postconditions:**
- Valid attendance event is persisted in the database
- Validation log contains successful validation entry
- System remains ready to process subsequent events
- No error notifications are generated
- Database integrity is maintained

---

### Test Case: Verify rejection of invalid attendance data
- **ID:** tc-021-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User has admin or system-level access to submit attendance events
- Attendance validation API endpoint (POST /attendance/validate) is accessible
- Validation error logging system is active
- Admin notification system is configured and operational
- Database is running and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare an invalid attendance event JSON payload with missing employee ID field but including other fields like timestamp and event type | Invalid JSON payload is created with employee ID field intentionally omitted or set to null |
| 2 | Send POST request to /attendance/validate endpoint with the invalid attendance event payload | API receives the request and processes it through validation logic |
| 3 | Review the API response status code | API returns HTTP 400 Bad Request status code indicating validation failure |
| 4 | Examine the API response body for error details | Response contains error message clearly stating 'Missing required field: employee_id' or similar, with validation_status: 'failed' and list of validation errors |
| 5 | Query the attendance database to confirm the invalid event was not stored | Database does not contain the invalid attendance event, confirming rejection prevented data storage |
| 6 | Check the validation error logs for the rejected event | Error log entry exists with details including timestamp, rejected payload, specific validation error (missing employee_id), and rejection reason |
| 7 | Verify admin notification system for validation error alert | Admin receives notification (email, dashboard alert, or system message) containing validation error details including event timestamp, error type, missing field information, and payload summary |
| 8 | Measure the validation response time | Validation and rejection process completes within 500 milliseconds |

**Postconditions:**
- Invalid attendance event is not stored in the database
- Error log contains detailed rejection entry
- Admin is notified of validation failure
- System continues to operate normally and accept subsequent valid events
- Data integrity is preserved

---

### Test Case: Test duplicate event detection
- **ID:** tc-021-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has admin or system-level access to submit attendance events
- Attendance validation API endpoint (POST /attendance/validate) is accessible
- Database contains at least one existing attendance event for testing
- Duplicate detection mechanism is enabled in the validation system
- Validation logs are accessible and recording events

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare a valid attendance event JSON payload with all required fields: employee ID, timestamp, event type, and location | Valid JSON payload is created with complete and correct data |
| 2 | Send POST request to /attendance/validate endpoint with the attendance event payload for the first time | API returns HTTP 200 OK and event is accepted, validated, and stored successfully in the database |
| 3 | Verify the first event is stored by querying the database using employee ID and timestamp | Database query returns the stored attendance event with all field values matching the submitted payload |
| 4 | Immediately send another POST request to /attendance/validate endpoint with the exact same attendance event payload (duplicate) | API receives the duplicate request and processes it through validation and duplicate detection logic |
| 5 | Review the API response status code for the duplicate submission | API returns HTTP 409 Conflict or HTTP 200 OK with duplicate detection message indicating the event was identified as a duplicate |
| 6 | Examine the API response body for duplicate detection details | Response contains message such as 'Duplicate event detected and discarded' with details including original event timestamp and duplicate detection criteria (matching employee_id, timestamp, event_type) |
| 7 | Query the database to confirm only one instance of the event exists | Database query returns only one record for the specific employee ID and timestamp combination, confirming duplicate was not stored |
| 8 | Check validation logs for duplicate detection entry | Log entry exists showing duplicate detection with details including original event ID, duplicate submission timestamp, and 'discarded' status |
| 9 | Measure the duplicate detection response time | Duplicate detection and rejection process completes within 500 milliseconds |

**Postconditions:**
- Only one instance of the attendance event exists in the database
- Duplicate event is logged but not stored
- System maintains data integrity without duplicate records
- Validation logs contain both acceptance and duplicate detection entries
- System remains operational for processing new unique events

---

