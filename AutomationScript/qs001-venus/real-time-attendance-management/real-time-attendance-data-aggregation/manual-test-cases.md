# Manual Test Cases

## Story: As Attendance System Administrator, I want to integrate biometric device data to achieve real-time attendance data aggregation
**Story ID:** story-1

### Test Case: Validate successful biometric data ingestion
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Admin user has valid credentials and access to admin dashboard
- Biometric device is operational and accessible
- Attendance database is available and has sufficient storage
- Network connectivity between system and biometric device is stable
- Test biometric device API credentials are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the admin dashboard using valid administrator credentials | Admin dashboard loads successfully and displays configuration options |
| 2 | Navigate to biometric device configuration section in admin dashboard | Biometric device configuration page is displayed with input fields for connection settings |
| 3 | Enter biometric device connection details including API endpoint, authentication credentials, and polling interval | All configuration fields accept input and display entered values correctly |
| 4 | Click 'Save' or 'Apply' button to save the biometric device connection settings | Success message is displayed confirming connection settings saved successfully, and settings are persisted in the system |
| 5 | Simulate a biometric attendance event by having a test employee scan their biometric credential on the connected device | Biometric device registers the attendance event and makes data available via API |
| 6 | Wait for system to retrieve the attendance event data and monitor the data ingestion process | System retrieves event data from biometric device within 1 minute of the event occurrence |
| 7 | Query the attendance database to verify the newly ingested attendance record | Attendance record exists in database with correct employee ID, timestamp matching the biometric event time (within acceptable margin), and device identifier |
| 8 | Compare the stored data fields with the original biometric event details | All data fields match exactly including employee ID, timestamp, location, and event type (check-in/check-out) |

**Postconditions:**
- Biometric device connection remains active and configured
- Test attendance record is stored in the database
- System continues to monitor and ingest subsequent biometric events
- Admin dashboard reflects successful connection status

---

### Test Case: Verify retry mechanism on connection failure
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Biometric device connection is already configured and operational
- Admin has access to system logs and monitoring dashboard
- System retry mechanism is enabled with configured retry intervals
- Ability to control biometric device API availability for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Access the biometric device API control panel or test environment | API control interface is accessible and shows current API status as active |
| 2 | Disable or stop the biometric device API service temporarily to simulate connection failure | Biometric device API becomes unavailable and returns connection errors |
| 3 | Wait for the system to attempt its next scheduled data pull from the biometric device | System attempts connection and fails due to unavailable API |
| 4 | Access system logs and search for connection failure entries related to biometric device | System logs contain clear connection failure messages with timestamp, device identifier, and error details |
| 5 | Monitor system behavior and logs for automatic retry attempts | System automatically initiates retry attempts according to configured retry policy without manual intervention |
| 6 | Review system logs to verify retry attempts are being logged | Each retry attempt is logged with accurate timestamps, attempt number, and failure reason |
| 7 | Re-enable or restart the biometric device API service to restore availability | Biometric device API becomes available and responds to connection requests successfully |
| 8 | Monitor system logs and data ingestion status for successful reconnection | System successfully reconnects to biometric device on next retry attempt |
| 9 | Verify that system resumes normal data ingestion operations | System resumes pulling attendance data from biometric device and processes new events successfully |
| 10 | Check admin dashboard for connection status update | Admin dashboard shows connection restored and displays successful data ingestion status |

**Postconditions:**
- Biometric device connection is restored and operational
- All connection failures and retry attempts are logged in system logs
- System resumes normal data ingestion operations
- No data loss occurred during the connection failure period

---

### Test Case: Ensure secure data transmission
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Biometric device connection is configured and active
- Network traffic inspection tools are available (e.g., Wireshark, Fiddler)
- Test environment allows network traffic monitoring
- Invalid API credentials are available for unauthorized access testing
- Admin has access to system audit logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Start network traffic monitoring tool and configure it to capture traffic between the system and biometric device | Network monitoring tool is active and capturing packets on the relevant network interface |
| 2 | Trigger a biometric attendance event to initiate data transmission from device to system | Data transmission occurs and network traffic is captured by monitoring tool |
| 3 | Analyze captured network packets to inspect the data transmission protocol and encryption | Data is transmitted using secure protocol (HTTPS/TLS) and payload is encrypted, not readable in plain text |
| 4 | Verify authentication headers and tokens in the captured traffic | Authentication credentials are present, properly formatted, and transmitted securely (not in plain text) |
| 5 | Attempt to access the biometric device API endpoint using invalid or missing authentication credentials | API request is rejected immediately without processing |
| 6 | Review the error response returned by the API for unauthorized access attempt | API returns proper HTTP 401 Unauthorized or 403 Forbidden status code with appropriate error message indicating authentication failure |
| 7 | Attempt to access the API using expired authentication tokens | Access is denied with proper error message indicating token expiration |
| 8 | Navigate to system audit logs section in admin dashboard | Audit logs interface is accessible and displays recent access attempts |
| 9 | Search audit logs for entries related to the unauthorized access attempts made in previous steps | All unauthorized access attempts are logged with timestamp, source IP, attempted credentials, and failure reason |
| 10 | Verify that successful authentication attempts are also logged in audit logs | Successful access attempts are logged with timestamp, authenticated user/service, and action performed |

**Postconditions:**
- Network monitoring tool is stopped and traffic capture is saved for review
- All unauthorized access attempts are documented in audit logs
- System security remains intact with no unauthorized access granted
- Biometric device connection continues to operate securely

---

## Story: As Attendance System Administrator, I want to aggregate manual attendance entries to achieve comprehensive real-time attendance data
**Story ID:** story-2

### Test Case: Validate ingestion of manual attendance data
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Admin user has valid credentials and access to manual data upload interface
- Sample manual attendance CSV file is prepared with valid data format
- Biometric attendance data already exists in the system for comparison
- Attendance database is operational and accessible
- Admin monitoring interface is available and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the admin dashboard using valid administrator credentials | Admin dashboard loads successfully and displays manual data upload options |
| 2 | Navigate to the manual attendance data upload section | Manual data upload interface is displayed with file upload controls and format instructions |
| 3 | Click 'Browse' or 'Choose File' button and select the prepared sample manual attendance CSV file | File selection dialog opens and selected file name is displayed in the upload interface |
| 4 | Click 'Upload' or 'Import' button to initiate the manual attendance data ingestion | File upload begins and progress indicator is displayed |
| 5 | Wait for the system to process and ingest the uploaded CSV file | System completes ingestion within 5 minutes and displays success message with number of records processed |
| 6 | Verify that system normalizes the manual attendance records to match the standard database schema | All manual attendance records are converted to standard format with consistent field names, date/time formats, and data types |
| 7 | Query the attendance database to retrieve both biometric and manual attendance records for the same time period | Database query returns combined results showing both biometric and manual attendance entries |
| 8 | Verify that manual entries are merged with biometric data without creating duplicate records | No duplicate attendance records exist for the same employee at the same timestamp; manual entries supplement biometric data appropriately |
| 9 | Check that attendance records are accurate by comparing uploaded CSV data with database entries | All fields match exactly including employee ID, date, time, attendance type, and any additional metadata |
| 10 | Navigate to the admin monitoring interface for manual data ingestion | Monitoring interface loads and displays recent ingestion activities |
| 11 | Review the ingestion status for the recently uploaded CSV file | Ingestion status shows successful completion with timestamp, file name, number of records processed, and any warnings or errors |
| 12 | Verify that any errors or validation warnings are clearly displayed in the monitoring interface | Errors and warnings are displayed with specific details including row numbers, field names, and error descriptions |

**Postconditions:**
- Manual attendance data is successfully stored in the database
- Manual and biometric attendance data are merged without duplicates
- Ingestion status is recorded in the monitoring interface
- System is ready to accept additional manual data uploads

---

### Test Case: Verify conflict detection for duplicate entries
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Admin user has access to manual data upload interface
- Test CSV file with intentional duplicate attendance records is prepared
- Existing attendance data is present in the database for conflict testing
- Admin monitoring interface is accessible
- Conflict resolution workflow is configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the admin dashboard using valid administrator credentials | Admin dashboard loads successfully |
| 2 | Navigate to the manual attendance data upload section | Manual data upload interface is displayed |
| 3 | Select and upload the test CSV file containing duplicate attendance records (same employee, same date/time) | File is uploaded and system begins processing |
| 4 | Wait for system to complete validation and ingestion process | System completes processing and displays summary of results including detected conflicts |
| 5 | Verify that system identifies and flags duplicate records during ingestion | System detects duplicate entries and flags them as conflicts without automatically overwriting existing data |
| 6 | Check system logs for conflict detection entries | System logs contain detailed conflict entries with employee ID, timestamp, conflicting values, and conflict type |
| 7 | Navigate to the admin monitoring interface to view flagged conflicts | Monitoring interface displays a conflicts section or tab with list of detected conflicts |
| 8 | Review the conflict details displayed in the monitoring interface | Each conflict is clearly identified with employee name/ID, date/time, existing value, new value, and conflict reason |
| 9 | Verify that conflicts are presented in a user-friendly format for admin review | Conflicts are displayed in a table or list format with clear labels, color coding, and action options |
| 10 | Select a flagged conflict and choose resolution option (e.g., keep existing, use new, or merge) | Resolution options are available and selectable for each conflict |
| 11 | Apply the selected resolution to resolve the conflict | System accepts the resolution choice and updates the conflict status |
| 12 | Trigger reprocessing of the resolved conflicts | System reprocesses the data according to the resolution choices made |
| 13 | Verify that attendance records are updated in the database according to the resolution | Database records reflect the resolved conflicts with correct data based on admin's resolution choices |
| 14 | Check that resolved conflicts are marked as completed in the monitoring interface | Resolved conflicts show updated status with resolution timestamp and admin user who resolved them |

**Postconditions:**
- All duplicate conflicts are detected and logged
- Conflicts are resolved according to admin decisions
- Attendance database contains accurate, deduplicated records
- Conflict resolution history is maintained in system logs
- Monitoring interface reflects current conflict status

---

## Story: As Attendance System Administrator, I want to monitor data ingestion health to achieve reliable real-time attendance data
**Story ID:** story-5

### Test Case: Validate ingestion health dashboard displays accurate status
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in as Attendance System Administrator
- Ingestion health monitoring dashboard is accessible
- Data ingestion system is operational
- Test environment has capability to simulate ingestion scenarios
- Alert notification system is configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the ingestion health monitoring dashboard | Dashboard loads successfully and displays current ingestion status overview |
| 2 | Simulate normal data ingestion by triggering a standard data feed from attendance sources | Dashboard shows healthy status with green indicators, displays current metrics including ingestion rate, records processed, and last successful ingestion timestamp |
| 3 | Verify all metrics on the dashboard are updating in real-time | Metrics refresh automatically showing live data, ingestion count increments, and status remains healthy |
| 4 | Simulate ingestion failure by stopping the data source or introducing a connection error | Dashboard status changes to failure state with red indicators, error message is displayed, and failure timestamp is recorded |
| 5 | Check for alert notification sent to administrators | Alert is sent immediately via configured channels (email/SMS/in-app) with details of the ingestion failure including timestamp and error type |
| 6 | Navigate to the logs section from the dashboard | Logs section opens displaying recent ingestion events |
| 7 | Review logs for the simulated failure event | Detailed logs are available showing failure timestamp, error description, affected data source, stack trace if applicable, and troubleshooting information |
| 8 | Filter logs by failure events only | Logs are filtered successfully showing only failure events with complete details for troubleshooting |
| 9 | Restore normal data ingestion | Dashboard status returns to healthy state, metrics resume normal updates, and recovery event is logged |

**Postconditions:**
- Dashboard accurately reflects current ingestion health status
- All simulated events are logged in the system
- Alert notifications were successfully delivered
- Data ingestion is restored to normal operational state
- Test data from simulation is cleaned up or marked as test data

---

## Story: As Attendance System Administrator, I want to handle data discrepancies to achieve accurate attendance aggregation
**Story ID:** story-9

### Test Case: Validate detection of duplicate attendance records
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as Attendance System Administrator
- Attendance data processing system is operational
- Discrepancy detection algorithms are enabled
- Admin notification system is configured
- Test attendance records are prepared for injection
- Admin interface for discrepancy management is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare duplicate attendance records with identical employee ID, date, and timestamp | Test duplicate records are ready for injection with matching key fields |
| 2 | Inject duplicate attendance records into the system through the data ingestion pipeline | Records are successfully ingested into the system for processing |
| 3 | Wait for the system to process the ingested records | System completes processing and runs discrepancy detection algorithms |
| 4 | Check the discrepancy detection system for flagged duplicates | System automatically flags the duplicate records and marks them as discrepancies with duplicate type classification |
| 5 | Verify that admin notification was sent | Administrator receives notification via configured channels indicating duplicate records detected with count and affected employee IDs |
| 6 | Navigate to the admin interface for discrepancy management | Discrepancy management interface loads showing list of flagged discrepancies |
| 7 | Admin reviews the flagged duplicate records in the interface | Duplicates are clearly identified with side-by-side comparison showing matching fields, timestamp details, and source information for easy resolution |
| 8 | Admin selects the duplicate records and chooses resolution action (keep one, merge, or delete) | Resolution options are available and clearly presented with preview of outcome |
| 9 | Admin resolves duplicates by selecting to keep the first record and remove the duplicate | System processes the resolution request successfully |
| 10 | Verify attendance data is updated after resolution | Attendance data reflects the resolution with duplicate removed, only one valid record remains, and discrepancy status is cleared |
| 11 | Check that the discrepancy no longer appears in the flagged items list | Resolved discrepancy is removed from active discrepancies list and marked as resolved |

**Postconditions:**
- Duplicate attendance records are successfully detected and flagged
- Administrator was notified of the discrepancy
- Discrepancy is resolved and attendance data is accurate
- Resolution action is recorded in the system
- No duplicate records remain in active attendance data

---

### Test Case: Verify logging of discrepancy events
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Attendance System Administrator
- Discrepancy detection system is operational
- Logging system is enabled and configured
- Test data is available to generate various discrepancy types
- Log viewing interface is accessible to administrators

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate multiple discrepancy events by injecting duplicate records into the system | Duplicate records are processed and flagged as discrepancies |
| 2 | Generate conflicting timestamp discrepancy by injecting records with same employee but overlapping time periods | Conflicting timestamp records are processed and flagged as discrepancies |
| 3 | Generate anomaly discrepancy by injecting unusual attendance pattern (e.g., multiple check-ins without check-out) | Anomaly records are processed and flagged as discrepancies |
| 4 | Navigate to the discrepancy logs section in the admin interface | Discrepancy logs interface loads successfully |
| 5 | Review the logs for all generated discrepancy events | All discrepancy events are logged with accurate timestamps, discrepancy type, affected employee IDs, record details, and detection time |
| 6 | Verify each log entry contains complete information including event ID, timestamp, discrepancy type, affected records, and detection details | Each log entry displays comprehensive information with all required fields populated accurately |
| 7 | Filter logs by discrepancy type (duplicate) | Logs are filtered successfully showing only duplicate discrepancy events |
| 8 | Filter logs by date range covering the test period | Logs are filtered to show only events within the specified date range |
| 9 | Search logs by specific employee ID involved in discrepancies | Logs are filtered to show only discrepancies related to the searched employee ID |
| 10 | Export discrepancy logs for audit purposes | Logs are exported successfully in a standard format (CSV/PDF) with complete and accurate discrepancy history |
| 11 | Verify the exported file contains all log entries with timestamps and details | Exported file contains complete and accurate discrepancy history matching the displayed logs |
| 12 | Resolve one of the discrepancies and check if resolution is logged | Resolution action is logged with timestamp, admin user who resolved it, resolution method, and outcome |

**Postconditions:**
- All discrepancy events are logged in the system
- Logs contain complete and accurate information for audit purposes
- Log filtering and search functionality is verified
- Discrepancy history is available for compliance and troubleshooting
- Resolution actions are tracked in the logs

---

