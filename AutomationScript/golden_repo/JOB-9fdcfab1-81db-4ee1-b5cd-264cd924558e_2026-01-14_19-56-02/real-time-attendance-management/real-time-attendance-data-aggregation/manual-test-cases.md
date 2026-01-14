# Manual Test Cases

## Story: As Attendance Manager, I want to integrate biometric devices to achieve real-time attendance data capture
**Story ID:** story-11

### Test Case: Validate successful biometric data capture and storage
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Biometric device is connected and authenticated with the system
- Test employee profile exists in the system with valid employee ID
- Database is accessible and has sufficient storage capacity
- System API endpoint POST /api/attendance/biometric is operational
- Network connectivity between biometric device and system is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate biometric device sending valid attendance event with employee ID, timestamp, and biometric data | System receives the biometric event successfully and returns HTTP 200 status code |
| 2 | Verify the system processes and stores the attendance record with correct employee ID and timestamp | Attendance record is created in the system with matching employee ID, accurate timestamp, and event type (check-in/check-out) |
| 3 | Query the attendance database to retrieve the newly created attendance record | Database record exists with all fields populated correctly: employee ID, timestamp, biometric device ID, and event status |
| 4 | Verify the attendance record data matches the original biometric event data | All data fields in the database record match exactly with the biometric event data sent by the device |
| 5 | Check system logs for any errors or warnings related to the biometric data capture | No errors or warnings are logged; system logs show successful data capture and storage operation |
| 6 | Verify the data capture latency by comparing event timestamp with storage timestamp | Data is stored within 1 minute of the biometric event capture time |

**Postconditions:**
- Attendance record is successfully stored in the database
- System logs reflect successful operation with no errors
- Biometric device remains connected and ready for next event
- Database integrity is maintained

---

### Test Case: Verify rejection of duplicate biometric attendance events
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Biometric device is connected and authenticated with the system
- Test employee profile exists in the system
- An initial valid attendance event has been successfully captured and stored
- System duplicate detection mechanism is enabled
- Database contains the original attendance record

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Send a duplicate attendance event for the same employee with identical timestamp and event type as the previously stored record | System detects the duplicate event and rejects it with appropriate error code (e.g., HTTP 409 Conflict) |
| 2 | Verify that the system logs a warning message indicating duplicate event detection | System logs contain a warning entry with details of the duplicate event including employee ID, timestamp, and rejection reason |
| 3 | Query the attendance database to check for duplicate records with same employee ID and timestamp | Only one attendance record exists in the database; no duplicate records are found |
| 4 | Verify the original attendance record remains unchanged in the database | Original attendance record data is intact with no modifications to timestamp, employee ID, or other fields |
| 5 | Check that the duplicate rejection is recorded in the audit trail | Audit trail contains an entry showing the duplicate event was rejected with timestamp and reason |

**Postconditions:**
- Only the original attendance record exists in the database
- System logs contain warning about duplicate rejection
- Biometric device connection remains stable
- System is ready to process new valid events

---

### Test Case: Test system behavior on biometric device connectivity loss
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Biometric device is initially connected and operational
- System monitoring and error logging mechanisms are active
- Administrator notification system is configured and operational
- Test employee profile exists in the system
- Network connectivity can be controlled for testing purposes

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate biometric device offline scenario by disconnecting the device or blocking network communication | System detects the connectivity loss within the configured timeout period |
| 2 | Verify that the system logs a connectivity error with device ID, timestamp, and error details | System logs contain a connectivity error entry with all relevant details including device identifier and error type |
| 3 | Check that an administrator notification is sent regarding the device connectivity loss | Administrator receives notification (email/alert) indicating which biometric device is offline and the time of disconnection |
| 4 | Verify the system continues to operate and monitor for device reconnection | System remains operational and continues monitoring for the offline device without crashing or freezing |
| 5 | Resume device connectivity by restoring network connection or reconnecting the device | System detects the device is back online and re-establishes connection successfully |
| 6 | Send a valid attendance event from the reconnected biometric device | System receives and processes the attendance event successfully, storing it in the database with correct data |
| 7 | Verify that the system logs the successful reconnection and event processing | System logs show device reconnection event and successful processing of the attendance event with no errors |
| 8 | Check that administrator receives notification of device reconnection | Administrator receives notification confirming the device is back online and operational |

**Postconditions:**
- Biometric device is reconnected and operational
- System logs contain complete error and recovery information
- Administrator has been notified of both disconnection and reconnection
- Attendance event after reconnection is successfully stored
- System is ready to process subsequent events normally

---

## Story: As Attendance Manager, I want to aggregate manual attendance entries to achieve comprehensive data coverage
**Story ID:** story-12

### Test Case: Validate successful manual attendance upload and reconciliation
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Attendance Manager role and authorized permissions
- Valid manual attendance CSV file is prepared with correct format and data
- Automated attendance records exist in the system for reconciliation
- System API endpoint POST /api/attendance/manual is operational
- Database is accessible and audit trail mechanism is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the manual attendance upload interface and select the valid CSV file containing manual attendance entries | File selection dialog opens and the CSV file is successfully selected |
| 2 | Upload the manual attendance CSV file to the system | System accepts the file upload and returns HTTP 200 status code indicating successful receipt |
| 3 | Verify that the system parses and validates the CSV file data including employee IDs, dates, times, and attendance types | System successfully validates all data fields, confirms correct format, and displays validation success message |
| 4 | Allow the system to automatically reconcile manual entries with existing automated attendance data | System completes reconciliation process and identifies any conflicts between manual and automated records |
| 5 | Review the reconciliation results to verify that conflicts are flagged accurately with details | System displays flagged conflicts showing employee ID, date, time, manual entry value, automated entry value, and conflict type |
| 6 | Verify that non-conflicting manual entries are automatically integrated into the unified attendance database | Non-conflicting manual attendance records are successfully stored in the database with appropriate status |
| 7 | Query the audit trail to verify entries for the manual upload operation | Audit trail contains complete records showing upload timestamp, user who performed the upload, file name, number of records processed, and operation status |
| 8 | Verify audit trail entries include details of all manual attendance changes made | Each manual attendance entry has corresponding audit record with employee ID, original value (if any), new value, user ID, and timestamp |
| 9 | Check that the audit trail is complete and accessible for compliance review | 100% of manual changes are recorded in audit trail with no missing entries, and records are retrievable through audit interface |

**Postconditions:**
- Manual attendance entries are successfully uploaded and validated
- Reconciliation is complete with conflicts accurately flagged
- Non-conflicting records are integrated into unified attendance database
- Complete audit trail exists for all manual changes
- System is ready for manager to review and approve flagged conflicts

---

### Test Case: Verify rejection of invalid manual attendance files
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Attendance Manager role
- Invalid manual attendance file is prepared with incorrect format (e.g., wrong column headers, invalid data types, missing required fields)
- System validation rules are configured and active
- Manual attendance upload interface is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the manual attendance upload interface | Upload interface is displayed with file selection option |
| 2 | Select and upload a manual attendance file with invalid format (e.g., incorrect column headers or structure) | System receives the file and initiates validation process |
| 3 | Wait for system to complete file validation | System detects format errors and rejects the file upload |
| 4 | Verify that the system displays a clear error message indicating the specific validation failure | Error message is displayed specifying the format issue (e.g., 'Invalid column headers', 'Missing required field: Employee ID', 'Invalid date format in row 5') |
| 5 | Check that no records from the invalid file are stored in the database | Database query confirms no new attendance records were created from the rejected file |
| 6 | Verify that the rejection is logged in the system logs with error details | System logs contain entry showing file rejection with timestamp, user ID, file name, and specific validation errors |
| 7 | Confirm that the user can retry the upload with a corrected file | Upload interface remains accessible and allows user to select and upload a new file |

**Postconditions:**
- Invalid file is rejected and not processed
- No incorrect data is stored in the database
- Clear error message is provided to the user
- System logs contain rejection details
- User can attempt to upload a corrected file

---

### Test Case: Test batch processing performance for manual uploads
- **ID:** tc-006
- **Type:** boundary
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Attendance Manager role
- Valid manual attendance file containing exactly 500 records is prepared
- All 500 records have valid data format and employee IDs exist in system
- System performance monitoring tools are available
- Database has sufficient capacity for 500 new records
- System is under normal load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current system time before starting the upload process | Start time is recorded for performance measurement |
| 2 | Navigate to manual attendance upload interface and select the file containing 500 manual attendance records | File with 500 records is successfully selected |
| 3 | Upload the batch file containing 500 manual attendance records | System accepts the file and begins processing the batch |
| 4 | Monitor the system processing status and progress indicators | System displays processing progress (e.g., progress bar, percentage complete, records processed count) |
| 5 | Wait for the system to complete validation, reconciliation, and storage of all 500 records | System completes processing and displays completion message |
| 6 | Note the system time when processing completes and calculate total processing time | Total processing time from upload initiation to completion is calculated |
| 7 | Verify that the batch processing completed within 2 minutes (120 seconds) | Processing time is less than or equal to 2 minutes, meeting the performance requirement |
| 8 | Query the database to verify all 500 records were successfully stored | Database contains exactly 500 new attendance records from the uploaded batch |
| 9 | Verify data integrity by sampling random records from the batch to ensure accuracy | Sampled records match the original file data with correct employee IDs, dates, times, and attendance types |
| 10 | Check system logs for any errors or warnings during batch processing | System logs show successful batch processing with no errors or data loss |

**Postconditions:**
- All 500 manual attendance records are successfully processed and stored
- Processing completed within the 2-minute performance requirement
- Data integrity is maintained with no data loss
- System logs confirm successful batch operation
- System remains stable and responsive after batch processing

---

## Story: As Attendance Manager, I want to reconcile attendance data discrepancies to achieve data accuracy
**Story ID:** story-18

### Test Case: Validate detection and reporting of attendance discrepancies
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in as Attendance Manager with reconciliation permissions
- Both manual and automated attendance systems are operational
- Test employee records exist in the system
- Access to GET /api/attendance/reconciliation endpoint is available
- Audit trail logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a manual attendance record for Employee ID 'EMP001' with check-in time '09:00 AM' for date '2024-01-15' | Manual attendance record is successfully saved in the system |
| 2 | Create an automated attendance record for the same Employee ID 'EMP001' with check-in time '09:30 AM' for the same date '2024-01-15' | Automated attendance record is successfully saved in the system |
| 3 | Trigger the reconciliation process by navigating to Attendance Reconciliation module or calling GET /api/attendance/reconciliation | Reconciliation process initiates and runs successfully |
| 4 | Wait for the reconciliation process to complete and check for discrepancy flags | System detects the 30-minute time difference and flags the discrepancy for Employee ID 'EMP001' on date '2024-01-15' |
| 5 | Navigate to the discrepancy report section and open the generated report | Discrepancy report is accessible and displays all flagged discrepancies |
| 6 | Review the discrepancy report for Employee ID 'EMP001' | Report clearly lists the discrepancy with details including Employee ID, date, manual check-in time (09:00 AM), automated check-in time (09:30 AM), and time difference (30 minutes) |
| 7 | Select the discrepancy entry for Employee ID 'EMP001' and click on 'Override' or 'Resolve' option | Override dialog or form opens with current values displayed |
| 8 | Enter the correct check-in time as '09:00 AM', add justification comment 'Manual record verified with security logs', and submit the override | Override is successfully saved and confirmation message is displayed |
| 9 | Navigate to the audit trail section and search for changes related to Employee ID 'EMP001' on date '2024-01-15' | Audit trail entry is present showing the override action with timestamp, manager ID, old value (09:30 AM), new value (09:00 AM), and justification comment |
| 10 | Verify the attendance record for Employee ID 'EMP001' reflects the corrected time | Attendance record shows check-in time as '09:00 AM' with an indicator that it was manually overridden |

**Postconditions:**
- Discrepancy is resolved and marked as completed
- Attendance record reflects the corrected data
- Complete audit trail exists for the override action
- Discrepancy report shows the entry as resolved
- System data integrity is maintained

---

### Test Case: Verify reconciliation process performance
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in as Attendance Manager with reconciliation permissions
- Typical data volume is defined as 1000 employee records with 30 days of attendance data
- Test dataset with typical volume is prepared in both manual and automated attendance databases
- System performance monitoring tools are available
- Access to GET /api/attendance/reconciliation endpoint is available
- No other heavy processes are running on the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify the test dataset contains 1000 employee records with 30 days of attendance data (approximately 30,000 attendance records) | Dataset is confirmed to contain typical data volume as per system specifications |
| 2 | Note the current system time and initiate the reconciliation process by calling GET /api/attendance/reconciliation or clicking 'Run Reconciliation' button | Reconciliation process starts successfully and status shows 'In Progress' |
| 3 | Monitor the reconciliation process progress indicator or status updates | Progress indicator shows incremental completion percentage and estimated time remaining |
| 4 | Wait for the reconciliation process to complete and note the completion time | Reconciliation process completes successfully with status changed to 'Completed' |
| 5 | Calculate the total time taken by subtracting start time from completion time | Total reconciliation time is 10 minutes or less |
| 6 | Verify that all 30,000 attendance records were processed by checking the reconciliation summary report | Summary report shows total records processed equals 30,000 with breakdown of matched records, discrepancies found, and any errors |
| 7 | Check system resource utilization during the reconciliation process (CPU, memory, database connections) | System resources remain within acceptable limits and do not cause system degradation |

**Postconditions:**
- Reconciliation process completed within performance requirements
- All attendance records in the dataset were processed
- System remains stable and responsive
- Reconciliation report is generated and accessible
- No data corruption or loss occurred during the process

---

