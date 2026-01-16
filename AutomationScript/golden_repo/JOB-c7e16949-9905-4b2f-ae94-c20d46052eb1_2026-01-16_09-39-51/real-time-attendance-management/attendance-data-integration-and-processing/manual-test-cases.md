# Manual Test Cases

## Story: As Attendance System Integrator, I want to connect biometric devices to the system to achieve real-time attendance data ingestion
**Story ID:** story-1

### Test Case: Validate successful connection and data ingestion from biometric device
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Attendance system is running and accessible
- Biometric device API is available and operational
- Valid OAuth2 credentials are available for authentication
- Network connectivity between system and biometric device is stable
- Ingestion dashboard is accessible for monitoring
- Test employee ID exists in the system database

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the biometric device configuration page in the attendance system | Configuration page loads successfully with fields for device connection settings |
| 2 | Enter valid biometric device API endpoint URL in the configuration field | API endpoint URL is accepted and displayed in the field |
| 3 | Enter valid OAuth2 client ID and client secret credentials | Credentials are accepted and masked appropriately for security |
| 4 | Click 'Test Connection' button to initiate authentication | System establishes authenticated connection successfully and displays 'Connection Successful' message |
| 5 | Save the biometric device configuration settings | Configuration is saved successfully with confirmation message displayed |
| 6 | Simulate an attendance event from the biometric device with valid employee ID and current timestamp | Biometric device sends attendance event to the system via API endpoint /api/attendance/ingest |
| 7 | Monitor the system processing time from event receipt to completion | System receives and processes the attendance event within 1 minute (60 seconds) |
| 8 | Verify the attendance record appears in the system database | Attendance record is created with correct employee ID, timestamp, and device source information |
| 9 | Navigate to the ingestion logs dashboard | Ingestion logs page loads successfully showing recent activities |
| 10 | Search for the simulated attendance event in the ingestion logs | Event is logged with 'SUCCESS' status, accurate timestamp, employee ID, and processing duration |

**Postconditions:**
- Biometric device remains connected and authenticated
- Attendance event is successfully stored in the database
- Ingestion log entry is created with success status
- System is ready to receive additional attendance events
- No error alerts are generated

---

### Test Case: Verify rejection of invalid attendance events
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Attendance system is running and accessible
- Biometric device is connected and authenticated
- Data validation rules are configured in the system
- Error logging mechanism is enabled
- Test access to error logs dashboard is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare an attendance event payload with missing employee ID field but valid timestamp | Test payload is ready with incomplete data structure |
| 2 | Send the attendance event with missing employee ID to the system via /api/attendance/ingest endpoint | System receives the event and initiates validation process |
| 3 | Verify the API response status code and error message | System rejects the event with HTTP 400 Bad Request status and returns error message 'Employee ID is required' |
| 4 | Check that no attendance record was created in the database | No attendance record exists for the invalid event |
| 5 | Navigate to the error logs dashboard | Error logs page loads successfully |
| 6 | Search for the rejected event in error logs | Event is logged with 'VALIDATION_ERROR' status, timestamp, and detailed error message 'Missing required field: employee_id' |
| 7 | Prepare a second attendance event payload with valid employee ID but invalid timestamp format (e.g., 'invalid-date-format') | Test payload is ready with incorrect timestamp format |
| 8 | Send the attendance event with invalid timestamp format to the system | System receives the event and initiates validation process |
| 9 | Verify the API response status code and error message | System rejects the event with HTTP 400 Bad Request status and returns error message 'Invalid timestamp format' |
| 10 | Check that no attendance record was created in the database for this event | No attendance record exists for the invalid timestamp event |
| 11 | Review the error logs dashboard for all rejected events | Both invalid events are recorded with detailed error messages including event payload, validation failure reason, timestamp of rejection, and device source |

**Postconditions:**
- No invalid attendance records are stored in the database
- All validation errors are logged with detailed information
- System continues to accept valid events normally
- Error logs are available for integrator review
- Data integrity is maintained

---

### Test Case: Test automatic retry on ingestion failure
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Attendance system is running and accessible
- Biometric device is connected and authenticated
- Automatic retry mechanism is enabled with 3 retry attempts configured
- Network simulation tools are available to simulate failures
- Alert notification system is configured
- Access to system logs and monitoring dashboard is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare a valid attendance event with correct employee ID and timestamp | Valid test event payload is ready for transmission |
| 2 | Configure network simulation tool to block connectivity between biometric device and attendance system | Network connectivity is temporarily blocked, simulating network failure |
| 3 | Send the valid attendance event from biometric device to the system | Event transmission fails due to network connectivity issue |
| 4 | Monitor the system logs for automatic retry attempts | System automatically initiates first retry attempt within configured retry interval |
| 5 | Verify the first retry attempt fails due to continued network blockage | First retry attempt fails and is logged with 'RETRY_ATTEMPT_1' status |
| 6 | Monitor for the second automatic retry attempt | System automatically initiates second retry attempt and logs 'RETRY_ATTEMPT_2' status |
| 7 | Verify the second retry attempt fails | Second retry attempt fails and is logged appropriately |
| 8 | Monitor for the third automatic retry attempt | System automatically initiates third and final retry attempt with 'RETRY_ATTEMPT_3' status logged |
| 9 | Before the third retry completes, restore network connectivity by removing the network blockage | Network connectivity is restored successfully between biometric device and system |
| 10 | Verify the third retry attempt succeeds | System successfully ingests the pending attendance event on the third retry attempt |
| 11 | Check the attendance database for the event record | Attendance record is created successfully with correct employee ID, timestamp, and ingestion metadata |
| 12 | Review the ingestion logs for complete retry history | Logs show all three retry attempts with timestamps and final 'SUCCESS' status after third attempt |
| 13 | Check the alert notifications dashboard | No alert notification is sent to the integrator since ingestion succeeded within the 3 retry attempts |
| 14 | Verify system continues to process new events normally | System is operational and ready to receive and process additional attendance events |

**Postconditions:**
- Attendance event is successfully ingested after retry
- Complete retry history is logged with all attempts documented
- No alert is generated since ingestion succeeded within retry limit
- Network connectivity is restored to normal state
- System continues normal operation without manual intervention
- Data integrity is maintained with no data loss

---

## Story: As Attendance System Integrator, I want to connect badge scan devices to the system to achieve real-time attendance data ingestion
**Story ID:** story-2

### Test Case: Validate successful connection and data ingestion from badge scan device
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Attendance system is running and accessible
- Badge scan device API is available and operational
- Valid OAuth2 credentials are available for authentication
- Network connectivity between system and badge scan device is stable
- Ingestion dashboard is accessible for monitoring
- Test employee ID with valid badge exists in the system database

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the badge scan device configuration page in the attendance system | Configuration page loads successfully with fields for badge scan device connection settings |
| 2 | Enter valid badge scan device API endpoint URL in the configuration field | API endpoint URL is accepted and displayed in the field |
| 3 | Enter valid OAuth2 client ID and client secret credentials for badge scan device | Credentials are accepted and masked appropriately for security |
| 4 | Click 'Test Connection' button to initiate authentication with badge scan device | System establishes authenticated connection successfully and displays 'Connection Successful' message |
| 5 | Save the badge scan device configuration settings | Configuration is saved successfully with confirmation message displayed |
| 6 | Simulate a badge scan event from the badge scan device with valid employee ID and current scan timestamp | Badge scan device sends scan event to the system via API endpoint /api/attendance/ingest-badge |
| 7 | Monitor the system processing time from event receipt to completion | System receives and processes the badge scan event within 1 minute (60 seconds) |
| 8 | Verify the attendance record appears in the system database | Attendance record is created with correct employee ID, scan timestamp, and badge scan device source information |
| 9 | Navigate to the ingestion logs dashboard | Ingestion logs page loads successfully showing recent badge scan activities |
| 10 | Search for the simulated badge scan event in the ingestion logs | Event is logged with 'SUCCESS' status, accurate timestamp, employee ID, badge ID, and processing duration |

**Postconditions:**
- Badge scan device remains connected and authenticated
- Badge scan event is successfully stored in the database
- Ingestion log entry is created with success status
- System is ready to receive additional badge scan events
- No error alerts are generated

---

### Test Case: Verify rejection of invalid badge scan events
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Attendance system is running and accessible
- Badge scan device is connected and authenticated
- Data validation rules are configured in the system
- Error logging mechanism is enabled
- Test access to error logs dashboard is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare a badge scan event payload with missing employee ID field but valid scan timestamp | Test payload is ready with incomplete data structure |
| 2 | Send the badge scan event with missing employee ID to the system via /api/attendance/ingest-badge endpoint | System receives the event and initiates validation process |
| 3 | Verify the API response status code and error message | System rejects the event with HTTP 400 Bad Request status and returns error message 'Employee ID is required' |
| 4 | Check that no attendance record was created in the database | No attendance record exists for the invalid badge scan event |
| 5 | Navigate to the error logs dashboard | Error logs page loads successfully |
| 6 | Search for the rejected badge scan event in error logs | Event is logged with 'VALIDATION_ERROR' status, timestamp, and detailed error message 'Missing required field: employee_id' |
| 7 | Prepare a second badge scan event payload with valid employee ID but invalid timestamp format (e.g., 'not-a-valid-timestamp') | Test payload is ready with incorrect timestamp format |
| 8 | Send the badge scan event with invalid timestamp format to the system | System receives the event and initiates validation process |
| 9 | Verify the API response status code and error message | System rejects the event with HTTP 400 Bad Request status and returns error message 'Invalid scan timestamp format' |
| 10 | Check that no attendance record was created in the database for this event | No attendance record exists for the invalid timestamp badge scan event |
| 11 | Review the error logs dashboard for all rejected badge scan events | Both invalid events are recorded with detailed error messages including event payload, validation failure reason, timestamp of rejection, and badge scan device source |

**Postconditions:**
- No invalid badge scan records are stored in the database
- All validation errors are logged with detailed information
- System continues to accept valid badge scan events normally
- Error logs are available for integrator review
- Data integrity is maintained

---

### Test Case: Test automatic retry on badge scan ingestion failure
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Attendance system is running and accessible
- Badge scan device is connected and authenticated
- Automatic retry mechanism is enabled with 3 retry attempts configured
- Network simulation tools are available to simulate failures
- Alert notification system is configured
- Access to system logs and monitoring dashboard is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare a valid badge scan event with correct employee ID and scan timestamp | Valid test badge scan event payload is ready for transmission |
| 2 | Configure network simulation tool to block connectivity between badge scan device and attendance system | Network connectivity is temporarily blocked, simulating network failure |
| 3 | Send the valid badge scan event from badge scan device to the system | Event transmission fails due to network connectivity issue |
| 4 | Monitor the system logs for automatic retry attempts | System automatically initiates first retry attempt within configured retry interval |
| 5 | Verify the first retry attempt fails due to continued network blockage | First retry attempt fails and is logged with 'RETRY_ATTEMPT_1' status |
| 6 | Monitor for the second automatic retry attempt | System automatically initiates second retry attempt and logs 'RETRY_ATTEMPT_2' status |
| 7 | Verify the second retry attempt fails | Second retry attempt fails and is logged appropriately |
| 8 | Monitor for the third automatic retry attempt | System automatically initiates third and final retry attempt with 'RETRY_ATTEMPT_3' status logged |
| 9 | Before the third retry completes, restore network connectivity by removing the network blockage | Network connectivity is restored successfully between badge scan device and system |
| 10 | Verify the third retry attempt succeeds | System successfully ingests the pending badge scan event on the third retry attempt |
| 11 | Check the attendance database for the badge scan event record | Attendance record is created successfully with correct employee ID, scan timestamp, and ingestion metadata |
| 12 | Review the ingestion logs for complete retry history | Logs show all three retry attempts with timestamps and final 'SUCCESS' status after third attempt |
| 13 | Check the alert notifications dashboard | No alert notification is sent to the integrator since badge scan ingestion succeeded within the 3 retry attempts |
| 14 | Verify system continues to process new badge scan events normally | System is operational and ready to receive and process additional badge scan events |

**Postconditions:**
- Badge scan event is successfully ingested after retry
- Complete retry history is logged with all attempts documented
- No alert is generated since ingestion succeeded within retry limit
- Network connectivity is restored to normal state
- System continues normal operation without manual intervention
- Data integrity is maintained with no data loss

---

