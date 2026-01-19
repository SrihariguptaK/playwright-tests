# Manual Test Cases

## Story: As HR Manager, I want to synchronize employee personal data daily to achieve up-to-date records
**Story ID:** story-16

### Test Case: Validate successful daily synchronization of employee data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 35 mins

**Preconditions:**
- HR system API is accessible and operational
- API authentication credentials are configured correctly
- Scheduled synchronization job is configured for daily execution
- Test employee data exists in HR system with all mandatory fields populated
- Network connectivity between systems is stable
- Database has sufficient storage for employee records

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Trigger the scheduled synchronization job manually or wait for scheduled execution time | Synchronization job starts successfully and initiates connection to HR system API /employees endpoint |
| 2 | Monitor the synchronization process through system logs or dashboard | Employee data is retrieved from HR system API successfully with HTTP 200 status code |
| 3 | Wait for the synchronization process to complete | All employee records are processed and updated in the new platform database without errors |
| 4 | Verify updated records in the new platform by querying the employee database or viewing through UI | Employee records in the new platform reflect the latest data from HR system including all personal information fields |
| 5 | Compare sample employee records between HR system and new platform | Data matches exactly between both systems for all mandatory and optional fields |
| 6 | Check synchronization logs in the system log files or monitoring dashboard | Logs show successful completion status with no errors recorded |
| 7 | Verify the total synchronization completion time in the logs | Synchronization completed within 30 minutes SLA requirement |
| 8 | Check the synchronization summary report for record counts | Summary shows total records processed, records updated, records created, and 99.9% or higher success rate |

**Postconditions:**
- All employee records are synchronized successfully
- New platform database contains up-to-date employee information
- Synchronization logs are stored with timestamp and status
- No error notifications sent to HR team
- System is ready for next scheduled synchronization

---

### Test Case: Verify handling of incomplete employee data
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- HR system API is accessible and operational
- API authentication credentials are configured correctly
- Test environment has ability to simulate incomplete employee data
- Mandatory field validation rules are configured in the system
- At least one employee record in HR system has missing mandatory fields
- Synchronization job is ready to execute

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare test data in HR system with employee records missing mandatory fields (e.g., employee ID, first name, last name, or email) | Test employee records exist in HR system with one or more mandatory fields empty or null |
| 2 | Trigger the synchronization job to process employee data including incomplete records | Synchronization job starts and begins retrieving employee data from HR system API |
| 3 | Monitor the synchronization process as it encounters incomplete employee records | System detects missing mandatory fields during validation phase |
| 4 | Check synchronization logs for error entries related to incomplete records | Synchronization logs contain specific error messages identifying which records have missing mandatory fields and which fields are missing |
| 5 | Verify that incomplete records are not updated in the new platform database | Incomplete employee records are not created or updated in the new platform; existing records remain unchanged |
| 6 | Confirm that synchronization continues processing remaining valid records after encountering incomplete data | System skips incomplete records and successfully processes all valid employee records without stopping the entire synchronization |
| 7 | Review the synchronization summary report | Report shows total records processed, number of successful updates, and number of failed records with reasons |
| 8 | Verify that error notifications are sent to HR team | HR team receives error report listing all incomplete records with details of missing mandatory fields |

**Postconditions:**
- Valid employee records are synchronized successfully
- Incomplete records are not updated in the new platform
- Error logs contain detailed information about incomplete records
- HR team is notified of data quality issues
- System maintains data integrity by rejecting incomplete records

---

## Story: As HR Analyst, I want to manually trigger employee data synchronization to achieve immediate updates
**Story ID:** story-17

### Test Case: Verify authorized user can trigger manual sync
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- HR system API is accessible and operational
- Manual synchronization feature is deployed and configured
- Test user account with HR Analyst role exists in the system
- User has valid credentials for login
- Role-based access control is properly configured
- Synchronization page is accessible in the application
- Employee data exists in HR system for synchronization

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with username and password fields |
| 2 | Enter valid credentials for authorized HR Analyst user and click login button | User is successfully authenticated and redirected to the application dashboard |
| 3 | Verify access to synchronization page by navigating to the HR synchronization section | Synchronization page is accessible and displays the 'Sync Now' button without access denied errors |
| 4 | Review the synchronization page interface for current sync status | Page displays last synchronization timestamp, status, and the enabled 'Sync Now' button |
| 5 | Click the 'Sync Now' button to trigger manual synchronization | System initiates manual synchronization process and displays a progress indicator or status message |
| 6 | Monitor the synchronization status displayed on the page | Status updates in real-time showing 'In Progress' or similar message with progress information |
| 7 | Wait for synchronization to complete and observe the final status | Status changes to 'Completed' or 'Success' with summary of records processed, updated, and any errors |
| 8 | Verify synchronization results displayed to the user | Results show total records synchronized, completion time, and success/failure counts |
| 9 | Navigate to system logs or audit trail section | Logs section is accessible and displays recent synchronization events |
| 10 | Check logs for the manual sync event entry | Event is logged with event type 'Manual Sync', correct username of the HR Analyst, accurate timestamp, and completion status |
| 11 | Verify the timestamp in the log matches the time when 'Sync Now' was clicked | Timestamp is accurate within acceptable margin (few seconds) of when the button was clicked |

**Postconditions:**
- Manual synchronization completed successfully
- Employee data is updated in the new platform
- Synchronization event is logged with user details and timestamp
- User remains logged in and can perform additional actions
- System is ready for next synchronization request

---

### Test Case: Verify unauthorized user cannot trigger manual sync
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Manual synchronization feature is deployed with role-based access control
- Test user account without HR Analyst role exists (e.g., regular employee or different department user)
- User has valid credentials for login but lacks HR synchronization permissions
- API endpoint /api/hr/sync/manual is protected with authorization checks
- Security policies are properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with username and password fields |
| 2 | Enter valid credentials for non-HR user (unauthorized user) and click login button | User is successfully authenticated and redirected to the application dashboard appropriate for their role |
| 3 | Attempt to navigate to the synchronization page through the application menu or direct URL | Access is denied with appropriate error message such as 'Access Denied', '403 Forbidden', or 'You do not have permission to access this page' |
| 4 | Verify that synchronization page or 'Sync Now' button is not visible in the user interface | Synchronization menu option is hidden or disabled for unauthorized user role |
| 5 | Open API testing tool (e.g., Postman, curl) and prepare a request to /api/hr/sync/manual endpoint | API testing tool is ready with the manual sync endpoint URL configured |
| 6 | Include the unauthorized user's authentication token in the API request headers | Request is properly formatted with valid authentication token for non-HR user |
| 7 | Send POST request to /api/hr/sync/manual endpoint | API request is transmitted to the server |
| 8 | Review the API response status code and message | Request is rejected with HTTP 403 Forbidden or 401 Unauthorized status code and error message indicating insufficient permissions or authorization failure |
| 9 | Verify the error response body contains appropriate authorization error details | Response body includes error message such as 'User does not have required role for this operation' or 'Authorization failed' |
| 10 | Check system logs for the unauthorized access attempt | Security logs record the failed authorization attempt with user details, timestamp, and reason for denial |
| 11 | Verify that no synchronization was triggered by the unauthorized request | No synchronization event is logged and employee data remains unchanged |

**Postconditions:**
- Unauthorized user cannot access synchronization functionality
- No manual synchronization was executed
- Security logs contain record of unauthorized access attempt
- System security and data integrity maintained
- User remains logged in with their authorized access level

---

## Story: As Integration Engineer, I want to detect and log data conflicts during HR synchronization to achieve data integrity
**Story ID:** story-18

### Test Case: Verify detection and logging of data conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- HR synchronization system is operational and accessible
- API endpoint /api/hr/sync is available and responding
- Test employee records exist in both source HR system and target database
- Conflicting employee data is prepared in source system (e.g., different job title, department, or salary for same employee ID)
- Log access permissions are configured for test user
- Notification system is configured and support team contact details are set up
- Database connection to local database is established

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare conflicting employee data by modifying an existing employee record in the source HR system with different values for key fields (e.g., Employee ID: EMP001, Name: John Doe, Department changed from 'IT' to 'Finance', Salary changed from 75000 to 85000) while keeping the same employee in target database with original values | Source HR system contains employee record with updated values that differ from target database record for the same employee ID |
| 2 | Trigger the HR synchronization job manually or wait for scheduled synchronization to run via /api/hr/sync endpoint | Synchronization job initiates successfully and begins processing employee records |
| 3 | Monitor the synchronization process as the system compares incoming data from source HR system with existing records in target database | System performs field-level comparison between source and target records for employee EMP001 |
| 4 | Observe system behavior when conflict is encountered for employee EMP001 | System detects data conflict for key fields (Department and Salary mismatch) and flags the record for conflict logging |
| 5 | Access the conflict log file or database table to verify conflict details are recorded | Conflict log entry contains: Employee ID (EMP001), conflicting field names (Department, Salary), source values (Finance, 85000), target values (IT, 75000), timestamp of detection, and conflict severity level |
| 6 | Check the notification system (email, messaging platform, or notification dashboard) for conflict alerts sent to support team | Support team receives notification within 5 minutes containing conflict summary, affected employee ID, conflicting fields, and link to detailed log entry |
| 7 | Verify the timestamp in the conflict log matches the actual time of synchronization run | Timestamp in conflict log is accurate and corresponds to when the synchronization job detected the conflict |
| 8 | Confirm that the conflicting record was not automatically overwritten in the target database | Target database still contains original values (Department: IT, Salary: 75000) for employee EMP001, data integrity is maintained |

**Postconditions:**
- Conflict is logged in the system with complete details
- Support team has received notification about the conflict
- Conflicting employee record remains unchanged in target database
- Conflict log is accessible for troubleshooting and resolution
- System is ready for next synchronization cycle

---

### Test Case: Verify synchronization continues for non-conflicting data
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- HR synchronization system is operational and accessible
- API endpoint /api/hr/sync is available and responding
- Test dataset contains a mix of employee records: at least 2 conflicting records and at least 3 non-conflicting records
- Conflicting records have mismatched key field values between source and target
- Non-conflicting records have matching data or are new records to be inserted
- Database connection to local database is established
- Sufficient database storage and system resources are available
- Notification system is configured for conflict alerts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare test dataset with 5 employee records: Record 1 (EMP001) - conflicting Department field, Record 2 (EMP002) - conflicting Salary field, Record 3 (EMP003) - non-conflicting update to phone number, Record 4 (EMP004) - non-conflicting new employee, Record 5 (EMP005) - non-conflicting update to address | Test dataset is ready with 2 conflicting and 3 non-conflicting employee records in source HR system |
| 2 | Initiate the HR synchronization job via /api/hr/sync endpoint | Synchronization job starts and begins processing all 5 employee records from source system |
| 3 | Monitor synchronization progress as system processes the mixed dataset | System processes each record sequentially, performing field-level comparisons for existing records and identifying new records |
| 4 | Observe system behavior when first conflicting record (EMP001) is encountered | System detects conflict for EMP001, logs the conflict details, and continues processing remaining records without stopping the synchronization job |
| 5 | Observe system behavior when first non-conflicting record (EMP003) is processed | System successfully updates phone number for EMP003 in target database without any errors or conflicts |
| 6 | Observe system behavior when second conflicting record (EMP002) is encountered | System detects conflict for EMP002, logs the conflict details, and continues processing remaining records |
| 7 | Observe system behavior when new employee record (EMP004) is processed | System successfully inserts new employee EMP004 into target database with all field values from source system |
| 8 | Observe system behavior when final non-conflicting record (EMP005) is processed | System successfully updates address for EMP005 in target database |
| 9 | Wait for synchronization job to complete and verify completion status | Synchronization job completes successfully within 5 minutes with status indicating partial success (3 records updated/inserted, 2 conflicts detected) |
| 10 | Query target database to verify non-conflicting records (EMP003, EMP004, EMP005) were updated/inserted correctly | EMP003 shows updated phone number, EMP004 exists as new record with all correct values, EMP005 shows updated address in target database |
| 11 | Query target database to verify conflicting records (EMP001, EMP002) were not overwritten | EMP001 and EMP002 retain their original values in target database, no data corruption occurred |
| 12 | Review conflict logs to confirm both conflicts were logged | Conflict log contains 2 entries with details for EMP001 and EMP002, including timestamps and field-level conflict information |
| 13 | Check notification system for alerts sent to support team | Support team received notifications for both conflicts (EMP001 and EMP002) within 5 minutes of detection |

**Postconditions:**
- Synchronization job completed successfully for non-conflicting records
- 3 non-conflicting employee records (EMP003, EMP004, EMP005) are updated/inserted in target database
- 2 conflicting employee records (EMP001, EMP002) remain unchanged in target database
- All conflicts are logged with complete details
- Support team has been notified of all conflicts
- System is ready for conflict resolution and next synchronization cycle
- Data integrity is maintained across all records

---

