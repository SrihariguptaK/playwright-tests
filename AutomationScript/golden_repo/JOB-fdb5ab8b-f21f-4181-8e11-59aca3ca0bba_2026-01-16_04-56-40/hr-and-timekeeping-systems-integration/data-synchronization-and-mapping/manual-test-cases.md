# Manual Test Cases

## Story: As Data Engineer, I want to map HR employee data fields to the integration schema to achieve accurate data synchronization
**Story ID:** story-13

### Test Case: Verify correct mapping of mandatory employee fields
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Data Engineer has valid credentials and access to the system
- HR database contains sample employee records with all mandatory fields populated
- Integration schema mapping configuration is properly defined
- Timekeeping system API is accessible and operational
- Network connectivity between HR and timekeeping systems is established

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the data synchronization module and select the HR employee data source | HR employee data source is successfully selected and available for processing |
| 2 | Provide sample HR employee data containing all mandatory fields (employee ID, first name, last name, email, department, hire date, employment status) | System accepts the sample data and displays it in the preview pane |
| 3 | Initiate the mapping process by clicking 'Apply Mapping' button | System processes the data and maps all mandatory fields to the integration schema without errors. Mapping status shows 'Success' with 0 errors |
| 4 | Review the mapped data in the integration schema format | All mandatory fields are correctly mapped with proper data types and formats. No data loss or truncation is observed |
| 5 | Trigger the synchronization process by clicking 'Sync to Timekeeping System' button | Synchronization process initiates successfully and progress indicator shows data transfer in progress |
| 6 | Monitor the synchronization status until completion | Synchronization completes successfully with status 'Completed'. Success message displays number of records processed |
| 7 | Access the timekeeping system and navigate to the employee records section | Timekeeping system displays the synchronized employee records |
| 8 | Verify data integrity by comparing source HR data with target timekeeping system data for each mandatory field | All employee records match source data accurately. Employee ID, names, email, department, hire date, and employment status are identical in both systems |

**Postconditions:**
- Employee data is successfully synchronized to timekeeping system
- No data loss or corruption occurred during mapping and synchronization
- Synchronization logs show successful completion
- Both systems contain identical employee information

---

### Test Case: Test handling of invalid data during mapping
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Data Engineer has valid credentials and access to the system
- HR database contains test employee records with intentional data quality issues
- Integration schema mapping configuration is properly defined with validation rules
- Error logging system is enabled and operational
- Test data includes records with invalid data types and missing mandatory fields

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the data synchronization module and select the HR employee data source | HR employee data source is successfully selected |
| 2 | Provide HR employee data containing invalid data types (e.g., text in date field, special characters in numeric field) | System accepts the data for validation processing |
| 3 | Provide HR employee data with missing mandatory fields (e.g., missing employee ID, missing email address) | System accepts the data for validation processing |
| 4 | Initiate the mapping process by clicking 'Apply Mapping' button | System processes the data and detects mapping errors. Error summary displays total number of invalid records and error types |
| 5 | Navigate to the error logs section and review the detailed error information | Error logs contain detailed field-level information including record identifier, field name, error type, invalid value, and expected format for each error |
| 6 | Attempt to trigger synchronization with the dataset containing invalid records by clicking 'Sync to Timekeeping System' button | System displays validation warning indicating invalid records will be rejected |
| 7 | Confirm synchronization to proceed with valid records only | System rejects invalid records and continues processing valid ones. Synchronization status shows number of successful and rejected records |
| 8 | Review the synchronization summary report | Report clearly indicates which records were successfully synchronized and which were rejected with reasons |
| 9 | Access the detailed error logs and verify accuracy of field-level error information | Logs contain precise information for each rejected record including employee identifier, specific field names with errors, error descriptions, and timestamps |

**Postconditions:**
- Invalid records are rejected and not synchronized to timekeeping system
- Valid records are successfully synchronized
- Comprehensive error logs are generated with field-level details
- Data integrity is maintained in target system
- Error report is available for Data Engineer review and remediation

---

### Test Case: Validate mapping configuration update process
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 18 mins

**Preconditions:**
- Data Engineer has authorized user credentials with mapping configuration permissions
- Existing mapping configuration is in place and operational
- Audit trail system is enabled and functioning
- Test employee data is available for validation
- Backup of current mapping configuration exists

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system with authorized Data Engineer credentials | Login successful and user dashboard is displayed |
| 2 | Navigate to the mapping configuration section by clicking 'Configuration' > 'Field Mapping' | Mapping configuration interface loads successfully displaying current mapping rules |
| 3 | Verify access permissions by checking available actions (view, edit, save) | All configuration management options are visible and enabled for authorized user |
| 4 | Review current mapping rules for HR employee fields to integration schema | Current mapping rules are displayed in a clear, editable format showing source fields, target fields, and transformation rules |
| 5 | Modify a mapping rule by changing the transformation format for 'hire_date' field from 'MM/DD/YYYY' to 'YYYY-MM-DD' | Modification is accepted and field shows updated transformation rule |
| 6 | Add a comment describing the reason for the mapping change | Comment field accepts the input and displays it with the modified rule |
| 7 | Click 'Save Changes' button to persist the mapping configuration updates | System displays confirmation message 'Mapping configuration saved successfully' and returns to configuration view |
| 8 | Navigate to the audit trail section and search for recent mapping configuration changes | Audit trail displays the recent change with timestamp, user ID, field modified, old value, new value, and comment |
| 9 | Return to the data synchronization module and load test employee data | Test data is loaded successfully |
| 10 | Trigger synchronization with the updated mapping configuration | Synchronization process initiates and applies the new mapping rules |
| 11 | Verify that the 'hire_date' field is transformed according to the new rule (YYYY-MM-DD format) | Data is mapped according to the new rules without errors. Hire date appears in YYYY-MM-DD format in the integration schema |
| 12 | Review synchronization logs to confirm successful application of updated mappings | Logs show successful synchronization with no mapping errors. All records processed with new transformation rules |

**Postconditions:**
- Mapping configuration is successfully updated with new rules
- Audit trail contains complete record of the configuration change
- Synchronization uses updated mapping rules for all subsequent operations
- Data is transformed correctly according to new mapping specifications
- System maintains data integrity with updated configuration

---

## Story: As Scheduler, I want to configure synchronization job schedules to achieve timely data updates
**Story ID:** story-14

### Test Case: Verify scheduling configuration and job execution
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 65 mins

**Preconditions:**
- Scheduler has valid credentials with scheduling permissions
- Synchronization service is running and operational
- HR and timekeeping systems are accessible
- System clock is synchronized and accurate
- No conflicting synchronization jobs are currently scheduled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system with Scheduler credentials | Login successful and Scheduler dashboard is displayed |
| 2 | Navigate to synchronization settings by clicking 'Settings' > 'Synchronization Schedule' | Synchronization schedule configuration page loads successfully |
| 3 | Click 'Create New Schedule' button to configure a new synchronization job | Schedule configuration form is displayed with fields for interval, start time, and job parameters |
| 4 | Select 'Hourly' from the interval dropdown menu | Hourly interval is selected and additional time configuration options appear |
| 5 | Set the schedule to run every 1 hour starting from the next hour | Schedule parameters are accepted and displayed in the configuration form |
| 6 | Enter a descriptive name for the schedule (e.g., 'Hourly Employee Data Sync') | Schedule name is accepted and displayed |
| 7 | Click 'Save Schedule' button to persist the configuration | System displays confirmation message 'Schedule saved successfully' with next execution time. Schedule appears in the active schedules list |
| 8 | Note the next scheduled execution time and wait for the scheduled job execution time to arrive | System time advances to the scheduled execution time |
| 9 | Monitor the job execution dashboard during the scheduled time window | Synchronization job starts automatically at the scheduled time. Job status changes from 'Scheduled' to 'Running' |
| 10 | Wait for the job to complete execution | Job completes successfully and status changes to 'Completed' |
| 11 | Navigate to the synchronization logs section by clicking 'Logs' > 'Synchronization History' | Synchronization logs page loads displaying recent job executions |
| 12 | Locate the most recent job execution entry and verify the details | Job is logged as successful with accurate timestamp matching the scheduled time, job name, duration, and number of records processed |

**Postconditions:**
- Synchronization schedule is active and saved in the system
- First scheduled job executed successfully at the configured time
- Job execution is logged with complete details and timestamp
- Schedule remains active for subsequent hourly executions
- Data synchronization completed successfully

---

### Test Case: Test manual synchronization trigger
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler has valid credentials with manual synchronization permissions
- Synchronization service is running and operational
- HR and timekeeping systems are accessible and contain data to synchronize
- No synchronization job is currently running
- User is logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system with authorized Scheduler credentials | Login successful and Scheduler dashboard is displayed |
| 2 | Navigate to the synchronization control panel by clicking 'Synchronization' > 'Manual Sync' | Manual synchronization interface loads successfully |
| 3 | Verify that the manual synchronization trigger button is visible and enabled | Manual trigger button labeled 'Run Sync Now' is visible, enabled, and accessible to the authorized Scheduler |
| 4 | Review the current synchronization status display | Status shows 'Ready' or 'Idle' indicating no job is currently running |
| 5 | Click the 'Run Sync Now' manual synchronization trigger button | System displays confirmation dialog asking 'Are you sure you want to start synchronization now?' |
| 6 | Click 'Confirm' to proceed with manual synchronization | Synchronization job starts immediately. Status changes to 'Running' and progress indicator appears |
| 7 | Monitor the job progress on the synchronization dashboard | Progress indicator shows real-time status with percentage complete and records processed |
| 8 | Wait for the synchronization job to complete | Job completes successfully. Status changes to 'Completed' and success message displays with summary statistics |
| 9 | Navigate to the synchronization logs by clicking 'View Logs' button | Synchronization logs page opens displaying recent job executions |
| 10 | Verify the manually triggered job appears in the logs with correct details | Job is logged with 'Manual' trigger type, current timestamp, Scheduler username, 'Completed' status, and number of records synchronized |
| 11 | Review the detailed job execution log for any errors or warnings | Log shows successful completion with no errors. All records processed successfully |

**Postconditions:**
- Manual synchronization job completed successfully
- Job execution is logged with manual trigger indicator
- Data is synchronized between HR and timekeeping systems
- System is ready for next synchronization job
- Logs are updated with complete job details

---

### Test Case: Validate job retry on failure
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- Scheduler has valid credentials and system access
- Synchronization service is running
- Retry configuration is set to maximum 3 attempts with 5-minute intervals
- Alert notification system is enabled
- Test environment allows simulation of job failures
- Monitoring dashboard is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system with Scheduler credentials | Login successful and dashboard is displayed |
| 2 | Navigate to the test configuration panel by clicking 'Settings' > 'Test Controls' | Test configuration interface loads successfully |
| 3 | Enable failure simulation mode by toggling 'Simulate Job Failure' switch to ON | Failure simulation is enabled. Warning message displays indicating next synchronization job will fail |
| 4 | Navigate to synchronization control panel and trigger a manual synchronization job | Synchronization job starts and immediately encounters simulated failure |
| 5 | Monitor the job status on the synchronization dashboard | Job status changes to 'Failed'. Error message displays cause of failure |
| 6 | Navigate to the logs section and verify failure is logged | Failure is logged with timestamp, error details, and 'Retry Pending' status. Alert notification is generated |
| 7 | Check the alert notifications panel | Alert is displayed indicating synchronization job failed and automatic retry is scheduled |
| 8 | Wait for the configured retry interval (5 minutes) and monitor the system | System automatically retries the job after 5 minutes. Job status shows 'Retrying - Attempt 1 of 3' |
| 9 | Observe the first retry attempt with failure simulation still enabled | First retry attempt fails. Status updates to 'Failed - Retry 1'. Next retry is scheduled |
| 10 | Wait for the second retry interval and observe the second retry attempt | System automatically retries the job again. Job status shows 'Retrying - Attempt 2 of 3'. Second retry fails |
| 11 | Disable failure simulation mode by toggling 'Simulate Job Failure' switch to OFF before the third retry | Failure simulation is disabled. System is ready for normal operation |
| 12 | Wait for the third retry interval and observe the final retry attempt | System automatically retries the job for the third time. Job status shows 'Retrying - Attempt 3 of 3' |
| 13 | Monitor the third retry attempt execution | Third retry succeeds without simulated failure. Job completes successfully and status changes to 'Completed' |
| 14 | Navigate to the detailed job history and review the complete retry sequence | Job history shows initial failure, two failed retry attempts, and final successful retry with timestamps and status for each attempt |
| 15 | Verify the final job status in the synchronization logs | Job is marked as 'Successful' after retries. Log includes complete retry history with all attempt details and final success status |

**Postconditions:**
- Job retry mechanism functioned correctly according to configuration
- All retry attempts are logged with accurate details
- Job ultimately succeeded after retries
- Alert notifications were generated appropriately
- System returned to normal operational state
- Complete audit trail of failure and retry sequence is available

---

## Story: As Data Engineer, I want to handle data transformation errors gracefully to achieve reliable synchronization
**Story ID:** story-18

### Test Case: Verify detection and logging of transformation errors
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is authenticated as Data Engineer with appropriate permissions
- Synchronization system is operational and accessible
- Test dataset with known transformation errors is prepared
- Error logging service is enabled and configured
- Database connection is established

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare test data containing records with known transformation errors (invalid data types, missing required fields, format violations) | Test dataset is ready with at least 5 records containing different types of transformation errors |
| 2 | Load the test dataset into the source system for synchronization | Test data is successfully loaded and available for synchronization process |
| 3 | Navigate to the synchronization dashboard and initiate synchronization process for the test dataset | Synchronization process starts and displays 'In Progress' status |
| 4 | Monitor the synchronization process as it encounters transformation errors | System detects transformation errors and continues processing without stopping. Error counter increments for each invalid record |
| 5 | Wait for synchronization process to complete | Synchronization completes with status 'Completed with Errors'. Valid records are processed successfully |
| 6 | Navigate to error logs section via /sync/errors endpoint or UI | Error logs page loads successfully showing list of logged errors |
| 7 | Review error log entries for the completed synchronization job | All transformation errors are logged with detailed context including: timestamp, record identifier, error type, error message, field name, invalid value, and transformation rule violated |
| 8 | Verify error classification in the logs | Errors are properly classified by type (data type mismatch, missing field, format violation, business rule violation) |
| 9 | Access error reports and verify accessibility | Error reports are accessible, accurately display all logged errors, and provide complete context for troubleshooting |

**Postconditions:**
- All transformation errors are logged in the system
- Valid records are successfully synchronized to target system
- Invalid records are skipped and marked in error logs
- Error logs are available for administrator review
- System remains in operational state

---

### Test Case: Test notification delivery upon error detection
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is authenticated as Data Engineer
- Administrator accounts are configured with valid email addresses
- Notification service is enabled and configured
- SMTP or notification gateway is operational
- Test data with transformation errors is prepared
- Synchronization system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure notification settings to ensure administrators are subscribed to error notifications | Administrator notification preferences are set to receive error alerts |
| 2 | Prepare and load test dataset containing multiple records with transformation errors | Test dataset with error-prone data is loaded into source system |
| 3 | Initiate synchronization process with the error-prone dataset | Synchronization starts and begins processing records |
| 4 | Monitor system as transformation errors are detected during synchronization | System detects transformation errors and triggers notification mechanism |
| 5 | Check notification delivery time from error detection to notification sent | Notification is sent to administrators within 2 minutes of error detection (promptly) |
| 6 | Verify notification recipients list | All configured administrators receive the notification. No unauthorized recipients are included |
| 7 | Open and review notification content | Notification contains: error summary with count, job identifier, timestamp, error types breakdown, severity level, and link to detailed error logs |
| 8 | Click on the link to detailed error logs provided in the notification | Link navigates directly to the relevant error report with filtered view of the specific synchronization job errors |
| 9 | Verify notification format and readability | Notification is well-formatted, easy to read, and contains actionable information for administrators |

**Postconditions:**
- Administrators have received error notifications
- Notification logs show successful delivery
- Error details are accessible via notification links
- System continues normal operation

---

### Test Case: Validate synchronization performance with errors
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- User is authenticated as Data Engineer with performance monitoring access
- Synchronization system is operational
- Performance monitoring tools are configured and active
- SLA performance baseline is documented (expected synchronization duration)
- Large test dataset with known percentage of error-prone records is prepared
- System resources are at normal operational levels

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Review and document the SLA performance limits for synchronization (e.g., maximum duration, throughput requirements) | SLA limits are clearly documented and understood (e.g., synchronization should complete within X minutes for Y records) |
| 2 | Prepare test dataset containing 10,000 records with 20% containing transformation errors | Test dataset is ready with 8,000 valid records and 2,000 records with various transformation errors |
| 3 | Record baseline synchronization time by running synchronization with 10,000 valid records (no errors) | Baseline synchronization completes successfully and duration is recorded (e.g., 5 minutes) |
| 4 | Clear any cached data and reset system to initial state | System is reset and ready for performance test with error-prone data |
| 5 | Start performance monitoring tools to track CPU, memory, and I/O metrics | Performance monitoring is active and recording metrics |
| 6 | Initiate synchronization process with the error-prone dataset and start timer | Synchronization starts processing records with timestamp recorded |
| 7 | Monitor synchronization progress and observe error handling overhead | System processes records, detects errors, logs them, and continues without stopping. Progress indicator shows steady advancement |
| 8 | Wait for synchronization to complete and record end time | Synchronization completes with status 'Completed with Errors' and total duration is recorded |
| 9 | Calculate total synchronization duration and compare against SLA limits | Synchronization duration with 20% error rate remains within SLA limits (e.g., completes within 6 minutes, not exceeding 20% overhead from baseline) |
| 10 | Review performance metrics (CPU, memory, I/O) during synchronization | System resources remain within acceptable operational ranges. No resource exhaustion or bottlenecks observed |
| 11 | Verify that valid records were processed at expected throughput rate | 8,000 valid records were successfully synchronized. Throughput meets or exceeds minimum SLA requirements |
| 12 | Review error logging overhead impact on performance | Error detection and logging adds minimal overhead (less than 10% performance impact). Error logs are complete and accurate |

**Postconditions:**
- Synchronization performance with errors is documented and within SLA
- Valid records are successfully synchronized
- All errors are properly logged without performance degradation
- Performance metrics are recorded for future reference
- System returns to normal operational state

---

## Story: As Scheduler, I want to view synchronization job history to achieve audit and troubleshooting capabilities
**Story ID:** story-19

### Test Case: Verify recording and retrieval of synchronization job history
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 18 mins

**Preconditions:**
- User is authenticated as Scheduler with appropriate permissions
- Synchronization system is operational
- Job execution database is accessible and configured
- At least 3 different synchronization job types are configured
- Job history UI is accessible
- Export functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Execute a synchronization job of type 'Daily Customer Sync' and wait for completion | Job completes successfully with status 'Completed'. Job execution details are visible in the system |
| 2 | Execute a synchronization job of type 'Product Catalog Sync' that completes with errors | Job completes with status 'Completed with Errors'. Error count is displayed |
| 3 | Execute a synchronization job of type 'Inventory Sync' and manually stop it mid-execution | Job is stopped with status 'Cancelled'. Partial completion data is recorded |
| 4 | Wait 30 seconds to ensure all job metadata is persisted to the database | All three job executions are recorded in the job execution database |
| 5 | Navigate to the synchronization job history page via UI or /sync/jobs/history endpoint | Job history page loads within 2 seconds displaying list of recent synchronization jobs |
| 6 | Verify that all three executed jobs appear in the job history list | All three jobs are displayed with complete metadata including: job ID, job type, start time, end time, duration, status, records processed, and user who initiated the job |
| 7 | Apply date range filter to show only jobs from today | Job history list updates to display only jobs executed today. All three test jobs are visible |
| 8 | Apply status filter to show only jobs with status 'Completed with Errors' | Job history list updates to display only the 'Product Catalog Sync' job. Other jobs are filtered out |
| 9 | Clear filters and apply job type filter to show only 'Daily Customer Sync' jobs | Job history list updates to display only jobs of type 'Daily Customer Sync'. Filtered results are accurate |
| 10 | Clear all filters and sort job history by start time in descending order | Job history list is sorted with most recent jobs appearing first. Sort order is correct |
| 11 | Click on one of the job records to view detailed job execution information | Detailed view opens showing comprehensive job information including: full metadata, execution timeline, records processed/failed, transformation details, and linked error logs if applicable |
| 12 | Return to job history list and select export option for CSV format | Export dialog appears with CSV format selected and option to choose date range and filters |
| 13 | Configure export to include all jobs from today and initiate export | CSV file is generated and downloaded successfully. File name includes timestamp |
| 14 | Open the exported CSV file and verify its contents | CSV file contains accurate job information for all three test jobs with columns: job ID, job type, start time, end time, duration, status, records processed, records failed, initiated by |
| 15 | Return to job history UI and select export option for JSON format | Export dialog appears with JSON format selected |
| 16 | Configure export to include all jobs and initiate JSON export | JSON file is generated and downloaded successfully |
| 17 | Open the exported JSON file and validate its structure and content | JSON file is well-formed with valid syntax. Contains array of job objects with complete metadata matching the CSV export data |

**Postconditions:**
- All synchronization jobs are recorded with complete metadata
- Job history is accessible and displays accurate information
- Filters and sorting work correctly
- Exported files contain correct and complete job information
- System remains in operational state

---

### Test Case: Test access control for job history feature
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Multiple user accounts are configured with different roles
- Test user account with 'Scheduler' role exists and is active
- Test user account with 'Viewer' role (unauthorized) exists and is active
- Test user account with no assigned role exists
- Role-based access control (RBAC) is enabled and configured
- Job history feature has access restrictions configured
- At least 5 synchronization jobs exist in job history

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log out any currently authenticated user to start with clean session | User is logged out successfully. Session is cleared |
| 2 | Attempt to access job history page URL (/sync/jobs/history) without authentication | Access is denied. System redirects to login page or returns 401 Unauthorized error |
| 3 | Log in using test account with 'Viewer' role (unauthorized for job history) | Login is successful. User is authenticated with 'Viewer' role |
| 4 | Attempt to navigate to job history page via UI menu or direct URL | Access is denied with appropriate error message: 'Access Denied: You do not have permission to view job history. Contact your administrator.' Job history menu option is not visible or disabled |
| 5 | Attempt to access job history API endpoint directly via /sync/jobs/history GET request | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 6 | Verify that no job history data is exposed in the error response | Error response contains only access denial message. No sensitive job data is leaked |
| 7 | Log out the 'Viewer' user | User is logged out successfully |
| 8 | Log in using test account with no assigned role | Login is successful. User is authenticated but has no specific role assigned |
| 9 | Attempt to access job history page | Access is denied with appropriate error message. User cannot view job history |
| 10 | Log out the user with no role | User is logged out successfully |
| 11 | Log in using test account with 'Scheduler' role (authorized) | Login is successful. User is authenticated with 'Scheduler' role |
| 12 | Navigate to job history page via UI menu | Job history menu option is visible and accessible. User can click to navigate |
| 13 | Access job history page | Full access is granted. Job history page loads successfully within 2 seconds displaying all synchronization jobs |
| 14 | Verify all job history features are accessible: filtering, sorting, pagination, detailed view, and export | All features are fully functional. Scheduler can view job details, apply filters, sort results, navigate pages, and export data |
| 15 | Apply various filters and access detailed job information | All job history data is accessible. Filters work correctly. Detailed job information displays complete metadata |
| 16 | Export job history in CSV format | Export is successful. CSV file downloads with complete job history data |
| 17 | Verify access control is logged in system audit logs | Audit logs show denied access attempts by unauthorized users and successful access by Scheduler role |

**Postconditions:**
- Unauthorized users cannot access job history
- Authorized Scheduler users have full access to job history
- Access control is properly enforced at UI and API levels
- Access attempts are logged for audit purposes
- No sensitive data is exposed through error messages

---

