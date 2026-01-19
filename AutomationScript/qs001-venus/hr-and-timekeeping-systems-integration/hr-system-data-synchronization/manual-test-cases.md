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
| 2 | Monitor the synchronization process as employee data is retrieved from HR system | Employee data is successfully retrieved from HR API with HTTP 200 status code and data extraction completes without errors |
| 3 | Observe the data validation process for mandatory fields | All mandatory fields are validated successfully and no validation errors are generated |
| 4 | Verify that employee records are updated or created in the new platform database | All employee records are successfully inserted or updated in the database with correct data mapping |
| 5 | Navigate to the employee records section in the new platform and verify updated records | Employee records in the new platform reflect the latest data from HR system including all personal information fields |
| 6 | Access the synchronization logs via /api/hr/sync logs or admin dashboard | Synchronization logs show successful completion status with no errors logged |
| 7 | Check the completion timestamp in the synchronization logs | Synchronization completed within 30 minutes SLA from start time |
| 8 | Verify the total count of records processed matches the count in HR system | Record count matches 100% with no data loss reported |

**Postconditions:**
- All employee records are synchronized and up-to-date in the new platform
- Synchronization logs contain complete execution details with success status
- No error notifications sent to HR team
- System is ready for next scheduled synchronization
- Database integrity is maintained

---

### Test Case: Verify handling of incomplete employee data
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- HR system API is accessible and operational
- API authentication credentials are configured correctly
- Test employee records with missing mandatory fields are prepared in HR system
- Validation rules for mandatory fields are configured in the synchronization system
- Error logging mechanism is functional
- At least one complete employee record exists for processing verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare test data in HR system with employee records missing mandatory fields (e.g., employee ID, first name, last name, or email) | Test employee records with incomplete data are available in HR system API response |
| 2 | Trigger the synchronization job to process employee data including incomplete records | Synchronization job starts and begins retrieving employee data from HR API |
| 3 | Monitor the validation process as incomplete employee records are processed | System detects missing mandatory fields and generates validation errors for incomplete records |
| 4 | Access synchronization logs and search for error entries related to incomplete records | Synchronization logs contain specific error messages identifying which records failed validation and which mandatory fields are missing |
| 5 | Verify that incomplete employee records are not created or updated in the new platform database | Incomplete records are skipped and not inserted/updated in the database, maintaining data integrity |
| 6 | Check that synchronization continues processing remaining valid employee records after encountering incomplete data | System continues processing and successfully synchronizes all complete employee records without stopping |
| 7 | Verify error notification is sent to HR team with details of incomplete records | HR team receives error report listing all incomplete records with specific missing field information |
| 8 | Confirm the synchronization job completes with partial success status | Synchronization completes with status indicating successful processing of valid records and errors for incomplete records |

**Postconditions:**
- Only complete employee records are synchronized to the new platform
- Incomplete records remain unprocessed and are not stored in database
- Error logs contain detailed information about validation failures
- HR team is notified of incomplete records requiring correction
- System maintains data quality and integrity
- Synchronization process completed without system failure

---

## Story: As HR Analyst, I want to manually trigger employee data synchronization to achieve immediate updates
**Story ID:** story-17

### Test Case: Verify authorized user can trigger manual sync
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 40 mins

**Preconditions:**
- HR Analyst user account exists with proper role-based access control permissions
- HR system API is accessible and operational
- Manual synchronization endpoint /api/hr/sync/manual is deployed and functional
- User has valid login credentials for HR Analyst role
- Synchronization page UI is accessible in the application
- Test employee data exists in HR system for synchronization
- Logging system is operational to capture manual sync events

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid HR Analyst credentials | Login is successful and user is authenticated as HR Analyst |
| 2 | Access the synchronization page from the main navigation menu or dashboard | Synchronization page loads successfully and 'Sync Now' button is visible and enabled for HR Analyst |
| 3 | Click the 'Sync Now' button to trigger manual employee data synchronization | Manual synchronization process initiates immediately and status indicator shows 'Synchronization in Progress' |
| 4 | Observe the real-time synchronization status displayed on the page | Status updates are displayed showing progress such as 'Connecting to HR API', 'Retrieving data', 'Validating records', 'Updating database' |
| 5 | Wait for the synchronization process to complete | Synchronization completes within 30 minutes and final status shows 'Synchronization Completed Successfully' with summary of records processed |
| 6 | Review the synchronization results displayed on the page | Results show total records processed, successful updates, any errors encountered, and completion timestamp |
| 7 | Navigate to the synchronization logs section or access logs via admin panel | Manual sync event is logged in the system logs |
| 8 | Verify the log entry contains user information and timestamp | Log entry shows correct HR Analyst username, timestamp of manual sync trigger, and event type as 'Manual Synchronization' |
| 9 | Verify employee records in the new platform reflect the latest data from HR system | Employee records are updated with the most recent data from HR system matching the manual sync timestamp |

**Postconditions:**
- Employee data is synchronized and up-to-date in the new platform
- Manual sync event is logged with correct user and timestamp details
- Synchronization status is displayed accurately to the HR Analyst
- User remains logged in and can perform additional operations
- System is ready for subsequent manual or scheduled synchronizations

---

### Test Case: Verify unauthorized user cannot trigger manual sync
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Non-HR user account exists without HR Analyst role permissions
- Role-based access control is properly configured in the system
- Manual synchronization endpoint /api/hr/sync/manual has authorization checks enabled
- User has valid login credentials for non-HR role (e.g., regular employee, viewer)
- Security policies are enforced at both UI and API levels

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid credentials for a non-HR user account | Login is successful and user is authenticated with non-HR role permissions |
| 2 | Attempt to navigate to the synchronization page via direct URL or menu navigation | Access is denied and user receives 'Access Denied' or '403 Forbidden' error message, or synchronization page is not visible in navigation menu |
| 3 | Verify that the synchronization page does not load and user is redirected to unauthorized access page or dashboard | User cannot access the synchronization page and appropriate error message is displayed indicating insufficient permissions |
| 4 | Using API testing tool (e.g., Postman, cURL), attempt to directly call the manual sync API endpoint /api/hr/sync/manual with non-HR user authentication token | API request is rejected with HTTP 401 Unauthorized or 403 Forbidden status code |
| 5 | Verify the API error response contains appropriate authorization error message | Response body contains error message such as 'Unauthorized access' or 'Insufficient permissions to perform this operation' |
| 6 | Check security logs for unauthorized access attempts | Security logs record the unauthorized access attempt with user details, timestamp, and denied action |
| 7 | Verify that no synchronization process was initiated by the unauthorized attempt | Synchronization logs show no new manual sync events triggered by the non-HR user |
| 8 | Confirm employee data remains unchanged and no unintended synchronization occurred | Employee records show no updates from unauthorized sync attempt and data integrity is maintained |

**Postconditions:**
- Unauthorized user access is successfully blocked at both UI and API levels
- No manual synchronization is triggered by unauthorized user
- Security logs contain record of unauthorized access attempt
- Employee data remains unchanged and secure
- System security controls are validated as functional
- User session remains active but restricted to authorized functions only

---

