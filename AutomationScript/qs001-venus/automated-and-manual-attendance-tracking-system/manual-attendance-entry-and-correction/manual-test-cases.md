# Manual Test Cases

## Story: As Attendance Officer, I want to manually input attendance records to achieve accurate tracking when biometric data is unavailable
**Story ID:** story-23

### Test Case: Validate successful manual attendance record addition
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has valid attendance officer credentials
- User has authorization to access manual attendance entry functionality
- At least one active employee exists in the system
- Database is accessible and operational
- Manual attendance entry page is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid attendance officer credentials (username and password), then click Login button | User is successfully authenticated and redirected to the dashboard with access to manual attendance entry page |
| 2 | Navigate to the manual attendance entry page from the dashboard menu | Manual attendance entry page is displayed with empty form fields for employee ID, date, time, and status |
| 3 | Enter a valid employee ID in the employee ID field | Employee ID is accepted and employee name is displayed or auto-populated if applicable |
| 4 | Select or enter a valid date in the date field (current or past date within allowed range) | Date is accepted without validation errors and displayed in correct format |
| 5 | Enter a valid time in the time field (format HH:MM) | Time is accepted without validation errors and displayed in correct format |
| 6 | Select attendance status from the dropdown (e.g., Present, Absent, Late) | Status is selected and displayed in the form |
| 7 | Click the Submit button to save the manual attendance record | Record is successfully saved to the database and a confirmation message is displayed (e.g., 'Attendance record added successfully') |
| 8 | Verify the newly added record appears in the attendance records list | The manual attendance record is visible in the list with correct employee ID, date, time, and status |

**Postconditions:**
- Manual attendance record is saved in the database
- Confirmation message is displayed to the user
- Record is visible in attendance records list
- Audit trail entry is created for the new record
- User remains logged in and can add additional records

---

### Test Case: Verify validation rejects invalid employee IDs
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as authorized attendance officer
- Manual attendance entry page is accessible
- Database contains valid employee records
- System validation rules are configured for employee ID verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the manual attendance entry page from the dashboard | Manual attendance entry page is displayed with empty form fields |
| 2 | Enter a non-existent employee ID (e.g., 'EMP99999' or any ID not in the database) in the employee ID field | Employee ID field accepts the input |
| 3 | Tab out of the employee ID field or trigger validation | Validation error message is displayed (e.g., 'Employee ID does not exist' or 'Invalid employee ID') |
| 4 | Enter valid date and time in respective fields | Date and time fields accept the input without errors |
| 5 | Select attendance status from the dropdown | Status is selected successfully |
| 6 | Click the Submit button to attempt saving the record | Submission is blocked and error message is displayed indicating 'Cannot submit record with invalid employee ID' or similar message |
| 7 | Verify that no record is created in the database | No new attendance record appears in the attendance records list |

**Postconditions:**
- No attendance record is saved in the database
- Error message is displayed to the user
- Form remains on the page with entered data
- User can correct the employee ID and resubmit
- No audit trail entry is created for failed submission

---

### Test Case: Ensure audit trail records manual attendance edits
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as authorized attendance officer
- At least one manual attendance record exists in the system
- User has permission to edit attendance records
- Audit logging functionality is enabled and operational
- Audit log table is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance records list page | Attendance records list is displayed with existing manual attendance records |
| 2 | Locate an existing manual attendance record and click the Edit button or icon | Edit form is displayed with current data pre-populated (employee ID, date, time, status) |
| 3 | Note the original attendance time value for verification purposes | Original time value is visible and recorded |
| 4 | Modify the attendance time field to a different valid time (e.g., change from 09:00 to 09:30) | Time field accepts the new value without validation errors |
| 5 | Click the Submit or Save button to save the changes | Changes are successfully saved and confirmation message is displayed (e.g., 'Attendance record updated successfully') |
| 6 | Verify the updated record shows the new time in the attendance records list | Attendance record displays the modified time value |
| 7 | Navigate to the audit logs section or view audit history for the specific attendance record | Audit log page or section is displayed |
| 8 | Review the audit log entry for the edited record | Audit log shows edit details accurately including: user ID/name of the attendance officer, timestamp of the change, original time value, new time value, and action type (Edit/Update) |
| 9 | Verify the timestamp in the audit log matches the time when the edit was performed | Timestamp is accurate and reflects the actual time of modification |

**Postconditions:**
- Attendance record is updated with new time value
- Audit trail entry is created in the audit log table
- Audit log contains user ID, timestamp, and change details
- Original and modified values are preserved in audit history
- User can view complete audit history for the record

---

## Story: As Attendance Officer, I want to correct attendance records with audit logging to maintain data integrity
**Story ID:** story-26

### Test Case: Validate attendance record correction with audit logging
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User has valid attendance officer credentials with correction privileges
- User is authorized to edit attendance records
- At least one attendance record exists in the system that requires correction
- Audit logging system is enabled and functional
- Database and audit log tables are accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid attendance officer credentials, then click Login button | User is successfully authenticated and redirected to the dashboard with access to attendance management page |
| 2 | Navigate to the attendance management page from the dashboard menu | Attendance management page is displayed showing list of attendance records with search and filter options |
| 3 | Search for or locate the specific attendance record that needs correction using employee ID, date, or other filters | Target attendance record is displayed in the results list |
| 4 | Click the Edit button or icon for the selected attendance record | Edit form is displayed with current data pre-populated including employee ID, date, time, status, and any other relevant fields |
| 5 | Review the current attendance details and identify the field(s) requiring correction | All current values are visible and editable fields are enabled |
| 6 | Modify the attendance details (e.g., change time from 08:45 to 09:00, or status from Absent to Present) | Modified values are accepted in the form fields without validation errors |
| 7 | Add correction notes or reason in the comments field if available | Comments are accepted and displayed in the form |
| 8 | Click the Submit or Save button to save the corrected attendance record | System validates the corrections against attendance business rules (shift schedules, date ranges, etc.) and accepts the changes |
| 9 | Observe the confirmation message displayed by the system | Confirmation message is displayed (e.g., 'Attendance record corrected successfully') and changes are saved within 2 seconds |
| 10 | Verify the corrected record in the attendance records list shows updated values | Attendance record displays the corrected values accurately |
| 11 | Navigate to the audit log section or view audit history for the corrected record | Audit log is displayed with entries for the selected record |
| 12 | Review the latest audit log entry for the correction | Audit log entry shows: user ID/name of the attendance officer who made the correction, timestamp of the correction, original values (before correction), new values (after correction), action type (Correction/Edit), and any comments or reasons provided |

**Postconditions:**
- Attendance record is updated with corrected values in the database
- Audit log entry is created with complete change details
- Audit trail includes user ID, timestamp, original values, and new values
- Confirmation message is displayed to the user
- Data integrity is maintained with full traceability
- User can perform additional corrections if needed

---

### Test Case: Verify audit history display for attendance records
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as authorized attendance officer
- At least one attendance record exists with previous corrections or changes
- Audit logging has captured historical changes for the record
- Audit history display functionality is available
- User has permission to view audit logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance management page or attendance records list | Attendance records list is displayed with available records |
| 2 | Locate a specific attendance record that has been previously modified or corrected | Target attendance record is visible in the list |
| 3 | Click on the View Audit History button, icon, or link associated with the selected attendance record | Audit history page or modal is displayed for the specific attendance record |
| 4 | Review the audit log entries displayed in chronological order | Audit log shows all changes made to the record with entries listed from most recent to oldest or vice versa |
| 5 | Verify each audit log entry contains user information (user ID or username) | Each entry displays the user who made the change clearly |
| 6 | Verify each audit log entry contains timestamp information (date and time of change) | Each entry displays accurate timestamp in readable format (e.g., 'DD-MM-YYYY HH:MM:SS') |
| 7 | Verify each audit log entry shows the type of action performed (Create, Edit, Delete, Correction) | Action type is clearly indicated for each entry |
| 8 | Verify each audit log entry shows the changed fields with original and new values | For each modification, the audit log displays 'Field Name: Old Value → New Value' or similar format |
| 9 | If multiple changes exist, verify all historical changes are displayed completely | Complete audit trail is visible showing the full history of the attendance record from creation to current state |
| 10 | Verify any comments or reasons for corrections are displayed in the audit history | Comments or correction reasons are visible alongside the corresponding audit entries |

**Postconditions:**
- Audit history is displayed accurately for the selected record
- All changes are visible with user and timestamp information
- User can review complete change history for accountability
- Audit log data remains unchanged after viewing
- User can close audit history and return to attendance management page

---

## Story: As Attendance Officer, I want to view real-time attendance logs to monitor daily attendance status
**Story ID:** story-28

### Test Case: Validate real-time attendance log display and filtering
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Attendance officer account exists with valid credentials
- Attendance officer role has access permissions to attendance log dashboard
- Attendance streaming API is operational and returning data
- Database contains validated attendance records from biometric and manual sources
- Test environment is configured with GET /api/attendance/logs endpoint
- Browser is supported and updated to latest version

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance system login page | Login page is displayed with username and password fields |
| 2 | Enter valid attendance officer credentials (username and password) | Credentials are accepted and login button is enabled |
| 3 | Click the login button | Access granted and user is redirected to attendance log dashboard |
| 4 | Verify the attendance log dashboard loads with default view | Dashboard displays attendance log table with columns for employee name, date, time, status, and source (biometric/manual) |
| 5 | View attendance logs with default filters applied | Logs are displayed showing recent validated records sorted by most recent timestamp, with data from both biometric and manual sources visible |
| 6 | Verify only validated attendance records are displayed | All displayed records show validation status as 'Validated' and no unvalidated records appear in the list |
| 7 | Locate and click on the employee filter dropdown | Employee filter dropdown opens showing list of employees with attendance records |
| 8 | Select a specific employee from the dropdown list | Employee is selected and filter is applied |
| 9 | Observe the filtered attendance logs | Logs display only attendance records for the selected employee |
| 10 | Locate and click on the date filter field | Date picker calendar opens for date selection |
| 11 | Select a specific date or date range from the date picker | Date is selected and applied to the filter |
| 12 | Observe the filtered attendance logs with both employee and date filters applied | Logs display only attendance records matching both the selected employee and the selected date/date range |
| 13 | Locate and click on the status filter dropdown | Status filter dropdown opens showing available status options (Present, Absent, Late, etc.) |
| 14 | Select a specific status from the dropdown | Status is selected and filter is applied |
| 15 | Observe the filtered attendance logs with all three filters applied | Logs display only attendance records matching the selected employee, date, and status criteria |
| 16 | Verify the record count updates to reflect filtered results | Total record count displayed on dashboard updates to show number of records matching applied filters |

**Postconditions:**
- User remains logged in to the attendance dashboard
- Applied filters remain active on the dashboard
- Filtered attendance logs are displayed correctly
- System maintains session state for the attendance officer
- No data modifications have occurred

---

### Test Case: Verify automatic data refresh functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Attendance officer is already logged into the system
- Attendance log dashboard is currently displayed
- Attendance streaming API is operational and actively receiving new attendance data
- System auto-refresh is configured to refresh every 1 minute
- Database is being updated with new attendance entries during test execution
- System clock is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current timestamp displayed on the dashboard | Current timestamp is visible showing last refresh time |
| 2 | Note the current number of attendance records displayed | Record count is visible and documented for comparison |
| 3 | Observe the attendance log dashboard without any user interaction | Dashboard remains active and visible with current data displayed |
| 4 | Wait for 1 minute while monitoring the dashboard | After approximately 60 seconds, dashboard automatically refreshes without manual intervention |
| 5 | Verify the timestamp updates to reflect the automatic refresh | Last refresh timestamp updates to current time showing data was refreshed |
| 6 | Check if any new attendance records appear in the log | New attendance entries that were added to the system in the last minute are now visible in the dashboard |
| 7 | Verify the refresh completes within 5 seconds as per performance requirements | Data refresh operation completes within 5 seconds from initiation |
| 8 | Continue observing the dashboard for an additional 1 minute without interaction | Dashboard remains active and responsive |
| 9 | Wait for the second automatic refresh cycle to complete | After another 60 seconds, dashboard automatically refreshes again |
| 10 | Verify the timestamp updates again to reflect the second automatic refresh | Last refresh timestamp updates to current time, confirming second automatic refresh occurred |
| 11 | Check for any additional new attendance records in the log | Any new attendance entries added in the second minute interval are now visible in the dashboard |
| 12 | Verify no error messages or warnings appear during automatic refresh cycles | Dashboard refreshes smoothly without displaying any errors, warnings, or interruptions to the user experience |
| 13 | Confirm data freshness is maintained at 99% within 1 minute as per success metrics | All displayed data reflects attendance entries recorded within the last 1 minute, meeting the 99% data freshness requirement |

**Postconditions:**
- Attendance dashboard continues to auto-refresh every minute
- User remains logged in with active session
- Latest attendance data is displayed on the dashboard
- System performance remains within acceptable limits (refresh within 5 seconds)
- No system errors or data inconsistencies are present
- Auto-refresh functionality continues to operate for subsequent cycles

---

