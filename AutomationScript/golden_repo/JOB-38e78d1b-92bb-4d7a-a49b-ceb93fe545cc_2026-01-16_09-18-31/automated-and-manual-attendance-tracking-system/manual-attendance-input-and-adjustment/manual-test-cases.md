# Manual Test Cases

## Story: As HR Officer, I want to input manual attendance entries to achieve complete attendance records
**Story ID:** story-24

### Test Case: Validate manual attendance creation with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- Manual attendance entry page is accessible
- At least one employee exists in the system
- No existing attendance record exists for the selected employee and date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance entry page | Form is displayed with required fields including employee selector, date picker, time in, time out, and attendance status fields |
| 2 | Select an employee from the employee dropdown list | Employee is selected and displayed in the form |
| 3 | Select a valid date using the date picker | Date is populated in the date field |
| 4 | Enter valid time in (e.g., 09:00 AM) and time out (e.g., 05:00 PM) | Time values are accepted and displayed in the respective fields without validation errors |
| 5 | Select attendance status (e.g., Present, Half-day) | Attendance status is selected and displayed |
| 6 | Add optional remarks or notes in the remarks field | Remarks are entered successfully |
| 7 | Click the Submit button to save the manual attendance entry | Entry is saved successfully, confirmation message is displayed showing 'Manual attendance entry created successfully', and the form is cleared or redirected to the attendance list |
| 8 | Verify the submission response time | System responds and saves the entry within 3 seconds |

**Postconditions:**
- Manual attendance entry is saved in the database
- Audit log contains entry creation record with HR officer username and timestamp
- Employee attendance record is updated for the specified date
- Confirmation message is visible to the user

---

### Test Case: Verify validation prevents overlapping attendance records
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- Manual attendance entry page is accessible
- An existing attendance record exists for employee 'John Doe' on date '2024-01-15' with time 09:00 AM to 05:00 PM

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance entry page | Manual attendance form is displayed |
| 2 | Select employee 'John Doe' from the employee dropdown | Employee 'John Doe' is selected |
| 3 | Select date '2024-01-15' which already has an attendance record | Date is populated in the date field |
| 4 | Enter overlapping time in as 10:00 AM and time out as 06:00 PM | Time values are entered in the form |
| 5 | Click Submit button to attempt creating the overlapping attendance record | System displays validation error message 'Attendance record already exists for this employee on the selected date' or 'Overlapping attendance period detected' and blocks submission |
| 6 | Change the date to '2024-01-16' which has no existing attendance record | Date field is updated to '2024-01-16' |
| 7 | Keep the same time in (10:00 AM) and time out (06:00 PM) values | Time values remain in the form |
| 8 | Click Submit button to resubmit with corrected non-overlapping data | Submission succeeds, confirmation message 'Manual attendance entry created successfully' is displayed, and entry is saved |

**Postconditions:**
- No overlapping attendance record is created
- Valid attendance entry for the corrected date is saved in the database
- Audit log records the successful entry creation
- Original attendance record for 2024-01-15 remains unchanged

---

### Test Case: Ensure audit trail logs manual attendance changes
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as authorized HR officer with username 'hr.officer@company.com'
- Manual attendance entry page is accessible
- Audit logging system is enabled and functioning
- Database has audit trail table configured
- At least one employee exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance entry page | Manual attendance form is displayed |
| 2 | Select employee 'Jane Smith', date '2024-01-20', time in '08:30 AM', time out '04:30 PM', and status 'Present' | All fields are populated with the entered values |
| 3 | Click Submit button to create the manual attendance entry | Entry is saved successfully and confirmation message is displayed |
| 4 | Access the audit log table or audit trail report for manual attendance | Audit log displays a new record with action 'CREATE', user 'hr.officer@company.com', timestamp of creation, employee 'Jane Smith', date '2024-01-20', and all entered attendance details |
| 5 | Navigate to the attendance records list and locate the created entry for Jane Smith on 2024-01-20 | Attendance record is displayed in the list |
| 6 | Click Edit button on the attendance record | Edit form is displayed with existing attendance data pre-populated |
| 7 | Modify the time out from '04:30 PM' to '05:00 PM' and add remarks 'Extended work hours' | Modified values are entered in the form |
| 8 | Click Update button to save the modifications | Entry is updated successfully and confirmation message 'Attendance record updated successfully' is displayed |
| 9 | Access the audit log table or audit trail report again | Audit log displays a new record with action 'UPDATE', user 'hr.officer@company.com', timestamp of modification, employee 'Jane Smith', date '2024-01-20', old value 'time out: 04:30 PM', new value 'time out: 05:00 PM', and remarks modification details |
| 10 | Navigate back to the attendance records list and locate the entry for Jane Smith on 2024-01-20 | Attendance record is displayed |
| 11 | Click Delete button on the attendance record | Confirmation dialog appears asking 'Are you sure you want to delete this attendance record?' |
| 12 | Click Confirm or Yes to proceed with deletion | Entry is deleted successfully and confirmation message 'Attendance record deleted successfully' is displayed |
| 13 | Access the audit log table or audit trail report once more | Audit log displays a new record with action 'DELETE', user 'hr.officer@company.com', timestamp of deletion, employee 'Jane Smith', date '2024-01-20', and all details of the deleted record |
| 14 | Verify that all three audit log entries (CREATE, UPDATE, DELETE) are present and contain complete information | All audit log entries are present with 100% completeness including user, timestamp, action type, and affected data |

**Postconditions:**
- Audit log contains three entries for the attendance record: CREATE, UPDATE, and DELETE
- Each audit entry includes HR officer username, accurate timestamp, action type, and complete data details
- Audit trail completeness is 100% for all manual attendance modifications
- Deleted attendance record is no longer visible in the active records list but is preserved in audit history

---

## Story: As HR Officer, I want to bulk upload manual attendance records to achieve efficient data entry
**Story ID:** story-26

### Test Case: Validate successful bulk upload with valid CSV
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- Bulk upload page is accessible
- Valid CSV file is prepared with correct schema (columns: employee_id, date, time_in, time_out, status, remarks)
- CSV file contains 50 valid attendance records
- All employees referenced in CSV exist in the system
- No overlapping attendance records exist for the dates in the CSV

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the bulk upload page from the main attendance menu | Bulk upload page is displayed with file upload form, instructions for CSV format, and a sample CSV download link |
| 2 | Review the CSV format instructions and required columns | Instructions clearly state required columns: employee_id, date, time_in, time_out, status, remarks |
| 3 | Click 'Choose File' or 'Browse' button to open file selector | File selection dialog opens |
| 4 | Select the valid CSV file containing 50 attendance records | Selected file name is displayed next to the file input field |
| 5 | Click 'Upload' or 'Submit' button to initiate the bulk upload process | System displays a progress indicator showing 'Processing file...' or upload progress percentage |
| 6 | Wait for the system to process the CSV file | System completes processing within 2 minutes and displays upload summary report |
| 7 | Review the upload summary report displayed on screen | Summary shows: Total records: 50, Successfully uploaded: 50, Failed: 0, Processing time, and a success message 'All records uploaded successfully' |
| 8 | Navigate to the manual attendance records list or search for specific records from the uploaded CSV | All 50 attendance records from the CSV are visible in the system |
| 9 | Verify a sample of 5 records by comparing CSV data with saved records in the system | All verified records match the CSV data exactly including employee_id, date, time_in, time_out, status, and remarks |
| 10 | Check the database or audit log for bulk upload entry | Audit log shows bulk upload event with HR officer username, timestamp, file name, and number of records processed |

**Postconditions:**
- All 50 valid attendance records are persisted in the database
- Upload summary report is available for download or viewing
- Audit log contains bulk upload event details
- No duplicate or overlapping records are created
- System performance meets the 2-minute processing requirement for 50 records

---

### Test Case: Verify error reporting for invalid CSV records
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- Bulk upload page is accessible
- CSV file is prepared with 20 records: 15 valid records and 5 invalid records
- Invalid records include: missing employee_id, invalid date format, time_out before time_in, non-existent employee_id, and missing required status field

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the bulk upload page | Bulk upload form is displayed with file upload option |
| 2 | Click 'Choose File' button and select the CSV file containing 15 valid and 5 invalid records | File name is displayed in the file input field |
| 3 | Click 'Upload' button to submit the CSV file | System begins processing the file and displays progress indicator |
| 4 | Wait for the system to complete validation and processing | System completes processing and displays upload summary with error details |
| 5 | Review the upload summary report | Summary shows: Total records: 20, Successfully uploaded: 15, Failed: 5, with a warning message 'Some records failed validation' |
| 6 | Expand or view the detailed error report section | Detailed error messages are displayed for each of the 5 invalid records including: Row 3 - 'Missing employee_id', Row 7 - 'Invalid date format, expected YYYY-MM-DD', Row 11 - 'Time out cannot be before time in', Row 14 - 'Employee ID EMP999 does not exist', Row 18 - 'Missing required field: status' |
| 7 | Download or export the error report if option is available | Error report is downloaded as CSV or PDF file containing all error details with row numbers and error descriptions |
| 8 | Verify that valid records were saved by navigating to attendance records list | 15 valid attendance records from the CSV are visible and saved in the system |
| 9 | Open the original CSV file and correct the 5 invalid records based on error messages | CSV file is corrected with valid employee_id, proper date format (YYYY-MM-DD), correct time sequence, existing employee_id, and required status field |
| 10 | Return to bulk upload page and upload the corrected CSV file | File upload form is displayed |
| 11 | Select the corrected CSV file and click Upload button | System processes the file |
| 12 | Review the upload summary for the corrected file | Summary shows: Total records: 5, Successfully uploaded: 5, Failed: 0, with success message 'All records uploaded successfully' |
| 13 | Verify the 5 corrected records are now saved in the system | All 5 previously failed records are now visible in the attendance records list with correct data |

**Postconditions:**
- 15 valid records from initial upload are saved in the database
- 5 invalid records from initial upload are rejected and not saved
- Detailed error report is available showing specific validation errors for each failed record
- 5 corrected records from second upload are saved in the database
- Total of 20 attendance records are now in the system
- Audit log contains both upload attempts with success and failure counts

---

### Test Case: Ensure access control for bulk upload functionality
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Two user accounts exist: one unauthorized user (role: Employee) with username 'employee@company.com' and one authorized HR officer (role: HR Officer) with username 'hr.officer@company.com'
- Bulk upload functionality is restricted to HR Officer role only
- Role-based access control is configured and active
- Both users have valid login credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the application login page | Login page is displayed with username and password fields |
| 2 | Enter username 'employee@company.com' and corresponding password for the unauthorized user | Credentials are entered in the login form |
| 3 | Click Login button | User is successfully logged in and redirected to the employee dashboard |
| 4 | Attempt to navigate to the bulk upload page by entering the URL directly (e.g., /attendance/bulk-upload) or through menu navigation | Access is denied with error message 'Access Denied: You do not have permission to access this page' or 'Unauthorized access' and user is redirected to dashboard or error page |
| 5 | Verify that bulk upload menu option is not visible in the navigation menu for the employee user | Bulk upload option is not displayed in the attendance menu or navigation |
| 6 | Log out from the employee account | User is logged out successfully and redirected to login page |
| 7 | Enter username 'hr.officer@company.com' and corresponding password for the authorized HR officer | Credentials are entered in the login form |
| 8 | Click Login button | HR officer is successfully logged in and redirected to the HR dashboard |
| 9 | Navigate to the attendance menu or main navigation | Bulk upload option is visible in the attendance menu for HR officer |
| 10 | Click on the bulk upload menu option or navigate to /attendance/bulk-upload | Access is granted and bulk upload page is displayed with file upload form and instructions |
| 11 | Verify all bulk upload functionality is available including file selection, upload button, and format instructions | All bulk upload features are accessible and functional for the HR officer |
| 12 | Check audit log for access attempts | Audit log shows denied access attempt by 'employee@company.com' and successful access by 'hr.officer@company.com' with timestamps |

**Postconditions:**
- Unauthorized employee user cannot access bulk upload functionality
- Authorized HR officer has full access to bulk upload page and features
- Role-based access control is enforced correctly
- Access attempts are logged in audit trail
- No security breach or unauthorized data modification occurred

---

## Story: As HR Officer, I want to audit manual attendance changes to achieve compliance and traceability
**Story ID:** story-28

### Test Case: Verify audit log creation for manual attendance changes
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in as HR Officer with audit log access permissions
- Manual attendance module is accessible and functional
- Audit log database is operational and configured
- At least one employee record exists in the system
- Test data for manual attendance entries is prepared

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the manual attendance entry module | Manual attendance entry page loads successfully |
| 2 | Create a new manual attendance entry for an employee with date, time-in, and time-out details | Manual attendance entry is created successfully and confirmation message is displayed |
| 3 | Navigate to the audit log module via the menu or dashboard | Audit log interface loads successfully showing recent audit entries |
| 4 | Search for the recently created manual attendance entry in the audit log by filtering with current date and 'CREATE' action type | Audit log displays the CREATE action with correct user identity, timestamp, employee details, and attendance data |
| 5 | Return to manual attendance module and update the previously created attendance entry by modifying the time-out value | Manual attendance entry is updated successfully and confirmation message is displayed |
| 6 | Navigate back to the audit log module and filter by current date and 'UPDATE' action type | Audit log displays the UPDATE action with user identity, timestamp, old values, and new values for the modified fields |
| 7 | Return to manual attendance module and delete the previously created attendance entry | Manual attendance entry is deleted successfully and confirmation message is displayed |
| 8 | Navigate back to the audit log module and filter by current date and 'DELETE' action type | Audit log displays the DELETE action with user identity, timestamp, and details of the deleted attendance record |
| 9 | Apply multiple filters in the audit log: select specific user, date range (today), and all action types (CREATE, UPDATE, DELETE) | System returns all three audit records (CREATE, UPDATE, DELETE) matching the filter criteria with accurate details and within 5 seconds |
| 10 | Click on the 'Export' button in the audit log interface and select CSV format | CSV file download initiates successfully |
| 11 | Open the downloaded CSV file and verify its contents | CSV file contains all filtered audit records with columns for action type, user, timestamp, employee details, old values, new values, and is properly formatted |

**Postconditions:**
- All manual attendance actions (CREATE, UPDATE, DELETE) are logged in the audit database
- Audit logs contain complete and accurate information including user identity and timestamps
- Exported CSV file is saved in the downloads folder
- Test attendance entry is deleted from the system
- Audit logs remain immutable and intact

---

### Test Case: Ensure audit log access control
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System has role-based access control configured
- Test user accounts exist: one unauthorized user (e.g., regular employee) and one authorized HR officer
- Audit log module is deployed and accessible
- Authentication system is functional
- Manual attendance audit logs contain data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the application login page in a browser | Login page loads successfully with username and password fields |
| 2 | Enter credentials for an unauthorized user (regular employee without HR or auditor role) and click Login | User is successfully authenticated and redirected to their dashboard |
| 3 | Attempt to navigate to the audit log module by entering the audit log URL directly or searching for it in the menu | Access is denied with an error message stating 'Access Denied: You do not have permission to view audit logs' or the audit log option is not visible in the menu |
| 4 | Attempt to access the audit log API endpoint directly (GET /api/manual-attendance/audit-logs) using browser or API testing tool | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 5 | Log out from the unauthorized user account | User is successfully logged out and redirected to the login page |
| 6 | Enter credentials for an authorized HR officer with audit log access permissions and click Login | HR officer is successfully authenticated and redirected to their dashboard |
| 7 | Navigate to the audit log module via the menu or dashboard | Audit log module is accessible and loads successfully, displaying the audit log interface with search and filter options |
| 8 | Verify that audit log records are visible and can be filtered by date, user, and action type | Audit logs are displayed correctly with all filtering options functional and records are retrievable |
| 9 | Access the audit log API endpoint directly (GET /api/manual-attendance/audit-logs) using the authorized session | API returns 200 OK status code with audit log data in JSON format |

**Postconditions:**
- Unauthorized user remains unable to access audit logs
- Authorized HR officer has full access to audit log functionality
- Access control rules are enforced at both UI and API levels
- All access attempts are logged in the system security logs
- User sessions are properly managed and terminated after logout

---

