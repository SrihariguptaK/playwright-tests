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
| 3 | Select a valid date using the date picker | Date is populated in the date field without errors |
| 4 | Enter valid time in (e.g., 09:00 AM) and time out (e.g., 05:00 PM) | Time fields accept the input and display the entered values |
| 5 | Select attendance status (e.g., Present, Half-day) | Status is selected and displayed in the form |
| 6 | Click the Submit button | Form is submitted, entry is saved to the database, and a success confirmation message is displayed with the entry details |
| 7 | Verify the response time of the submission | Submission completes within 3 seconds |

**Postconditions:**
- Manual attendance entry is saved in the database
- Audit log contains the creation record with HR officer username and timestamp
- Confirmation message is displayed to the user
- Form is cleared or reset for next entry

---

### Test Case: Verify validation prevents overlapping attendance records
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- Manual attendance entry page is accessible
- An existing attendance record exists for employee 'John Doe' on date '2024-01-15' with time 09:00 AM to 05:00 PM

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance entry page | Manual attendance form is displayed |
| 2 | Select employee 'John Doe' from the dropdown | Employee 'John Doe' is selected |
| 3 | Select date '2024-01-15' which already has an attendance record | Date is populated in the date field |
| 4 | Enter overlapping time period (e.g., 10:00 AM to 06:00 PM) | Time values are entered in the form |
| 5 | Click the Submit button | System displays validation error message indicating overlapping attendance record exists and blocks submission. Error message clearly states the conflict with existing record details |
| 6 | Change the date to '2024-01-16' which has no existing record | Date field is updated to '2024-01-16' |
| 7 | Keep the same time values (10:00 AM to 06:00 PM) and click Submit | Form is submitted successfully, entry is saved, and confirmation message is displayed |

**Postconditions:**
- No overlapping attendance record is created
- Valid non-overlapping record is saved in the database
- Audit log records the successful creation with timestamp
- User receives appropriate feedback for both validation error and successful submission

---

### Test Case: Ensure audit trail logs manual attendance changes
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an authorized HR officer with username 'hr.officer@company.com'
- Manual attendance entry page is accessible
- Audit logging system is enabled and functioning
- Database has audit trail table configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance entry page and create a new attendance entry for employee 'Jane Smith' on '2024-01-20' with time 08:00 AM to 04:00 PM | Manual attendance entry is created successfully with confirmation message |
| 2 | Access the audit log table or audit trail interface and search for the latest entry | Audit log displays a CREATE record with employee name 'Jane Smith', date '2024-01-20', user 'hr.officer@company.com', timestamp of creation, and action type 'CREATE' |
| 3 | Navigate to the attendance records list and select the newly created entry for 'Jane Smith' | Attendance record details are displayed with edit option |
| 4 | Click Edit button and modify the time out from 04:00 PM to 05:00 PM, then save the changes | Attendance record is updated successfully with confirmation message |
| 5 | Access the audit log and search for modification records for this entry | Audit log displays an UPDATE record showing the change from '04:00 PM' to '05:00 PM', user 'hr.officer@company.com', timestamp of modification, action type 'UPDATE', and both old and new values |
| 6 | Navigate back to the attendance records list and select the same entry for 'Jane Smith' | Updated attendance record is displayed |
| 7 | Click Delete button and confirm the deletion | Attendance record is deleted successfully with confirmation message |
| 8 | Access the audit log and search for deletion records | Audit log displays a DELETE record with employee name 'Jane Smith', date '2024-01-20', user 'hr.officer@company.com', timestamp of deletion, action type 'DELETE', and the deleted record details |
| 9 | Verify all three audit entries (CREATE, UPDATE, DELETE) are present and contain complete information | All audit trail entries are complete with 100% data integrity including user, timestamp, action type, and affected data |

**Postconditions:**
- Audit log contains three entries for the same attendance record: CREATE, UPDATE, and DELETE
- Each audit entry includes user identification, timestamp, action type, and relevant data changes
- Audit trail completeness is 100% for all operations
- Deleted attendance record is no longer visible in active records but preserved in audit log

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
- Valid CSV file is prepared with correct schema (columns: employee_id, date, time_in, time_out, status)
- CSV file contains 50 valid attendance records
- All employees referenced in CSV exist in the system
- No overlapping attendance records exist for the dates in CSV

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the bulk upload page from the main attendance menu | Bulk upload page is displayed with file upload form, CSV template download link, and instructions for file format |
| 2 | Click on 'Download CSV Template' link to verify template format | CSV template file is downloaded with correct column headers: employee_id, date, time_in, time_out, status |
| 3 | Click 'Choose File' button and select the prepared valid CSV file containing 50 records | File name is displayed in the upload form showing the selected file |
| 4 | Click 'Upload' or 'Submit' button to initiate the bulk upload process | System displays a processing indicator and begins validating and processing the file |
| 5 | Wait for the upload process to complete and observe the processing time | Upload completes within 2 minutes and displays a success summary showing: Total records: 50, Successful: 50, Failed: 0 |
| 6 | Review the detailed upload summary report | Summary report displays success count, failure count, processing time, and a list of successfully uploaded records with employee names and dates |
| 7 | Navigate to the manual attendance records list and filter by the upload date | All 50 uploaded attendance records are visible in the system with correct data matching the CSV file |
| 8 | Select a few random records from the uploaded batch and verify their details | Record details match exactly with the corresponding entries in the uploaded CSV file (employee, date, time in, time out, status) |

**Postconditions:**
- All 50 valid records from CSV are persisted in the database
- Upload summary report is available for review
- Audit log contains bulk upload event with timestamp and user details
- Upload success rate is 100% for valid data
- System performance meets the 2-minute processing requirement

---

### Test Case: Verify error reporting for invalid CSV records
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- Bulk upload page is accessible
- CSV file is prepared with mixed valid and invalid records (20 total: 15 valid, 5 invalid)
- Invalid records include: missing employee_id, invalid date format, time_out before time_in, non-existent employee, and overlapping attendance

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the bulk upload page | Bulk upload form is displayed with file selection option |
| 2 | Select the CSV file containing 20 records (15 valid, 5 invalid) and click Upload | System begins processing the file and displays processing indicator |
| 3 | Wait for the validation and upload process to complete | System completes processing and displays upload summary with Total: 20, Successful: 15, Failed: 5 |
| 4 | Review the error report section of the upload summary | Detailed error messages are displayed for each of the 5 failed records including: row number, field name, error type, and specific error description (e.g., 'Row 3: employee_id is required', 'Row 7: Invalid date format, expected YYYY-MM-DD', 'Row 12: time_out cannot be before time_in', 'Row 15: Employee ID EMP999 does not exist', 'Row 18: Overlapping attendance record exists for this employee and date') |
| 5 | Download or copy the error report | Error report is available for download in CSV or text format with all error details |
| 6 | Verify that valid records were saved by navigating to attendance records list | 15 valid records from the CSV are successfully saved and visible in the system |
| 7 | Correct the 5 invalid records in the CSV file based on the error messages | CSV file is updated with corrected data for the 5 previously failed records |
| 8 | Navigate back to bulk upload page and upload the corrected CSV file containing only the 5 corrected records | File is selected and ready for upload |
| 9 | Click Upload button to submit the corrected file | System processes the file and displays success summary showing Total: 5, Successful: 5, Failed: 0 |
| 10 | Verify all corrected records are now saved in the system | All 5 corrected records are visible in the attendance records list with accurate data |

**Postconditions:**
- 15 valid records from initial upload are persisted in database
- 5 invalid records from initial upload are rejected with detailed error messages
- 5 corrected records from second upload are persisted in database
- Total of 20 attendance records are successfully saved after correction
- Error report provides actionable information for data correction
- Audit log contains both upload attempts with success/failure details

---

### Test Case: Ensure access control for bulk upload functionality
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Two user accounts are available: one unauthorized user (role: Employee) and one authorized HR officer (role: HR Officer)
- Bulk upload functionality is restricted to HR Officer role only
- Both users have valid login credentials
- Application implements role-based access control (RBAC)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the application login page in a browser | Login page is displayed with username and password fields |
| 2 | Enter credentials for unauthorized user (Employee role) and click Login | User is successfully logged in and redirected to the employee dashboard |
| 3 | Attempt to navigate to the bulk upload page by entering the URL directly (e.g., /attendance/bulk-upload) | Access is denied with error message 'Access Forbidden: You do not have permission to access this page' or user is redirected to unauthorized access page with HTTP 403 status |
| 4 | Check the main navigation menu for bulk upload option | Bulk upload menu item is not visible or not accessible to the unauthorized user |
| 5 | Log out from the unauthorized user account | User is logged out successfully and redirected to login page |
| 6 | Enter credentials for authorized HR officer and click Login | HR officer is successfully logged in and redirected to the HR dashboard |
| 7 | Check the main navigation menu for bulk upload option | Bulk upload menu item is visible and accessible in the attendance or HR management section |
| 8 | Click on the bulk upload menu item or navigate to /attendance/bulk-upload | Bulk upload page is displayed successfully with file upload form and all functionality accessible |
| 9 | Verify all bulk upload features are functional (file selection, upload button, template download) | All bulk upload features are available and functional for the authorized HR officer |

**Postconditions:**
- Unauthorized user (Employee role) cannot access bulk upload functionality
- Authorized HR officer has full access to bulk upload page and features
- Access control is enforced at both UI and API levels
- Security audit log records unauthorized access attempt
- Role-based access control is functioning correctly

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
| 3 | Navigate to the audit log module via the menu or dashboard | Audit log interface loads successfully showing the list of audit records |
| 4 | Search for the recently created manual attendance entry in the audit log by filtering with current date and 'CREATE' action type | Audit log displays the CREATE action with correct user identity, timestamp, employee details, and attendance data |
| 5 | Return to manual attendance module and update the previously created attendance entry by modifying the time-out value | Manual attendance entry is updated successfully and confirmation message is displayed |
| 6 | Navigate back to the audit log module and filter by current date and 'UPDATE' action type | Audit log displays the UPDATE action with user identity, timestamp, old values, and new values for the modified fields |
| 7 | Return to manual attendance module and delete the previously created attendance entry | Manual attendance entry is deleted successfully and confirmation message is displayed |
| 8 | Navigate back to the audit log module and filter by current date and 'DELETE' action type | Audit log displays the DELETE action with user identity, timestamp, and details of the deleted attendance record |
| 9 | Apply multiple filters in the audit log: select specific user, date range covering today, and all action types (CREATE, UPDATE, DELETE) | System returns all three audit records (CREATE, UPDATE, DELETE) matching the filter criteria with accurate details and within 5 seconds response time |
| 10 | Click on the 'Export' button in the audit log interface and select CSV format | CSV file download initiates successfully |
| 11 | Open the downloaded CSV file and verify its contents | CSV file contains all three audit records with columns for action type, user identity, timestamp, employee details, and change details matching the data displayed in the audit log interface |

**Postconditions:**
- All manual attendance changes are logged in the audit database
- Audit logs contain complete and accurate information for CREATE, UPDATE, and DELETE actions
- CSV export file is downloaded and contains correct audit data
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
- Audit log module is operational
- Manual attendance audit logs contain data
- Login functionality is working correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the application login page | Login page loads successfully with username and password fields |
| 2 | Enter credentials for an unauthorized user (regular employee without HR or auditor role) and click login | User is logged in successfully and redirected to their dashboard |
| 3 | Attempt to navigate to the audit log module by entering the URL directly or searching for it in the menu | Access is denied with an appropriate error message such as 'Access Denied: Insufficient Permissions' or the audit log option is not visible in the menu |
| 4 | Attempt to access the audit log API endpoint directly (GET /api/manual-attendance/audit-logs) using browser or API testing tool | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 5 | Logout from the unauthorized user account | User is logged out successfully and redirected to the login page |
| 6 | Enter credentials for an authorized HR officer with audit log access permissions and click login | HR officer is logged in successfully and redirected to their dashboard |
| 7 | Navigate to the audit log module via the menu or dashboard | Audit log module is accessible and loads successfully displaying the audit log interface |
| 8 | Verify that audit log records are visible and can be filtered and searched | Audit log records are displayed correctly with all filtering and search functionalities working as expected |
| 9 | Access the audit log API endpoint directly (GET /api/manual-attendance/audit-logs) using the authorized session | API returns 200 OK status code with audit log data in the response |

**Postconditions:**
- Unauthorized users cannot access audit logs through UI or API
- Authorized HR officers have full access to audit log functionality
- Access control is enforced at both UI and API levels
- Security logs may record unauthorized access attempts
- All users are logged out after testing

---

