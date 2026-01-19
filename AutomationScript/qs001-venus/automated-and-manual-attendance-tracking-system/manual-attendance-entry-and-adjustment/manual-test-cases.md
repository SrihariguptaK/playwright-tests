# Manual Test Cases

## Story: As HR Officer, I want to add manual attendance entries to achieve complete attendance records
**Story ID:** story-3

### Test Case: Validate adding manual attendance entry
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- User has permissions to access manual attendance entry features
- Attendance system is accessible and operational
- At least one employee exists in the system with valid employee ID

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance entry page from the main dashboard or menu | Manual attendance form is displayed with fields for employee ID, date, time, and reason. All required field indicators are visible |
| 2 | Enter valid employee ID in the employee ID field | Employee ID is accepted and employee name is displayed or validated |
| 3 | Select a valid date from the date picker | Date is populated in the date field in correct format |
| 4 | Enter valid time in the time field (e.g., 09:00 AM) | Time is accepted and displayed in correct format |
| 5 | Enter a reason for manual entry in the reason field (e.g., 'Missed biometric scan') | Reason text is accepted and displayed in the field |
| 6 | Click the Submit or Save button | Entry is saved successfully and a confirmation message is displayed (e.g., 'Manual attendance entry added successfully') |
| 7 | Navigate to attendance reports section | Attendance reports page is displayed with search or filter options |
| 8 | Search for the newly added manual attendance entry using employee ID and date | Manual attendance entry is listed correctly in the report with all entered details (employee ID, date, time, reason) and marked as manual entry |

**Postconditions:**
- Manual attendance entry is saved in the database
- Entry is visible in attendance reports
- Audit log contains record of the manual entry creation with HR officer details and timestamp

---

### Test Case: Verify duplicate detection for manual entries
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- User has permissions to access manual attendance entry features
- At least one biometric attendance record exists for a specific employee, date, and time
- Manual attendance entry page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance entry page | Manual attendance form is displayed with all required fields |
| 2 | Enter employee ID that has an existing biometric attendance record | Employee ID is accepted and validated |
| 3 | Select the same date as the existing biometric record | Date is populated in the date field |
| 4 | Enter the same time as the existing biometric record | Time is populated in the time field |
| 5 | Enter a reason and click Submit | System rejects the entry and displays a duplicate warning message (e.g., 'Duplicate attendance record detected. A biometric entry already exists for this employee at this date and time') |
| 6 | Modify the time field to a unique time that does not conflict with existing records (e.g., change from 09:00 AM to 09:30 AM) | Updated time is displayed in the time field |
| 7 | Click Submit button again | Entry is accepted successfully and confirmation message is displayed (e.g., 'Manual attendance entry added successfully') |
| 8 | Verify the entry appears in attendance records | Manual attendance entry is visible with the unique time and marked as manual entry |

**Postconditions:**
- Duplicate entry is prevented and not saved in the database
- Valid unique entry is saved successfully
- System maintains data integrity by preventing duplicate attendance records

---

### Test Case: Ensure audit logging of manual attendance changes
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- At least one manual attendance entry exists in the system
- User has permissions to edit and delete manual attendance entries
- Audit logging system is enabled and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance management page | List of existing manual attendance entries is displayed with options to edit or delete |
| 2 | Select an existing manual attendance entry and click Edit button | Edit form is displayed with current attendance details pre-populated |
| 3 | Modify the time field to a different valid time | Updated time is displayed in the time field |
| 4 | Click Save or Update button | Change is saved successfully and confirmation message is displayed (e.g., 'Manual attendance entry updated successfully') |
| 5 | Navigate to audit logs section or access audit trail for the edited entry | Audit log displays the edit action with details including: user who made the change, timestamp, old value, new value, and entry ID |
| 6 | Return to manual attendance management page and select a manual attendance entry | Entry details are displayed with delete option available |
| 7 | Click Delete button and confirm the deletion | Entry is deleted successfully and confirmation message is displayed (e.g., 'Manual attendance entry deleted successfully') |
| 8 | Navigate to audit logs section and search for the deletion record | Audit log displays the deletion action with details including: user who deleted the entry, timestamp, deleted entry details, and action type as 'DELETE' |
| 9 | Verify that both edit and delete actions are recorded with complete information | Audit logs contain complete records of both edit and delete operations with user details, timestamps, and action details |

**Postconditions:**
- Edited entry reflects updated values in the database
- Deleted entry is removed from active attendance records
- Audit logs contain complete records of all changes with user and timestamp details
- Audit trail is immutable and cannot be modified by users

---

## Story: As HR Officer, I want to edit manual attendance entries to correct errors and maintain accurate records
**Story ID:** story-4

### Test Case: Validate successful manual attendance entry edit
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- User has permissions to edit manual attendance entries
- At least one manual attendance entry exists in the system
- Manual attendance management page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance management page from the main dashboard or menu | List of manual attendance entries is displayed with columns showing employee ID, date, time, reason, and action buttons (Edit/Delete) |
| 2 | Locate a specific manual attendance entry using search or filter options | Target entry is visible in the list with all current details displayed |
| 3 | Click the Edit button or icon for the selected entry | Edit form is displayed with current attendance details pre-populated in all fields (employee ID, date, time, reason) |
| 4 | Modify the attendance time field to a different valid time (e.g., change from 09:00 AM to 10:30 AM) | Updated time is displayed in the time field and field is highlighted or marked as modified |
| 5 | Optionally modify the reason field to reflect the correction (e.g., 'Corrected entry - actual check-in time') | Updated reason text is displayed in the reason field |
| 6 | Click Submit, Save, or Update button | Entry is updated successfully and confirmation message is displayed (e.g., 'Manual attendance entry updated successfully') |
| 7 | Verify the updated entry in the manual attendance list | Entry displays the updated time and reason, and shows last modified timestamp |
| 8 | Navigate to attendance reports section | Attendance reports page is displayed |
| 9 | Search for the edited entry in the attendance report using employee ID and date | Report displays the updated attendance entry with the new time and reflects changes made within 5 minutes |

**Postconditions:**
- Manual attendance entry is updated in the database with new values
- Updated entry is visible in attendance reports within 5 minutes
- Audit log contains record of the edit with user details and timestamp
- Original entry data is preserved in audit history

---

### Test Case: Verify prevention of duplicate attendance entries on edit
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- User has permissions to edit manual attendance entries
- At least one manual attendance entry exists in the system
- At least one biometric attendance record exists for the same employee on the same date but different time
- Manual attendance management page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance management page | List of manual attendance entries is displayed with edit options |
| 2 | Select a manual attendance entry for an employee who has an existing biometric record on the same date | Entry is selected and details are visible |
| 3 | Click Edit button for the selected entry | Edit form is displayed with current attendance details pre-populated |
| 4 | Modify the time field to match the exact time of the existing biometric attendance record for the same employee and date | Updated time is displayed in the time field |
| 5 | Click Submit or Update button | System rejects the edit and displays a duplicate warning message (e.g., 'Cannot update entry. A biometric attendance record already exists for this employee at this date and time' or 'Duplicate attendance detected') |
| 6 | Verify that the entry remains unchanged in the list | Original entry values are preserved and no changes are saved |
| 7 | Click Edit button again for the same entry | Edit form is displayed with original values |
| 8 | Modify the time field to a unique time that does not conflict with any existing biometric or manual records (e.g., 11:45 AM) | Updated unique time is displayed in the time field |
| 9 | Click Submit or Update button | Edit is accepted successfully and confirmation message is displayed (e.g., 'Manual attendance entry updated successfully') |
| 10 | Verify the updated entry appears in the list with the new unique time | Entry is displayed with the updated time and no duplicate conflicts exist |

**Postconditions:**
- Duplicate edit is prevented and original entry remains unchanged
- Valid unique edit is saved successfully in the database
- System maintains data integrity by preventing duplicate attendance records
- No conflicting attendance records exist for the same employee, date, and time

---

### Test Case: Ensure audit logging of manual attendance edits
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- User has permissions to edit manual attendance entries
- At least one manual attendance entry exists in the system
- Audit logging system is enabled and operational
- User has access to view audit logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance management page | List of manual attendance entries is displayed with edit options |
| 2 | Note the current details of a specific manual attendance entry (employee ID, date, original time, reason) | Original entry details are visible and documented |
| 3 | Click Edit button for the selected entry | Edit form is displayed with current attendance details pre-populated |
| 4 | Modify the time field to a different valid time (e.g., change from 09:00 AM to 09:45 AM) | Updated time is displayed in the time field |
| 5 | Modify the reason field (e.g., 'Time correction based on manager approval') | Updated reason is displayed in the reason field |
| 6 | Click Submit or Update button | Entry is updated successfully and confirmation message is displayed |
| 7 | Navigate to audit logs section or audit trail viewer | Audit logs interface is displayed with search and filter options |
| 8 | Search for audit records related to the edited manual attendance entry using entry ID or employee ID and date | Audit log entry for the edit action is displayed |
| 9 | Verify audit log contains the following details: action type (UPDATE/EDIT), user who made the change (HR officer username), timestamp of the change, entry ID, old values (original time and reason), new values (updated time and reason) | Audit log record displays all required information accurately including: Action: 'EDIT' or 'UPDATE', User: logged-in HR officer's username or ID, Timestamp: exact date and time of the edit, Entry ID: unique identifier of the edited entry, Old Values: original time and reason, New Values: updated time and reason |
| 10 | Verify the timestamp in the audit log matches the time when the edit was performed | Timestamp is accurate and reflects the actual time of the edit operation |
| 11 | Verify that the audit log entry is immutable and cannot be edited or deleted | No edit or delete options are available for audit log entries, ensuring audit trail integrity |

**Postconditions:**
- Manual attendance entry is updated with new values in the database
- Audit log contains complete and accurate record of the edit operation
- Audit log includes user details (HR officer who made the change) and precise timestamp
- Audit log preserves both old and new values for traceability
- Audit trail remains immutable and tamper-proof

---

## Story: As HR Officer, I want to delete manual attendance entries to remove incorrect or obsolete records
**Story ID:** story-5

### Test Case: Validate successful deletion of manual attendance entry
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- At least one manual attendance entry exists in the system
- User has delete permissions for manual attendance entries
- Manual attendance management page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance management page | List of manual entries is displayed with employee names, dates, times, and action buttons |
| 2 | Select an entry and initiate deletion by clicking the delete button | Confirmation dialog is displayed with message asking 'Are you sure you want to delete this attendance entry?' and showing entry details |
| 3 | Confirm deletion by clicking 'Yes' or 'Confirm' button | Entry is deleted from the list and confirmation message 'Attendance entry deleted successfully' is displayed |
| 4 | Refresh the manual attendance management page | Deleted entry no longer appears in the list of manual attendance entries |
| 5 | Wait 5 minutes and check the attendance reports | Deleted entry is removed from all relevant attendance reports |

**Postconditions:**
- Manual attendance entry is permanently deleted from the database
- Deletion is logged in the audit trail
- Attendance reports reflect the deletion within 5 minutes
- User remains on the manual attendance management page

---

### Test Case: Ensure audit logging of manual attendance deletions
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- At least one manual attendance entry exists in the system
- Audit logging system is enabled and functioning
- User has access to audit logs or can verify through admin

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance management page and select an entry to delete | Manual attendance entry is selected and delete option is available |
| 2 | Delete a manual attendance entry by confirming the deletion dialog | Entry is deleted successfully and confirmation message is displayed |
| 3 | Navigate to audit log interface or access audit log database | Audit log interface loads successfully showing recent activities |
| 4 | Search for the deletion event in the audit logs using the deleted entry details or timestamp | Audit log records deletion with user identity (HR officer name/ID), exact timestamp, operation type (DELETE), and details of the deleted entry (employee ID, date, time) |
| 5 | Verify all required fields are present in the audit log entry | Audit log contains: user ID, username, timestamp, action type (DELETE), affected employee ID, attendance date, attendance time, and previous entry values |

**Postconditions:**
- Audit log entry is permanently stored in the audit database
- Audit log is available for compliance reporting
- Deletion event is traceable with complete details

---

### Test Case: Verify deletion authorization
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as an unauthorized user (non-HR officer or user without delete permissions)
- At least one manual attendance entry exists in the system
- Authorization and role-based access control is properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance management page as unauthorized user | Either page access is denied or delete buttons are not visible/disabled for manual entries |
| 2 | Attempt to access delete functionality through UI or direct API call (DELETE /api/attendance/manual/{id}) | Deletion is blocked and access denied message is displayed with text like 'You do not have permission to delete attendance entries' or HTTP 403 Forbidden error |
| 3 | Verify the manual attendance entry still exists in the system | Entry remains unchanged and is still visible in the manual attendance list |
| 4 | Check audit logs for the unauthorized deletion attempt | Audit log records the failed deletion attempt with user identity and timestamp |

**Postconditions:**
- Manual attendance entry remains intact and undeleted
- Unauthorized access attempt is logged
- System security is maintained
- No data integrity issues occur

---

### Test Case: System prevents deletion of biometric attendance records
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- At least one biometric attendance entry exists in the system
- Biometric and manual attendance entries are distinguishable in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to attendance management page showing both manual and biometric entries | Attendance entries are displayed with clear indication of entry type (manual vs biometric) |
| 2 | Attempt to select a biometric attendance entry for deletion | Delete button is either not visible, disabled, or grayed out for biometric entries |
| 3 | If delete option is visible, click on delete for biometric entry | System displays error message 'Biometric attendance records cannot be deleted' or similar prevention message |
| 4 | Attempt direct API call to delete biometric entry (DELETE /api/attendance/manual/{biometric_id}) | API returns error response (HTTP 400 or 403) with message indicating biometric records cannot be deleted |
| 5 | Verify the biometric attendance entry still exists | Biometric entry remains unchanged in the system |

**Postconditions:**
- Biometric attendance record remains intact
- System maintains data integrity for biometric records
- Prevention attempt may be logged in audit trail

---

## Story: As HR Officer, I want to generate audit logs for manual attendance changes to achieve compliance and traceability
**Story ID:** story-9

### Test Case: Validate audit logging of manual attendance additions
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- Manual attendance management system is accessible
- Audit logging system is enabled and functioning
- User has permissions to add manual attendance entries

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance management page and click 'Add New Entry' button | Manual attendance entry form is displayed with fields for employee, date, time, and reason |
| 2 | Add a manual attendance entry by filling in employee name, date, check-in time, check-out time, and reason, then submit | Manual attendance entry is created successfully and confirmation message 'Attendance entry added successfully' is displayed |
| 3 | Note the exact timestamp of the addition operation | Current timestamp is recorded for verification purposes |
| 4 | Navigate to audit log interface (GET /api/audit/manual-attendance) | Audit log interface loads showing list of recent manual attendance operations |
| 5 | Retrieve audit logs and search for the newly added entry | Audit log records the addition with user identity (HR officer name/ID), timestamp matching the operation time, operation type (CREATE/ADD), employee ID, date, times, and reason |
| 6 | Verify all required audit fields are present and accurate | New addition entry appears in audit logs with complete details: user ID, username, timestamp, action type, affected employee, attendance date, check-in time, check-out time, and reason for manual entry |

**Postconditions:**
- Manual attendance entry exists in the system
- Audit log entry is permanently stored
- Audit trail is complete and traceable
- Compliance requirements are met

---

### Test Case: Verify audit log filtering and export
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an authorized compliance officer or HR officer with audit log access
- Multiple audit log entries exist in the system with different users and dates
- Audit log interface is accessible
- Export functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to audit log interface for manual attendance | Audit log page loads displaying all manual attendance audit entries with filter options |
| 2 | Apply filter by selecting a specific user from the user dropdown filter | Audit logs are filtered to show only entries for the selected user |
| 3 | Apply additional filter by selecting a date range (e.g., last 7 days) | Filtered audit logs are displayed correctly showing only entries matching both user and date range criteria |
| 4 | Verify the filtered results show correct data matching the filter criteria | All displayed entries match the selected user and fall within the specified date range |
| 5 | Click on 'Export' or 'Download CSV' button | CSV file download is initiated |
| 6 | Open the downloaded CSV file and verify its contents | CSV file downloads with correct data including all columns: timestamp, user ID, username, action type, employee ID, attendance date, times, and change details matching the filtered view |
| 7 | Verify CSV formatting and data integrity | CSV is properly formatted with headers, all data is readable, no truncation or corruption, and row count matches the filtered results |

**Postconditions:**
- Audit logs remain unchanged in the system
- CSV file is saved to user's download folder
- Filters can be cleared or modified for new searches
- Export is available for compliance reporting

---

### Test Case: Ensure audit logs are available within 1 minute
- **ID:** tc-007
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- Manual attendance entry exists that can be edited
- Audit logging system is functioning
- System time is synchronized and accurate
- User has access to audit log interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current system time before performing the operation | Current timestamp is recorded (e.g., 10:30:00 AM) |
| 2 | Navigate to manual attendance management page and select an existing entry to edit | Manual attendance entry is selected and edit form is displayed |
| 3 | Perform manual attendance edit by modifying check-in or check-out time and save changes | Changes are saved successfully and confirmation message is displayed with exact timestamp of the edit |
| 4 | Immediately navigate to audit log interface | Audit log interface loads successfully |
| 5 | Refresh audit logs and search for the edit operation performed | Audit log entry for the edit operation appears in the list |
| 6 | Compare the audit log entry timestamp with the operation timestamp | Audit log entry is created within 1 minute of the manual attendance edit operation (e.g., if edit was at 10:30:00, audit log shows timestamp between 10:30:00 and 10:31:00) |
| 7 | Verify the audit log contains complete details of the edit operation | Audit log shows user ID, timestamp, action type (EDIT/UPDATE), employee ID, field changed, old value, and new value |

**Postconditions:**
- Manual attendance entry reflects the edited values
- Audit log entry is available and complete
- Performance SLA of 1 minute is met
- System maintains real-time audit trail

---

### Test Case: Validate audit logging of manual attendance edits and deletions
- **ID:** tc-008
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 9 mins

**Preconditions:**
- User is logged in as an authorized HR officer
- Manual attendance entries exist in the system
- Audit logging system is enabled
- User has permissions for edit and delete operations

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to manual attendance management page and select an entry to edit | Edit form is displayed with current values populated |
| 2 | Modify the check-in time and save the changes | Entry is updated successfully and confirmation message is displayed |
| 3 | Access audit log interface and search for the edit operation | Audit log shows EDIT operation with user ID, timestamp, employee ID, field changed (check-in time), old value, and new value |
| 4 | Return to manual attendance management page and select a different entry to delete | Delete confirmation dialog is displayed |
| 5 | Confirm deletion of the manual attendance entry | Entry is deleted successfully and confirmation message is displayed |
| 6 | Access audit log interface and search for the deletion operation | Audit log shows DELETE operation with user ID, timestamp, employee ID, and all details of the deleted entry (date, times, reason) |
| 7 | Verify both audit log entries contain detailed change information | Edit log shows before/after values; Delete log shows all deleted data; both include user identity, timestamp, and operation type |

**Postconditions:**
- Manual attendance entry reflects the edit
- Deleted entry is removed from the system
- Both operations are fully logged in audit trail
- Audit logs are available for compliance review

---

## Story: As HR Officer, I want to validate manual attendance inputs to prevent data entry errors and ensure data quality
**Story ID:** story-11

### Test Case: Validate mandatory field enforcement
- **ID:** tc-001
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Officer with manual attendance entry permissions
- Manual attendance entry form is accessible
- At least one employee exists in the system
- Database is operational and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the manual attendance entry section from the HR dashboard | Manual attendance entry form is displayed with all mandatory fields clearly marked (Employee ID, Date, Time) |
| 2 | Leave Employee ID field empty and attempt to submit the form | Form submission is blocked and error message 'Employee ID is required' is displayed near the Employee ID field |
| 3 | Enter valid Employee ID, leave Date field empty, and attempt to submit the form | Form submission is blocked and error message 'Date is required' is displayed near the Date field |
| 4 | Enter valid Employee ID and Date, leave Time field empty, and attempt to submit the form | Form submission is blocked and error message 'Time is required' is displayed near the Time field |
| 5 | Fill all mandatory fields (Employee ID, Date, Time) with valid data and click Submit button | Form is submitted successfully, success confirmation message is displayed, and the new attendance entry appears in the attendance records |

**Postconditions:**
- Valid attendance entry is saved in the database
- Form is cleared or redirected to attendance list view
- Audit log records the manual attendance entry creation

---

### Test Case: Verify real-time validation feedback
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Officer with manual attendance entry permissions
- Manual attendance entry form is open and displayed
- Real-time validation is enabled on the form
- Network latency is normal (under 1 second response time)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Click on the Date field and enter an invalid date format (e.g., '32/13/2023' or 'abc123') | Error message 'Invalid date format' is displayed immediately (within 1 second) below or near the Date field in red text |
| 2 | Clear the Date field and enter a valid date format (e.g., 'DD/MM/YYYY' or system-accepted format like '15/06/2023') | Error message 'Invalid date format' disappears immediately and the field is marked as valid with a green indicator or checkmark |
| 3 | Click on the Time field and enter an invalid time format (e.g., '25:70' or 'invalid') | Error message 'Invalid time format' is displayed immediately (within 1 second) below or near the Time field |
| 4 | Clear the Time field and enter a valid time format (e.g., 'HH:MM' format like '09:30') | Error message 'Invalid time format' disappears immediately and the field is marked as valid |

**Postconditions:**
- All validation messages are cleared for valid inputs
- Form is ready for submission with valid data
- No data is saved to the database during validation testing

---

### Test Case: Ensure duplicate entry prevention
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as HR Officer with manual attendance entry permissions
- Manual attendance entry form is accessible
- An existing manual attendance record exists in the database (e.g., Employee ID: EMP001, Date: 15/06/2023, Time: 09:00)
- Database contains at least one attendance entry for testing duplicate detection

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the manual attendance entry form | Form is displayed with empty fields ready for data entry |
| 2 | Enter Employee ID that matches an existing record (e.g., 'EMP001') | Employee ID is accepted and field shows valid state |
| 3 | Enter Date that matches the existing record (e.g., '15/06/2023') | Date is accepted and field shows valid state |
| 4 | Enter Time that matches the existing record (e.g., '09:00') | Time is accepted and field shows valid state |
| 5 | Click Submit button to attempt submission of the duplicate attendance entry | Form submission is blocked, error message 'Duplicate attendance entry detected. An attendance record for this employee on this date and time already exists' is displayed prominently, and the form remains on the entry page without saving |
| 6 | Modify the Time field to a different value (e.g., '10:00') and click Submit button | Form is submitted successfully as the entry is no longer a duplicate, success message is displayed, and the new attendance record is saved |

**Postconditions:**
- No duplicate attendance entries exist in the database
- Original attendance record remains unchanged
- New non-duplicate entry is successfully saved
- Audit log shows the duplicate prevention action and successful submission

---

