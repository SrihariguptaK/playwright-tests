# Manual Test Cases

## Story: As Attendance Manager, I want to manually input attendance records to achieve complete and accurate attendance data
**Story ID:** story-19

### Test Case: Validate successful manual attendance record creation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has Attendance Manager role with manual input permissions
- User is logged into the attendance system
- At least one active employee exists in the system
- Attendance database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to manual attendance input page by clicking on 'Manual Attendance' menu option | Manual attendance input form is displayed with fields for employee selection, date, time, and attendance details |
| 2 | Manager selects a valid employee from the dropdown list | Employee is selected and displayed in the form without errors |
| 3 | Manager enters valid date in the date field (e.g., current date) | Date is accepted and displayed in correct format |
| 4 | Manager enters valid check-in time (e.g., 09:00 AM) and check-out time (e.g., 05:00 PM) | Time values are accepted and displayed in correct format without validation errors |
| 5 | Manager enters any additional attendance details or notes in the remarks field | Form accepts all data without errors and all fields show entered values |
| 6 | Manager clicks the 'Submit' button to save the attendance record | System processes the request within 3 seconds, attendance record is saved to the database, and a success confirmation message is displayed (e.g., 'Attendance record created successfully') |
| 7 | Manager verifies the newly created record appears in the attendance list for the selected employee and date | Attendance record is visible in the system with all entered details displayed correctly |

**Postconditions:**
- New attendance record is saved in the attendance database
- Audit log entry is created for the manual attendance addition
- Attendance record is available for reporting and queries
- Form is cleared and ready for next entry

---

### Test Case: Verify audit logging on manual attendance edits
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User has Attendance Manager role with edit permissions
- User is logged into the attendance system
- At least one existing attendance record is available in the system
- Admin user account exists with audit log access permissions
- Audit logging functionality is enabled and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the attendance records list and selects an existing attendance record to edit | Edit form is displayed with current attendance data pre-populated in all fields (employee name, date, check-in time, check-out time) |
| 2 | Manager modifies the check-in time from the original value to a new valid time (e.g., from 09:00 AM to 09:15 AM) | Modified time is accepted and displayed in the field without validation errors |
| 3 | Manager clicks the 'Save' or 'Update' button to submit the changes | System saves the modified attendance record within 3 seconds and displays a confirmation message (e.g., 'Attendance record updated successfully') |
| 4 | Manager logs out and Admin user logs into the system | Admin is successfully logged in and dashboard is displayed |
| 5 | Admin navigates to the audit logs section and filters for the edited attendance record | Audit log displays the entry showing the manager's username, timestamp of the change, original values, modified values, and action type (Edit) |
| 6 | Admin verifies all audit details are complete and accurate | Audit log shows complete information: user who made the change, exact timestamp, field changed (check-in time), old value (09:00 AM), new value (09:15 AM), and employee identifier |

**Postconditions:**
- Attendance record is updated with new values in the database
- Complete audit trail entry exists with all change details
- Original values are preserved in audit history
- Audit log is accessible to authorized users

---

### Test Case: Ensure access control for manual attendance input
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Two user accounts exist: one with Attendance Manager role and one without manual input permissions
- Both users have valid login credentials
- Manual attendance input functionality is protected by role-based access control
- System is operational and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Non-authorized user (e.g., regular employee or user without manager role) logs into the system | User is successfully logged in and redirected to their default dashboard |
| 2 | Non-authorized user attempts to access the manual attendance input page by navigating to the URL or menu option | System denies access and displays an error message (e.g., 'Access Denied: You do not have permission to access this page' or 'Unauthorized Access') |
| 3 | Non-authorized user verifies that manual attendance input menu option is not visible or is disabled in their interface | Manual attendance input option is either hidden or displayed as disabled/grayed out |
| 4 | Non-authorized user logs out of the system | User is successfully logged out and redirected to login page |
| 5 | Authorized manager logs into the system with valid credentials | Manager is successfully logged in and dashboard is displayed |
| 6 | Authorized manager navigates to the manual attendance input page | Manual attendance input page is accessible and the input form is displayed with all fields functional |
| 7 | Manager selects an employee, enters valid date and time details, and clicks 'Submit' | System accepts the submission, processes within 3 seconds, saves the attendance record, and displays success confirmation message |
| 8 | Manager verifies the record is saved by checking the attendance list | Newly created attendance record is visible in the system with correct details |

**Postconditions:**
- Non-authorized user remains unable to access manual attendance input functionality
- Authorized manager successfully created attendance record
- Access control rules are enforced and validated
- Security audit log may contain access denial attempt

---

## Story: As Attendance Manager, I want to audit manual attendance changes to achieve accountability and data integrity
**Story ID:** story-22

### Test Case: Validate audit logging on manual attendance changes
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has Attendance Manager role with edit permissions
- Manager is logged into the attendance system
- At least one existing manual attendance record is available
- Authorized user account exists with audit log access permissions
- Audit logging system is operational and configured
- Unauthorized user account exists without audit log access

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the attendance records list and selects an existing manual attendance record to edit | Edit form is displayed with current attendance data pre-populated |
| 2 | Manager modifies the attendance time (e.g., changes check-in from 09:00 AM to 09:30 AM) | Modified time is accepted and displayed in the field |
| 3 | System prompts manager to provide a reason for the change in a mandatory text field | Reason for change dialog or field is displayed and marked as required |
| 4 | Manager enters a valid reason for the change (e.g., 'Correcting biometric failure entry') | Reason is accepted and displayed in the field without errors |
| 5 | Manager clicks 'Save' or 'Submit' button to save the changes | System saves the modified attendance record and logs audit details within 1 second, displaying a success confirmation message |
| 6 | Manager logs out and authorized user with audit access logs into the system | Authorized user is successfully logged in and dashboard is displayed |
| 7 | Authorized user navigates to the audit logs section and searches for the recently modified attendance record | Audit logs page is displayed with search and filter options |
| 8 | Authorized user views the audit log entry for the modified record | Audit log displays complete details: manager's username, exact timestamp of change, employee identifier, field modified, old value, new value, and reason for change ('Correcting biometric failure entry') |
| 9 | Authorized user logs out and unauthorized user attempts to log in | Unauthorized user is successfully logged in to their account |
| 10 | Unauthorized user attempts to access the audit logs section by navigating to the URL or menu | System denies access and displays an error message (e.g., 'Access Denied: You do not have permission to view audit logs') |
| 11 | Unauthorized user verifies that audit logs menu option is not visible in their interface | Audit logs option is either hidden or displayed as disabled in the navigation menu |

**Postconditions:**
- Attendance record is updated with new values in the database
- Complete audit trail entry exists with user, timestamp, reason, and all change details
- Audit log is accessible only to authorized users
- Unauthorized access attempts are blocked
- Audit logging completed within 1 second of change

---

### Test Case: Ensure reason for change is mandatory
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User has Attendance Manager role with edit permissions
- Manager is logged into the attendance system
- At least one existing manual attendance record is available for editing
- Reason for change field is configured as mandatory
- System validation is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the attendance records list and selects an existing manual attendance record to edit | Edit form is displayed with current attendance data pre-populated in all fields |
| 2 | Manager modifies the attendance time (e.g., changes check-out time from 05:00 PM to 06:00 PM) | Modified time is accepted and displayed in the field |
| 3 | System displays the reason for change field marked as mandatory (with asterisk or required indicator) | Reason for change field is visible and clearly marked as required |
| 4 | Manager leaves the reason for change field empty and attempts to click 'Save' or 'Submit' button | System prevents the save operation and displays a validation error message (e.g., 'Reason for change is required' or 'Please provide a reason for this modification') |
| 5 | Manager verifies that the attendance record has not been saved by checking the record details | Attendance record still shows the original values and modifications are not saved |
| 6 | Manager enters a valid reason for the change in the reason field (e.g., 'Employee worked overtime') | Reason is accepted and displayed in the field, validation error is cleared |
| 7 | Manager clicks 'Save' or 'Submit' button again with the reason provided | System accepts the submission, saves the modified attendance record within 3 seconds, logs audit details within 1 second, and displays a success confirmation message |
| 8 | Manager verifies the updated record appears in the attendance list with the new values | Attendance record is updated and displays the new check-out time (06:00 PM) |
| 9 | Manager or authorized user checks the audit log for this change | Audit log entry exists showing the manager's username, timestamp, old value, new value, and the provided reason ('Employee worked overtime') |

**Postconditions:**
- Attendance record is updated only after reason is provided
- Complete audit trail entry exists with mandatory reason field populated
- System validation for mandatory reason field is confirmed working
- Data integrity is maintained through mandatory audit reason

---

## Story: As Employee, I want to view my attendance records to achieve transparency and self-service
**Story ID:** story-23

### Test Case: Validate employee attendance record viewing
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has existing attendance records in the system
- Self-service portal is accessible and operational
- Employee is authenticated and authorized to access the portal

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to the self-service portal URL and enters valid username and password, then clicks login button | Portal home page is displayed with employee name and navigation menu visible |
| 2 | Employee clicks on the 'Attendance' or 'My Attendance' menu option from the navigation menu | Attendance records page is displayed showing all attendance records with timestamps, source (biometric/manual), and date information in a tabular format |
| 3 | Employee selects a start date and end date from the date range filter controls and clicks 'Apply' or 'Filter' button | Attendance records are filtered and only records within the selected date range are displayed on the screen |

**Postconditions:**
- Employee remains logged into the portal
- Filtered attendance records are displayed on screen
- No data modifications have occurred

---

### Test Case: Verify attendance data export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 2 mins

**Preconditions:**
- Employee is logged into the self-service portal
- Employee has navigated to the attendance section
- Attendance records are visible on screen
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee views the attendance records displayed on the screen and verifies records are visible | Attendance records are displayed on screen with all relevant columns including date, time, source, and status |
| 2 | Employee locates and clicks the 'Export' or 'Download CSV' button on the attendance page | CSV file is automatically downloaded to the default download location with filename containing 'attendance' and current date, and the file contains all displayed attendance records with correct data matching the on-screen display |

**Postconditions:**
- CSV file is saved in the downloads folder
- CSV file contains accurate attendance data matching screen display
- Employee remains on the attendance page
- No changes to attendance data in the system

---

### Test Case: Ensure access control for attendance data
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee is logged into the self-service portal
- Multiple employees exist in the system with different employee IDs
- Each employee has their own attendance records
- System has proper authentication and authorization mechanisms in place

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee manually modifies the URL in the browser address bar to include another employee's ID (e.g., changing /attendance/employee/123 to /attendance/employee/456) and presses Enter | System displays 'Access Denied' or '403 Forbidden' error message and does not display the other employee's attendance data |
| 2 | Employee navigates back to their own attendance section using the proper navigation menu or by entering their correct employee ID in the URL | Employee's own attendance data is displayed correctly with all records, timestamps, and source information visible and accurate |

**Postconditions:**
- Employee can only view their own attendance data
- Unauthorized access attempt is logged in system audit trail
- No data breach has occurred
- Employee session remains active and valid

---

## Story: As Attendance Manager, I want to validate manual attendance inputs to achieve data accuracy and prevent errors
**Story ID:** story-25

### Test Case: Validate rejection of manual attendance with invalid employee ID
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Attendance Manager is logged into the system with appropriate permissions
- Manual attendance entry form is accessible
- Employee database contains valid employee records
- System validation rules are active and configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to manual attendance entry form and enters a non-existent employee ID (e.g., 'EMP99999') in the employee ID field, then enters valid date and time, and attempts to submit | System displays a validation error message such as 'Employee ID does not exist' or 'Invalid Employee ID' in red text near the employee ID field, and the submit button is disabled or submission is prevented |
| 2 | Manager clears the invalid employee ID field and enters a valid, existing employee ID from the system | Validation error message is cleared and removed from the screen, employee name is displayed (if applicable), and form fields become enabled for submission |
| 3 | Manager verifies all other fields contain valid data and clicks the 'Submit' or 'Save' button | Attendance record is saved successfully to the database, success confirmation message is displayed, and the form is either cleared or redirected to the attendance list page |

**Postconditions:**
- Valid attendance record is saved in the database
- No invalid employee ID records exist in the system
- Manager remains logged in and can perform additional operations
- Audit log contains record of successful attendance entry

---

### Test Case: Verify detection of duplicate attendance entries
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Attendance Manager is logged into the system
- Manual attendance entry form is accessible
- An attendance record already exists for a specific employee at a specific date and time
- Duplicate detection validation is enabled in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager enters the same employee ID, date, and time as an existing attendance record in the manual attendance entry form and attempts to submit | System rejects the duplicate entry and displays an error message such as 'Duplicate attendance record detected' or 'Attendance already exists for this employee at this time', preventing submission |
| 2 | Manager modifies the time field to a unique value that does not conflict with existing records while keeping the same employee ID and date | Duplicate validation error is cleared, validation passes, and no error messages are displayed on the form |
| 3 | Manager clicks the 'Submit' or 'Save' button to save the attendance record | Attendance record is saved successfully to the database, success confirmation message is displayed such as 'Attendance record saved successfully', and the new record appears in the attendance list |

**Postconditions:**
- No duplicate attendance records exist in the database
- New unique attendance record is successfully saved
- Data integrity is maintained
- Manager can continue entering additional records

---

### Test Case: Ensure real-time validation feedback during manual input
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 3 mins

**Preconditions:**
- Attendance Manager is logged into the system
- Manual attendance entry form is open and accessible
- Real-time validation is enabled and configured
- JavaScript is enabled in the browser

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager enters an invalid date format (e.g., '32/13/2023' or 'abc-def-ghij') in the date field and moves focus to another field or waits briefly | Validation error message is displayed immediately (within 1 second) below or near the date field indicating 'Invalid date format' or 'Please enter date in DD/MM/YYYY format' in red text |
| 2 | Manager clears the date field and enters a valid date format (e.g., '15/01/2024' or system-accepted format) and moves focus to another field | Validation error message is immediately removed from the screen, the date field shows a success indicator (such as green border or checkmark), and no error messages are visible |

**Postconditions:**
- Form contains valid date format
- No validation errors are displayed
- Manager can proceed with completing the form
- Real-time validation continues to function for other fields

---

## Story: As Attendance Manager, I want to handle biometric device failures by switching to manual attendance input to achieve uninterrupted attendance tracking
**Story ID:** story-26

### Test Case: Validate detection and notification of biometric device failure
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Attendance Manager role
- Biometric device is currently online and functioning
- System monitoring is active and configured
- Notification system is enabled
- Manual attendance input feature is available in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate biometric device failure by disconnecting the device or stopping the device service | System detects the biometric device failure within 1 minute of the simulated failure |
| 2 | Verify that the system sends a notification to the attendance manager | Attendance manager receives an alert notification promptly (within 1 minute) indicating biometric device failure with device details |
| 3 | Navigate to the attendance input section and verify manual input mode availability | Manual attendance input mode is automatically enabled and accessible to the manager |
| 4 | Manager clicks on the option to switch to manual input mode | System successfully switches to manual attendance input interface with all necessary fields available for data entry |

**Postconditions:**
- System is in manual attendance input mode
- Biometric device status shows as offline/failed
- Notification has been logged in the system
- Manager can proceed with manual attendance entry

---

### Test Case: Verify logging of fallback events
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Attendance Manager role
- System is in manual input mode due to biometric device failure
- Biometric device failure has been detected and logged
- Audit logging system is active and configured
- At least one employee record exists for attendance entry

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the manual attendance input interface | Manual attendance input form is displayed with fields for employee ID, date, time, and attendance status |
| 2 | Enter valid employee attendance data manually (employee ID, date, check-in time, check-out time) | All fields accept the input data without validation errors |
| 3 | Submit the manual attendance entry | Attendance record is saved successfully and confirmation message is displayed |
| 4 | Navigate to the audit log section and filter for fallback events | System displays the fallback event log entry with accurate timestamp, manager user ID, employee ID, and fallback reason (biometric device failure) |
| 5 | Verify the completeness of the audit log entry details | Audit log contains all required information: event type (fallback), timestamp, user details (manager name/ID), device ID, and action performed (manual attendance entry) |

**Postconditions:**
- Manual attendance record is stored in the database
- Fallback event is logged in the audit trail
- Attendance data integrity is maintained
- Log entry is available for compliance and reporting purposes

---

### Test Case: Ensure system resumes biometric capture after device restoration
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Attendance Manager role
- System is currently in manual input mode due to biometric device failure
- Biometric device is currently offline or disconnected
- Manual attendance entries have been made during the failure period
- System monitoring is actively checking device status

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate biometric device restoration by reconnecting the device or restarting the device service | Biometric device comes online and is accessible to the system |
| 2 | Wait for the system to detect the restored device status | System detects that the biometric device is online within 1 minute and updates the device status to 'Active' or 'Online' |
| 3 | Verify that the system automatically disables manual input mode | Manual attendance input mode is automatically disabled and the system displays a notification indicating biometric capture has resumed |
| 4 | Navigate to the attendance capture interface | Biometric attendance capture interface is active and ready to accept biometric inputs from employees |
| 5 | Simulate a biometric attendance capture (fingerprint scan or face recognition) | System successfully captures biometric attendance data and creates an attendance record automatically |
| 6 | Check the audit log for device restoration event | System has logged the device restoration event with timestamp and automatic mode switch details |

**Postconditions:**
- System is back in biometric attendance capture mode
- Manual input mode is disabled
- Biometric device status shows as online/active
- Device restoration event is logged in audit trail
- System is ready to process biometric attendance normally

---

