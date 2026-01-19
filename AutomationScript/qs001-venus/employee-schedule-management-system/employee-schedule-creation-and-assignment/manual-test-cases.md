# Manual Test Cases

## Story: As Scheduler, I want to assign shift templates to employees to create their work schedules
**Story ID:** story-3

### Test Case: Validate successful schedule assignment with valid inputs
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one employee exists in the system
- At least one shift template is available
- Database is accessible and operational
- No existing schedules conflict with the test date range

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule assignment page by clicking on 'Schedule Management' menu and selecting 'Create Schedule' | Schedule assignment form is displayed with fields for employee selection, date range, and shift template selection |
| 2 | Select an employee from the employee dropdown list | Employee is selected and displayed in the employee field without errors |
| 3 | Enter a valid start date in the 'From Date' field (e.g., current date + 7 days) | Start date is accepted and displayed in the correct format |
| 4 | Enter a valid end date in the 'To Date' field (e.g., start date + 5 days) | End date is accepted and displayed in the correct format, no validation errors shown |
| 5 | Select one or more shift templates from the available shift templates list | Selected shift templates are highlighted and added to the assignment queue |
| 6 | Click the 'Submit' or 'Save Schedule' button | System processes the request, validates the data, and displays a success confirmation message (e.g., 'Schedule successfully assigned') |
| 7 | Verify the schedule appears in the employee's schedule view | Assigned shifts are visible in the employee's schedule with correct dates and shift details |

**Postconditions:**
- Schedule is saved in the EmployeeSchedules database
- Employee has assigned shifts for the specified date range
- Confirmation message is displayed to the scheduler
- Response time is under 3 seconds

---

### Test Case: Reject schedule assignment with overlapping shifts
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- An employee exists in the system
- Employee already has a shift assigned for a specific date and time (e.g., 9:00 AM - 5:00 PM on a specific date)
- Shift templates with overlapping times are available
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule assignment page | Schedule assignment form is displayed |
| 2 | Select the employee who already has an existing shift assignment | Employee is selected successfully |
| 3 | Select a date range that includes the date with the existing shift | Date range is accepted |
| 4 | Assign a shift template that overlaps with the existing shift time (e.g., 8:00 AM - 4:00 PM on the same date) | Shift template is selected and added to assignment queue |
| 5 | Click the 'Submit' or 'Save Schedule' button | System validates the assignment and displays a validation error message indicating overlapping shifts (e.g., 'Error: Shift overlaps with existing assignment on [date]') |
| 6 | Attempt to save the schedule again without resolving the conflict | Save operation is blocked, error message persists, and schedule is not saved to the database |
| 7 | Remove or modify the overlapping shift template to resolve the conflict | Validation error is cleared and the form allows submission |

**Postconditions:**
- No schedule is saved with overlapping shifts
- Original schedule remains unchanged
- Error message is displayed to the scheduler
- System maintains data integrity

---

### Test Case: Ensure unauthorized users cannot assign schedules
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- A user account exists with a non-Scheduler role (e.g., Employee, Manager, or Viewer role)
- Authentication system is operational
- Schedule assignment page requires Scheduler role authorization
- API endpoint POST /api/schedules has role-based access control enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using credentials of a non-Scheduler user (e.g., Employee role) | User is successfully authenticated and logged into the system |
| 2 | Attempt to navigate to the schedule assignment page by entering the URL directly or clicking on the menu option (if visible) | Access is denied with an authorization error message (e.g., 'Access Denied: You do not have permission to access this page') or the page is not accessible/visible |
| 3 | Using an API testing tool (e.g., Postman, cURL), attempt to call POST /api/schedules endpoint with valid schedule data and the non-Scheduler user's authentication token | API returns a 403 Forbidden or 401 Unauthorized status code with an error message (e.g., 'Authorization error: Insufficient permissions') |
| 4 | Verify that no schedule data is created or modified in the database | Database query confirms no new schedule records were created by the unauthorized user |
| 5 | Logout and login with a user having Scheduler role | Scheduler user can successfully access the schedule assignment page and API endpoint |

**Postconditions:**
- Unauthorized users cannot access schedule assignment functionality
- No unauthorized schedule modifications are made
- Security logs record the unauthorized access attempts
- Role-based access control is enforced

---

## Story: As Scheduler, I want to modify assigned employee schedules to correct or update shifts
**Story ID:** story-4

### Test Case: Validate successful schedule modification with audit trail
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- An employee exists with at least one assigned schedule
- Database is accessible and operational
- Audit logging system is enabled and functional
- No conflicting shifts exist for the modification time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to employee schedule view by selecting 'Schedule Management' and then 'View Schedules' | Employee schedule list page is displayed showing all employees with schedules |
| 2 | Select an employee from the list to view their schedule details | Employee's schedule details are displayed with all assigned shifts, dates, and times |
| 3 | Click on a specific shift to open the edit mode or click 'Edit' button | Shift details are displayed in editable format with fields for start time, end time, and shift template |
| 4 | Modify the shift start time (e.g., change from 9:00 AM to 10:00 AM) | New start time is accepted and displayed in the input field without errors |
| 5 | Modify the shift end time (e.g., change from 5:00 PM to 6:00 PM) | New end time is accepted and displayed in the input field without errors |
| 6 | Click 'Save' or 'Update Schedule' button | System validates the changes, updates the schedule, and displays a confirmation message (e.g., 'Schedule successfully updated') |
| 7 | Verify the updated shift is displayed with the new times in the employee schedule view | Modified shift shows the updated start and end times correctly |
| 8 | Access the audit trail or change history for this schedule | Audit trail displays the modification record with scheduler username, timestamp, old values, and new values |
| 9 | Verify the audit trail contains all required information (user, timestamp, changes made) | Audit record shows: modified by [Scheduler name], timestamp [date and time], changes: start time 9:00 AM → 10:00 AM, end time 5:00 PM → 6:00 PM |

**Postconditions:**
- Schedule is updated in the EmployeeSchedules database
- Audit trail record is created with complete modification details
- Confirmation message is displayed to the scheduler
- Update response time is under 3 seconds
- Modified schedule is visible to authorized users

---

### Test Case: Reject schedule modification with overlapping shifts
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- An employee exists with multiple assigned shifts
- Employee has at least two shifts on the same day or consecutive days that could potentially overlap
- Database is accessible and operational
- Validation rules for overlapping shifts are configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to employee schedule view | Employee schedule list is displayed |
| 2 | Select an employee who has multiple shifts assigned | Employee's schedule details are displayed showing all assigned shifts |
| 3 | Identify two shifts: one existing shift (e.g., 2:00 PM - 10:00 PM) and another shift to modify (e.g., 9:00 AM - 5:00 PM on the same date) | Both shifts are visible in the schedule view |
| 4 | Click to edit the second shift (9:00 AM - 5:00 PM) | Shift details open in edit mode |
| 5 | Modify the shift end time to create an overlap (e.g., change end time from 5:00 PM to 8:00 PM, which overlaps with the 2:00 PM - 10:00 PM shift) | Modified time is entered in the field |
| 6 | Click 'Save' or 'Update Schedule' button | System validates the modification and displays a validation error message (e.g., 'Error: Modified shift overlaps with existing shift from 2:00 PM - 10:00 PM') |
| 7 | Attempt to save the changes again without resolving the overlap | Save operation is blocked, error message persists, and the schedule modification is not saved to the database |
| 8 | Verify the original schedule remains unchanged in the database | Employee schedule still shows the original shift times without the conflicting modification |
| 9 | Modify the shift to a non-overlapping time (e.g., change end time to 1:00 PM) | Validation error is cleared and the system allows the modification to be saved |

**Postconditions:**
- No schedule is saved with overlapping shifts
- Original schedule remains intact
- Validation error message is displayed
- Data integrity is maintained
- No audit trail entry is created for the rejected modification

---

### Test Case: Verify notification sent upon schedule update
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- An employee exists with at least one assigned schedule
- Employee has a valid email address or notification contact configured
- A manager is assigned to the employee with valid notification contact
- Notification system is operational and configured
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to employee schedule view | Employee schedule list is displayed |
| 2 | Select an employee and open their schedule for editing | Employee's schedule details are displayed in editable format |
| 3 | Modify a shift (e.g., change shift time from 9:00 AM - 5:00 PM to 10:00 AM - 6:00 PM) | Modified shift times are accepted in the input fields |
| 4 | Click 'Save' or 'Update Schedule' button | Schedule is updated successfully and confirmation message is displayed (e.g., 'Schedule updated and notifications sent') |
| 5 | Check the notification queue or notification log in the system | Two notification entries are created: one for the employee and one for the manager |
| 6 | Verify the notification content for the employee includes schedule change details | Employee notification shows: 'Your schedule has been updated. New shift: [Date] 10:00 AM - 6:00 PM (previously 9:00 AM - 5:00 PM)' |
| 7 | Verify the notification content for the manager includes schedule change details | Manager notification shows: 'Schedule updated for [Employee Name]. New shift: [Date] 10:00 AM - 6:00 PM' |
| 8 | Check notification delivery status in the system or notification service dashboard | Notification delivery status shows 'Delivered' or 'Sent' for both employee and manager notifications |
| 9 | Verify notification delivery timestamp is recorded | Delivery timestamp is displayed and is within acceptable time frame (within 1 minute of schedule update) |
| 10 | Optionally, check the employee's and manager's email inbox or notification center | Both recipients have received the notification with correct schedule change information |

**Postconditions:**
- Schedule is successfully updated in the database
- Notifications are sent to both employee and manager
- Notification delivery status is confirmed and logged
- Notification delivery success rate meets the 98% threshold
- Audit trail includes notification delivery information

---

## Story: As Scheduler, I want to delete assigned employee schedules to remove outdated or incorrect shifts
**Story ID:** story-7

### Test Case: Validate successful schedule deletion with confirmation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one assigned schedule exists in the system
- User has delete permissions for schedules
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the assigned schedules list page | Assigned schedules list page loads successfully and displays all existing schedules with employee names, shift times, and dates |
| 2 | Select one or more schedule(s) for deletion by clicking the checkbox next to the schedule entry | Selected schedule(s) are highlighted and checkbox is marked, delete button becomes enabled |
| 3 | Click the 'Delete' button | Confirmation dialog appears with warning message asking 'Are you sure you want to delete the selected schedule(s)?' with 'Confirm' and 'Cancel' options |
| 4 | Click 'Confirm' button in the confirmation dialog | Deletion process executes within 2 seconds, confirmation message 'Schedule(s) deleted successfully' is displayed, and deleted schedule(s) are removed from the list |
| 5 | Verify the schedule list is updated | Deleted schedule(s) no longer appear in the assigned schedules list |

**Postconditions:**
- Selected schedule(s) are permanently deleted from the database
- Deletion action is logged in audit trail with user ID and timestamp
- Schedule list reflects the updated state without deleted entries
- Confirmation message is cleared after user acknowledgment

---

### Test Case: Prevent deletion when dependencies exist
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one assigned schedule exists that is linked to active tasks or dependencies
- User has delete permissions for schedules
- Database contains schedule with active dependencies

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the assigned schedules list page | Assigned schedules list page loads successfully displaying all schedules including those with dependencies |
| 2 | Select a schedule that is linked to active tasks or has dependencies | Schedule is selected and highlighted, delete button becomes enabled |
| 3 | Click the 'Delete' button | Confirmation dialog appears asking for deletion confirmation |
| 4 | Click 'Confirm' button in the confirmation dialog | System validates dependencies and displays error message 'Cannot delete schedule: Active dependencies exist. Please remove linked tasks before deletion.' Deletion is blocked and schedule remains in the list |
| 5 | Verify the schedule still exists in the list | Schedule with dependencies remains unchanged in the assigned schedules list |

**Postconditions:**
- Schedule with dependencies is not deleted
- Error message is displayed to the user
- Schedule remains in the database unchanged
- Attempted deletion is logged in audit trail with failure reason

---

### Test Case: Ensure audit log records deletion actions
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one assigned schedule exists without dependencies
- Audit logging system is enabled and operational
- User has access to view audit logs or admin has access to verify logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the assigned schedules list page | Assigned schedules list page loads successfully with available schedules |
| 2 | Note the schedule ID and details of the schedule to be deleted | Schedule ID, employee name, shift date and time are recorded for verification |
| 3 | Select the schedule for deletion and click 'Delete' button | Confirmation dialog appears |
| 4 | Click 'Confirm' button to complete the deletion | Schedule is deleted successfully and confirmation message is displayed |
| 5 | Navigate to the audit log section or access audit log database | Audit log interface or database is accessible |
| 6 | Search for the deletion action using the schedule ID or timestamp | Audit log entry is found containing: action type 'DELETE', schedule ID, user ID of the scheduler who performed deletion, timestamp of deletion, and status 'SUCCESS' |
| 7 | Verify all required audit information is present and accurate | Audit log entry contains complete information: user ID matches logged-in scheduler, timestamp is accurate, schedule ID matches deleted schedule, and all mandatory fields are populated |

**Postconditions:**
- Audit log contains complete deletion record
- Audit entry includes user ID, timestamp, schedule ID, and action type
- Audit trail maintains 100% accuracy for deletion actions
- Audit log is immutable and cannot be modified

---

