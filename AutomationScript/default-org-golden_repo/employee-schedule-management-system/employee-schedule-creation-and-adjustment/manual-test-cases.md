# Manual Test Cases

## Story: As Scheduler, I want to assign shift templates to employees to create their schedules
**Story ID:** story-3

### Test Case: Assign shift templates to employees successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one shift template exists in the system
- At least one employee exists in the employee directory
- Schedule assignment page is accessible
- No existing schedules conflict with the test dates

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule assignment page | Page displays employee selector and calendar view with available dates |
| 2 | Select one or more employees from the employee directory | Selected employees are highlighted and displayed in the selection panel |
| 3 | Select specific dates on the calendar for shift assignment | Selected dates are highlighted on the calendar |
| 4 | Choose shift templates from the available templates list and assign to selected employees on the chosen dates | Assignments are displayed on the calendar with employee names and shift details, no validation errors appear |
| 5 | Click the Submit or Save button to finalize assignments | System processes the request, schedules are saved successfully, and a confirmation message is displayed |

**Postconditions:**
- Employee schedules are saved in the database
- Assigned shifts are visible in the calendar view
- Notification trigger is sent to assigned employees
- Schedule data is retrievable via API

---

### Test Case: Detect and prevent overlapping shift assignments
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one employee has an existing shift assignment
- Multiple shift templates are available
- Schedule assignment page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule assignment page and select an employee who already has a shift assigned | Employee is selected and existing shifts are visible on the calendar |
| 2 | Assign a new shift template that overlaps with the employee's existing shift on the same date | System detects the conflict and displays a conflict alert message indicating overlapping shifts with specific time details |
| 3 | Attempt to save the conflicting schedule by clicking the Submit or Save button | Save operation is blocked, error message is displayed stating that conflicts must be resolved before saving, and the schedule is not saved to the database |

**Postconditions:**
- No conflicting schedule is saved in the database
- Original employee schedule remains unchanged
- Conflict alert remains visible until resolved
- User can modify or remove the conflicting assignment

---

### Test Case: Display assigned shifts in calendar view
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one employee exists in the system
- At least one shift template is available
- Schedule assignment page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule assignment page and select an employee | Employee is selected and calendar view is displayed |
| 2 | Assign one or more shift templates to the selected employee on specific dates | Shift assignments are created and displayed on the calendar |
| 3 | Click Submit or Save button to save the assignments | Assignments are saved successfully with confirmation message displayed |
| 4 | View the employee schedule calendar after saving | Assigned shifts are displayed correctly on the calendar with accurate dates, times, shift names, and employee information |
| 5 | Verify shift details by clicking on individual shifts in the calendar | Each shift displays complete details including shift template name, start time, end time, role, and assigned employee |

**Postconditions:**
- All assigned shifts are visible in the calendar view
- Shift data matches the assigned templates
- Calendar displays accurate date and time information
- Shifts are retrievable for reporting and employee viewing

---

## Story: As Employee, I want to view my assigned schedule to plan my workdays
**Story ID:** story-4

### Test Case: Employee views assigned schedule successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has at least one shift assigned in the schedule
- System is accessible and operational
- Employee has not logged in yet

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid employee credentials (username and password) | Authentication succeeds, employee is logged in, and the dashboard or home page loads successfully |
| 2 | Navigate to 'My Schedule' page from the main menu or dashboard | My Schedule page loads and displays a calendar view with all assigned shifts for the employee |
| 3 | Verify that assigned shifts are visible on the calendar with basic information (date, time, shift name) | All assigned shifts are displayed on the correct dates with accurate basic information |
| 4 | Click on a specific shift in the calendar to view detailed information | Shift details popup or panel is displayed showing complete information including shift name, start time, end time, role, location, and any additional notes |
| 5 | Close the shift details popup and verify calendar remains functional | Popup closes and calendar view remains intact with all shifts still visible |

**Postconditions:**
- Employee remains logged in
- Schedule data is displayed accurately
- No data modifications have occurred
- Employee can continue to navigate the system

---

### Test Case: Schedule loads within performance requirements
- **ID:** tc-005
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee is logged into the system
- Employee has assigned shifts in the schedule
- Network connection is stable
- Performance monitoring tool or timer is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Start timer or performance monitoring tool | Timer is started and ready to measure load time |
| 2 | Navigate to 'My Schedule' page or click on the schedule menu option | Schedule page begins loading |
| 3 | Measure the time from navigation click until the schedule calendar is fully rendered with all shift data visible | Schedule data loads completely and is displayed within 2 seconds, meeting the performance requirement |
| 4 | Verify that all shifts are visible and interactive after the load completes | All assigned shifts are displayed correctly and calendar is fully functional |

**Postconditions:**
- Schedule page is fully loaded
- Performance requirement of 2 seconds is met
- All schedule data is accessible
- Page remains responsive for further interactions

---

### Test Case: Notifications display for schedule changes
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee account exists and is logged into the system
- Employee has at least one assigned shift
- Scheduler has access to modify employee schedules
- Notification system is enabled and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Scheduler logs in and navigates to schedule management page | Scheduler successfully accesses the schedule management interface |
| 2 | Scheduler selects the employee's existing schedule and makes a modification (change shift time, date, or assignment) | Schedule modification is accepted by the system |
| 3 | Scheduler saves the updated schedule | Schedule is saved successfully and notification trigger is sent to the affected employee |
| 4 | Employee views the notification center or notification icon in the system | New notification is visible indicating a schedule change has occurred |
| 5 | Employee clicks on the notification to view details | Notification content is displayed showing accurate information about the schedule change including what was changed, old values, new values, and effective date. Notification includes actionable link to view updated schedule |
| 6 | Click on the actionable link in the notification | Employee is navigated to 'My Schedule' page showing the updated schedule with changes highlighted or indicated |

**Postconditions:**
- Notification is marked as read or viewed
- Employee is aware of schedule changes
- Updated schedule is displayed in calendar view
- Notification remains in history for future reference

---

## Story: As Scheduler, I want to receive alerts for scheduling conflicts to prevent errors
**Story ID:** story-5

### Test Case: Detect overlapping shift conflicts during scheduling
- **ID:** tc-001
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role permissions
- Schedule management interface is accessible
- At least one employee exists in the system
- Employee has no existing shifts assigned for the test time period

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management interface | Schedule management interface loads successfully with employee list visible |
| 2 | Select an employee from the employee list | Employee is selected and available for shift assignment |
| 3 | Assign a shift to the employee (e.g., Monday 9:00 AM - 5:00 PM) | First shift is assigned successfully without any alerts |
| 4 | Assign a second overlapping shift to the same employee (e.g., Monday 3:00 PM - 11:00 PM) | Conflict alert is displayed immediately indicating overlapping shift times with specific details of the conflict |
| 5 | Review the conflict alert message | Alert clearly shows both conflicting shift times and identifies the overlap period |
| 6 | Attempt to save the schedule with the unresolved conflict | Save action is blocked and error message is displayed stating that conflicts must be resolved before saving |

**Postconditions:**
- Schedule is not saved due to unresolved conflict
- Conflict alert remains visible on screen
- Employee still has only the first shift assigned
- System remains in edit mode awaiting conflict resolution

---

### Test Case: Enforce minimum rest period between shifts
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role permissions
- Schedule management interface is accessible
- Minimum rest period policy is configured in the system (e.g., 8 hours between shifts)
- At least one employee exists in the system
- Employee has no existing shifts assigned for the test time period

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management interface | Schedule management interface loads successfully |
| 2 | Select an employee from the employee list | Employee is selected and ready for shift assignment |
| 3 | Assign a shift to the employee (e.g., Monday 9:00 AM - 5:00 PM) | First shift is assigned successfully without alerts |
| 4 | Assign a second shift that violates the minimum rest period (e.g., Monday 9:00 PM - Tuesday 5:00 AM, only 4 hours rest) | Alert is displayed immediately indicating rest period violation with specific details about required vs actual rest time |
| 5 | Review the rest period violation alert | Alert clearly states the minimum rest period requirement and the actual time between shifts |
| 6 | Adjust the second shift to comply with rest period policy (e.g., change to Tuesday 1:00 AM - 9:00 AM, providing 8 hours rest) | Alert disappears immediately and no validation errors are shown |
| 7 | Attempt to save the schedule | Schedule saves successfully with confirmation message displayed |

**Postconditions:**
- Schedule is saved successfully with both shifts
- No conflict alerts are displayed
- Employee has two shifts assigned with compliant rest period between them
- Audit log records the schedule creation

---

### Test Case: Revalidate conflicts after schedule adjustments
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role permissions
- Schedule management interface is accessible
- At least one employee exists in the system
- Employee has an existing schedule with a conflict (overlapping shifts or rest period violation)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management interface | Schedule management interface loads with existing schedule visible |
| 2 | View the schedule with existing conflicts | Conflict alerts are displayed for the existing scheduling conflicts |
| 3 | Select one of the conflicting shifts for editing | Shift details are displayed in editable form |
| 4 | Modify the shift time to resolve the conflict (e.g., change end time to eliminate overlap) | System rechecks conflicts in real-time and conflict alert disappears immediately |
| 5 | Verify that no conflict alerts are displayed | All conflict alerts have been cleared and schedule shows as valid |
| 6 | Make an additional minor adjustment to another shift (non-conflicting change) | System revalidates all shifts in real-time and confirms no new conflicts introduced |
| 7 | Save the schedule after resolving all conflicts | Schedule saves successfully with confirmation message displayed |
| 8 | Verify the saved schedule | All shifts are saved correctly with no conflicts and updated times are reflected |

**Postconditions:**
- Schedule is saved successfully without any conflicts
- All conflict alerts have been resolved and cleared
- Employee shifts are updated with adjusted times
- System displays confirmation of successful save
- Audit log records the schedule modifications

---

## Story: As Scheduler, I want to manually adjust assigned shifts to handle exceptions
**Story ID:** story-7

### Test Case: Edit assigned shift successfully with validation
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role permissions
- Schedule management interface is accessible
- At least one employee exists with assigned shifts
- Employee has at least one shift assigned that can be edited
- No existing conflicts in the current schedule

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management interface | Schedule management interface loads successfully showing list of assigned shifts |
| 2 | Locate an assigned shift in the schedule view | Assigned shift is visible with current details (employee name, date, time, role) |
| 3 | Select the assigned shift for editing by clicking on it | Shift details are displayed in an editable form with all fields populated (start time, end time, role, employee) |
| 4 | Modify the shift start time to a valid new time (e.g., change from 9:00 AM to 10:00 AM) | Start time field updates with the new value and no validation errors are shown |
| 5 | Modify the shift end time to a valid new time (e.g., change from 5:00 PM to 6:00 PM) | End time field updates with the new value and no validation errors are shown |
| 6 | Modify the role assignment if applicable (e.g., change from 'Cashier' to 'Floor Staff') | Role field updates with the new value and no validation errors are shown |
| 7 | Review all modified fields to ensure changes are correct | All fields display the updated values correctly |
| 8 | Click the Save button to save the changes | Shift is updated successfully and confirmation message is displayed (e.g., 'Shift updated successfully') |
| 9 | Verify the updated shift in the schedule view | Schedule displays the shift with all updated details (new times and role) |

**Postconditions:**
- Shift is updated with new times and role in the database
- Schedule view reflects the updated shift details
- Confirmation message is displayed to the user
- Audit log contains entry with user ID, timestamp, and details of the modification
- No conflicts exist in the schedule

---

### Test Case: Prevent saving adjustments with conflicts
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role permissions
- Schedule management interface is accessible
- At least one employee exists with assigned shifts
- Employee has at least two shifts assigned on different times
- Current schedule has no conflicts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management interface | Schedule management interface loads successfully with assigned shifts visible |
| 2 | Select an assigned shift for editing | Shift details are displayed in editable form with current values |
| 3 | Modify the shift time to create an overlap with another existing shift for the same employee (e.g., change shift from 9:00 AM - 5:00 PM to 2:00 PM - 10:00 PM when employee already has a shift from 6:00 PM - 11:00 PM) | Validation error is displayed immediately indicating the conflict with specific details about the overlapping shifts |
| 4 | Review the validation error message | Error message clearly identifies the conflicting shifts with times and explains the overlap |
| 5 | Attempt to save the changes by clicking the Save button | Save action is blocked and error message is displayed stating 'Cannot save shift with unresolved conflicts' or similar |
| 6 | Verify that the Save button is disabled or the save action shows an error | Save functionality is prevented and user cannot proceed until conflict is resolved |
| 7 | Modify the shift again to remove the conflict (e.g., change end time to 5:00 PM to eliminate overlap) | Validation error disappears and no conflict messages are shown |
| 8 | Attempt to save the changes again | Shift saves successfully with confirmation message displayed |

**Postconditions:**
- Shift is saved only after conflict resolution
- No conflicting shifts exist in the schedule
- Validation errors are cleared after successful save
- Schedule reflects the corrected shift times
- Audit log records the successful adjustment

---

### Test Case: Verify audit trail records manual adjustments
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role permissions
- Schedule management interface is accessible
- Audit log system is functioning and accessible
- At least one employee exists with assigned shifts
- User has permissions to view audit logs
- System timestamp is accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management interface | Schedule management interface loads successfully |
| 2 | Note the current timestamp before making changes | Current system time is recorded for verification purposes |
| 3 | Select an assigned shift for editing | Shift details are displayed in editable form |
| 4 | Make a manual adjustment to the shift (e.g., change start time from 9:00 AM to 10:00 AM) | Shift time is updated in the form with no validation errors |
| 5 | Save the changes by clicking the Save button | Adjustment is saved successfully and confirmation message is displayed |
| 6 | Navigate to the audit log interface or section | Audit log interface loads successfully showing list of recent activities |
| 7 | Query or filter audit logs for the specific shift adjustment (using shift ID, employee name, or time range) | Audit log displays filtered results relevant to the recent adjustment |
| 8 | Locate the audit entry for the manual adjustment just made | Audit entry exists in the log for the shift modification |
| 9 | Verify the audit entry contains the user ID or username who made the change | Audit entry shows correct user identification matching the logged-in scheduler |
| 10 | Verify the audit entry contains an accurate timestamp of when the change was made | Timestamp in audit entry matches the time when the save action was performed (within acceptable margin) |
| 11 | Verify the audit entry contains details of what was changed (old value vs new value) | Audit entry shows the previous shift time (9:00 AM) and new shift time (10:00 AM) along with any other modified fields |
| 12 | Verify the audit entry contains the action type (e.g., 'Shift Updated' or 'Manual Adjustment') | Audit entry clearly identifies the type of action performed |

**Postconditions:**
- Shift adjustment is saved in the database
- Complete audit trail entry exists with all required information
- Audit log contains user ID/username of the scheduler who made the change
- Audit log contains accurate timestamp of the modification
- Audit log contains before and after values of the modified shift
- Audit log is accessible for compliance and tracking purposes

---

## Story: As Scheduler, I want to receive notifications when schedules are created or changed to keep employees informed
**Story ID:** story-10

### Test Case: Verify automatic notification on schedule creation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role and has appropriate permissions
- At least one employee exists in the system with valid email address
- Notification service is running and configured properly
- System time is synchronized for accurate timestamp tracking

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads successfully with all required fields visible |
| 2 | Select an employee from the employee dropdown list | Employee is selected and displayed in the schedule form |
| 3 | Enter schedule details including date, time, shift type, and location | All schedule details are entered and validated without errors |
| 4 | Click the 'Save' or 'Create Schedule' button | Schedule is saved successfully and confirmation message is displayed |
| 5 | Note the current timestamp and wait for up to 1 minute | System triggers notification automatically within 1 minute of schedule creation |
| 6 | Verify notification delivery status in the scheduler dashboard or notification log | Notification status shows as 'Sent' or 'Delivered' with timestamp within 1 minute of schedule creation |
| 7 | Check employee's email inbox or system alert panel | Employee receives notification via email or system alert |
| 8 | Review the notification content received by the employee | Notification contains accurate schedule details including employee name, date, time, shift type, and location matching the created schedule |

**Postconditions:**
- New schedule is created and stored in the database
- Notification is sent and logged in the notification tracking system
- Employee has received notification with accurate schedule information
- Notification delivery status is available for scheduler review

---

### Test Case: Resend notification manually
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role and has appropriate permissions
- At least one schedule exists with a previously sent notification
- Notification tracking system is operational
- Scheduler has access to notification status interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduler dashboard or notification management section | Dashboard or notification management page loads successfully |
| 2 | Locate and access the notification status view or notification history | Notification status interface is displayed with list of sent notifications |
| 3 | View the notification status for a specific schedule | Delivery status is displayed showing details such as 'Sent', 'Delivered', 'Failed', timestamp, recipient, and schedule information |
| 4 | Identify a notification that needs to be resent and locate the resend option | Resend notification button or link is visible and enabled for the selected notification |
| 5 | Click the 'Resend Notification' button | System prompts for confirmation or immediately processes the resend request |
| 6 | Confirm the resend action if prompted | Notification is resent to the employee and confirmation message is displayed |
| 7 | Refresh or check the notification status view | Notification status is updated showing new 'Resent' status with updated timestamp and delivery confirmation |
| 8 | Verify employee receives the resent notification | Employee receives duplicate notification via email or system alert with same schedule details |

**Postconditions:**
- Notification is resent and logged in the notification tracking system
- Notification status is updated with resend timestamp and delivery status
- Employee has received the resent notification
- Notification history shows both original and resent notification records

---

### Test Case: Ensure notification privacy and security
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Multiple user accounts exist with different roles (Scheduler, Employee, Unauthorized user)
- At least one schedule with notifications exists in the system
- Authentication and authorization mechanisms are properly configured
- Test user account without notification access permissions is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log out from any existing session | User is successfully logged out and redirected to login page |
| 2 | Log in with an unauthorized user account (user without scheduler or notification access permissions) | User is successfully authenticated and logged into the system with limited permissions |
| 3 | Attempt to navigate directly to the notification status page or notification management URL | Access is denied with appropriate error message such as '403 Forbidden' or 'Access Denied - Insufficient Permissions' |
| 4 | Attempt to access notification details via API endpoint or direct link if available | API returns authorization error (401 or 403) and access is blocked |
| 5 | Search for any navigation menu items or links related to notifications | Notification management options are not visible or accessible in the user interface for unauthorized user |
| 6 | Attempt to view another employee's notification details by manipulating URL parameters or request data | System validates authorization and denies access, preventing unauthorized viewing of notification data |
| 7 | Log out and log in with a Scheduler role account | Scheduler user can successfully access notification status and management features |
| 8 | Verify that notification content does not expose sensitive information to unauthorized parties | Notification privacy is maintained and only authorized users can access notification details |

**Postconditions:**
- Unauthorized access attempts are logged in security audit logs
- No notification data is exposed to unauthorized users
- System security and privacy controls are validated as functioning correctly
- Authorized users retain proper access to notification features

---

