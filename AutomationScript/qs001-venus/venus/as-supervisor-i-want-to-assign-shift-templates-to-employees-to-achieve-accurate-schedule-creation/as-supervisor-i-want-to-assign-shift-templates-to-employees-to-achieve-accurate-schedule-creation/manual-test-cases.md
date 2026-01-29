# Manual Test Cases

## Story: As Supervisor, I want to assign shift templates to employees to achieve accurate schedule creation
**Story ID:** db-story-story-2

### Test Case: Verify successful assignment of shift template to employee for specific dates
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Supervisor role
- At least one employee exists in the system
- At least one shift template is available in ShiftTemplates table
- Employee has no existing shifts for the selected date range
- Schedule creation page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads successfully with employee selection and calendar interface visible |
| 2 | Select an employee from the employee dropdown list | Employee is selected and their current schedule information is displayed |
| 3 | Select a date range (start date and end date) for shift assignment | Date range is highlighted on the calendar view and ready for template assignment |
| 4 | Choose a shift template from the available shift templates list | Shift template is selected and preview of shift details (time, duration, break) is displayed |
| 5 | Click 'Assign Shift' button to assign the selected template to the employee for the chosen dates | System processes the assignment and displays a success message confirming shift template assignment |
| 6 | Verify the assigned shifts appear in the calendar view | Assigned shifts are visible in the calendar with correct dates, times, and employee name displayed |

**Postconditions:**
- Shift template is successfully assigned to employee in EmployeeSchedules table
- Employee schedule is updated in the system
- Calendar view reflects the new shift assignments
- No validation errors or conflicts are present

---

### Test Case: Verify system detects and alerts supervisor for overlapping shift assignments
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Supervisor role
- Employee already has an assigned shift on a specific date and time
- Schedule creation page is accessible
- Conflict detection rules are configured in backend

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads with current employee schedules visible |
| 2 | Select the employee who already has an existing shift assignment | Employee is selected and existing shifts are displayed in the calendar view |
| 3 | Select a date that overlaps with an existing shift for this employee | Date is selected and available for template assignment |
| 4 | Choose a shift template that has overlapping time with the existing shift | Shift template is selected and ready for assignment |
| 5 | Click 'Assign Shift' button to attempt assignment | System validates the assignment and detects the overlapping shift conflict |
| 6 | Review the conflict alert message displayed by the system | Clear alert message is displayed indicating overlapping shift conflict with details of conflicting shifts (date, time, existing shift details) |
| 7 | Verify that the conflicting shift was not saved to the schedule | New shift is not added to EmployeeSchedules table and calendar view shows only the original shift |

**Postconditions:**
- Conflicting shift assignment is prevented
- Original employee schedule remains unchanged
- Supervisor is informed of the conflict with actionable information
- System maintains data integrity

---

### Test Case: Verify system detects and alerts supervisor when work hour limits are exceeded
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Supervisor role
- Employee has existing shifts that approach maximum work hour limits
- Work hour limit rules are configured in the system
- Schedule creation page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads successfully |
| 2 | Select an employee who is near their work hour limit for the week/period | Employee is selected and current total work hours are visible |
| 3 | Select a date within the current work period | Date is selected on the calendar |
| 4 | Choose a shift template that would cause total hours to exceed the maximum allowed work hour limit | Shift template is selected showing shift duration |
| 5 | Click 'Assign Shift' button to attempt assignment | System validates total work hours and detects the limit violation |
| 6 | Review the alert message displayed by the system | Alert message clearly indicates work hour limit exceeded with details: current hours, proposed hours, maximum allowed hours, and period affected |
| 7 | Verify the shift was not assigned to the employee | Shift is not saved to EmployeeSchedules table and employee's total hours remain within limits |

**Postconditions:**
- Work hour limit violation is prevented
- Employee schedule remains compliant with work hour regulations
- Supervisor is alerted with specific violation details
- No unauthorized shift assignment is recorded

---

### Test Case: Verify supervisor can manually adjust assigned shifts with successful validation
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Supervisor role
- Employee has at least one assigned shift in the schedule
- Schedule creation page is accessible
- Validation rules are active in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads with existing employee schedules visible in calendar view |
| 2 | Select an employee with existing shift assignments | Employee is selected and their assigned shifts are displayed in the calendar |
| 3 | Click on an existing assigned shift in the calendar to open edit mode | Shift details panel opens showing current shift information (start time, end time, break duration, shift type) |
| 4 | Modify the shift start time to a valid new time that does not create conflicts | New start time is entered and field accepts the input |
| 5 | Modify the shift end time to a valid new time | New end time is entered and field accepts the input |
| 6 | Click 'Save Changes' or 'Update Shift' button | System validates the manual adjustments against conflict rules and work hour limits |
| 7 | Verify validation success message is displayed | Success message confirms shift has been updated with validation passed |
| 8 | Check the calendar view for updated shift details | Calendar displays the modified shift with new start and end times correctly reflected |

**Postconditions:**
- Shift is updated in EmployeeSchedules table with new times
- Modified shift passes all validation rules
- Calendar view reflects the updated schedule
- Employee record shows the adjusted shift

---

### Test Case: Verify system prevents manual adjustment of shifts that would create conflicts
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Supervisor role
- Employee has multiple assigned shifts
- At least two shifts exist with potential for overlap if modified
- Validation rules are configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads with employee schedules visible |
| 2 | Select an employee with multiple existing shifts | Employee is selected and all assigned shifts are displayed in calendar view |
| 3 | Click on a shift to open it for editing | Shift edit panel opens with current shift details editable |
| 4 | Modify the shift time to overlap with another existing shift for the same employee | Modified time values are entered in the fields |
| 5 | Click 'Save Changes' button to attempt saving the conflicting modification | System runs validation and detects the scheduling conflict |
| 6 | Review the validation error message displayed | Error message clearly states the conflict with details of overlapping shifts and specific times that conflict |
| 7 | Verify the shift modification was not saved | Original shift times remain unchanged in the calendar and EmployeeSchedules table |

**Postconditions:**
- Invalid shift modification is rejected
- Original shift data remains intact
- No scheduling conflicts exist in the system
- Supervisor is informed of validation failure with clear reasoning

---

### Test Case: Verify employees receive notifications when schedule is created
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Supervisor role
- Employee account exists with valid notification settings (email/SMS enabled)
- Notification service is operational
- At least one shift template is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads successfully |
| 2 | Select an employee from the employee list | Employee is selected and ready for shift assignment |
| 3 | Select a date range for the new schedule | Date range is selected and highlighted on calendar |
| 4 | Assign a shift template to the selected employee and dates | Shift template is assigned successfully |
| 5 | Click 'Confirm' or 'Save Schedule' button to finalize the schedule creation | System saves the schedule and triggers notification process |
| 6 | Verify notification confirmation message appears for the supervisor | Message confirms that notification has been sent to the employee |
| 7 | Check employee's notification inbox/email (if accessible in test environment) | Employee receives notification containing schedule details: date, shift time, location, and any relevant instructions |

**Postconditions:**
- Schedule is created and saved in EmployeeSchedules table
- Notification is successfully sent to employee
- Notification delivery is logged in the system
- Employee is informed of their new schedule assignment

---

### Test Case: Verify employees receive notifications when schedule is modified
- **ID:** tc-007
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Supervisor role
- Employee has an existing assigned shift
- Employee notification settings are enabled
- Notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads with existing schedules visible |
| 2 | Select an employee with an existing shift assignment | Employee is selected and current shifts are displayed |
| 3 | Click on an existing shift to edit it | Shift edit panel opens with current shift details |
| 4 | Modify the shift details (change start time, end time, or date) | Modified values are entered successfully |
| 5 | Click 'Save Changes' button to save the modification | System validates and saves the modified shift successfully |
| 6 | Verify notification confirmation message is displayed | Confirmation message indicates notification has been sent to employee about schedule modification |
| 7 | Check employee's notification inbox/email for modification notice | Employee receives notification with updated schedule details highlighting what was changed (original vs. new times/dates) |

**Postconditions:**
- Modified schedule is saved in EmployeeSchedules table
- Notification is sent to employee about the modification
- Notification delivery is logged
- Employee is aware of schedule changes

---

### Test Case: Verify supervisor can view employee schedules in calendar view
- **ID:** tc-008
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Supervisor role
- Multiple employees have assigned shifts in the system
- Schedule creation page is accessible
- Calendar view feature is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads with calendar view interface visible |
| 2 | Verify calendar view displays current month/week by default | Calendar shows current time period with date grid clearly visible |
| 3 | Select an employee from the employee filter/dropdown | Calendar view updates to show only the selected employee's shifts |
| 4 | Verify assigned shifts are displayed on the calendar with shift details | Each shift appears on correct date with visible information: shift time, duration, and shift type/template name |
| 5 | Navigate to next week/month using calendar navigation controls | Calendar updates to show next time period with any scheduled shifts for that period |
| 6 | Navigate back to previous week/month using calendar navigation controls | Calendar updates to show previous time period with historical shift data |
| 7 | Switch calendar view mode (if available: day view, week view, month view) | Calendar adjusts display format while maintaining all shift information visibility |
| 8 | Click on a shift in the calendar to view detailed information | Shift details panel opens showing complete information: employee name, date, start time, end time, break duration, location, and status |

**Postconditions:**
- Calendar view accurately displays all employee schedules
- Supervisor can navigate through different time periods
- All shift information is accessible and readable
- Calendar view remains functional and responsive

---

### Test Case: Verify calendar view displays multiple employees' schedules simultaneously
- **ID:** tc-009
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Supervisor role
- At least 3 different employees have assigned shifts
- Schedule creation page with calendar view is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads with calendar view |
| 2 | Select 'All Employees' or multiple employees from the filter options | Calendar view updates to show shifts for all selected employees |
| 3 | Verify shifts from different employees are visually distinguishable | Each employee's shifts are displayed with different colors or clear labels showing employee names |
| 4 | Check that overlapping shifts (different employees, same time) are both visible | Calendar displays both shifts clearly without one hiding the other, possibly stacked or side-by-side |
| 5 | Verify calendar legend or key is present | Legend shows color coding or symbols used to differentiate between employees |

**Postconditions:**
- Multiple employee schedules are visible simultaneously
- Calendar view provides clear visual differentiation between employees
- All shift data is accessible and readable
- Supervisor can effectively monitor team schedules

---

### Test Case: Verify system handles concurrent schedule edits by multiple supervisors
- **ID:** tc-010
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- Two supervisor accounts are logged in on different sessions/browsers
- Same employee schedule is accessible to both supervisors
- System supports concurrent editing with conflict resolution

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Supervisor 1: Navigate to schedule creation page and select an employee | Supervisor 1 sees employee schedule and can edit |
| 2 | Supervisor 2: Navigate to schedule creation page and select the same employee | Supervisor 2 sees the same employee schedule and can edit |
| 3 | Supervisor 1: Begin editing a shift (change start time) | Shift enters edit mode for Supervisor 1 |
| 4 | Supervisor 2: Simultaneously edit the same shift (change end time) | Shift enters edit mode for Supervisor 2 |
| 5 | Supervisor 1: Save the changes first | Changes are saved successfully and database is updated with Supervisor 1's modifications |
| 6 | Supervisor 2: Attempt to save changes after Supervisor 1 | System detects concurrent edit conflict and displays appropriate message (e.g., 'This shift has been modified by another user. Please refresh and try again.') |
| 7 | Supervisor 2: Refresh the schedule view | Updated schedule reflects Supervisor 1's changes, Supervisor 2's unsaved changes are discarded or highlighted for review |

**Postconditions:**
- Data integrity is maintained
- Only one set of changes is saved (first save wins or merge conflict resolution)
- Both supervisors are aware of concurrent editing situation
- No data loss or corruption occurs

---

### Test Case: Verify system performance with maximum concurrent schedule edits
- **ID:** tc-011
- **Type:** boundary
- **Priority:** Medium
- **Estimated Time:** 20 mins

**Preconditions:**
- Test environment supports performance testing
- 100 supervisor accounts are available or can be simulated
- Sufficient employee and shift data exists in the system
- Performance monitoring tools are configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare 100 concurrent supervisor sessions accessing the schedule creation page | All 100 sessions successfully load the schedule creation interface |
| 2 | Initiate simultaneous schedule edit operations from all 100 sessions | System accepts all edit requests without crashing or timing out |
| 3 | Monitor system response time for each edit operation | Response time remains within acceptable limits (e.g., under 3 seconds per operation) |
| 4 | Execute save operations from all 100 sessions simultaneously | All save operations are processed successfully without data loss or corruption |
| 5 | Verify database integrity after concurrent operations | All schedule changes are correctly saved in EmployeeSchedules table with no duplicate or missing entries |
| 6 | Check system logs for errors or warnings during concurrent operations | No critical errors are logged; system handles load gracefully |
| 7 | Verify API endpoint performance metrics | POST /api/schedules and PUT /api/schedules/{id} endpoints maintain acceptable performance under load |

**Postconditions:**
- System successfully handles 100 concurrent schedule edits
- All data is saved accurately without corruption
- System performance remains within acceptable parameters
- No system crashes or critical failures occur

---

### Test Case: Verify role-based access control prevents non-supervisor users from assigning shifts
- **ID:** tc-012
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User account with non-supervisor role exists (e.g., Employee, Viewer)
- Role-based access control is configured and active
- Schedule creation functionality requires supervisor privileges

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system with a non-supervisor user account | User successfully logs in with limited role permissions |
| 2 | Attempt to navigate to the schedule creation page via direct URL or menu | System denies access and displays authorization error message or redirects to unauthorized page |
| 3 | Verify schedule creation menu option is not visible or is disabled | Schedule creation option is either hidden from navigation menu or displayed as disabled/grayed out |
| 4 | Attempt to access POST /api/schedules endpoint directly (if testing API access) | API returns 403 Forbidden or 401 Unauthorized status code with appropriate error message |
| 5 | Verify user can only view their own schedule (if applicable to role) | User can access read-only view of their personal schedule but cannot modify or create schedules for others |

**Postconditions:**
- Non-supervisor user is prevented from accessing schedule creation functionality
- Security controls are enforced at both UI and API levels
- No unauthorized schedule modifications are possible
- System maintains proper role-based access control

---

