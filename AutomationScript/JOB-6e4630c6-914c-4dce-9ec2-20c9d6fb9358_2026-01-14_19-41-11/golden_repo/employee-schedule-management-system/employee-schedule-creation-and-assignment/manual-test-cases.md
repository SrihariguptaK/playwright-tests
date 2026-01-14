# Manual Test Cases

## Story: As Scheduling Manager, I want to assign shift templates to employees to create employee schedules
**Story ID:** story-4

### Test Case: Assign shift template to employee successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager with appropriate permissions
- At least one employee exists in the system
- At least one shift template is configured and available
- No existing shifts assigned to the selected employee for the target date range
- Schedule creation page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule creation page | Schedule creation UI is displayed with options to select employees, shift templates, and date ranges |
| 2 | Select an employee from the employee dropdown or list | Selected employee is highlighted and displayed in the assignment form |
| 3 | Select a shift template from the available templates dropdown | Shift template details (start time, end time, duration) are displayed |
| 4 | Select a date range for the shift assignment using the date picker | Date range is accepted and displayed in the form without validation errors |
| 5 | Click the Submit or Save button to create the assignment | System processes the request, schedule is saved to the database, and a success confirmation message is displayed (e.g., 'Schedule assigned successfully') |
| 6 | Verify the assigned schedule appears in the schedule list or calendar view | The newly assigned shift is visible with correct employee name, shift template, and date range |

**Postconditions:**
- Employee schedule is saved in the EmployeeSchedules table
- Schedule is visible in calendar and list views
- No scheduling conflicts exist
- System remains on schedule management page or displays success confirmation

---

### Test Case: Prevent overlapping shift assignment
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Scheduling Manager with appropriate permissions
- An employee exists in the system with at least one shift already assigned
- The existing shift has a specific date and time range (e.g., 9:00 AM - 5:00 PM on a specific date)
- A shift template exists that would overlap with the existing shift
- Schedule creation page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule creation page | Schedule creation UI is displayed |
| 2 | Select the employee who already has an assigned shift | Employee is selected and their existing schedules are loaded in the background |
| 3 | Select a shift template that overlaps with the employee's existing shift time | Shift template is selected and details are displayed |
| 4 | Select a date range that includes the date of the existing shift | Date range is entered in the form |
| 5 | Click Submit or Save button to attempt the assignment | System validates the assignment and displays a validation error message indicating overlapping shifts (e.g., 'Error: This shift overlaps with an existing shift for this employee on [date]') |
| 6 | Verify that the Save button remains disabled or the form prevents submission | Assignment is not saved, and the user cannot proceed until the conflict is resolved |
| 7 | Attempt to modify the date range or shift template to resolve the conflict | Form allows modifications and validation error clears when conflict is resolved |

**Postconditions:**
- No overlapping shift is saved to the database
- Original employee schedule remains unchanged
- User remains on schedule creation page with error message visible
- System maintains data integrity

---

### Test Case: Enforce maximum working hours per employee
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduling Manager with appropriate permissions
- Maximum working hours per day and per week are configured in the system (e.g., 12 hours/day, 40 hours/week)
- An employee exists in the system
- Employee may have existing shifts that contribute to their total hours
- Shift templates exist that would cause the employee to exceed maximum hours
- Schedule creation page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule creation page | Schedule creation UI is displayed |
| 2 | Select an employee from the employee list | Employee is selected and current hours summary may be displayed |
| 3 | Select shift templates and date ranges that would result in exceeding maximum hours per day (e.g., assigning 14 hours in a single day when max is 12) | Shift assignments are entered in the form |
| 4 | Click Submit or Save button | System validates total working hours and displays a warning or error message (e.g., 'Error: Assignment exceeds maximum working hours per day (12 hours). Current total: 14 hours') |
| 5 | Verify that the assignment is blocked from being saved | Save operation is prevented and user cannot proceed until hours are within limits |
| 6 | Alternatively, assign shifts that would exceed maximum hours per week (e.g., 45 hours when max is 40) | System displays appropriate error message for weekly hour limit violation (e.g., 'Error: Assignment exceeds maximum working hours per week (40 hours). Current total: 45 hours') |
| 7 | Attempt to save the schedule with hours exceeding weekly limit | Save is blocked and error message remains visible until hours are adjusted to be within limits |
| 8 | Modify the shift assignments to bring hours within acceptable limits | Error message clears and Save button becomes enabled when hours are compliant |

**Postconditions:**
- No schedule exceeding maximum hours is saved to the database
- Employee working hours remain within configured limits
- User remains on schedule creation page with validation feedback
- System enforces business rules for employee working hours

---

## Story: As Scheduling Manager, I want to view employee schedules in a calendar to monitor shift assignments
**Story ID:** story-5

### Test Case: View schedules in calendar with filters
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Scheduling Manager with appropriate permissions
- Multiple employees exist in the system with assigned schedules
- Schedules include various shift types and departments
- At least one scheduling conflict exists in the data for testing conflict highlighting
- At least one unassigned shift or gap exists in the schedule
- Schedule calendar page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule calendar page from the main menu or dashboard | Calendar page loads within 3 seconds displaying the default view (e.g., current week) with all employee schedules visible |
| 2 | Verify that the calendar displays schedules with employee names, shift times, and shift types | All scheduled shifts are visible in the calendar with complete information displayed clearly |
| 3 | Locate and click on the employee filter dropdown | Employee filter dropdown opens showing a list of all employees |
| 4 | Select a specific employee from the filter dropdown | Calendar updates to display only the schedules for the selected employee, other employees' schedules are hidden |
| 5 | Locate and click on the shift type filter dropdown | Shift type filter dropdown opens showing available shift types (e.g., Morning, Evening, Night) |
| 6 | Select a specific shift type from the filter dropdown | Calendar further filters to show only shifts matching both the selected employee and shift type |
| 7 | Verify that scheduling conflicts are visually highlighted (e.g., with red color, warning icon, or border) | Any overlapping shifts or scheduling conflicts are clearly marked with visual indicators that distinguish them from normal shifts |
| 8 | Verify that unassigned shifts or gaps in coverage are visually indicated (e.g., with different color, empty slots, or warning markers) | Unassigned shifts and coverage gaps are clearly visible with distinct visual styling that makes them easy to identify |
| 9 | Clear all filters or select 'All' options to return to full calendar view | Calendar resets to show all employees and all shift types with all schedules visible |

**Postconditions:**
- Calendar remains in the last selected view state
- All filters are functional and can be reapplied
- No data is modified during viewing
- System performance remains within 3-second load time SLA

---

### Test Case: Edit shift from calendar view
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager with edit permissions
- Calendar page is loaded and displaying employee schedules
- At least one shift is visible in the calendar view
- The shift to be edited does not have any restrictions preventing modification
- System allows direct editing from calendar interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate a specific shift in the calendar view | Shift is visible with employee name, time, and shift details displayed |
| 2 | Click on the shift block in the calendar | Edit form or modal dialog opens displaying the current shift details including employee, shift template, start time, end time, and date |
| 3 | Verify that all shift fields are editable and populated with current values | Form displays all editable fields with existing data pre-filled |
| 4 | Modify one or more shift details (e.g., change shift time, change shift template, or adjust date) | Modified values are accepted in the form fields without errors |
| 5 | Click the Save or Update button in the edit form | System validates the changes, saves the updated shift to the database, and displays a success confirmation message (e.g., 'Shift updated successfully') |
| 6 | Verify that the edit form closes automatically after successful save | Edit form or modal closes and returns user to the calendar view |
| 7 | Verify that the calendar automatically refreshes to display the updated shift information | Calendar shows the modified shift with updated details in the correct position, reflecting all changes made |
| 8 | Optionally, click on the same shift again to verify changes were persisted | Edit form opens showing the updated values, confirming that changes were saved correctly |

**Postconditions:**
- Shift is updated in the EmployeeSchedules table with new values
- Calendar view reflects the updated shift information
- No scheduling conflicts are introduced by the edit
- User remains on the calendar page with updated view
- Audit trail is created for the shift modification (if applicable)

---

## Story: As Scheduling Manager, I want to validate schedules to prevent overlapping shifts for employees
**Story ID:** story-6

### Test Case: Detect overlapping shifts during schedule creation
- **ID:** tc-001
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager with schedule creation permissions
- Employee database is accessible and contains active employees
- At least one employee has an existing shift scheduled (e.g., Employee ID: EMP001 has shift from 9:00 AM to 5:00 PM on 2024-01-15)
- Schedule creation interface is loaded and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads successfully with employee selection and shift assignment options visible |
| 2 | Select an employee who already has an existing shift (e.g., EMP001 with shift 9:00 AM - 5:00 PM on 2024-01-15) | Employee is selected and their existing schedule information is displayed or accessible |
| 3 | Assign a new shift that overlaps with the existing shift (e.g., 3:00 PM - 11:00 PM on 2024-01-15) | Validation error is displayed immediately in real-time stating 'Shift overlap detected: Employee EMP001 already has a shift from 9:00 AM to 5:00 PM on 2024-01-15' or similar detailed conflict message |
| 4 | Attempt to save the schedule by clicking the Save button | Save operation is blocked, error message persists or is reinforced, and schedule is not saved to the database. User remains on the schedule creation page with the conflict highlighted |

**Postconditions:**
- Schedule with overlapping shifts is not saved to the database
- Validation error is logged in the system audit log with timestamp, user ID, and conflict details
- Employee's original shift remains unchanged
- User remains on schedule creation page to resolve the conflict

---

### Test Case: Resolve overlapping shift and save successfully
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Scheduling Manager with schedule creation permissions
- An overlapping shift conflict exists for an employee (e.g., EMP001 has existing shift 9:00 AM - 5:00 PM and attempted new shift 3:00 PM - 11:00 PM on 2024-01-15)
- Validation error is currently displayed on the schedule creation page
- Schedule has not been saved due to the conflict

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Review the validation error message displaying the shift overlap details | Error message clearly shows the conflicting shift times and employee information |
| 2 | Modify the new shift times to remove the overlap (e.g., change shift from 3:00 PM - 11:00 PM to 6:00 PM - 11:00 PM on 2024-01-15) | Validation error is cleared immediately in real-time, no conflict message is displayed, and the interface indicates the schedule is valid |
| 3 | Click the Save button to save the schedule | Schedule is saved successfully to the database, success confirmation message is displayed (e.g., 'Schedule saved successfully'), and the new shift appears in the employee's schedule |
| 4 | Verify the saved schedule by navigating to the employee's schedule view | Both shifts are visible for the employee with no overlaps: original shift (9:00 AM - 5:00 PM) and new shift (6:00 PM - 11:00 PM) on 2024-01-15 |

**Postconditions:**
- Schedule is successfully saved in the database without conflicts
- Employee EMP001 has both shifts assigned with no overlaps
- Successful save operation is logged in the system audit log
- No validation errors are present
- User can proceed with additional schedule management tasks

---

## Story: As Scheduling Manager, I want to enforce maximum working hours per employee to comply with labor regulations
**Story ID:** story-7

### Test Case: Block schedule saving when max hours exceeded
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Scheduling Manager with schedule management permissions
- Maximum working hours limits are configured in the system (e.g., 8 hours per day, 40 hours per week)
- Employee database is accessible with active employees
- Selected employee (e.g., EMP002) has existing shifts totaling near the maximum limit (e.g., 35 hours for the week)
- Schedule creation/editing interface is loaded and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule assignment page | Schedule assignment page loads successfully with employee selection and shift assignment options visible |
| 2 | Select an employee (e.g., EMP002) who has existing shifts for the current week | Employee is selected and current assigned hours summary is displayed (e.g., 35 hours assigned for the week) |
| 3 | Assign a new shift that would exceed the maximum daily hours (e.g., assign a 10-hour shift when max is 8 hours per day) | Validation error is displayed immediately stating 'Maximum daily hours exceeded: Assigned 10 hours exceeds the limit of 8 hours per day' or similar clear message |
| 4 | Alternatively, assign shifts that would exceed maximum weekly hours (e.g., add 8 more hours when employee already has 35 hours and max is 40 hours per week) | Validation error is displayed stating 'Maximum weekly hours exceeded: Total of 43 hours exceeds the limit of 40 hours per week' with breakdown of hours |
| 5 | Attempt to save the schedule by clicking the Save button | Save operation is blocked, error message persists indicating hours must be reduced, and schedule is not saved to the database |

**Postconditions:**
- Schedule exceeding maximum hours is not saved to the database
- Validation error is logged in the system audit log with details of the violation
- Employee's existing shifts remain unchanged
- User remains on the schedule page to adjust the hours
- System maintains compliance with labor regulations

---

### Test Case: Save schedule within max hours successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduling Manager with schedule management permissions
- Maximum working hours limits are configured in the system (e.g., 8 hours per day, 40 hours per week)
- Employee database is accessible with active employees
- Selected employee (e.g., EMP003) has existing shifts within acceptable limits (e.g., 32 hours for the week)
- Schedule creation interface is loaded and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule assignment page | Schedule assignment page loads successfully with all necessary controls and information visible |
| 2 | Select an employee (e.g., EMP003) to assign shifts | Employee is selected and current hours summary is displayed showing 32 hours assigned for the week and remaining available hours (8 hours remaining) |
| 3 | Assign shifts that are within the allowed daily and weekly limits (e.g., assign a 7-hour shift on a day with no existing shifts) | No validation errors are displayed, hours summary updates to show 39 total hours for the week (within 40-hour limit), and the interface indicates the schedule is valid |
| 4 | Review the hours summary display to confirm compliance | Summary clearly shows total daily hours (7 hours) and total weekly hours (39 hours) are within the maximum limits, with visual indicators showing compliance (e.g., green status) |
| 5 | Click the Save button to save the schedule | Schedule is saved successfully to the database, success confirmation message is displayed (e.g., 'Schedule saved successfully - all hours within compliance limits'), and the new shift appears in the employee's schedule |
| 6 | Verify the saved schedule by navigating to the employee's schedule view or hours summary report | All assigned shifts are visible, total hours are accurately calculated and displayed (39 hours for the week), and no compliance warnings are present |

**Postconditions:**
- Schedule is successfully saved in the database with all shifts within maximum hours limits
- Employee EMP003 has total of 39 hours assigned for the week (within 40-hour limit)
- Successful save operation is logged in the system audit log
- No validation errors or warnings are present
- System maintains full compliance with labor regulations
- Hours summary is accurately updated and available for reporting

---

