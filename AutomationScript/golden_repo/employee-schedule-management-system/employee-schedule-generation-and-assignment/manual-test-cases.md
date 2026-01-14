# Manual Test Cases

## Story: As Scheduling Manager, I want to generate employee schedules using shift templates to achieve efficient workforce planning
**Story ID:** story-4

### Test Case: Generate schedule with valid shift templates and employee assignments
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduling Manager with appropriate permissions
- At least one shift template exists in the system
- At least 5 employees are available in the system with defined roles
- Employee availability data is up to date
- Database is accessible and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule generation page from the main dashboard menu | Schedule generation form is displayed with date range selector, shift template dropdown, and employee assignment section visible |
| 2 | Select a valid date range (e.g., next week Monday to Sunday) using the date picker and select available shift templates from the dropdown list | Date range is accepted and displayed correctly, shift templates are loaded and displayed in the selection area without any validation errors |
| 3 | Assign employees to shifts by selecting employees from the eligible employee list, ensuring each employee's availability matches the shift time and their role is compatible with shift requirements | Employee assignments are accepted, system validates availability and role compatibility in real-time, green checkmarks or success indicators appear next to valid assignments |
| 4 | Click the 'Generate Schedule' or 'Submit' button to create the schedule | Schedule is successfully generated within 5 seconds, confirmation message is displayed (e.g., 'Schedule generated successfully'), and the generated schedule ID or reference number is shown |

**Postconditions:**
- Schedule is saved in the Schedules database table
- All employee assignments are persisted
- Schedule is viewable in the schedule list view
- Confirmation notification is logged in the system
- Assigned employees can view their shifts

---

### Test Case: Prevent double-booking of employees during schedule generation
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Scheduling Manager with appropriate permissions
- At least two shift templates with overlapping time slots exist
- At least one employee is available in the system
- Schedule generation page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule generation page and select a date range that includes overlapping shift times | Schedule generation form is displayed with date range and shift template options available |
| 2 | Select two or more shift templates that have overlapping time periods (e.g., Shift A: 9 AM - 5 PM and Shift B: 3 PM - 11 PM) | Both shift templates are loaded and displayed in the schedule generation interface |
| 3 | Assign the same employee to both overlapping shifts | System immediately displays a validation error message (e.g., 'Employee [Name] is already assigned to an overlapping shift'), error indicator appears next to the conflicting assignment, and the assignment is not accepted |
| 4 | Attempt to generate the schedule by clicking the 'Generate Schedule' button while conflicting assignments remain | Schedule generation is blocked, error message is displayed (e.g., 'Cannot generate schedule: Resolve conflicts before proceeding'), list of conflicting assignments is shown, and the schedule is not saved to the database |

**Postconditions:**
- No schedule is created or saved in the system
- Employee is not double-booked in any shifts
- Error messages remain visible until conflicts are resolved
- System maintains data integrity
- User can modify assignments to resolve conflicts

---

## Story: As Scheduling Manager, I want to assign employees to shifts to ensure proper shift coverage
**Story ID:** story-5

### Test Case: Assign employee to shift with valid availability and role
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager with assignment permissions
- At least one shift schedule exists with unassigned shifts
- At least one employee with matching role and availability exists in the system
- Employee availability data is current and accurate
- Shift details include required role and time information

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift schedule view from the main menu and select a specific shift that needs employee assignment | Shift schedule is displayed with all shifts listed, selected shift is highlighted, and shift details panel shows shift time, required role, and current assignment status |
| 2 | Click on 'Assign Employee' button or link, then review and select an eligible employee from the filtered list of employees matching the shift role and availability criteria | List of eligible employees is displayed showing only employees with matching role and availability, employee details include name, role, and availability status, selection is made without any errors |
| 3 | Confirm the employee selection and click 'Save' or 'Assign' button to complete the assignment | Assignment is successfully saved to the database, confirmation message is displayed (e.g., 'Employee [Name] successfully assigned to shift'), shift now shows the assigned employee name, and the shift status updates to 'Assigned' |

**Postconditions:**
- Employee assignment is persisted in the Schedules database
- Shift shows as filled/assigned in the schedule view
- Employee can view the assigned shift in their personal schedule
- Shift coverage metrics are updated
- Assignment audit log is created

---

### Test Case: Prevent assignment of employee to overlapping shifts
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Scheduling Manager with assignment permissions
- At least two shifts with overlapping time periods exist in the schedule
- At least one employee is already assigned to one of the overlapping shifts
- Shift schedule view is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift schedule view and identify an employee who is already assigned to a shift during a specific time period | Shift schedule is displayed showing all shifts and current assignments, employee's existing assignment is visible |
| 2 | Select a different shift that overlaps with the employee's currently assigned shift time and attempt to assign the same employee to this overlapping shift | System immediately displays a validation error message (e.g., 'Cannot assign [Employee Name]: Employee is already assigned to an overlapping shift from [time] to [time]'), error icon or red indicator appears, and the assignment action is prevented |
| 3 | Click 'Save' or 'Save Changes' button while the conflicting assignment attempt is still active | Save operation is blocked, error message persists or is reinforced (e.g., 'Cannot save: Resolve assignment conflicts before saving'), detailed conflict information is displayed showing both overlapping shifts, and no changes are committed to the database |

**Postconditions:**
- No conflicting assignment is saved in the system
- Employee remains assigned only to the original shift
- Overlapping shift remains unassigned or retains previous assignment
- Data integrity is maintained with no double-bookings
- Error state is cleared when user selects a different employee or shift
- System is ready for valid assignment attempts

---

