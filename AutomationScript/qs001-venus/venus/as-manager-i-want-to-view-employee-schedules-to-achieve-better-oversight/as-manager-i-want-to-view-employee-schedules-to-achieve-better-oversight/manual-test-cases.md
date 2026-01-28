# Manual Test Cases

## Story: As Manager, I want to view employee schedules to achieve better oversight.
**Story ID:** story-4

### Test Case: Validate successful viewing of employee schedules
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has appropriate permissions to view employee schedules
- EmployeeSchedules table contains schedule data for the test period
- At least one shift is marked as unfilled in the system
- System is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee schedule view from the main dashboard or menu | Schedule interface is displayed with calendar format showing current date range, navigation controls, and filter options are visible |
| 2 | Select a date range using the date picker (e.g., select start date and end date for a 7-day period) | Schedule for the selected period is displayed showing all employee shifts, shift times, employee names, and shift types in calendar format within 2 seconds |
| 3 | Review the displayed schedule and identify unfilled shifts by looking for visual indicators | Unfilled shifts are clearly highlighted with distinct visual markers (e.g., different color, border, or icon) making them easily distinguishable from filled shifts |

**Postconditions:**
- Manager remains on the employee schedule view
- Selected date range remains active
- Schedule data is displayed accurately reflecting the current state of the EmployeeSchedules table
- No data has been modified in the system

---

### Test Case: Verify filtering of schedules by employee
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has appropriate permissions to view employee schedules
- EmployeeSchedules table contains schedule data for multiple employees
- At least one employee has multiple shifts assigned in the current period
- Employee filter dropdown is populated with active employees
- System is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee schedule view from the main dashboard or menu | Schedule interface is displayed with calendar format, showing all employees' shifts, and filter options including employee filter dropdown are visible |
| 2 | Click on the employee filter dropdown and select a specific employee from the list | Schedule is filtered and refreshed to show only the selected employee's shifts, with the employee's name displayed in the filter indicator, and response time is under 2 seconds |
| 3 | Review all displayed shifts in the calendar view and verify each shift belongs to the selected employee | Only the selected employee's shifts are visible in the calendar, showing their shift times, dates, and shift types, with no shifts from other employees displayed |

**Postconditions:**
- Manager remains on the employee schedule view
- Employee filter remains active showing the selected employee
- Schedule displays only the filtered employee's data
- Filter can be cleared or changed to view other employees
- No data has been modified in the system

---

