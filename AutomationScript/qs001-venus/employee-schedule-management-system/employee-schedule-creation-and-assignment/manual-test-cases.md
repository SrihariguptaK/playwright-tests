# Manual Test Cases

## Story: As Scheduler, I want to assign shift templates to employees to achieve efficient schedule creation
**Story ID:** story-2

### Test Case: Assign shift template to single employee without conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one employee exists in the system
- At least one shift template is available
- Selected employee has no existing shifts for the target date
- Employee schedule assignment page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to employee schedule assignment page | Schedule assignment form is displayed with employee selection dropdown, shift template dropdown, and date picker fields |
| 2 | Select one employee from the employee dropdown list | Employee is selected and displayed in the form without validation errors |
| 3 | Select a shift template from the shift template dropdown | Shift template is selected and shift details (start time, end time, duration) are displayed |
| 4 | Select a specific date using the date picker | Date is selected and displayed in the form, inputs accepted without validation errors |
| 5 | Click the Submit or Assign button to submit the assignment | System processes the request, shift is assigned successfully, and confirmation message is displayed indicating successful assignment |
| 6 | Verify the assigned shift appears in the employee's schedule view | The newly assigned shift is visible in the employee's schedule with correct date, time, and shift template details |

**Postconditions:**
- Shift template is successfully assigned to the employee for the specified date
- Assignment is saved in the EmployeeSchedules table
- Employee schedule reflects the new shift assignment
- No conflicts exist in the employee's schedule

---

### Test Case: Prevent overlapping shift assignments for the same employee
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- An employee exists in the system
- Employee already has a shift assigned for a specific date and time (e.g., 9:00 AM - 5:00 PM)
- At least one shift template exists that would overlap with the existing shift
- Employee schedule assignment page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to employee schedule assignment page | Schedule assignment form is displayed |
| 2 | Select the employee who already has an existing shift assigned | Employee is selected successfully |
| 3 | Select a shift template that overlaps with the employee's existing shift time | Shift template is selected |
| 4 | Select the same date as the existing shift | Date is selected |
| 5 | Attempt to submit the assignment by clicking Submit or Assign button | System displays conflict error message indicating overlapping shift detected and prevents the assignment from being saved |
| 6 | Adjust the assignment to a non-overlapping time by selecting a different date or different shift template with non-overlapping hours | System accepts the adjusted inputs without displaying any validation errors |
| 7 | Submit the adjusted assignment | Shift is assigned successfully and confirmation message is displayed |
| 8 | Verify both shifts appear in the employee's schedule without conflicts | Both the original and newly assigned shifts are visible in the schedule with no time overlaps |

**Postconditions:**
- Original shift assignment remains unchanged
- New non-overlapping shift is successfully assigned
- No overlapping shifts exist for the employee
- Error handling for conflicts is validated

---

### Test Case: Bulk assign shift templates to multiple employees
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple employees (at least 3) exist in the system
- At least one shift template is available
- Selected employees have no conflicting shifts for the target date range
- Bulk assignment feature is enabled and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to employee schedule assignment page with bulk assignment capability | Bulk assignment form is displayed with multi-select employee dropdown, shift template selector, and date range picker |
| 2 | Select multiple employees using the multi-select employee dropdown (select at least 3 employees) | All selected employees are displayed in the selection list |
| 3 | Select a shift template from the shift template dropdown | Shift template is selected and shift details are displayed |
| 4 | Specify a date range using the date range picker (e.g., 5 consecutive days) | Date range is selected and displayed, bulk assignment form accepts all inputs without errors |
| 5 | Click Submit or Assign button to submit the bulk assignment | System processes the bulk assignment request and displays a progress indicator |
| 6 | Wait for processing to complete | System displays confirmation message indicating shifts have been assigned to all selected employees successfully, showing count of successful assignments |
| 7 | Navigate to the first selected employee's schedule view | Employee's schedule displays the assigned shifts for all dates in the specified range |
| 8 | Navigate to the second selected employee's schedule view | Employee's schedule displays the assigned shifts for all dates in the specified range |
| 9 | Navigate to the third selected employee's schedule view and verify schedules | Employee's schedule displays the assigned shifts for all dates in the specified range, all schedules reflect assigned shifts without conflicts |

**Postconditions:**
- Shift template is assigned to all selected employees for the specified date range
- All assignments are saved in the EmployeeSchedules table
- Each employee's schedule reflects the new shift assignments
- No scheduling conflicts exist for any of the selected employees
- Bulk assignment operation completed within performance requirements

---

## Story: As Scheduler, I want to handle bulk schedule assignments to achieve efficient workforce planning
**Story ID:** story-9

### Test Case: Perform bulk assignment without conflicts
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple employees (at least 5) exist in the system
- At least one shift template is available
- None of the selected employees have existing shifts for the target date range
- Bulk assignment endpoint POST /api/schedules/bulk is operational
- System can handle batch processing for multiple employees

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the bulk schedule assignment page | Bulk assignment interface is displayed with employee multi-select, shift template selector, and date range fields |
| 2 | Select multiple employees (at least 5) from the employee multi-select dropdown | All selected employees are displayed in the selection list, selection is accepted without errors |
| 3 | Select a shift template from the available shift templates dropdown | Shift template is selected and template details (name, start time, end time) are displayed |
| 4 | Specify a date range using the date range picker (e.g., 7 consecutive days) | Date range is selected and displayed in the form |
| 5 | Click Preview or Review button to view assignment summary | System displays a summary showing all employees, selected shift template, date range, and total number of assignments to be created |
| 6 | Review the summary for accuracy and click Submit or Confirm button to submit the bulk assignment | System initiates batch processing, displays progress indicator, and processes all assignments |
| 7 | Wait for bulk assignment processing to complete | System displays success confirmation message indicating all assignments were saved successfully with count of total assignments created |
| 8 | Navigate to the schedule view and select the first employee from the bulk assignment | Employee's schedule is displayed showing all assigned shifts for the specified date range |
| 9 | Verify the schedule details match the assigned shift template | Shift times, dates, and template details match the bulk assignment parameters |
| 10 | Repeat verification for at least 2 more employees from the bulk assignment | All verified employee schedules reflect the assigned shifts correctly for the entire date range without any conflicts |

**Postconditions:**
- Shift template is assigned to all selected employees for the entire date range
- All assignments are persisted in the database
- Each employee's schedule displays the new assignments
- No scheduling conflicts exist
- Success confirmation is logged
- Bulk assignment completed within acceptable performance timeframe

---

### Test Case: Detect conflicts during bulk assignment
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple employees exist in the system (at least 4)
- At least one of the selected employees has an existing shift that will conflict with the bulk assignment
- At least one shift template is available
- Conflict detection mechanism is enabled
- Bulk assignment page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the bulk schedule assignment page | Bulk assignment interface is displayed |
| 2 | Select multiple employees including at least one employee who has a conflicting schedule for the target date | All employees are selected and displayed in the selection list, selection is accepted |
| 3 | Select a shift template that will overlap with the existing shift of at least one selected employee | Shift template is selected successfully |
| 4 | Specify a date range that includes the date with the conflicting shift | Date range is selected and displayed |
| 5 | Click Preview or Review button to view assignment summary | System displays summary of the bulk assignment |
| 6 | Click Submit or Confirm button to submit the bulk assignment | System validates all assignments and detects conflicts for affected employees |
| 7 | Review the conflict report displayed by the system | System reports conflicts clearly, displaying employee names, conflicting dates, and existing shift details for each affected employee. Assignment is not saved for employees with conflicts |
| 8 | Adjust the selection by either removing the employee with conflicts or changing the date range to avoid conflicts | Adjusted selection or date range is accepted by the system |
| 9 | Click Submit or Confirm button to resubmit the adjusted bulk assignment | System validates the adjusted assignment, finds no conflicts, and processes the bulk assignment |
| 10 | Wait for processing to complete | System displays success confirmation message indicating assignments were saved successfully for all employees without conflicts |
| 11 | Verify schedules for the employees included in the final bulk assignment | All verified employee schedules reflect the assigned shifts correctly without any conflicts |

**Postconditions:**
- Employees without conflicts have shifts successfully assigned
- Employees with conflicts do not have conflicting shifts assigned
- Conflict detection mechanism is validated
- Error messages are clear and actionable
- Final assignments are saved correctly in the database
- System maintains data integrity by preventing overlapping shifts

---

