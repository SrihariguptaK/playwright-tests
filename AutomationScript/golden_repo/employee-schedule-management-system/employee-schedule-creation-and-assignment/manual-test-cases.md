# Manual Test Cases

## Story: As Scheduler, I want to assign shift templates to employees to achieve efficient schedule creation
**Story ID:** story-2

### Test Case: Validate successful assignment of shift template to single employee
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one active employee exists in the system
- At least one shift template is available
- Selected employee has no existing shifts for the target date range
- Schedule assignment page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule assignment page from the main menu | Schedule assignment page loads successfully and displays the assignment form with employee selection dropdown, date range picker, and shift template selector |
| 2 | Click on the employee dropdown and select one employee from the list | Selected employee is highlighted and displayed in the employee field |
| 3 | Click on the date range picker and select a start date and end date for the assignment | Selected date range is displayed in the date field and accepted by the system |
| 4 | Click on the shift template dropdown and select an available shift template | Selected shift template is displayed with its details (shift name, time, duration) |
| 5 | Click the 'Assign' or 'Submit' button to save the assignment | System processes the assignment, schedule is saved to the database, and a success confirmation message is displayed with assignment details |
| 6 | Verify the confirmation message contains employee name, date range, and shift template details | Confirmation message displays all relevant assignment information accurately |

**Postconditions:**
- Schedule assignment is saved in EmployeeSchedules table
- Employee has the assigned shift template for the specified dates
- Assignment is visible in the calendar view
- Success notification is displayed to the scheduler

---

### Test Case: Verify bulk assignment of shift templates to multiple employees
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least 3 active employees exist in the system
- At least one shift template is available
- Selected employees have no existing shifts for the target date range
- System supports bulk assignment for up to 100 employees

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule assignment page from the main menu | Schedule assignment page loads successfully and displays the assignment form with multi-select employee dropdown, date range picker, and shift template selector |
| 2 | Click on the employee dropdown and select multiple employees (at least 3) using checkboxes or multi-select functionality | All selected employees are highlighted and displayed in the employee field with count indicator |
| 3 | Click on the date range picker and select a start date and end date for the bulk assignment | Selected date range is displayed in the date field and accepted by the system |
| 4 | Click on the shift template dropdown and select an available shift template to assign to all selected employees | Selected shift template is displayed with its details and indicates it will be applied to all selected employees |
| 5 | Click the 'Assign to All' or 'Bulk Assign' button to save the assignments | System processes all assignments simultaneously, schedules are saved to the database for all employees, and a success confirmation message is displayed |
| 6 | Verify the confirmation message shows the number of employees assigned and assignment details | Confirmation message displays total number of employees assigned, date range, and shift template details accurately |

**Postconditions:**
- Schedule assignments are saved in EmployeeSchedules table for all selected employees
- All selected employees have the assigned shift template for the specified dates
- Assignments are visible in the calendar view for each employee
- Bulk assignment success notification is displayed to the scheduler

---

### Test Case: Validate conflict detection during schedule assignment
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one active employee exists in the system
- Selected employee already has an existing shift assigned for a specific date and time
- At least one shift template is available that overlaps with the existing shift
- Conflict validation rules are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule assignment page and select an employee who has an existing shift on a specific date | Assignment form is displayed and employee is selected, existing schedule information may be visible |
| 2 | Select a date range that includes the date where the employee already has an assigned shift | Date range is accepted and displayed in the date field |
| 3 | Select a shift template that has overlapping time with the employee's existing shift on that date | Shift template is selected and displayed in the form |
| 4 | Click the 'Assign' or 'Submit' button to attempt saving the assignment | System validates the assignment and displays a conflict warning message indicating the overlapping shift details (date, time, existing shift name) |
| 5 | Review the conflict warning message and click 'Confirm' or 'Submit' again to attempt to override the conflict | System blocks the save operation and displays an error message stating that conflicting schedules cannot be saved |
| 6 | Verify the error message provides clear information about the conflict and suggests corrective actions | Error message clearly identifies the conflicting shift, date, time, and provides options to modify the assignment or cancel |

**Postconditions:**
- No new schedule assignment is saved to the database
- Employee's existing shift remains unchanged
- Conflict error message is displayed to the scheduler
- System maintains data integrity with 0% conflicting schedules saved

---

## Story: As Scheduler, I want to view employee schedules in a calendar to achieve better schedule management
**Story ID:** story-3

### Test Case: Validate calendar displays correct employee schedules
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one employee has assigned shifts in the system
- Schedule data exists in EmployeeSchedules table
- Calendar view page is accessible
- Filter options are available for employee and date range

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule calendar page from the main menu | Calendar view page loads successfully within 3 seconds and displays the current week or month with a calendar grid layout |
| 2 | Verify the calendar displays the current period with date headers and any existing shift assignments | Calendar shows correct dates for the current period and any assigned shifts are visible on their respective dates |
| 3 | Click on the employee filter dropdown and select a specific employee from the list | Employee filter is applied and the selected employee name is displayed in the filter field |
| 4 | Click on the date range filter and select a specific start and end date | Date range filter is applied and the selected date range is displayed in the filter field |
| 5 | Click 'Apply Filters' or observe automatic calendar update | Calendar view refreshes and updates to show only the schedules for the selected employee within the specified date range |
| 6 | Click on a shift displayed in the calendar to view its details | Shift details popup or panel appears showing shift name, time, duration, and employee name |
| 7 | Compare the displayed shift details with the assigned schedule data in the system | All shift details (name, time, date, duration, employee) match exactly with the assigned schedules in the database |

**Postconditions:**
- Calendar displays accurate schedule information
- Filters are applied correctly
- Shift details are accessible and accurate
- No data load errors occurred

---

### Test Case: Verify calendar navigation between weeks and months
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Calendar view page is accessible
- Schedule data exists for multiple weeks and months
- Navigation controls (next/previous buttons, view switcher) are available
- System can load calendar data within 3 seconds

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule calendar page and verify the default view is displayed | Calendar view opens showing the current week or month with proper date headers and any existing schedules |
| 2 | Verify the current period indicator shows the correct week or month and year | Period indicator displays accurate current week/month information (e.g., 'Week of Jan 15, 2025' or 'January 2025') |
| 3 | Click the 'Next' navigation button or right arrow to move to the next period | Calendar updates to display the next week or month, period indicator updates accordingly, and schedules for the new period are loaded within 3 seconds |
| 4 | Verify that schedule data for the new period is displayed correctly without errors | All shifts assigned to the new period are visible on their correct dates with accurate details and no loading errors |
| 5 | Click the 'Previous' navigation button or left arrow to move back to the previous period | Calendar updates to display the previous week or month, period indicator updates accordingly, and schedules are loaded correctly |
| 6 | Verify that schedule data for the previous period is displayed correctly without errors | All shifts assigned to the previous period are visible on their correct dates with accurate details and no loading errors |
| 7 | If available, switch between week view and month view using the view toggle | Calendar layout changes to the selected view type (week or month) and displays schedules appropriately for that view |
| 8 | Navigate forward and backward multiple times to test continuous navigation | Calendar navigates smoothly through multiple periods, data loads consistently within 3 seconds, and no errors occur |

**Postconditions:**
- Calendar navigation functions correctly in both directions
- Schedule data loads accurately for all navigated periods
- No data load errors or performance issues
- Period indicator reflects the currently displayed period

---

### Test Case: Validate export functionality of calendar view
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Scheduler role
- Calendar view is displayed with schedule data
- At least one employee has assigned shifts visible in the calendar
- Export functionality is enabled and accessible
- User has permissions to export schedule data
- PDF and Excel export options are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule calendar page and ensure schedules are displayed for the current period | Calendar view is visible with employee schedules displayed on their respective dates |
| 2 | Verify that multiple shifts are visible in the calendar for accurate export testing | Calendar shows multiple shift assignments across different dates and employees |
| 3 | Locate and click the 'Export' button or export icon in the calendar interface | Export options menu or dialog appears showing available export formats (PDF and Excel) |
| 4 | Select 'PDF' from the export format options | System processes the export request and generates a PDF file of the calendar view |
| 5 | Verify the PDF file is downloaded to the default download location | PDF file is successfully downloaded with a meaningful filename (e.g., 'Schedule_Calendar_Jan2025.pdf') |
| 6 | Open the downloaded PDF file using a PDF reader | PDF file opens successfully and displays the calendar layout with all visible schedules |
| 7 | Compare the PDF content with the calendar view on screen to verify accuracy | PDF contains accurate schedule data matching the calendar view including dates, employee names, shift names, and times |
| 8 | Return to the calendar view and click the 'Export' button again | Export options menu appears again |
| 9 | Select 'Excel' from the export format options | System processes the export request and generates an Excel file of the calendar data |
| 10 | Verify the Excel file is downloaded to the default download location | Excel file is successfully downloaded with a meaningful filename (e.g., 'Schedule_Calendar_Jan2025.xlsx') |
| 11 | Open the downloaded Excel file using a spreadsheet application | Excel file opens successfully and displays schedule data in a structured table format with columns for date, employee, shift, and time |
| 12 | Compare the Excel content with the calendar view on screen to verify accuracy and completeness | Excel file contains accurate schedule data matching the calendar view with all shifts, dates, employees, and times correctly represented |

**Postconditions:**
- PDF export file is generated and contains accurate calendar data
- Excel export file is generated and contains accurate schedule data
- Both exported files are accessible and readable
- Original calendar view remains unchanged
- Export functionality completes without errors

---

## Story: As Scheduler, I want to bulk assign shift templates to employees to save time during scheduling
**Story ID:** story-9

### Test Case: Validate successful bulk assignment of shift templates
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least 3 employees exist in the system without conflicting schedules
- At least one shift template is available in the system
- User has access to the bulk assignment page
- Date range for assignment is within valid scheduling period

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the bulk assignment page from the scheduling dashboard | Bulk assignment page loads successfully with employee list and shift template options visible |
| 2 | Select multiple employees (minimum 3) from the employee list by checking their checkboxes | Selected employees are highlighted and selection count is displayed (e.g., '3 employees selected') |
| 3 | Select a shift template from the available shift templates dropdown | Shift template is selected and displayed in the selection field with template details visible |
| 4 | Specify a valid date range by entering start date and end date for the bulk assignment | Date range is accepted and displayed correctly in the date fields without validation errors |
| 5 | Click the 'Submit' or 'Assign' button to initiate the bulk assignment | System processes the request and displays a loading indicator during processing |
| 6 | Wait for the bulk assignment operation to complete | Success confirmation message is displayed with summary showing all assignments were successful (e.g., '3 of 3 employees assigned successfully') |
| 7 | Navigate to the schedule view for the first selected employee | Employee's schedule displays the assigned shift template for the specified date range without conflicts |
| 8 | Navigate to the schedule view for the second selected employee | Employee's schedule displays the assigned shift template for the specified date range without conflicts |
| 9 | Navigate to the schedule view for the third selected employee | Employee's schedule displays the assigned shift template for the specified date range without conflicts |

**Postconditions:**
- All selected employees have the shift template assigned for the specified date range
- No scheduling conflicts exist for any of the assigned employees
- Assignment records are saved in the EmployeeSchedules database
- Audit log contains entries for the bulk assignment operation
- System remains in stable state ready for next operation

---

### Test Case: Verify conflict detection during bulk assignment
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least 3 employees exist in the system
- At least one employee has an existing schedule that will conflict with the bulk assignment
- At least two employees have no conflicting schedules
- At least one shift template is available in the system
- User has access to the bulk assignment page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the bulk assignment page from the scheduling dashboard | Bulk assignment page loads successfully with employee list and shift template options visible |
| 2 | Select multiple employees including at least one employee who has a conflicting schedule for the target date range | All selected employees are highlighted and selection count is displayed correctly |
| 3 | Select a shift template from the available shift templates dropdown | Shift template is selected and displayed in the selection field |
| 4 | Specify a date range that overlaps with the existing schedule of at least one selected employee | Date range is accepted and displayed in the date fields |
| 5 | Click the 'Submit' or 'Assign' button to attempt the bulk assignment | System processes the request and performs conflict validation for all selected employees |
| 6 | Observe the system response after validation completes | System displays a conflict alert or warning message indicating that one or more employees have scheduling conflicts |
| 7 | Review the detailed assignment summary displayed by the system | Summary clearly shows successful assignments and failed assignments separately with employee names and conflict reasons (e.g., '2 of 3 employees assigned successfully, 1 failed due to scheduling conflict') |
| 8 | Verify the failed assignment details in the summary | Failed assignment entry shows the employee name, conflicting date/time, and reason for failure |
| 9 | Navigate to the schedule view for the employee with the conflict | Employee's original schedule remains unchanged and the conflicting shift template was not assigned |
| 10 | Navigate to the schedule view for an employee without conflicts | Employee's schedule displays the newly assigned shift template for the specified date range |

**Postconditions:**
- Employees without conflicts have the shift template assigned successfully
- Employees with conflicts retain their original schedules unchanged
- No conflicting assignments exist in the system
- Assignment summary is logged with details of successful and failed assignments
- Database integrity is maintained with no partial or corrupted data
- System remains in stable state ready for next operation

---

