# Manual Test Cases

## Story: As Performance Manager, I want to configure review cycles to automate performance evaluations
**Story ID:** story-16

### Test Case: Validate successful creation of review cycle
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has role-based access to Review Cycle Configuration
- ReviewCycles table is accessible
- API endpoint POST /api/reviewcycles is operational
- At least one user or group exists in the system for assignment

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Review Cycle Configuration page | Page is displayed with existing cycles listed in a table format, showing cycle names, frequency, duration, and status |
| 2 | Click 'Add Review Cycle' button | Add Review Cycle form is displayed with empty fields for cycle name, frequency, duration, notification settings, and user/group assignment |
| 3 | Enter valid cycle name (e.g., 'Q1 2024 Performance Review') | Cycle name field accepts the input without validation errors |
| 4 | Select frequency from dropdown (e.g., 'Quarterly') | Frequency is selected and displayed in the field |
| 5 | Enter valid duration value (e.g., '30 days') | Duration field accepts the input without validation errors |
| 6 | Configure notification settings by selecting notification schedule (e.g., '7 days before start', '1 day before end') | Notification settings are configured and displayed correctly |
| 7 | Assign review cycle to users or groups by selecting from available list | Selected users or groups are added to the assignment list |
| 8 | Click 'Submit' button to save the review cycle configuration | System validates all inputs, saves the review cycle to ReviewCycles table, and displays success confirmation message with cycle details |
| 9 | Verify the newly created review cycle appears in the list of configured cycles | New review cycle is visible in the table with status 'Active' and all configured parameters displayed correctly |

**Postconditions:**
- Review cycle is saved in ReviewCycles table
- Review cycle status is set to 'Active'
- Assigned users or groups are linked to the review cycle
- System is ready to process notifications based on configured schedule
- API response time is under 2 seconds

---

### Test Case: Reject review cycle creation with invalid frequency
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has role-based access to Review Cycle Configuration
- ReviewCycles table is accessible
- API endpoint POST /api/reviewcycles is operational
- Form validation rules are configured for frequency field

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Review Cycle Configuration page | Page is displayed with existing cycles and 'Add Review Cycle' button visible |
| 2 | Click 'Add Review Cycle' button | Add Review Cycle form is displayed with all required fields empty |
| 3 | Enter valid cycle name (e.g., 'Invalid Frequency Test') | Cycle name field accepts the input |
| 4 | Enter invalid frequency value of zero (0) in the frequency field | Validation error message is displayed: 'Frequency must be a positive value' or similar error text, field is highlighted in red |
| 5 | Attempt to click 'Submit' button | Submission is blocked, form does not submit, error message remains visible, focus returns to frequency field |
| 6 | Clear frequency field and enter negative value (e.g., '-5') | Validation error message is displayed: 'Frequency must be a positive value', field is highlighted in red |
| 7 | Attempt to click 'Submit' button again | Submission is blocked, form does not submit, error message remains visible |
| 8 | Correct the frequency field by entering a valid positive value (e.g., '90 days') | Validation error message disappears, field highlighting is removed, field shows valid state |
| 9 | Complete remaining required fields with valid data and click 'Submit' | Form is submitted successfully, review cycle is created, and confirmation message is displayed |

**Postconditions:**
- No review cycle is created with invalid frequency values
- System maintains data integrity in ReviewCycles table
- User is informed of validation requirements
- Valid review cycle is created only after correction

---

## Story: As Performance Manager, I want to schedule review cycles for employees to ensure timely performance evaluations
**Story ID:** story-17

### Test Case: Validate successful review cycle scheduling
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has role-based access to Review Cycle Scheduling
- At least one review cycle template exists and is active
- ReviewCycleSchedules table is accessible
- API endpoint POST /api/reviewcycles/schedules is operational
- Multiple employees or groups exist in the system for assignment
- No existing scheduling conflicts for selected employees/groups

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Review Cycle Scheduling page | Page is displayed with available review cycle templates listed in a dropdown or selection list, showing template names and frequencies |
| 2 | Select a review cycle template from the available templates (e.g., 'Q1 2024 Performance Review') | Selected template is highlighted, template details (frequency, duration, notification settings) are displayed for reference |
| 3 | Click on 'Select Employees/Groups' button or field | Employee/Group selection interface is displayed with searchable list of available employees and groups |
| 4 | Select multiple employees or groups from the list (e.g., 'Engineering Team', 'John Doe', 'Jane Smith') | Selected employees and groups are added to the assignment list, count of selected items is displayed, selections are accepted without errors |
| 5 | Enter valid start date in the start date field (e.g., '2024-04-01') | Start date is accepted and displayed in correct format, date picker closes |
| 6 | Enter valid end date in the end date field that is after start date (e.g., '2024-04-30') | End date is accepted and displayed in correct format, no validation errors appear |
| 7 | Review the scheduling summary showing template, assignees, and date range | Summary displays all configured details accurately including template name, number of assignees, start date, and end date |
| 8 | Click 'Submit' button to save the schedule | System validates the schedule for conflicts, saves the schedule to ReviewCycleSchedules table, displays success confirmation message with schedule ID and details |
| 9 | Verify the newly created schedule appears in the list of scheduled review cycles | New schedule is visible in the scheduled cycles list with status 'Scheduled', showing template name, assignees count, start date, end date, and status |
| 10 | Verify API response time | System response time is under 2 seconds for the scheduling operation |

**Postconditions:**
- Review cycle schedule is saved in ReviewCycleSchedules table
- Schedule status is set to 'Scheduled'
- All selected employees and groups are linked to the schedule
- Automated notifications are queued based on template settings
- No scheduling conflicts exist
- System is ready to track review completion

---

### Test Case: Reject scheduling with conflicting dates
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has role-based access to Review Cycle Scheduling
- At least one review cycle template exists and is active
- ReviewCycleSchedules table is accessible
- An existing schedule already exists for specific employees/groups with defined date range (e.g., 'Engineering Team' scheduled from '2024-04-01' to '2024-04-30')
- API endpoint POST /api/reviewcycles/schedules is operational
- Date conflict validation is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Review Cycle Scheduling page | Page is displayed with available review cycle templates and existing schedules visible |
| 2 | Select a review cycle template from available templates | Template is selected and details are displayed |
| 3 | Select the same employees or groups that have an existing schedule (e.g., 'Engineering Team') | Employees/groups are selected and added to assignment list |
| 4 | Enter start date that overlaps with existing schedule (e.g., '2024-04-15') | Start date is entered in the field |
| 5 | Enter end date that extends beyond existing schedule (e.g., '2024-05-15') | End date is entered in the field |
| 6 | Click 'Submit' button to attempt scheduling | System detects scheduling conflict, displays validation error message: 'Scheduling conflict detected: Selected employees/groups already have a review cycle scheduled during this period' or similar, submission is blocked, conflicting schedule details are shown |
| 7 | Review the conflict details displayed by the system | Conflict information shows existing schedule dates, affected employees/groups, and existing template name |
| 8 | Adjust start date to non-conflicting date after existing schedule ends (e.g., '2024-05-01') | Start date is updated, validation error message disappears or updates to show no conflict |
| 9 | Adjust end date to valid date after new start date (e.g., '2024-05-31') | End date is updated, no validation errors are displayed |
| 10 | Click 'Submit' button again with corrected dates | System validates successfully with no conflicts, schedule is saved to ReviewCycleSchedules table, success confirmation message is displayed with schedule details |
| 11 | Verify the newly created schedule appears in the list without conflicts | New schedule is visible in the scheduled cycles list with status 'Scheduled', no conflict warnings are present |

**Postconditions:**
- No schedule is created with conflicting dates
- System maintains scheduling integrity in ReviewCycleSchedules table
- User is informed of specific conflict details
- Valid schedule is created only after resolving conflicts
- Both original and new schedules exist without overlap

---

## Story: As Performance Manager, I want to track the status of review cycles to monitor progress and completion
**Story ID:** story-22

### Test Case: Validate accurate display of review cycle statuses
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Performance Manager with valid credentials
- Multiple review cycles exist in the system with different statuses (scheduled, in-progress, completed, overdue)
- User has role-based access permissions to view review cycle statuses
- At least one review cycle is overdue to test alert functionality

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Review Cycle Status page from the main dashboard or navigation menu | Review Cycle Status page loads successfully and displays a list of all review cycles with their respective statuses (scheduled, in-progress, completed, overdue) |
| 2 | Verify that each review cycle in the list shows accurate status information including cycle name, status label, start date, end date, and assigned groups | All review cycles display correct status information matching the actual state in the system. Status labels are clearly visible and color-coded appropriately |
| 3 | Apply filter to show only 'In-Progress' review cycles using the status filter dropdown | List updates immediately to display only review cycles with 'In-Progress' status. Other statuses are filtered out |
| 4 | Apply sorting by date in descending order using the date sort option | List reorders to show review cycles with most recent dates at the top, maintaining the applied status filter |
| 5 | Clear all filters and sort by status in ascending order | All review cycles are displayed again, sorted alphabetically by status (completed, in-progress, overdue, scheduled) |
| 6 | Observe the page for overdue review cycle alerts | Alert notification is displayed prominently for overdue cycles, showing the cycle name, how many days overdue, and a visual indicator (icon or color) |
| 7 | Trigger an overdue condition by waiting for a review cycle to pass its end date or manually adjusting system time (if test environment allows) | System automatically updates the review cycle status to 'Overdue' and displays an alert notification within 1 minute of the condition being met |

**Postconditions:**
- Review cycle statuses remain accurately displayed
- Applied filters and sorting preferences are maintained until cleared by user
- Overdue alerts remain visible until acknowledged or resolved
- System logs the user's access to review cycle status page

---

### Test Case: Verify detailed view of review cycle status
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Performance Manager with valid credentials
- Review Cycle Status page is accessible and loaded
- At least one review cycle exists in the system with complete information
- User has permissions to view detailed review cycle information

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the Review Cycle Status page, identify a review cycle from the list (preferably one with 'In-Progress' status) | Review cycle is visible in the list with basic information displayed (name, status, dates) |
| 2 | Click on the selected review cycle row or details link/button | System navigates to the detailed view page for the selected review cycle |
| 3 | Verify that the detailed view displays comprehensive status information including: cycle name, current status, start date, end date, assigned groups/departments, number of reviews completed, number of reviews pending, and overall progress percentage | All detailed status information is displayed accurately and matches the data from the list view. Information is well-organized and easy to read |
| 4 | Verify that the detailed view shows a breakdown of review statuses by individual reviewers or teams | Detailed breakdown is visible showing which reviewers/teams have completed their reviews and which are pending |
| 5 | Check for any additional information such as comments, notes, or history of status changes | Additional contextual information is displayed if available, including audit trail of status changes with timestamps |
| 6 | Navigate back to the Review Cycle Status list page using the back button or breadcrumb navigation | System returns to the Review Cycle Status list page with previously applied filters and sorting maintained |

**Postconditions:**
- User remains on the Review Cycle Status page or detailed view as appropriate
- No data is modified during the view operation
- System logs the user's access to detailed review cycle information
- Navigation history is preserved for easy return to previous views

---

