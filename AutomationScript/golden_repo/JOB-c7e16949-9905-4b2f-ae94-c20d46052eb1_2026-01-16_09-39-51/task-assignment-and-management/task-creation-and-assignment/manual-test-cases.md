# Manual Test Cases

## Story: As Manager, I want to create tasks with detailed information to achieve clear task delegation
**Story ID:** story-9

### Test Case: Validate successful task creation with valid input
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to create tasks
- At least one employee exists in the system to assign tasks
- Database is accessible and operational
- Task creation page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page by clicking on 'Create Task' button or menu option | Task creation form is displayed with all mandatory fields including task title, description, deadline, priority dropdown, and assignee selection list |
| 2 | Enter valid task title in the title field (e.g., 'Complete Q4 Report') | Task title is accepted and displayed in the input field without any validation errors |
| 3 | Enter valid task description in the description field (e.g., 'Prepare and submit the quarterly financial report including all departmental expenses') | Task description is accepted and displayed in the text area without any validation errors |
| 4 | Select a future deadline date and time using the date/time picker (e.g., current date + 7 days) | Deadline is accepted and displayed in the deadline field without any validation errors |
| 5 | Select priority level from the priority dropdown (e.g., 'High', 'Medium', or 'Low') | Selected priority is displayed in the dropdown field without any validation errors |
| 6 | Select one or more employees from the assignee selection list | Selected employees are highlighted and displayed in the assignee field without any validation errors |
| 7 | Click the 'Submit' or 'Create Task' button to submit the task creation form | Task is created successfully, saved to the database, and a confirmation message is displayed (e.g., 'Task created successfully') with task details including title, assignees, deadline, and priority |

**Postconditions:**
- Task is saved in the database with all entered details
- Task appears in the task list with correct information
- Selected employees are linked to the task as assignees
- Manager remains on confirmation page or is redirected to task list
- System logs the task creation activity

---

### Test Case: Verify rejection of task creation with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to create tasks
- Task creation page is accessible
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page by clicking on 'Create Task' button or menu option | Task creation form is displayed with all mandatory fields including task title, description, deadline, priority, and assignee selection |
| 2 | Leave the task title field empty | Task title field remains empty without any pre-filled data |
| 3 | Leave the task description field empty | Task description field remains empty without any pre-filled data |
| 4 | Leave the deadline field empty without selecting any date | Deadline field remains empty without any default date |
| 5 | Leave the priority field unselected or at default state | Priority field shows no selection or default placeholder |
| 6 | Leave the assignee selection empty without selecting any employee | No employees are selected in the assignee field |
| 7 | Click the 'Submit' or 'Create Task' button to attempt form submission | Validation errors are displayed for each missing mandatory field with clear error messages (e.g., 'Task title is required', 'Description is required', 'Deadline is required', 'Priority is required', 'At least one assignee is required') |
| 8 | Verify that the form submission is blocked | Form is not submitted, no task is created in the database, and user remains on the task creation page with validation errors visible |
| 9 | Fill in one mandatory field (e.g., task title) and attempt to submit again | Validation errors are still displayed for remaining empty mandatory fields, and submission is blocked until all mandatory fields are completed |

**Postconditions:**
- No task is created in the database
- User remains on the task creation page
- All validation error messages are visible
- Form data entered by user is retained (not cleared)
- No system errors or crashes occur

---

### Test Case: Test validation for deadline in the past
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to create tasks
- Task creation page is accessible
- System date and time are correctly configured
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page by clicking on 'Create Task' button or menu option | Task creation form is displayed with all fields including the deadline date/time picker |
| 2 | Enter valid data in task title field (e.g., 'Review Documentation') | Task title is accepted and displayed in the input field |
| 3 | Enter valid data in task description field (e.g., 'Review and update project documentation') | Task description is accepted and displayed in the text area |
| 4 | Select a priority level from the priority dropdown (e.g., 'Medium') | Selected priority is displayed in the dropdown field |
| 5 | Select at least one employee from the assignee selection list | Selected employee is highlighted and displayed in the assignee field |
| 6 | Enter or select a deadline date/time that is in the past (e.g., yesterday's date or current date with past time) | Validation error message is displayed immediately or upon field blur indicating invalid deadline (e.g., 'Deadline cannot be in the past' or 'Please select a future date and time') |
| 7 | Click the 'Submit' or 'Create Task' button to attempt form submission with past deadline | Form submission is blocked, validation error message is prominently displayed for the deadline field, and no task is created |
| 8 | Correct the deadline by selecting a future date and time (e.g., current date + 3 days) | Validation error message disappears, deadline field shows the valid future date/time, and no validation errors are displayed |
| 9 | Click the 'Submit' or 'Create Task' button again with corrected deadline | Form is submitted successfully, task is created, and confirmation message is displayed |

**Postconditions:**
- No task is created with past deadline
- Task is successfully created only after deadline is corrected to future date
- Final task in database has valid future deadline
- User receives appropriate feedback for both error and success states
- System maintains data integrity by preventing invalid deadline entries

---

## Story: As Manager, I want to assign tasks to multiple employees to achieve efficient workload distribution
**Story ID:** story-10

### Test Case: Validate task creation with multiple assignees
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to create and assign tasks
- At least three employees exist in the system for multi-selection testing
- Task creation page supports multi-select functionality for assignees
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page by clicking on 'Create Task' button or menu option | Task creation form is displayed with all fields including a multi-select assignee field showing list of available employees |
| 2 | Enter valid task title in the title field (e.g., 'Team Training Session') | Task title is accepted and displayed in the input field |
| 3 | Enter valid task description in the description field (e.g., 'Attend mandatory safety training session') | Task description is accepted and displayed in the text area |
| 4 | Select a future deadline date and time using the date/time picker | Deadline is accepted and displayed in the deadline field |
| 5 | Select priority level from the priority dropdown (e.g., 'High') | Selected priority is displayed in the dropdown field |
| 6 | Select the first employee from the assignee list by clicking or checking the selection box | First employee is highlighted/checked and displayed in the selected assignees area |
| 7 | Select the second employee from the assignee list by clicking or checking the selection box | Second employee is highlighted/checked and both selected employees are displayed in the selected assignees area |
| 8 | Select the third employee from the assignee list by clicking or checking the selection box | Third employee is highlighted/checked and all three selected employees are displayed correctly in the selected assignees area with their names visible |
| 9 | Verify that all selected employees are visible in the assignee display area | All three selected employees are clearly displayed with their names, and the count of assignees is accurate |
| 10 | Click the 'Submit' or 'Create Task' button to submit the task creation form | Task is created successfully with all three assignees linked, and a confirmation message is displayed listing all assigned employees (e.g., 'Task created successfully and assigned to: Employee1, Employee2, Employee3') |
| 11 | Verify the task details in the confirmation message or task list | Task appears with all three assignees correctly linked and displayed in the task details |

**Postconditions:**
- Task is saved in the database with all entered details
- All three selected employees are correctly linked to the task in the database
- Task appears in the task list showing multiple assignees
- Each assigned employee has the task associated with their account
- Confirmation message displays all assignee names
- System logs the task creation with multiple assignees

---

### Test Case: Verify validation error when no assignee selected
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to create tasks
- At least one employee exists in the system
- Task creation page is accessible
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page by clicking on 'Create Task' button or menu option | Task creation form is displayed with all fields including the assignee selection field showing list of available employees |
| 2 | Enter valid task title in the title field (e.g., 'Database Backup') | Task title is accepted and displayed in the input field |
| 3 | Enter valid task description in the description field (e.g., 'Perform weekly database backup and verification') | Task description is accepted and displayed in the text area |
| 4 | Select a future deadline date and time using the date/time picker | Deadline is accepted and displayed in the deadline field |
| 5 | Select priority level from the priority dropdown (e.g., 'Medium') | Selected priority is displayed in the dropdown field |
| 6 | Verify that no employee is selected in the assignee field (leave assignee selection empty) | Assignee field shows no selected employees, selection area is empty or shows placeholder text |
| 7 | Click the 'Submit' or 'Create Task' button to attempt form submission without selecting any assignee | Validation error message is displayed indicating that at least one assignee is required (e.g., 'Please select at least one assignee' or 'Assignee is required') |
| 8 | Verify that the form submission is blocked | Form is not submitted, no task is created in the database, and user remains on the task creation page with the validation error visible |
| 9 | Select one employee from the assignee list by clicking or checking the selection box | Selected employee is highlighted/checked and displayed in the selected assignees area, validation error message disappears |
| 10 | Click the 'Submit' or 'Create Task' button again to resubmit the form with an assignee selected | Form submits successfully, task is created with the selected assignee, and confirmation message is displayed |

**Postconditions:**
- No task is created when no assignee is selected
- Task is successfully created only after at least one assignee is selected
- Final task in database has at least one assignee linked
- User receives appropriate validation feedback
- System maintains data integrity by enforcing assignee requirement
- All other entered form data is retained during validation error state

---

