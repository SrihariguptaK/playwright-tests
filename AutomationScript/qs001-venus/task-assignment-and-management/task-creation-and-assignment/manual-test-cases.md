# Manual Test Cases

## Story: As Manager, I want to create tasks with detailed information to achieve clear task delegation
**Story ID:** story-11

### Test Case: Validate successful task creation with valid input
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has access to task creation functionality
- At least one employee exists in the system for task assignment
- Database is accessible and operational
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page by clicking on 'Create Task' button or menu option | Task creation form is displayed with all mandatory fields including task title, description, deadline, priority dropdown, and employee selection list |
| 2 | Enter valid task title (e.g., 'Complete Q4 Financial Report') | Task title field accepts the input and displays the entered text without validation errors |
| 3 | Enter valid task description (e.g., 'Prepare comprehensive financial report for Q4 including revenue, expenses, and projections') | Description field accepts the input and displays the entered text without validation errors |
| 4 | Select a future deadline date using the date picker (e.g., 7 days from current date) | Deadline field displays the selected date in the correct format and accepts the future date without validation errors |
| 5 | Select priority level from dropdown (e.g., 'High') | Priority dropdown displays the selected value and accepts the selection without validation errors |
| 6 | Select one or more employees from the employee selection list | Selected employees are highlighted or checked, and the selection is visually confirmed in the interface |
| 7 | Click the 'Submit' or 'Create Task' button to submit the task creation form | System processes the request within 2 seconds, task is created successfully, confirmation message is displayed (e.g., 'Task created successfully'), and notifications are sent to assigned employees |
| 8 | Verify the confirmation message content | Confirmation message includes task title, assigned employees, and success status |
| 9 | Navigate to manager's task list view | Newly created task appears in the task list with all entered details visible |

**Postconditions:**
- Task is saved persistently in the database
- Task appears in manager's task list
- Assigned employees receive task assignment notifications
- Task data is retrievable for future reference
- System returns to stable state ready for next operation

---

### Test Case: Verify rejection of task creation with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has access to task creation functionality
- Task creation form is accessible
- Form validation rules are configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page by clicking on 'Create Task' button or menu option | Task creation form is displayed with all mandatory fields in their initial empty state |
| 2 | Leave the task title field empty (do not enter any text) | Task title field remains empty and may show placeholder text if configured |
| 3 | Leave the deadline field empty (do not select any date) | Deadline field remains empty without any date selected |
| 4 | Optionally enter description and select priority, but keep title and deadline empty | Optional fields accept data, but mandatory fields remain empty |
| 5 | Click outside the empty mandatory fields or tab through them to trigger real-time validation | Real-time validation highlights missing fields with visual indicators (red border, asterisk, or warning icon) and displays inline error messages such as 'Task title is required' and 'Deadline is required' |
| 6 | Attempt to submit the form by clicking the 'Submit' or 'Create Task' button | Form submission is blocked, page does not refresh or navigate away, and inline error messages are displayed for each missing mandatory field (task title and deadline) |
| 7 | Verify error message content and placement | Error messages are clearly visible next to or below the respective empty fields, using clear language indicating which fields are required |
| 8 | Verify that no task is created in the system | No new task appears in the manager's task list and no database entry is created |

**Postconditions:**
- No task is created or saved in the database
- Form remains on the task creation page with entered data preserved
- Error messages are displayed to guide user correction
- No notifications are sent to any employees
- System remains in stable state awaiting valid input

---

### Test Case: Ensure system handles assignment to multiple employees
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has access to task creation functionality
- At least three employees exist in the system for multi-assignment testing
- Notification system is operational
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page | Task creation form is displayed with all required fields |
| 2 | Enter valid task title (e.g., 'Team Project Kickoff Meeting') | Task title field accepts and displays the entered text |
| 3 | Enter valid task description (e.g., 'Attend kickoff meeting for new project initiative') | Description field accepts and displays the entered text |
| 4 | Select a future deadline date (e.g., 3 days from current date) | Deadline field displays the selected date correctly |
| 5 | Select priority level (e.g., 'Medium') | Priority dropdown displays the selected value |
| 6 | Select multiple employees from the employee selection list (e.g., select 3 different employees by checking their checkboxes or using multi-select) | All selected employees are visually indicated as selected (checked, highlighted, or listed), and the count of selected employees is displayed if applicable |
| 7 | Submit the task creation form by clicking 'Submit' or 'Create Task' button | Task is created successfully within 2 seconds, confirmation message is displayed indicating successful creation and assignment to multiple employees |
| 8 | Verify that notifications are sent to each assigned employee by checking notification logs or employee notification inboxes | All assigned employees (all 3 selected) receive task assignment notifications with task details including title, deadline, and priority |
| 9 | Navigate to manager's task list view | Newly created task appears in the task list |
| 10 | Click on or expand the task to view assignment details | Task displays correct assignment details showing all selected employees as assignees, along with task title, description, deadline, and priority |
| 11 | Verify task visibility for each assigned employee by logging in as each employee or checking employee task views | Task appears in each assigned employee's task list with complete and accurate details |

**Postconditions:**
- Task is created and saved in the database with multiple employee assignments
- Task appears in manager's task list with all assignee details
- All assigned employees have received notifications
- Task is visible in each assigned employee's task list
- Assignment relationships are correctly stored in the database
- System is ready for subsequent operations

---

## Story: As Manager, I want to receive confirmation after assigning tasks to achieve assurance of successful delegation
**Story ID:** story-14

### Test Case: Validate confirmation message after successful task assignment
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has access to task assignment functionality
- At least one employee exists in the system for task assignment
- Task history logging is enabled and operational
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation/assignment page | Task assignment form is displayed with all required fields |
| 2 | Fill in all mandatory fields: task title (e.g., 'Prepare Monthly Report'), description (e.g., 'Compile and analyze monthly performance metrics'), deadline (e.g., 5 days from today), priority (e.g., 'High'), and select at least one employee | All fields accept valid input without validation errors |
| 3 | Submit the valid task assignment form by clicking 'Submit' or 'Assign Task' button | System processes the request within 2 seconds and displays a clear confirmation message (e.g., 'Task assigned successfully') with task details visible on screen |
| 4 | Review the confirmation message content displayed on screen | Confirmation message includes all key task details: task title ('Prepare Monthly Report'), deadline date, priority level ('High'), and list of assigned employees with their names |
| 5 | Verify the confirmation message format and clarity | Confirmation message is clearly formatted, easy to read, uses appropriate styling (success color/icon), and all information is accurate and complete |
| 6 | Navigate to task history log or audit trail section | Task history page or section is displayed showing list of task activities |
| 7 | Search or filter for the recently created task in the task history log | Recently assigned task appears in the task history log |
| 8 | Review the task history entry details | Task history entry shows confirmation message is recorded with timestamp, task details (title, deadline, priority, assigned employees), and manager who created the assignment, making it accessible for audit purposes |
| 9 | Verify the timestamp of the confirmation log entry | Timestamp matches the time of task assignment submission (within acceptable system time variance) |

**Postconditions:**
- Confirmation message has been displayed to the manager
- Task assignment is saved in the database
- Confirmation is logged in task history with complete details
- Task history entry is accessible for future audit
- Manager has assurance of successful task delegation
- System is ready for next operation

---

### Test Case: Verify error message display on assignment failure
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has access to task assignment functionality
- System is configured to validate task assignment data
- Test environment allows simulation of assignment failures

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation/assignment page | Task assignment form is displayed with all required fields |
| 2 | Fill in the task assignment form with invalid data (e.g., past deadline date, invalid employee ID, or leave mandatory fields empty) | Form accepts the input without immediate blocking |
| 3 | Submit the task assignment form with invalid data by clicking 'Submit' or 'Assign Task' button | System attempts to process the request and detects the invalid data or assignment failure condition |
| 4 | Observe the system response after submission attempt | Error message is displayed clearly on screen indicating the failure reason (e.g., 'Task assignment failed: Deadline cannot be in the past' or 'Task assignment failed: Selected employee does not exist' or 'Task assignment failed: Missing required fields') |
| 5 | Review the error message content and formatting | Error message is clearly visible, uses appropriate error styling (red color/error icon), provides specific information about what went wrong, and guides the user on how to correct the issue |
| 6 | Verify that no task was created in the system | No new task appears in the manager's task list and no database entry is created |
| 7 | Correct the invalid data based on the error message guidance (e.g., select a future deadline date, select a valid employee, fill in missing mandatory fields) | Form fields accept the corrected valid data without validation errors |
| 8 | Resubmit the task assignment form with corrected valid data by clicking 'Submit' or 'Assign Task' button | System processes the request successfully within 2 seconds |
| 9 | Verify the response after successful resubmission | Submission succeeds, confirmation message is displayed (e.g., 'Task assigned successfully') with complete task details including task title, deadline, priority, and assigned employees |
| 10 | Verify the task now appears in the manager's task list | Newly created task is visible in the task list with all correct details |

**Postconditions:**
- Initial invalid submission was rejected with clear error message
- No task was created from the invalid submission
- After correction, task is successfully created and saved
- Confirmation message is displayed for successful submission
- Task appears in manager's task list
- System demonstrates proper error handling and recovery
- System is in stable state ready for next operation

---

## Story: As Manager, I want to modify task assignments to achieve flexibility in workforce management
**Story ID:** story-18

### Test Case: Validate successful task update with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has authorization to modify task assignments
- At least one task exists in the system with assigned employees
- Task database is accessible and operational
- Notification system is active and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management dashboard and select an existing task to edit | Task edit page loads successfully displaying the task edit form with all current task data populated including title, description, deadline, priority, and assigned employees |
| 2 | Modify the task title to 'Updated Task Title' | Task title field accepts the new value without validation errors |
| 3 | Update the task description to include additional details | Description field accepts the updated text without validation errors |
| 4 | Change the deadline to a valid future date | Deadline field accepts the new date and displays it in the correct format without validation errors |
| 5 | Modify the priority level to a different valid priority value | Priority field accepts the new value and updates the selection without validation errors |
| 6 | Reassign the task by removing one employee and adding a different available employee | Employee assignment fields accept the changes, removed employee is deselected, and new employee is added to the assignment list without validation errors |
| 7 | Click the 'Submit' or 'Update Task' button to save the changes | System processes the update within 2 seconds, task is updated successfully in the database, and a confirmation message is displayed to the manager stating 'Task updated successfully' |
| 8 | Verify that notifications have been sent to affected employees | Notification system confirms that notifications were sent to both the newly assigned employee and the previously assigned employee within 5 seconds of the update |
| 9 | Navigate back to the task list and locate the updated task | Updated task appears in the task list with all modified details reflected correctly including new title, deadline, priority, and reassigned employees |

**Postconditions:**
- Task details are permanently updated in the database
- All affected employees have received notifications about the assignment changes
- Task list displays the updated task information
- Manager remains logged in and can perform additional actions
- System audit log records the task modification with timestamp and manager details

---

### Test Case: Verify rejection of invalid task updates
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has authorization to modify task assignments
- At least one task exists in the system
- Task database is accessible and operational
- Validation rules are configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management dashboard and select an existing task to edit | Task edit page loads successfully displaying the task edit form with current task data |
| 2 | Clear the task title field leaving it empty | Validation error message appears indicating 'Task title is required' or similar error message |
| 3 | Enter a past date in the deadline field (e.g., yesterday's date) | Validation error message appears indicating 'Deadline must be a future date' or similar error message |
| 4 | Enter an invalid priority value or select an option outside the allowed priority range | Validation error message appears indicating 'Invalid priority value' or similar error message |
| 5 | Attempt to remove all assigned employees without adding new ones, leaving the task unassigned | Validation error message appears indicating 'At least one employee must be assigned' or similar error message |
| 6 | Click the 'Submit' or 'Update Task' button while validation errors are present | Form submission is blocked, no data is sent to the server, and all validation error messages remain visible on the screen with clear indication of which fields need correction |
| 7 | Correct the task title by entering a valid title | Validation error for the title field disappears |
| 8 | Correct the deadline by entering a valid future date | Validation error for the deadline field disappears |
| 9 | Select a valid priority value | Validation error for the priority field disappears |
| 10 | Assign at least one valid employee to the task | Validation error for employee assignment disappears and all validation errors are now cleared |
| 11 | Click the 'Submit' or 'Update Task' button after correcting all errors | Form is submitted successfully, task is updated in the database, and confirmation message is displayed |

**Postconditions:**
- Task is only updated after all validation errors are corrected
- Invalid data is not saved to the database
- Manager remains on the task edit page until successful submission
- System maintains data integrity by preventing invalid updates

---

### Test Case: Ensure notifications are sent upon reassignment
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has authorization to modify task assignments
- At least one task exists with one or more employees assigned
- Multiple available employees exist in the system for reassignment
- Notification system is active and functional
- Test employees have valid notification channels configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management dashboard and select an existing task with assigned employees | Task edit page loads successfully displaying current task details and assigned employees |
| 2 | Note the currently assigned employees for reference | Current employee assignments are clearly visible in the form |
| 3 | Remove one or more currently assigned employees from the task | Selected employees are removed from the assignment list |
| 4 | Add one or more different available employees to the task assignment | New employees are successfully added to the assignment list |
| 5 | Click the 'Submit' or 'Update Task' button to save the reassignment | System processes the update within 2 seconds, task reassignment is saved successfully, and confirmation message is displayed stating 'Task updated successfully' |
| 6 | Access the notification system or notification log to verify sent notifications | Notification system shows that notifications were generated for all affected employees within 5 seconds of the update |
| 7 | Verify notification was sent to the newly assigned employee(s) | Notification log confirms that newly assigned employee(s) received a notification indicating they have been assigned to the task, including task details |
| 8 | Verify notification was sent to the previously assigned employee(s) who were removed | Notification log confirms that removed employee(s) received a notification indicating they have been unassigned from the task |
| 9 | Check the content of the notifications to ensure they contain relevant task information | Notifications include task title, description, deadline, priority, and the nature of the assignment change (assigned or unassigned) |
| 10 | Verify the timestamp of notifications to ensure they were sent within the 5-second requirement | All notification timestamps are within 5 seconds of the task update submission time |

**Postconditions:**
- Task reassignment is permanently saved in the database
- All affected employees (both newly assigned and removed) have received appropriate notifications
- Notification delivery is logged in the system
- Task list reflects the updated employee assignments
- Notification delivery time meets the 5-second performance requirement

---

## Story: As Manager, I want to validate task assignments to achieve error-free delegation
**Story ID:** story-19

### Test Case: Validate rejection of task assignment to non-existent employee
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has authorization to create or modify task assignments
- Task assignment form is accessible
- Employee validation system is active and operational
- Database contains valid employee records for comparison

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task assignment form (either create new task or edit existing task) | Task assignment form loads successfully with all required fields including employee assignment field |
| 2 | Fill in valid data for task title, description, deadline, and priority fields | All fields accept the valid data without validation errors |
| 3 | In the employee assignment field, enter a non-existent employee ID (e.g., 'EMP99999' or an ID that does not exist in the system) | System performs real-time validation and displays a validation error message indicating 'Employee does not exist' or 'Invalid employee ID' near the employee assignment field |
| 4 | Verify that the validation error message is clear and descriptive | Error message clearly states the issue, such as 'The selected employee does not exist in the system. Please select a valid employee.' |
| 5 | Attempt to click the 'Submit' or 'Save Task' button while the validation error is present | Form submission is blocked, no data is sent to the server, and the validation error message remains visible with focus on the employee assignment field |
| 6 | Verify that no task record is created or updated in the database | Database query confirms that no new task was created or existing task was not modified |
| 7 | Clear the invalid employee ID and select or enter a valid existing employee ID from the system | Validation error disappears, and the employee assignment field shows the valid employee information |
| 8 | Click the 'Submit' or 'Save Task' button with the valid employee assignment | Form is submitted successfully, task is saved to the database with the valid employee assignment, and confirmation message is displayed |

**Postconditions:**
- Invalid employee assignments are prevented from being saved
- Database maintains data integrity with only valid employee assignments
- Manager receives clear feedback about validation errors
- Task is only saved after valid employee is assigned

---

### Test Case: Validate rejection of past deadline input
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has authorization to create or modify task assignments
- Task assignment form is accessible
- Date validation system is active and operational
- System clock is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task assignment form (either create new task or edit existing task) | Task assignment form loads successfully with all required fields including deadline field |
| 2 | Fill in valid data for task title, description, priority, and employee assignment fields | All fields accept the valid data without validation errors |
| 3 | In the deadline field, enter a past date (e.g., yesterday's date or any date before today) | System performs real-time validation and displays a validation error message indicating 'Deadline must be a future date' or 'Invalid deadline - past dates are not allowed' near the deadline field |
| 4 | Verify that the validation error message is clear and descriptive | Error message clearly states the issue, such as 'Deadline cannot be in the past. Please select a future date.' |
| 5 | Attempt to click the 'Submit' or 'Save Task' button while the validation error is present | Form submission is blocked, no data is sent to the server, and the validation error message remains visible with focus on the deadline field |
| 6 | Verify that no task record is created or updated in the database | Database query confirms that no new task was created or existing task was not modified with the invalid deadline |
| 7 | Test with today's date in the deadline field | System either accepts today's date as valid (if business rules allow same-day deadlines) or displays validation error if only future dates are allowed, based on configured validation rules |
| 8 | Update the deadline field with a valid future date (e.g., tomorrow or any date after today) | Validation error disappears, and the deadline field displays the valid future date in the correct format |
| 9 | Click the 'Submit' or 'Save Task' button with the valid future deadline | Form is submitted successfully, task is saved to the database with the valid deadline, and confirmation message is displayed |

**Postconditions:**
- Invalid past deadlines are prevented from being saved
- Database maintains data integrity with only valid future deadlines
- Manager receives clear feedback about deadline validation errors
- Task is only saved after valid future deadline is entered

---

### Test Case: Ensure real-time validation feedback is delivered promptly
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has authorization to create or modify task assignments
- Task assignment form is accessible
- Real-time validation system is active and operational
- Network connection is stable
- Performance monitoring tools are available to measure response time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task assignment form and prepare a timer or performance monitoring tool to measure validation response time | Task assignment form loads successfully and timer is ready to measure validation feedback latency |
| 2 | Start the timer and enter a non-existent employee ID in the employee assignment field, then stop the timer when validation error appears | Validation error message 'Employee does not exist' appears within 1 second of input, and measured time is recorded |
| 3 | Verify the measured response time is under 1 second | Timer confirms that validation feedback was delivered in less than 1 second (e.g., 0.5-0.9 seconds) |
| 4 | Clear the employee field, start the timer, and enter a past date in the deadline field, then stop the timer when validation error appears | Validation error message 'Deadline must be a future date' appears within 1 second of input, and measured time is recorded |
| 5 | Verify the measured response time is under 1 second | Timer confirms that validation feedback was delivered in less than 1 second |
| 6 | Clear the deadline field, start the timer, and enter an invalid priority value, then stop the timer when validation error appears | Validation error message for invalid priority appears within 1 second of input, and measured time is recorded |
| 7 | Verify the measured response time is under 1 second | Timer confirms that validation feedback was delivered in less than 1 second |
| 8 | Clear the priority field, start the timer, and leave the task title field empty (if required), then stop the timer when validation error appears | Validation error message 'Task title is required' appears within 1 second of losing focus or attempting to proceed, and measured time is recorded |
| 9 | Verify the measured response time is under 1 second | Timer confirms that validation feedback was delivered in less than 1 second |
| 10 | Test multiple invalid inputs simultaneously (e.g., invalid employee, past deadline, and invalid priority) and measure the time for all validation errors to appear | All validation error messages appear within 1 second of input, confirming that multiple validations can be performed concurrently within the performance requirement |
| 11 | Review all measured response times to ensure consistent performance | All validation feedback response times are consistently under 1 second, meeting the performance requirement of validation feedback latency under 1 second |

**Postconditions:**
- Real-time validation system meets the 1-second performance requirement
- All validation errors are displayed promptly to provide immediate feedback
- System performance is documented and meets success metrics
- Manager experience is optimized with fast validation feedback

---

## Story: As Manager, I want to cancel task assignments to achieve flexibility in task management
**Story ID:** story-20

### Test Case: Validate successful task cancellation with reason
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has authorization to cancel tasks
- At least one task exists in the system that is not in completed status
- Task has at least one employee assigned to it
- Network connectivity is stable
- Notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management dashboard | Task management dashboard is displayed with list of tasks |
| 2 | Locate and select a task that is eligible for cancellation (not completed) | Task details are displayed with available actions |
| 3 | Click on the 'Cancel Task' button or option | Cancellation form is displayed with a mandatory reason field |
| 4 | Enter a valid cancellation reason in the text field (e.g., 'Project requirements changed') | Cancellation reason is accepted and displayed in the input field |
| 5 | Click the 'Confirm Cancellation' button | System processes the cancellation request within 2 seconds |
| 6 | Verify the task status has been updated | Task status is updated to 'Cancelled' and cancellation reason is saved in the system |
| 7 | Check for confirmation message on the screen | Success confirmation message is displayed indicating task has been cancelled successfully |
| 8 | Verify notifications were sent to all assigned employees | All assigned employees receive cancellation notifications within 5 seconds containing task details and cancellation reason |
| 9 | Check the task list to confirm the cancelled task reflects the new status | Task appears in the list with 'Cancelled' status and cancellation timestamp |

**Postconditions:**
- Task status is permanently set to 'Cancelled' in the database
- Cancellation reason is stored and associated with the task
- All assigned employees have received cancellation notifications
- Task cancellation is logged in the system audit trail
- Task is no longer available for further status updates except viewing
- Manager remains on the task management dashboard

---

### Test Case: Verify prevention of cancellation for completed tasks
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has authorization to access task management
- At least one task exists in the system with status marked as 'Completed'
- System validation rules for task cancellation are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management dashboard | Task management dashboard is displayed with list of all tasks |
| 2 | Locate and identify a task that has status marked as 'Completed' | Completed task is visible in the task list with 'Completed' status indicator |
| 3 | Select the completed task to view its details | Task details are displayed showing 'Completed' status |
| 4 | Attempt to click on the 'Cancel Task' button or option | System prevents the cancellation action - either the cancel button is disabled/hidden or clicking it triggers validation |
| 5 | Observe the system response to the cancellation attempt | System displays a clear error message such as 'Cannot cancel a task that is already completed' or 'Completed tasks cannot be cancelled' |
| 6 | Verify the task status remains unchanged | Task status remains as 'Completed' with no modifications to the task record |
| 7 | Confirm no notifications were sent to assigned employees | No cancellation notifications are generated or sent to any employees |

**Postconditions:**
- Task status remains 'Completed' without any changes
- No cancellation reason is recorded in the system
- No notifications are sent to assigned employees
- Task data integrity is maintained
- Error message is logged in the system for audit purposes
- Manager remains on the task details or task list page

---

