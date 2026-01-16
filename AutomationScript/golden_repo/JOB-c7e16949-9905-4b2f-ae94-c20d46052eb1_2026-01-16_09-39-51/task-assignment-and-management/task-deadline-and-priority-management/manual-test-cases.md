# Manual Test Cases

## Story: As Manager, I want to set task deadlines to achieve timely task completion
**Story ID:** story-11

### Test Case: Validate setting a valid future deadline
- **ID:** tc-011-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role
- User has permission to create tasks
- Task creation page is accessible
- System time is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page | Task creation form is displayed with all required fields including deadline date and time input fields |
| 2 | Enter a valid future date/time as deadline (e.g., tomorrow's date at 5:00 PM) | The deadline field accepts the input, displays the entered date/time correctly, and no validation errors are shown |
| 3 | Fill in other required task fields (task name, description, assignee) | All fields accept valid input without errors |
| 4 | Submit the form by clicking the Create/Save button | Task is created successfully, confirmation message is displayed, and user is redirected to task details or task list page |
| 5 | Verify the deadline is displayed in the task details view | The specified deadline date and time is correctly displayed in the task details section |
| 6 | Navigate to the task list view | The newly created task appears in the list with the deadline visible and correctly formatted |

**Postconditions:**
- Task is successfully created in the system
- Deadline is stored in the database with correct future date/time
- Deadline is visible to all authorized users in task views
- Task can be edited or deleted by authorized users

---

### Test Case: Verify rejection of past deadline
- **ID:** tc-011-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role
- User has permission to create tasks
- Task creation page is accessible
- System time is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page | Task creation form is displayed with all required fields including deadline date and time input fields |
| 2 | Enter a past date/time as deadline (e.g., yesterday's date or earlier today) | Validation error message is displayed indicating that deadline cannot be in the past (e.g., 'Deadline must be a future date and time') |
| 3 | Fill in other required task fields (task name, description, assignee) | All other fields accept valid input, but deadline validation error remains visible |
| 4 | Attempt to submit the form by clicking the Create/Save button | Submission is blocked, form is not submitted, error message remains visible or is highlighted, and user remains on the task creation page |
| 5 | Correct the deadline by entering a valid future date/time | Validation error message disappears, deadline field shows valid state |
| 6 | Submit the form again | Task is created successfully with the corrected deadline |

**Postconditions:**
- No task is created with past deadline
- System maintains data integrity by preventing invalid deadline entries
- User understands the validation requirement through clear error messaging
- After correction, task is successfully created with valid deadline

---

### Test Case: Validate modifying deadline with valid future date
- **ID:** tc-011-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role
- User has permission to edit tasks
- At least one task exists in the system with a deadline
- Task edit page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to an existing task and open the task edit page | Task edit form is displayed with current task details including the existing deadline |
| 2 | Modify the deadline to a different valid future date/time | The deadline field accepts the new input, displays the updated date/time correctly, and no validation errors are shown |
| 3 | Submit the form by clicking the Update/Save button | Task is updated successfully, confirmation message is displayed, and the modified deadline is saved |
| 4 | Verify the updated deadline in task details view | The new deadline date and time is correctly displayed, replacing the previous deadline |
| 5 | Check the task list view | The updated deadline is reflected in the task list with correct formatting |

**Postconditions:**
- Task deadline is successfully updated in the system
- Previous deadline is replaced with the new valid deadline
- Updated deadline is visible to all authorized users
- Task modification is logged in system audit trail

---

### Test Case: Verify rejection of past deadline during task modification
- **ID:** tc-011-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Manager role
- User has permission to edit tasks
- At least one task exists in the system with a deadline
- Task edit page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to an existing task and open the task edit page | Task edit form is displayed with current task details including the existing deadline |
| 2 | Modify the deadline to a past date/time | Validation error message is displayed indicating that deadline cannot be in the past |
| 3 | Attempt to submit the form by clicking the Update/Save button | Submission is blocked, form is not submitted, error message remains visible, and user remains on the task edit page |
| 4 | Verify that the original deadline remains unchanged in the database | Task retains its original deadline, no changes are persisted |

**Postconditions:**
- Task deadline remains unchanged
- System prevents invalid deadline modification
- Data integrity is maintained
- User receives clear feedback about validation failure

---

## Story: As Manager, I want to assign priority levels to tasks to achieve effective task prioritization
**Story ID:** story-12

### Test Case: Validate selection of valid priority levels
- **ID:** tc-012-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Manager role
- User has permission to create tasks
- Task creation page is accessible
- Priority dropdown contains predefined values: Low, Medium, High

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page | Task creation form is displayed with all required fields including a priority dropdown field |
| 2 | Click on the priority dropdown to view available options | Dropdown expands and displays all allowed priority levels: Low, Medium, and High |
| 3 | Select 'Low' priority from the dropdown | Low priority is selected and displayed in the dropdown field without any validation errors |
| 4 | Fill in other required task fields (task name, description, assignee, deadline) | All fields accept valid input without errors |
| 5 | Submit the form by clicking the Create/Save button | Task is created successfully with Low priority, confirmation message is displayed |
| 6 | Verify the priority is displayed in task details view | Task details page shows 'Low' priority clearly with appropriate visual indicator (color, icon, or label) |
| 7 | Navigate back to task creation page and create another task with 'Medium' priority | Task is created successfully with Medium priority displayed correctly in task details and list |
| 8 | Create a third task with 'High' priority | Task is created successfully with High priority displayed correctly in task details and list |
| 9 | Navigate to task list view and verify all three tasks | All tasks are displayed in the list with their respective priority levels (Low, Medium, High) clearly visible and correctly formatted |

**Postconditions:**
- Three tasks are successfully created with different priority levels
- Each priority level is correctly stored in the database
- Priority levels are visible in both task details and list views
- Priority indicators are displayed consistently across all views

---

### Test Case: Verify rejection of invalid priority values
- **ID:** tc-012-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Manager role
- User has API access credentials or testing tool configured
- API endpoint POST /api/tasks is accessible
- Valid authentication token is available
- API testing tool (Postman, curl, or similar) is set up

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare API request payload with valid task data but invalid priority value (e.g., 'Critical', 'Urgent', or numeric value like '1') | API request payload is properly formatted with invalid priority value |
| 2 | Send POST request to /api/tasks endpoint with the invalid priority value | API returns HTTP 400 Bad Request status code |
| 3 | Examine the API response body | Response contains validation error message indicating that priority value is invalid and lists allowed values (Low, Medium, High) |
| 4 | Verify that no task was created in the database | Task list or database query confirms no new task was created with invalid priority |
| 5 | Attempt API request with empty priority value | API returns validation error indicating priority is required or defaults to a valid value based on business rules |
| 6 | Attempt API request with null priority value | API returns validation error or handles null appropriately according to business rules |
| 7 | Send API request with valid priority value (e.g., 'High') to confirm API is functioning | API returns HTTP 201 Created status, task is created successfully with valid priority |

**Postconditions:**
- No tasks are created with invalid priority values
- API validation prevents data integrity issues
- System maintains only allowed priority values in database
- Error messages provide clear guidance on valid priority values

---

### Test Case: Validate updating task priority with valid values
- **ID:** tc-012-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role
- User has permission to edit tasks
- At least one task exists in the system with an assigned priority
- Task edit page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to an existing task with 'Low' priority and open the task edit page | Task edit form is displayed with current task details showing 'Low' priority selected in the dropdown |
| 2 | Click on the priority dropdown | Dropdown expands showing all priority options (Low, Medium, High) with 'Low' currently selected |
| 3 | Change the priority from 'Low' to 'High' | High priority is selected in the dropdown without validation errors |
| 4 | Submit the form by clicking the Update/Save button | Task is updated successfully, confirmation message is displayed, and priority change is saved |
| 5 | Verify the updated priority in task details view | Task details page now shows 'High' priority with appropriate visual indicator, replacing the previous 'Low' priority |
| 6 | Navigate to task list view | The updated task displays 'High' priority in the list view with correct formatting and visual indicator |
| 7 | Edit the same task again and change priority to 'Medium' | Priority is successfully updated to 'Medium' and displayed correctly in all views |

**Postconditions:**
- Task priority is successfully updated in the system
- Previous priority value is replaced with the new valid priority
- Updated priority is visible to all authorized users in all views
- Priority change is reflected immediately without requiring page refresh

---

## Story: As Manager, I want to view tasks sorted by priority and deadline to achieve better workload planning
**Story ID:** story-15

### Test Case: Validate sorting tasks by priority
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to view tasks
- Task database contains multiple tasks with varying priorities (High, Medium, Low)
- At least 10 tasks exist in the system for meaningful sorting validation
- Browser is supported and JavaScript is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task list page by clicking on 'Tasks' menu item or accessing the task list URL | Task list page loads successfully within 3 seconds, displaying all tasks with their priority levels visible |
| 2 | Locate the sorting options dropdown or button and select 'Sort by Priority' option | System processes the sorting request and tasks are reordered from High to Low priority (High priority tasks appear first, followed by Medium, then Low) |
| 3 | Verify the task order by examining the priority column or labels for each task in the displayed list | All High priority tasks are grouped at the top, followed by all Medium priority tasks, then all Low priority tasks. No tasks are out of sequence within their priority groups |
| 4 | Scroll through the entire task list to confirm consistent sorting throughout | Priority sorting is maintained throughout the entire list with no exceptions or errors |

**Postconditions:**
- Task list remains sorted by priority
- Sorting preference is persisted for the manager's session
- No data is modified or lost
- System performance remains within acceptable limits

---

### Test Case: Validate filtering tasks by assignee
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to view and filter tasks
- Multiple tasks exist in the system assigned to different employees
- At least one employee has multiple tasks assigned
- Employee assignee list is populated and accessible
- Browser is supported and JavaScript is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task list page by clicking on 'Tasks' menu item or accessing the task list URL | Task list page loads successfully within 3 seconds, displaying all tasks with assignee information visible |
| 2 | Locate the filter options section and click on the 'Filter by Assignee' dropdown or filter control | Assignee filter dropdown opens displaying a list of all employees who have tasks assigned to them |
| 3 | Select a specific employee from the assignee dropdown list | System applies the filter and task list updates immediately to show only tasks assigned to the selected employee |
| 4 | Verify that all displayed tasks show the selected employee as the assignee | All tasks in the filtered list display the selected employee's name in the assignee field. No tasks assigned to other employees are visible |
| 5 | Check the task count or summary information to confirm the number of filtered tasks | Task count reflects only the filtered tasks and matches the actual number of tasks displayed for the selected assignee |

**Postconditions:**
- Task list displays only filtered results
- Filter preference is persisted for the manager's session
- Original task data remains unchanged
- Filter can be cleared to return to full task list view
- System performance remains within acceptable limits

---

## Story: As Manager, I want to modify task deadlines and priorities to adapt to changing project needs
**Story ID:** story-16

### Test Case: Validate successful update of deadline and priority
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to edit tasks
- At least one task exists in the system that can be edited
- Task has an assignee configured
- Notification system is operational
- Current date and time are known for validation purposes
- Browser is supported and JavaScript is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task list page and locate a specific task to edit | Task list page displays with all tasks visible and accessible |
| 2 | Click on the task or select the 'Edit' button/icon for the chosen task | Task edit form is displayed showing current task details including existing deadline and priority values |
| 3 | Modify the deadline field by selecting a valid future date (at least 1 day from current date) | Date picker allows selection of future date and the field updates with the new date value. No validation errors are displayed |
| 4 | Modify the priority field by selecting a different valid priority level (High, Medium, or Low) | Priority dropdown allows selection and the field updates with the new priority value. No validation errors are displayed |
| 5 | Click the 'Save' or 'Submit' button to save the changes | Form submits successfully, processing completes within 2 seconds, and a success message is displayed confirming the task has been updated |
| 6 | Verify the task details in the task list or task detail view reflect the updated deadline and priority | Task displays the new deadline and priority values correctly in all views |
| 7 | Check that a notification was sent to the task assignee (verify in notification log or assignee's notification inbox) | Notification is successfully sent to the assignee informing them of the task updates, including the new deadline and priority |

**Postconditions:**
- Task deadline and priority are updated in the database
- Updated values are reflected in all task views
- Assignee has received notification of changes
- Task modification is logged in audit trail
- No data corruption or loss occurred
- System remains stable and responsive

---

### Test Case: Verify rejection of invalid deadline during edit
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to edit tasks
- At least one task exists in the system that can be edited
- Current date and time are known for validation purposes
- Client-side and server-side validation are enabled
- Browser is supported and JavaScript is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task list page and locate a specific task to edit | Task list page displays with all tasks visible and accessible |
| 2 | Click on the task or select the 'Edit' button/icon for the chosen task | Task edit form is displayed showing current task details including the deadline field |
| 3 | Modify the deadline field by selecting or entering a past date (any date before the current date) | Date field updates with the past date value |
| 4 | Click outside the deadline field or tab to the next field to trigger validation | Validation error message is displayed near the deadline field indicating 'Deadline cannot be set to a past date' or similar error message. The field may be highlighted in red or with an error indicator |
| 5 | Attempt to submit the form by clicking the 'Save' or 'Submit' button | Form submission is blocked and prevented. Error message remains visible or is re-displayed. Focus may return to the invalid deadline field. No data is saved to the database |
| 6 | Verify that the task retains its original deadline value by canceling the edit or checking the task details | Original task deadline remains unchanged in the database and task views. No updates were applied |

**Postconditions:**
- Task deadline remains unchanged with original value
- No invalid data is saved to the database
- Error message is clearly communicated to the user
- Form remains in edit mode allowing correction
- No notifications are sent to assignees
- System remains stable with no errors logged

---

