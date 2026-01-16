# Manual Test Cases

## Story: As Manager, I want to create tasks with detailed descriptions to achieve clear communication of work requirements
**Story ID:** story-1

### Test Case: Validate successful task creation with description
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has proper authentication and authorization
- Task creation page is accessible
- Database connection is active and stable
- Network connectivity is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page by clicking on 'Create Task' button or menu option | Task creation form is displayed with all required fields including task title input field and description input field. Form is properly rendered and ready for input. |
| 2 | Enter valid task title 'Quarterly Report Preparation' in the title field and enter detailed description 'Prepare comprehensive quarterly financial report including revenue analysis, expense breakdown, and forecasts for Q1 2024' in the description field | Both inputs are accepted without any validation errors. Text appears correctly in both fields. No error messages are displayed. Character count updates if present. |
| 3 | Click the 'Submit' or 'Create Task' button to submit the task creation form | Task is successfully saved to the database. A confirmation message is displayed stating 'Task created successfully' or similar. The form either clears for new entry or redirects to task list page. Task appears in the system with correct title and description. |

**Postconditions:**
- New task record exists in the database with correct title and description
- Task is visible in the task management system
- Manager remains logged in and can create additional tasks
- System logs the task creation event with timestamp and creator information

---

### Test Case: Reject task creation with empty description
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 2 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has proper authentication and authorization
- Task creation page is accessible
- Form validation rules are active
- Database connection is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task creation page by clicking on 'Create Task' button or menu option | Task creation form is displayed with all required fields including task title input field and description input field. Form is properly rendered and ready for input. |
| 2 | Enter task title 'Monthly Review Meeting' in the title field but leave the description field completely empty without entering any text | Validation error is displayed for the description field indicating it is required. Error message appears such as 'Description is required' or 'Please enter task description'. The description field may be highlighted in red or with an error indicator. |
| 3 | Attempt to submit the form by clicking the 'Submit' or 'Create Task' button | Form submission is blocked and prevented. Error message is prominently displayed stating 'Description field cannot be empty' or similar validation message. The form remains on the same page without saving any data. Focus may return to the description field. |

**Postconditions:**
- No task record is created in the database
- Manager remains on the task creation page with entered title still visible
- Form is ready for correction and resubmission
- No partial or incomplete data is saved to the system

---

### Test Case: Ensure task creation response time is within SLA
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has proper authentication and authorization
- Task creation page is accessible
- Database connection is active and performing normally
- Network connectivity is stable
- Performance monitoring tool or timer is available to measure response time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Start timer or performance monitoring tool. Submit valid task creation request with title 'System Performance Test Task' and description 'This task is created to validate system performance and response time requirements for task creation operations' by clicking the Submit button | Response is received from the server within 2 seconds. The system processes the request and returns a success response. Timer shows elapsed time of 2 seconds or less. Page updates or confirmation appears within the SLA timeframe. |
| 2 | Verify task is saved in the database by navigating to task list or querying the database directly for the newly created task using task title or timestamp | Task record exists in the database with correct title 'System Performance Test Task' and complete description matching the submitted text. All task attributes are properly saved including creation timestamp and creator information. |
| 3 | Check that confirmation message is displayed to the user on the screen after successful task creation | Confirmation message is shown to the manager stating 'Task created successfully' or similar positive feedback. Message appears within the 2-second SLA window. User interface provides clear visual indication of successful operation. |

**Postconditions:**
- Task is successfully created and stored in database
- Performance metrics confirm operation completed within 2-second SLA
- System remains responsive for subsequent operations
- Performance log records the response time for audit purposes

---

## Story: As Manager, I want to assign tasks to employees to achieve clear responsibility allocation
**Story ID:** story-2

### Test Case: Assign task to active employee successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has proper authorization to assign tasks
- At least one task exists in the system that is unassigned or available for assignment
- At least one active employee exists in the system
- Task assignment page is accessible
- Database connection is active and stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task assignment page by selecting an existing task and clicking 'Assign Task' button or accessing the assignment interface from the task management menu | Assignment form is displayed showing the task details and a dropdown or selection list containing only active employees. The employee list is populated correctly with names and relevant information. Form is properly rendered and ready for selection. |
| 2 | Select an active employee 'John Smith' from the employee dropdown list and confirm the task assignment selection | Selected employee is highlighted or shown in the assignment field. Assignment is accepted without any validation errors. No error messages are displayed. The system validates that the selected employee is active and eligible for task assignment. |
| 3 | Click the 'Submit' or 'Assign Task' button to complete the assignment operation | Confirmation message is displayed stating 'Task successfully assigned to John Smith' or similar success message. Assignment is saved to the database with correct task ID, employee ID, and assignment timestamp. The task status updates to 'Assigned' and shows the assigned employee name. |

**Postconditions:**
- Task assignment record exists in the database linking the task to the selected employee
- Task status is updated to 'Assigned' in the system
- Employee can view the assigned task in their task list
- Manager can see the assignment reflected in task management interface
- System logs the assignment event with timestamp and manager information

---

### Test Case: Prevent assignment to inactive employee
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has proper authorization to assign tasks
- At least one task exists in the system that is available for assignment
- At least one inactive employee exists in the system database
- Task assignment page is accessible
- Employee status validation rules are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task assignment page by selecting an existing task and clicking 'Assign Task' button or accessing the assignment interface | Assignment form is displayed with employee selection dropdown. The form loads correctly and is ready for interaction. |
| 2 | Attempt to locate and select an inactive employee 'Jane Doe' from the employee dropdown list or try to assign task to an inactive employee | Inactive employee 'Jane Doe' is not listed in the employee dropdown as the system filters to show only active employees. If somehow accessible through direct input or manipulation, an error message is displayed stating 'Cannot assign task to inactive employee' or 'Selected employee is not active'. Validation prevents the selection. |
| 3 | If inactive employee was somehow selected, attempt to submit the assignment by clicking the Submit button | Form submission is blocked and prevented. Clear error message is displayed stating 'Task cannot be assigned to inactive employee' or 'Please select an active employee'. No assignment record is created. The form remains on the assignment page for correction. |

**Postconditions:**
- No task assignment record is created in the database
- Task remains unassigned or retains previous assignment status
- Inactive employee does not receive any task assignment
- Manager remains on the assignment page to select a valid active employee
- System maintains data integrity by preventing invalid assignments

---

### Test Case: Verify assignment processing time within SLA
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Manager has proper authorization to assign tasks
- At least one task exists in the system available for assignment
- At least one active employee exists in the system
- Task assignment page is accessible
- Database connection is active and performing normally
- Network connectivity is stable
- Performance monitoring tool or timer is available to measure response time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Start timer or performance monitoring tool. Assign task to valid active employee 'Michael Johnson' by selecting from dropdown and clicking Submit button | Response is received from the server within 2 seconds. The system processes the assignment request and returns a success response. Timer shows elapsed time of 2 seconds or less. Assignment operation completes within the defined SLA timeframe. |
| 2 | Check the database directly or through admin interface for the assignment record by querying with task ID and employee ID | Assignment record exists in the database with correct task ID linked to employee ID 'Michael Johnson'. All assignment attributes are properly saved including assignment timestamp, manager ID who performed the assignment, and task status updated to 'Assigned'. |
| 3 | Confirm that confirmation message is displayed to the manager on the user interface after successful assignment | Confirmation message is shown to the manager stating 'Task successfully assigned to Michael Johnson' or similar positive feedback. Message appears within the 2-second SLA window. User interface provides clear visual indication of successful assignment operation with updated task status. |

**Postconditions:**
- Task is successfully assigned to the employee in the database
- Performance metrics confirm assignment operation completed within 2-second SLA
- Employee can view the newly assigned task in their interface
- System remains responsive for subsequent assignment operations
- Performance log records the response time for audit and monitoring purposes

---

## Story: As Manager, I want to receive confirmation messages after task assignments to achieve assurance of successful operations
**Story ID:** story-5

### Test Case: Display confirmation message after successful assignment
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has permission to assign tasks
- At least one employee exists in the system to assign tasks to
- At least one task is available for assignment
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task assignment page | Task assignment page loads successfully with list of available tasks and employees |
| 2 | Select a task from the available tasks list | Task is highlighted and selected, task details are visible |
| 3 | Select an employee from the employee list to assign the task to | Employee is selected and highlighted in the interface |
| 4 | Click the 'Assign Task' button to complete the assignment | System processes the assignment request and sends it to the server via POST /api/tasks/assign endpoint |
| 5 | Observe the screen for confirmation message | Confirmation message appears within 1 second displaying 'Task successfully assigned' with task title and assignee name clearly visible |
| 6 | Verify the confirmation message contains task title | Task title is displayed correctly in the confirmation message |
| 7 | Verify the confirmation message contains assignee details | Assignee name and relevant details are displayed correctly in the confirmation message |
| 8 | Wait for the message timeout period or click dismiss button if available | Confirmation message disappears automatically after timeout or upon user dismissal action |
| 9 | Verify the task assignment is reflected in the system | Task shows as assigned to the selected employee in the task list |

**Postconditions:**
- Task is successfully assigned to the employee
- Confirmation message has been displayed and dismissed
- Manager can proceed with next task assignment
- No duplicate assignment has been created
- System is ready for next operation

---

### Test Case: Display error message on assignment failure
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has permission to assign tasks
- Task assignment page is accessible
- Network connection is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task assignment page | Task assignment page loads successfully |
| 2 | Attempt to assign a task with invalid data (e.g., select a task but no employee, or use an invalid employee ID) | System attempts to process the assignment request |
| 3 | Click the 'Assign Task' button with invalid data | System validates the input and detects invalid data, assignment fails |
| 4 | Observe the screen for error message | Clear error message is displayed within 1 second explaining why the assignment failed (e.g., 'Assignment failed: Please select an employee' or 'Assignment failed: Invalid employee selected') |
| 5 | Verify the error message is user-friendly and provides actionable information | Error message uses clear language without technical jargon and indicates what needs to be corrected |
| 6 | Correct the invalid data by properly selecting both a valid task and a valid employee | Valid task and employee are selected and highlighted in the interface |
| 7 | Click the 'Assign Task' button again with corrected data | System processes the assignment request successfully |
| 8 | Observe the screen for confirmation message | Success confirmation message is displayed within 1 second showing 'Task successfully assigned' with task title and assignee details |
| 9 | Verify the task assignment is now reflected in the system | Task shows as assigned to the selected employee in the task list |

**Postconditions:**
- Error message was displayed for invalid assignment attempt
- Task is successfully assigned after correction
- Confirmation message was displayed after successful assignment
- No partial or duplicate assignments exist in the system
- System is ready for next operation

---

