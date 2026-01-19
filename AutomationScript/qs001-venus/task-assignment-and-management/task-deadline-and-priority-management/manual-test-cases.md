# Manual Test Cases

## Story: As Manager, I want to assign deadlines to tasks to achieve timely completion
**Story ID:** story-12

### Test Case: Validate successful deadline assignment with future date
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role
- At least one task exists in the system
- Task is accessible to the manager
- System time is synchronized and accurate
- At least one employee is assigned to the task

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management page and select an existing task | Task details page is displayed with task information |
| 2 | Click on the deadline update or edit button | Deadline input form is displayed with date and time picker fields |
| 3 | Enter a valid future date (e.g., 7 days from current date) in the date field | Date is accepted and displayed in the date field without validation errors |
| 4 | Enter a valid future time in the time field | Time is accepted and displayed in the time field without validation errors |
| 5 | Click the Submit or Save button to save the deadline update | System processes the request and displays a loading indicator |
| 6 | Observe the response after submission | Deadline is saved successfully, confirmation message is displayed to the manager (e.g., 'Deadline updated successfully'), and response time is under 2 seconds |
| 7 | Verify the task details page shows the updated deadline | Task details display the newly assigned deadline date and time correctly |
| 8 | Check the notification system for assigned employees | All assigned employees receive notifications about the deadline assignment |

**Postconditions:**
- Deadline is persistently saved in the task database
- Task details reflect the updated deadline
- Notifications are sent to all assigned employees
- Manager receives confirmation of successful update
- Task status remains unchanged unless modified

---

### Test Case: Verify rejection of past date deadline assignment
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Manager role
- At least one task exists in the system
- Task is accessible to the manager
- System time is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management page and select an existing task | Task details page is displayed with task information |
| 2 | Click on the deadline update or edit button | Deadline input form is displayed with date and time picker fields |
| 3 | Enter a past date (e.g., yesterday's date) in the date field | Date is entered in the field |
| 4 | Enter a time in the time field | Time is entered in the field |
| 5 | Observe the validation behavior after entering the past date | Validation error is displayed indicating that the deadline cannot be in the past (e.g., 'Deadline must be a future date and time') |
| 6 | Attempt to click the Submit or Save button | Submission is blocked and the form does not submit; error message remains visible |
| 7 | Clear the past date and enter a valid future date and time | Validation error disappears and input is accepted without errors |
| 8 | Click the Submit or Save button with valid future date | Form submits successfully and confirmation message is displayed |

**Postconditions:**
- No deadline is saved when past date is entered
- Task deadline remains unchanged from previous valid value or remains empty
- No notifications are sent to employees for invalid submission
- System maintains data integrity by preventing invalid deadline values

---

### Test Case: Ensure notifications are sent upon deadline update
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role
- At least one task exists with multiple employees assigned
- Task is accessible to the manager
- Notification system is operational
- Assigned employees have valid notification settings enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management page and select a task that has employees assigned | Task details page is displayed showing assigned employees |
| 2 | Click on the deadline update or edit button | Deadline input form is displayed |
| 3 | Enter a valid future date and time for the deadline | Date and time are accepted without validation errors |
| 4 | Click the Submit or Save button to update the deadline | System processes the request and displays a loading indicator |
| 5 | Observe the confirmation message displayed to the manager | Deadline update is saved successfully and confirmation message is displayed (e.g., 'Deadline updated successfully and notifications sent') |
| 6 | Access the notification system or notification logs | Notification system shows records of notifications being sent |
| 7 | Verify that all assigned employees received the deadline update notification | All assigned employees have received notifications containing the updated deadline information |
| 8 | Check the notification content for accuracy | Notification includes task name, updated deadline date and time, and manager who made the update |
| 9 | Verify the manager sees the confirmation message on the task page | Manager sees confirmation of successful update with indication that notifications were sent |

**Postconditions:**
- Deadline is saved in the database
- All assigned employees have received notifications
- Notification delivery rate meets 95% success metric
- Manager has confirmation of successful operation
- Notification logs are updated with delivery status

---

## Story: As Manager, I want to set task priority levels to achieve effective task scheduling
**Story ID:** story-13

### Test Case: Validate successful priority assignment with valid value
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role
- At least one task exists in the system
- Task is accessible to the manager
- Priority levels are predefined in the system (High, Medium, Low)
- At least one employee is assigned to the task

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management page and select an existing task | Task details page is displayed with task information |
| 2 | Click on the priority update or edit button | Priority selection form is displayed with a dropdown containing predefined priority levels (High, Medium, Low) |
| 3 | Click on the priority dropdown to view available options | Dropdown expands showing all predefined priority levels: High, Medium, and Low |
| 4 | Select 'High' priority level from the dropdown | Selection is accepted, 'High' is displayed in the dropdown field, and no validation errors appear |
| 5 | Click the Submit or Save button to save the priority update | System processes the request and displays a loading indicator |
| 6 | Observe the response after submission | Priority is saved successfully, confirmation message is displayed to the manager (e.g., 'Priority updated successfully'), and response time is under 2 seconds |
| 7 | Verify the task details page shows the updated priority | Task details display the newly assigned priority level 'High' correctly with appropriate visual indicator |
| 8 | Check the notification system for assigned employees | All assigned employees receive notifications about the priority update |

**Postconditions:**
- Priority is persistently saved in the task database
- Task details reflect the updated priority level
- Notifications are sent to all assigned employees
- Manager receives confirmation of successful update
- Task priority is visible in task lists and detail views

---

### Test Case: Verify rejection of invalid priority values
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Manager role
- At least one task exists in the system
- Task is accessible to the manager
- System has validation rules for priority values

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management page and select an existing task | Task details page is displayed with task information |
| 2 | Click on the priority update or edit button | Priority selection form is displayed with dropdown field |
| 3 | Attempt to manually enter an invalid priority value (e.g., 'Critical' or 'Urgent') if the field allows text input, or inspect the dropdown for invalid options | If text input is possible, invalid value is entered; if dropdown only, no invalid options are available |
| 4 | If invalid value was entered, observe the validation behavior | Validation error is displayed indicating that the priority value is invalid (e.g., 'Please select a valid priority level: High, Medium, or Low') |
| 5 | Attempt to click the Submit or Save button with invalid priority | Submission is blocked and the form does not submit; error message remains visible |
| 6 | Clear the invalid value and select a valid priority level from the dropdown (e.g., 'Medium') | Validation error disappears and selection is accepted without errors |
| 7 | Click the Submit or Save button with valid priority selection | Form submits successfully and confirmation message is displayed |

**Postconditions:**
- No priority is saved when invalid value is entered
- Task priority remains unchanged from previous valid value or remains empty
- No notifications are sent to employees for invalid submission
- System maintains data integrity by preventing invalid priority values
- Validation rules are enforced at 100% rate

---

### Test Case: Ensure notifications are sent upon priority update
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role
- At least one task exists with multiple employees assigned
- Task is accessible to the manager
- Notification system is operational
- Assigned employees have valid notification settings enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management page and select a task that has employees assigned | Task details page is displayed showing assigned employees |
| 2 | Click on the priority update or edit button | Priority selection form is displayed with dropdown field |
| 3 | Select a valid priority level from the dropdown (e.g., 'High') | Priority level is selected and displayed without validation errors |
| 4 | Click the Submit or Save button to update the priority | System processes the request and displays a loading indicator |
| 5 | Observe the confirmation message displayed to the manager | Priority update is saved successfully and confirmation message is displayed (e.g., 'Priority updated successfully and notifications sent') |
| 6 | Access the notification system or notification logs | Notification system shows records of notifications being sent |
| 7 | Verify that all assigned employees received the priority update notification | All assigned employees have received notifications containing the updated priority information |
| 8 | Check the notification content for accuracy | Notification includes task name, updated priority level, and manager who made the update |
| 9 | Verify the manager sees the confirmation message on the task page | Manager sees confirmation of successful update with indication that notifications were sent |

**Postconditions:**
- Priority is saved in the database
- All assigned employees have received notifications
- Notification delivery rate meets 95% success metric
- Manager has confirmation of successful operation
- Notification logs are updated with delivery status
- Task priority is visible in task lists with updated value

---

