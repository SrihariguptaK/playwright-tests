# Manual Test Cases

## Story: As Manager, I want to set deadlines for tasks to achieve timely completion
**Story ID:** story-3

### Test Case: Set valid future deadline successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Manager with valid credentials
- Manager has authorization to set task deadlines
- At least one task exists in the system that requires a deadline
- Task deadline setting interface is accessible
- System date and time are correctly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task deadline setting page | Deadline input form is displayed with date and time input fields |
| 2 | Enter a valid future date and time (e.g., 7 days from current date at 5:00 PM) | Input is accepted without errors, date and time fields show the entered values |
| 3 | Submit deadline by clicking the submit button | Deadline is saved successfully and confirmation message is displayed to the manager |
| 4 | Verify the deadline is stored in the database | Database query shows the deadline is correctly saved with the entered date and time |
| 5 | Check that notification is triggered for the assigned employee | System logs show notification event was triggered for the employee |

**Postconditions:**
- Deadline is successfully saved in the task table
- Confirmation message is displayed to the manager
- Notification is sent to the assigned employee
- Task status reflects the new deadline
- Audit log records the deadline setting action

---

### Test Case: Reject past date as deadline
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Manager with valid credentials
- Manager has authorization to set task deadlines
- At least one task exists in the system that requires a deadline
- Task deadline setting interface is accessible
- System date and time are correctly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to deadline setting page | Deadline input form is displayed with date and time input fields |
| 2 | Enter a past date (e.g., yesterday's date at 3:00 PM) | Validation error is displayed indicating that past dates cannot be set as deadlines |
| 3 | Attempt to submit deadline by clicking the submit button | Submission is blocked and error message is displayed: 'Deadline must be a future date' |
| 4 | Verify that no deadline is saved in the database | Database query confirms no new deadline entry was created |
| 5 | Verify that no notification is triggered | System logs show no notification event was triggered |

**Postconditions:**
- No deadline is saved in the database
- Error message is displayed to the manager
- No notification is sent to the employee
- Task remains in its previous state without deadline changes
- Form remains on the deadline setting page for correction

---

### Test Case: Verify deadline update processing time
- **ID:** tc-003
- **Type:** boundary
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as a Manager with valid credentials
- Manager has authorization to update task deadlines
- A task with an existing deadline is available in the system
- Task deadline update interface is accessible
- System date and time are correctly configured
- Performance monitoring tools are available to measure response time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task with existing deadline and open deadline update interface | Deadline update form is displayed with current deadline pre-populated |
| 2 | Update deadline with a valid future date (e.g., 10 days from current date at 2:00 PM) and note the timestamp before submission | New deadline value is entered successfully in the input fields |
| 3 | Submit the updated deadline and measure response time | Response is received within 2 seconds and confirmation message is displayed |
| 4 | Check database for updated deadline immediately after submission | Database query shows the deadline is updated correctly with the new date and time |
| 5 | Confirm confirmation message display to manager | Success message is shown to manager indicating deadline was updated successfully |
| 6 | Verify notification trigger for the employee | System logs confirm notification event was triggered for deadline change |

**Postconditions:**
- Deadline is successfully updated in the task table
- Update processing completed within 2 seconds SLA
- Confirmation message is displayed to the manager
- Notification is sent to the assigned employee about deadline change
- Audit log records the deadline update action with timestamp

---

## Story: As Manager, I want to assign priority levels to tasks to achieve effective workload management
**Story ID:** story-4

### Test Case: Assign valid priority level successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Manager with valid credentials
- Manager has authorization to assign task priorities
- At least one task exists in the system that requires priority assignment
- Task priority setting interface is accessible
- Predefined priority levels (Low, Medium, High) are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task priority setting page | Priority selection form is displayed with dropdown or radio buttons showing Low, Medium, and High options |
| 2 | Select a valid priority level (e.g., High) from the available options | Selection is accepted without errors and the chosen priority level is highlighted or selected |
| 3 | Submit priority by clicking the submit button | Priority is saved successfully and confirmation message is displayed to the manager |
| 4 | Verify the priority is stored correctly in the database | Database query shows the priority is correctly saved as 'High' for the task |
| 5 | Check that notification is triggered for the assigned employee | System logs show notification event was triggered for the employee about priority assignment |

**Postconditions:**
- Priority level is successfully saved in the task table
- Confirmation message is displayed to the manager
- Notification is sent to the assigned employee
- Task displays the assigned priority level in the task list
- Audit log records the priority assignment action

---

### Test Case: Reject invalid priority values
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Manager with valid credentials
- Manager has authorization to assign task priorities
- At least one task exists in the system that requires priority assignment
- Task priority setting interface is accessible
- System has validation rules to accept only Low, Medium, or High priority values

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to priority setting page | Priority selection form is displayed with predefined priority options |
| 2 | Attempt to enter an invalid priority value (e.g., 'Critical' or 'Urgent' or manually input text not in predefined list) | Validation error is displayed indicating that only Low, Medium, or High are valid priority levels |
| 3 | Attempt to submit the invalid priority by clicking the submit button | Submission is blocked and error message is displayed: 'Invalid priority value. Please select Low, Medium, or High' |
| 4 | Verify that no priority is saved in the database | Database query confirms no new priority entry was created or updated |
| 5 | Verify that no notification is triggered | System logs show no notification event was triggered |

**Postconditions:**
- No priority is saved or updated in the database
- Error message is displayed to the manager
- No notification is sent to the employee
- Task remains in its previous state without priority changes
- Form remains on the priority setting page for correction

---

### Test Case: Verify priority update processing time
- **ID:** tc-006
- **Type:** boundary
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as a Manager with valid credentials
- Manager has authorization to update task priorities
- A task with an existing priority level is available in the system
- Task priority update interface is accessible
- Performance monitoring tools are available to measure response time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task with existing priority and open priority update interface | Priority update form is displayed with current priority level pre-selected |
| 2 | Update priority with a valid level (e.g., change from Medium to High) and note the timestamp before submission | New priority level is selected successfully in the form |
| 3 | Submit the updated priority and measure response time | Response is received within 2 seconds and confirmation message is displayed |
| 4 | Check database for updated priority immediately after submission | Database query shows the priority is updated correctly to 'High' |
| 5 | Confirm confirmation message display to manager | Success message is shown to manager indicating priority was updated successfully |
| 6 | Verify notification trigger for the employee | System logs confirm notification event was triggered for priority change |

**Postconditions:**
- Priority level is successfully updated in the task table
- Update processing completed within 2 seconds SLA
- Confirmation message is displayed to the manager
- Notification is sent to the assigned employee about priority change
- Audit log records the priority update action with timestamp

---

## Story: As Manager, I want to modify task deadlines to achieve flexibility in scheduling
**Story ID:** story-8

### Test Case: Modify task deadline with valid future date
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to modify task deadlines
- At least one task exists in the system with an assigned deadline
- Task is in editable state
- System is connected to the task database

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task list and select a task that needs deadline modification | Task is selected and highlighted in the task list |
| 2 | Click on the 'Edit Deadline' button or option to open the deadline edit form | Deadline edit form is displayed showing the current deadline date in the input field |
| 3 | Clear the existing deadline and enter a new valid future date (e.g., a date 7 days from today) | New deadline date is entered in the input field without any validation errors or warnings |
| 4 | Click the 'Submit' or 'Update' button to save the new deadline | System processes the update within 2 seconds, deadline is updated in the database, and a confirmation message is displayed (e.g., 'Deadline updated successfully') |
| 5 | Verify the task list displays the updated deadline for the modified task | Task list shows the new deadline date for the selected task |
| 6 | Check that the assigned employee receives a notification about the deadline change | Notification is queued/sent to the assigned employee informing them of the deadline modification |

**Postconditions:**
- Task deadline is updated in the database with the new future date
- Confirmation message is displayed to the manager
- Deadline change is logged in the audit trail
- Notification is sent to the assigned employee
- Task list reflects the updated deadline

---

### Test Case: Reject modification with past date
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to modify task deadlines
- At least one task exists in the system with an assigned deadline
- Task is in editable state
- System is connected to the task database

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task list and select a task to modify | Task is selected and highlighted in the task list |
| 2 | Click on the 'Edit Deadline' button or option to open the deadline edit form | Deadline edit form is displayed showing the current deadline date |
| 3 | Clear the existing deadline and enter a past date (e.g., yesterday's date or any date before today) | Past date is entered in the input field and a validation error message is displayed (e.g., 'Deadline must be a future date' or 'Past dates are not allowed') |
| 4 | Attempt to click the 'Submit' or 'Update' button to save the invalid deadline | Submission is blocked, the update button is disabled or non-functional, and the error message remains visible indicating that past dates cannot be set as deadlines |
| 5 | Verify that the original deadline remains unchanged in the database | Task retains its original deadline and no changes are saved to the database |
| 6 | Close the edit form or navigate away | Form closes without saving changes and task list shows the original deadline |

**Postconditions:**
- Task deadline remains unchanged in the database
- No confirmation message is displayed
- No deadline change is logged in the audit trail
- No notification is sent to the assigned employee
- Error message is displayed to the manager explaining the validation failure

---

## Story: As Manager, I want to modify task priorities to achieve dynamic workload adjustment
**Story ID:** story-9

### Test Case: Modify task priority with valid level
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to modify task priorities
- At least one task exists in the system with an assigned priority
- Task is in editable state
- System is connected to the task database
- Valid priority levels are defined as Low, Medium, or High

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task list and select a task that needs priority modification | Task is selected and highlighted in the task list |
| 2 | Click on the 'Edit Priority' button or option to open the priority edit form | Priority edit form is displayed showing the current priority level (e.g., Low, Medium, or High) in a dropdown or selection field |
| 3 | Select a new valid priority level from the available options (e.g., change from Low to Medium) | New priority level 'Medium' is selected in the dropdown without any validation errors or warnings |
| 4 | Click the 'Submit' or 'Update' button to save the new priority | System processes the update within 2 seconds, priority is updated in the database, and a confirmation message is displayed (e.g., 'Priority updated successfully') |
| 5 | Verify the task list displays the updated priority for the modified task | Task list shows the new priority level 'Medium' for the selected task with appropriate visual indicators (e.g., color coding or priority badge) |
| 6 | Check that the assigned employee receives a notification about the priority change | Notification is queued/sent to the assigned employee informing them of the priority modification |

**Postconditions:**
- Task priority is updated in the database with the new valid level
- Confirmation message is displayed to the manager
- Priority change is logged in the audit trail
- Notification is sent to the assigned employee
- Task list reflects the updated priority with appropriate visual indicators

---

### Test Case: Reject modification with invalid priority
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Manager role
- Manager has authorization to modify task priorities
- At least one task exists in the system with an assigned priority
- Task is in editable state
- System is connected to the task database
- Valid priority levels are defined as Low, Medium, or High

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task list and select a task to modify | Task is selected and highlighted in the task list |
| 2 | Click on the 'Edit Priority' button or option to open the priority edit form | Priority edit form is displayed showing the current priority level |
| 3 | Attempt to enter or select an invalid priority value (e.g., 'Critical', 'Urgent', numeric value, or any value not in the predefined list of Low, Medium, High) | System displays a validation error message (e.g., 'Invalid priority value. Please select Low, Medium, or High') and highlights the invalid input |
| 4 | Attempt to click the 'Submit' or 'Update' button to save the invalid priority | Submission is blocked, the update button is disabled or non-functional, and the error message remains visible indicating that only Low, Medium, or High priority values are accepted |
| 5 | Verify that the original priority remains unchanged in the database | Task retains its original priority level and no changes are saved to the database |
| 6 | Close the edit form or navigate away | Form closes without saving changes and task list shows the original priority |

**Postconditions:**
- Task priority remains unchanged in the database
- No confirmation message is displayed
- No priority change is logged in the audit trail
- No notification is sent to the assigned employee
- Error message is displayed to the manager explaining the validation failure

---

