# Manual Test Cases

## Story: As Employee, I want to receive notifications when assigned tasks to achieve timely awareness
**Story ID:** story-13

### Test Case: Validate notification delivery upon task assignment
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager user account is active and logged into the system
- Employee user account is active with valid email address configured
- Task management module is accessible and functional
- Email service is configured and operational
- Employee has access to system inbox and email client

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to task creation page and creates a new task with all required fields (title, description, due date) | Task creation form is displayed and accepts all input data |
| 2 | Manager assigns the created task to a specific employee from the employee dropdown list | Employee is successfully selected and assigned to the task |
| 3 | Manager clicks 'Save' or 'Assign' button to complete the task assignment | System displays success message confirming task assignment and notification is triggered within 5 seconds |
| 4 | Employee logs into the system and navigates to the system inbox/notifications section | System inbox displays the new task assignment notification with task details (task name, assigned by, due date) |
| 5 | Employee checks their registered email inbox for notification email | Email notification is received containing task assignment details matching the system notification |
| 6 | Employee clicks on the notification in the dashboard to view full details | Notification details are displayed correctly showing complete task information including task title, description, assigned by manager name, assignment date, and due date |

**Postconditions:**
- Task assignment notification is marked as delivered in the system
- Notification appears in employee's system inbox
- Email notification is sent to employee's registered email address
- Notification delivery is logged in the system audit trail
- Employee can access the assigned task from the notification

---

### Test Case: Verify notification delivery logging
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager user account is active and logged into the system
- Employee user account is active in the system
- Notification logging system is enabled and functional
- User has administrative access to view notification logs
- Task assignment functionality is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager creates a new task with all required information (title, description, priority, due date) | Task is successfully created in the system |
| 2 | Manager assigns the task to an employee and saves the assignment | Task assignment is completed successfully and system confirms the assignment |
| 3 | System automatically triggers notification delivery to the assigned employee | Notification is sent to employee via system inbox and email, and delivery event is logged in the system |
| 4 | Administrator or authorized user navigates to the notification logs section or audit trail | Notification logs page is displayed with search and filter options |
| 5 | User filters or searches for the notification log entry by employee name, task ID, or timestamp | System displays the relevant notification log entry |
| 6 | User reviews the log entry details including timestamp, recipient, delivery status, notification type, and task reference | Log entry accurately reflects the notification event with correct employee name, task ID, delivery timestamp (within 5 seconds of assignment), delivery status (success/failure), notification channels (system inbox and email), and matches the actual notification sent |

**Postconditions:**
- Notification delivery log entry is permanently stored in the system
- Log entry contains complete audit information (timestamp, recipient, task ID, delivery status, channels)
- Log data is available for compliance and audit purposes
- System maintains data integrity of notification logs

---

## Story: As Employee, I want to update task status to achieve transparent progress tracking
**Story ID:** story-14

### Test Case: Validate successful task status update
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee user account is active and logged into the system
- At least one task is assigned to the employee
- Task is in a valid initial status (e.g., 'Not Started' or 'Assigned')
- Manager user account is active to receive status update notifications
- Task status update functionality is enabled and accessible
- Employee has authorization to update task status

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee logs into the system and navigates to 'My Tasks' or 'Assigned Tasks' section | List of assigned tasks is displayed showing task names, current status, due dates, and other relevant information |
| 2 | Employee identifies and clicks on a specific assigned task from the list | Task details page is displayed showing complete task information including title, description, current status, assigned by, due date, and priority |
| 3 | Employee locates the status field or status update dropdown on the task details page | Status update control is visible and accessible with predefined status options (e.g., Not Started, In Progress, Completed, On Hold) |
| 4 | Employee selects 'In Progress' from the status dropdown menu | Status dropdown displays 'In Progress' as the selected option without any errors |
| 5 | Employee clicks 'Save' or 'Update Status' button to submit the status change | System processes the update within 2 seconds and displays a success message confirming the status update |
| 6 | Employee verifies the updated status is reflected in the task details page | Task status field now displays 'In Progress' and the update timestamp is shown |
| 7 | Employee navigates back to the task list view | Task list displays the updated status 'In Progress' for the modified task |
| 8 | Manager checks their notifications or task monitoring dashboard | Manager receives real-time notification about the status update showing employee name, task name, old status, new status, and update timestamp |

**Postconditions:**
- Task status is permanently updated to 'In Progress' in the database
- Status change is visible to all authorized users (employee and manager)
- Manager receives notification of the status update
- Task list and task details reflect the updated status
- System logs the status change event with timestamp and user information

---

### Test Case: Verify rejection of invalid status transitions
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee user account is active and logged into the system
- Task is assigned to the employee with a specific current status
- System has defined status transition rules (e.g., cannot move from 'Completed' to 'Not Started')
- Task status validation rules are configured and active
- Employee has access to task status update functionality

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee logs into the system and navigates to the assigned tasks list | List of assigned tasks is displayed with current status for each task |
| 2 | Employee selects a task that is currently in 'Completed' status | Task details page opens showing the task with 'Completed' status |
| 3 | Employee attempts to change the status from 'Completed' to 'Not Started' (an invalid backward transition) | Status dropdown allows selection but system prepares to validate the transition |
| 4 | Employee clicks 'Save' or 'Update Status' button to submit the invalid status change | System validates the status transition and detects it as invalid according to business rules |
| 5 | System processes the validation and responds to the invalid transition attempt | System displays a clear validation error message (e.g., 'Invalid status transition: Cannot change from Completed to Not Started') and blocks the update from being saved |
| 6 | Employee verifies the task status remains unchanged | Task status remains 'Completed' and no changes are saved to the database |
| 7 | Employee dismisses the error message and checks available status options | System may optionally display only valid status transition options based on current status, or continue to show all options with validation on submit |

**Postconditions:**
- Task status remains unchanged at 'Completed'
- No status update is saved to the database
- No notification is sent to the manager
- Error message is displayed to inform the employee of the invalid transition
- System maintains data integrity by preventing invalid status changes
- Validation event may be logged for audit purposes

---

## Story: As Manager, I want to track task status updates to achieve real-time visibility into task progress
**Story ID:** story-17

### Test Case: Validate display of current task statuses
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager user account exists with valid credentials
- Manager has authorization to access task dashboard
- Multiple tasks exist in the system with various statuses (Not Started, In Progress, Completed, Blocked)
- Tasks have recent status updates recorded in the system
- Browser is supported and up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open web browser and navigate to the application login page | Login page is displayed with username and password fields |
| 2 | Enter valid manager credentials and click Login button | Manager is successfully authenticated and redirected to the dashboard home page |
| 3 | Navigate to the manager task dashboard by clicking on 'Tasks' or 'Dashboard' menu option | Task dashboard loads and displays a task list with multiple columns including a status column |
| 4 | Verify that the status column is visible and clearly labeled in the task list | Status column is present with header label 'Status' or similar, positioned appropriately in the task list |
| 5 | Review the status values displayed for at least 5 different tasks in the list | Each task displays a status value (e.g., Not Started, In Progress, Completed, Blocked) in the status column |
| 6 | Cross-reference displayed status values with the latest status updates recorded in the system database or task details | All displayed status values match the most recent status updates for each respective task with 100% accuracy |
| 7 | Scroll through the task list to verify status display for additional tasks | Status column consistently displays current status for all visible tasks without any missing or null values |

**Postconditions:**
- Manager remains logged into the system
- Task dashboard remains accessible
- No data has been modified during the test
- All task statuses remain unchanged

---

### Test Case: Validate filtering tasks by status
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Manager user is logged into the system
- Manager has access to the task dashboard
- Multiple tasks exist with different statuses including at least 3 tasks with 'In Progress' status
- Tasks with other statuses (Not Started, Completed, Blocked) also exist in the system
- Filter functionality is enabled on the task dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the manager task dashboard | Task dashboard is displayed showing all tasks with their respective statuses |
| 2 | Note the total number of tasks displayed before applying any filter | Total task count is visible and includes tasks with various statuses |
| 3 | Locate the status filter control (dropdown, checkbox, or filter button) on the dashboard | Status filter control is visible and accessible on the dashboard interface |
| 4 | Click on the status filter control to open filter options | Filter options are displayed showing available status values (Not Started, In Progress, Completed, Blocked) |
| 5 | Select 'In Progress' status from the filter options | 'In Progress' option is selected/highlighted in the filter control |
| 6 | Apply the filter by clicking 'Apply' or 'Filter' button, or observe auto-filtering if enabled | Task list refreshes and updates to display only tasks with 'In Progress' status |
| 7 | Verify that all displayed tasks show 'In Progress' in their status column | 100% of visible tasks have 'In Progress' status; no tasks with other statuses are displayed |
| 8 | Verify the task count matches the expected number of 'In Progress' tasks | Displayed task count matches the number of tasks with 'In Progress' status in the system |
| 9 | Clear the filter or select 'All' to return to unfiltered view | Task list updates to show all tasks again, regardless of status |

**Postconditions:**
- Filter can be cleared and reapplied
- Task list returns to showing all tasks when filter is removed
- No tasks have been modified during filtering
- Manager remains logged in and on the dashboard

---

## Story: As Manager, I want to receive alerts for overdue tasks to achieve proactive task management
**Story ID:** story-18

### Test Case: Validate alert generation for overdue tasks
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager user account exists with valid email address configured
- Manager has authorization to create and view tasks
- Alert generation service is running and operational
- Email notification service is configured and functional
- System time is accurate and synchronized
- Alert generation cycle runs at least every 1 minute

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as a manager user | Manager is successfully authenticated and logged into the system |
| 2 | Navigate to the task creation page or form | Task creation interface is displayed with all required fields |
| 3 | Create a new task with title 'Test Overdue Task', assign to an employee, set deadline to yesterday's date, and set status to 'In Progress' (incomplete) | Task is successfully created with deadline in the past and incomplete status |
| 4 | Save the task and note the task ID or name for reference | Task is saved to the system and task ID is visible |
| 5 | Verify the task is marked as overdue in the task list or task details | Task displays an 'Overdue' indicator or flag, confirming it is recognized as overdue by the system |
| 6 | Wait for the alert generation cycle to complete (maximum 1 minute as per SLA) | Alert generation service processes the overdue task within 1 minute |
| 7 | Navigate to the manager dashboard and locate the alerts section or notification area | Alerts section is visible on the dashboard |
| 8 | Verify that an alert for the overdue task appears in the manager dashboard | Alert is displayed in the dashboard showing the task name 'Test Overdue Task' and indicating it is overdue |
| 9 | Open the manager's email inbox associated with the manager account | Email inbox is accessible |
| 10 | Check for email notification about the overdue task | Email notification is received with subject line indicating overdue task, containing task details including task name, deadline, and overdue status |
| 11 | Verify email content includes relevant task information and actionable details | Email contains task name, original deadline, days overdue, and link to view task details |

**Postconditions:**
- Overdue task remains in the system
- Alert remains visible in dashboard until dismissed
- Email notification remains in inbox
- Task status remains unchanged
- Manager remains logged in

---

### Test Case: Verify alert dismissal functionality
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager user is logged into the system
- At least one overdue task alert is visible in the manager dashboard
- Alert was generated by an overdue task
- Manager has permission to dismiss alerts
- Dashboard is fully loaded and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the manager dashboard | Manager dashboard is displayed with all sections loaded |
| 2 | Locate the alerts section or notification panel on the dashboard | Alerts section is visible showing one or more overdue task alerts |
| 3 | Identify a specific overdue task alert and read its content | Alert is clearly visible with task name, overdue status, and relevant details displayed |
| 4 | Note the task name or ID from the alert for verification purposes | Task identifier is recorded for post-dismissal verification |
| 5 | Locate the dismiss button, close icon (X), or dismiss action associated with the alert | Dismiss control is visible and clearly associated with the alert |
| 6 | Click the dismiss button or close icon to dismiss the alert | System processes the dismiss action without errors |
| 7 | Verify that the alert is immediately removed from the dashboard alerts section | Alert is no longer visible in the alerts section; it has been removed from the display |
| 8 | Refresh the dashboard page to confirm alert dismissal persists | After page refresh, the dismissed alert does not reappear in the alerts section |
| 9 | Verify that the underlying overdue task still exists in the task list | Overdue task remains in the task list with overdue status; only the alert was dismissed, not the task itself |

**Postconditions:**
- Alert is permanently dismissed and no longer visible
- Overdue task remains in the system unchanged
- Manager can still access task details if needed
- Alert dismissal is recorded in the system
- Manager remains logged in and on dashboard

---

