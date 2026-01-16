# Manual Test Cases

## Story: As Employee, I want to receive notifications of assigned tasks to achieve awareness and timely action
**Story ID:** story-6

### Test Case: Receive notification on task assignment
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account is active and authenticated in the system
- Manager account has permission to assign tasks
- Notification service is running and operational
- Employee has access to notification dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager logs into the system and navigates to task management section | Task management interface is displayed successfully |
| 2 | Manager creates a new task with title, description, deadline, and priority | Task creation form accepts all required fields |
| 3 | Manager assigns the task to a specific employee and submits the assignment | Task assignment is processed successfully and confirmation message is displayed |
| 4 | Wait for notification delivery (maximum 5 minutes) | System triggers notification within the specified timeframe |
| 5 | Employee checks for new notifications in their notification center or email | Notification is displayed with task title, description, deadline, priority, and action link |
| 6 | Employee navigates to notification history in their dashboard | Notification history page loads successfully |
| 7 | Employee verifies the task assignment notification appears in the history list | Notification is listed in history with timestamp, task details, and read/unread status |

**Postconditions:**
- Task assignment notification is recorded in notification history
- Employee is aware of the newly assigned task
- Notification status is marked as delivered in the system

---

### Test Case: Receive notification on deadline change
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee account is active and authenticated
- Manager has permission to update task deadlines
- An existing task is already assigned to the employee
- Notification service is operational
- Employee has access to notification acknowledgment features

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager logs into the system and navigates to the assigned task | Task details page is displayed with current deadline information |
| 2 | Manager selects the option to edit task deadline | Deadline edit interface is displayed with current deadline value |
| 3 | Manager updates the task deadline to a new date and saves the changes | Deadline update is processed successfully and confirmation message is displayed |
| 4 | Wait for notification delivery (maximum 5 minutes) | System triggers notification for deadline change within specified timeframe |
| 5 | Employee checks for new notifications in their notification center | Notification is displayed showing the task name, old deadline, new deadline, and reason for change |
| 6 | Employee clicks on the notification to view full details | Notification expands to show complete task information with updated deadline highlighted |
| 7 | Employee clicks the acknowledge button on the notification | Acknowledgment is recorded and notification is marked as acknowledged |
| 8 | Verify acknowledgment status in the notification history | Notification shows acknowledgment timestamp and acknowledged status |

**Postconditions:**
- Deadline change notification is recorded in notification history
- Employee acknowledgment is saved in the system
- Task displays updated deadline information
- Notification is marked as read and acknowledged

---

### Test Case: Verify notification delivery under load
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Multiple employee accounts are active in the system
- Manager has permission to assign tasks to multiple employees
- Notification service is operational and monitored
- Performance monitoring tools are configured
- Test environment can simulate concurrent operations

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare a list of 50 tasks with varying priorities and deadlines | Task data is prepared and ready for bulk assignment |
| 2 | Manager initiates concurrent task assignments to 50 different employees simultaneously | All 50 task assignments are submitted to the system without errors |
| 3 | Monitor the notification service to verify all 50 notifications are triggered | System logs show 50 notification triggers with unique task IDs and employee IDs |
| 4 | Track notification delivery time for each of the 50 notifications | All notifications are queued for delivery with timestamps recorded |
| 5 | Verify that all 50 employees receive their respective notifications within 5 minutes | 100% of notifications are delivered within the 5-minute SLA timeframe |
| 6 | Check system performance metrics including CPU usage, memory consumption, and response times | System resources remain within acceptable thresholds (CPU < 80%, Memory < 85%) |
| 7 | Review system logs for any errors, warnings, or failed notification deliveries | No errors or delays are observed in system logs; all notifications show successful delivery status |
| 8 | Verify database integrity and notification records for all 50 assignments | All notification records are correctly stored with accurate timestamps and delivery status |

**Postconditions:**
- All 50 notifications are successfully delivered and recorded
- System performance remains stable under concurrent load
- No data loss or corruption occurred during load test
- Notification service maintains SLA compliance under stress

---

## Story: As Manager, I want to view and track task statuses to achieve effective monitoring of employee work
**Story ID:** story-7

### Test Case: View task list with statuses
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Manager account is authenticated and has appropriate permissions
- Multiple tasks exist in the system with various statuses (Not Started, In Progress, Completed, Blocked)
- Tasks have different priorities (High, Medium, Low) and deadlines
- Task tracking dashboard is accessible to the manager

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager logs into the system and navigates to the task tracking dashboard | Task tracking dashboard loads successfully and displays the complete task list with status indicators (color-coded or icon-based) |
| 2 | Verify that each task displays its current status, priority, deadline, assigned employee, and progress percentage | All task information is clearly visible with accurate status indicators for each task |
| 3 | Manager clicks on the priority filter dropdown and selects 'High' priority | Task list updates to display only high-priority tasks |
| 4 | Manager adds a deadline filter to show tasks due within the next 7 days | Task list further filters to show only high-priority tasks with deadlines in the next 7 days |
| 5 | Verify the filtered task count matches the number of tasks displayed | Task counter shows correct number of filtered results |
| 6 | Manager clicks on the status column header to sort tasks by status | Tasks are reordered and grouped by status (e.g., Blocked, Not Started, In Progress, Completed) in ascending order |
| 7 | Manager clicks the status column header again to reverse the sort order | Tasks are reordered in descending status order |
| 8 | Manager clears all filters to view the complete task list again | All tasks are displayed with their respective statuses and the filter indicators are cleared |

**Postconditions:**
- Task list displays accurate and current status information
- Filter and sort preferences are maintained during the session
- Manager has clear visibility of task distribution across statuses

---

### Test Case: Update task status successfully
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager is authenticated with task update permissions
- At least one task exists with status 'In Progress'
- Task status workflow rules are configured in the system
- Manager has access to task detail and edit functionality

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the task tracking dashboard and locates a task with 'In Progress' status | Task list is displayed and the target task is visible with 'In Progress' status indicator |
| 2 | Manager clicks on the task to open task details view | Task details page opens showing complete task information including current status |
| 3 | Manager clicks on the status dropdown or edit button to change the task status | Status selection interface is displayed with available status options based on workflow rules |
| 4 | Manager selects 'Completed' from the status dropdown | Status change is accepted and 'Completed' is highlighted as the selected option |
| 5 | Manager adds optional comments explaining the status change | Comment field accepts text input and displays character count if applicable |
| 6 | Manager clicks the 'Submit' or 'Save' button to confirm the status update | Status update is processed and a success confirmation message is displayed (e.g., 'Task status updated successfully') |
| 7 | Manager returns to the task tracking dashboard | Dashboard reloads and displays the updated task list |
| 8 | Manager locates the previously updated task in the task list | Task now displays 'Completed' status with updated timestamp and status indicator color/icon |
| 9 | Manager clicks on the task again to verify the status change is persisted | Task details show 'Completed' status with the manager's comment and update timestamp |

**Postconditions:**
- Task status is permanently updated to 'Completed' in the database
- Status change is logged in task history with timestamp and user information
- Assigned employee receives notification of status change (if applicable)
- Task statistics and reports reflect the updated status

---

### Test Case: Dashboard performance under normal load
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager account is authenticated
- System contains a representative dataset of tasks (100-500 tasks)
- Network conditions are stable and normal
- Performance monitoring tools are available to measure load times
- Browser cache is cleared to simulate first-time load

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the task tracking dashboard URL and starts timer | Dashboard begins loading and displays loading indicator |
| 2 | Measure the time taken for the dashboard to fully load with all task data and status indicators | Dashboard loads completely within 3 seconds showing all tasks with status indicators, filters, and controls |
| 3 | Verify all dashboard elements are interactive and responsive | All buttons, filters, and sorting controls are functional immediately after page load |
| 4 | Manager applies a filter for 'High' priority tasks | Filter is applied and task list updates within 1 second showing only high-priority tasks |
| 5 | Manager adds an additional filter for tasks with 'In Progress' status | Combined filters are applied and task list updates promptly (within 1 second) showing only high-priority, in-progress tasks |
| 6 | Manager sorts the filtered results by deadline in ascending order | Tasks are reordered by deadline within 1 second with earliest deadlines appearing first |
| 7 | Manager clears all filters and sorts to return to default view | Dashboard resets to show all tasks in default order within 1 second |
| 8 | Manager clicks the 'Export' button to generate a CSV report of task statuses | Export process initiates and progress indicator is displayed |
| 9 | Wait for CSV file generation and download to complete | CSV file is generated and downloaded within 5 seconds containing all task data with correct columns (Task ID, Title, Status, Priority, Deadline, Assigned Employee) |
| 10 | Open the downloaded CSV file and verify data accuracy | CSV file opens successfully and contains accurate task information matching the dashboard display with proper formatting |

**Postconditions:**
- Dashboard maintains performance standards under normal load
- All filtering and sorting operations complete within acceptable timeframes
- Exported CSV file contains accurate and complete task data
- System resources return to normal levels after operations complete

---

## Story: As Manager, I want to view audit logs of task changes to achieve accountability and traceability
**Story ID:** story-10

### Test Case: View audit logs filtered by task and date
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with manager role credentials
- Manager has authorization to access audit logs
- At least one task with change history exists in the system
- Audit log database contains historical task change records
- Browser is supported and up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit log interface by clicking on 'Audit Logs' menu option | Audit log UI is displayed with filter options, search bar, and empty or default log list view |
| 2 | Select a specific task from the task filter dropdown | Task is selected and displayed in the filter field |
| 3 | Enter start date in the 'From Date' field using date picker | Start date is populated in the date field in correct format |
| 4 | Enter end date in the 'To Date' field using date picker | End date is populated in the date field in correct format |
| 5 | Click 'Apply Filters' button | System processes the filter request and displays filtered audit logs matching the selected task and date range within 3 seconds. Logs show task changes with timestamps, user info, and change details |
| 6 | Verify the displayed logs contain only records for the selected task within the specified date range | All displayed logs match the filter criteria with correct task name and dates falling within the specified range |
| 7 | Click 'Export' button to download the filtered logs | CSV file download is initiated automatically |
| 8 | Open the downloaded CSV file | CSV file opens successfully and contains all filtered log entries with columns for timestamp, user, task, change type, old value, and new value. Data matches the displayed logs exactly |

**Postconditions:**
- Audit logs remain unchanged in the database
- Filter selections are retained in the UI
- CSV file is saved in the downloads folder
- User session remains active

---

### Test Case: Verify audit logs record all task changes
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with manager role credentials
- Manager has permissions to modify tasks and view audit logs
- At least one task exists in the system that can be modified
- Audit logging service is active and running
- System time is synchronized correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management interface | Task management interface is displayed with list of available tasks |
| 2 | Select a task and reassign it to a different team member | Task assignment is updated successfully and confirmation message is displayed |
| 3 | Modify the deadline of the same task to a new date | Task deadline is updated successfully and confirmation message is displayed |
| 4 | Change the priority of the same task from current priority to a different priority level | Task priority is updated successfully and confirmation message is displayed |
| 5 | Navigate to the audit log interface | Audit log UI is displayed |
| 6 | Filter audit logs by the modified task ID or name | System displays all audit log entries for the selected task |
| 7 | Verify that the assignment change is recorded in the audit logs | Audit log entry shows the assignment change with old assignee, new assignee, change type as 'Assignment', timestamp, and user who made the change |
| 8 | Verify that the deadline change is recorded in the audit logs | Audit log entry shows the deadline change with old deadline, new deadline, change type as 'Deadline', timestamp, and user who made the change |
| 9 | Verify that the priority change is recorded in the audit logs | Audit log entry shows the priority change with old priority, new priority, change type as 'Priority', timestamp, and user who made the change |
| 10 | Check the timestamps for all three log entries | All timestamps are accurate, reflect the actual time of changes, and are in chronological order |
| 11 | Check the user information for all three log entries | User information is complete and accurate, showing the correct username or user ID of the manager who performed each change |

**Postconditions:**
- All three task changes are permanently recorded in the audit log database
- Task reflects the final modified state with new assignment, deadline, and priority
- Audit logs are available for future queries and compliance reviews
- No data integrity issues exist in the audit trail

---

### Test Case: Ensure audit log access is restricted
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- System has role-based access control configured
- At least one unauthorized user account exists (non-manager role)
- At least one authorized manager account exists
- Audit logs contain data in the system
- Authentication and authorization services are functioning

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system using unauthorized user credentials (e.g., team member or developer role) | User is successfully authenticated and logged into the system with non-manager role |
| 2 | Attempt to navigate to the audit log interface by entering the audit log URL directly or clicking the menu option if visible | Access is denied with error message 'You do not have permission to access audit logs' or 'Access Denied - Manager authorization required'. User is redirected to home page or error page |
| 3 | Attempt to access audit logs via API endpoint GET /api/tasks/auditlogs using unauthorized user token | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 4 | Log out from the unauthorized user account | User is successfully logged out and redirected to login page |
| 5 | Log in to the system using authorized manager credentials | Manager is successfully authenticated and logged into the system with manager role |
| 6 | Navigate to the audit log interface by clicking on 'Audit Logs' menu option | Access is granted and audit log UI is displayed with full functionality including filters, search, and export options |
| 7 | Verify that audit logs are visible and contain task change records | Audit logs are displayed with complete information including timestamps, user details, task changes, and change types |
| 8 | Access audit logs via API endpoint GET /api/tasks/auditlogs using authorized manager token | API returns 200 OK status code with JSON response containing audit log data |

**Postconditions:**
- Unauthorized access attempts are logged in security logs
- Authorized manager retains access to audit logs
- No unauthorized data exposure occurred
- System security policies remain enforced
- User sessions are properly managed

---

