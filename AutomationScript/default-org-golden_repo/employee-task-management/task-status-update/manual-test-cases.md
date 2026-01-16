# Manual Test Cases

## Story: As Employee, I want to update task status to achieve accurate task progress tracking
**Story ID:** story-11

### Test Case: Validate successful status update with valid input
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid credentials and is authenticated in the system
- Employee has at least one task assigned to them
- Task management system is accessible and operational
- Database connection is active
- Predefined status options are configured in the system (e.g., Not Started, In Progress, Completed, On Hold)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management system login page and enter valid employee credentials (username and password), then click Login button | Employee is successfully authenticated and redirected to the dashboard. The assigned tasks section is visible |
| 2 | Navigate to the 'My Tasks' or 'Assigned Tasks' section from the main navigation menu | A list of all tasks assigned to the employee is displayed with current status, task names, and other relevant details |
| 3 | Select a specific task from the list by clicking on it to open the task details view | Task details page opens showing task information including current status, description, assignee, and status update option |
| 4 | Locate the status dropdown field and click on it to view available status options | Dropdown menu expands showing all predefined valid status options (e.g., Not Started, In Progress, Completed, On Hold) |
| 5 | Select a new valid status from the dropdown menu that is different from the current status | The selected status is highlighted in the dropdown and displayed in the status field |
| 6 | Click the 'Submit' or 'Update Status' button to save the status change | System processes the request within 2 seconds. A confirmation message is displayed (e.g., 'Task status updated successfully'). The task status is visibly updated in the task details view |
| 7 | Verify the updated status is reflected in the task list by navigating back to the 'My Tasks' section | The task shows the newly updated status in the task list view |
| 8 | Check that relevant stakeholders receive notification of the status change (if notification system is in scope) | Stakeholders receive notification via configured channels about the status update |

**Postconditions:**
- Task status is updated in the database with the new value
- Status update is logged with employee user ID and timestamp in the audit log
- Confirmation message is displayed to the employee
- Task list reflects the updated status
- Stakeholders are notified of the status change

---

### Test Case: Reject status update with invalid status value
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the task management system
- Employee has at least one task assigned
- System has predefined valid status values configured
- API endpoint PUT /api/tasks/{taskId}/status is operational
- Validation rules are properly configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the assigned tasks list and select a task to update | Task details page opens with status update option available |
| 2 | Attempt to submit a status update with an invalid status value (e.g., by manipulating the API request with a value not in the predefined list, or entering invalid data if direct input is possible) | System validates the input and detects the invalid status value |
| 3 | Observe the system response after attempting to submit the invalid status | System displays a clear error message (e.g., 'Invalid status value. Please select a valid status from the list') and prevents the status update from being saved to the database |
| 4 | Verify that the task status remains unchanged in the database by refreshing the task details page | Task status shows the original value before the invalid update attempt. No changes are persisted |
| 5 | Correct the status by selecting a valid option from the predefined status dropdown menu | Valid status option is selected and displayed in the status field |
| 6 | Click the 'Submit' or 'Update Status' button with the valid status selection | System accepts the valid status update, processes it successfully, and displays a confirmation message (e.g., 'Task status updated successfully') |
| 7 | Verify the task status is now updated with the valid value in both the task details and task list views | Task status reflects the newly updated valid status across all views |

**Postconditions:**
- Invalid status update is rejected and not saved to database
- Error message is displayed to the employee
- Valid status update is successfully saved after correction
- Audit log records the failed attempt and successful update with timestamps
- Task status reflects the valid updated value

---

### Test Case: Prevent unauthorized user from updating task status
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Task management system is operational with OAuth2 authentication enabled
- Role-based authorization is properly configured
- At least one task exists in the system
- Unauthorized user account exists (user without permission to update the specific task)
- API endpoint PUT /api/tasks/{taskId}/status has proper authorization checks

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using credentials of a user who is not authorized to update the specific task (e.g., user from different department, user without task assignment, or user with read-only access) | Unauthorized user is successfully authenticated but has limited permissions based on their role |
| 2 | Attempt to navigate to a task that the user is not authorized to update (either through UI navigation or direct URL access) | System checks user authorization for the task |
| 3 | Attempt to access the status update functionality for the unauthorized task (either by clicking update button or attempting API call) | System denies access immediately and displays an authorization error message (e.g., 'Access Denied: You are not authorized to update this task status' or '403 Forbidden') |
| 4 | Verify that no status update option is available or clickable for the unauthorized user in the UI | Status update controls are either hidden, disabled, or trigger authorization error when accessed |
| 5 | Attempt to directly call the API endpoint PUT /api/tasks/{taskId}/status with the unauthorized user's authentication token | API returns 403 Forbidden status code with appropriate error message indicating insufficient permissions |
| 6 | Verify in the database that no status change was recorded for the task | Task status remains unchanged. No audit log entry is created for a successful status update. Failed authorization attempt may be logged for security monitoring |
| 7 | Log out the unauthorized user and log in with an authorized user (task assignee or user with proper permissions) | Authorized user can successfully access the task and status update functionality is available |

**Postconditions:**
- Unauthorized user is prevented from updating task status
- Authorization error message is displayed to unauthorized user
- Task status remains unchanged in the database
- No unauthorized status update is logged in the audit trail
- Security event may be logged for the unauthorized access attempt
- Success metric of 0% unauthorized status updates is maintained

---

## Story: As Employee, I want to receive notifications for task status updates to stay informed
**Story ID:** story-16

### Test Case: Verify notification sent on task status update
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is registered in the system with valid email address and in-app notification capability
- Employee has notification preferences configured (email and/or in-app enabled)
- At least one task is assigned to the employee or employee is a stakeholder on a task
- Notification service is operational and integrated with the task management system
- Email service is configured and functional
- Task status update events are properly configured to trigger notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as an employee who is assigned to or is a stakeholder on a specific task | Employee is successfully logged in and can view their assigned tasks or tasks they are monitoring |
| 2 | Navigate to the task details and update the task status by selecting a new status from the dropdown and clicking Submit | Task status is successfully updated and confirmation message is displayed. Status update event is triggered in the system |
| 3 | Wait for notification processing (system should send notification within 1 minute as per performance requirements) | Notification service detects the status update event and initiates notification delivery to relevant employees |
| 4 | Check the in-app notification center or notification icon in the application interface | In-app notification appears showing the task status update with accurate information including task name, old status, new status, and timestamp |
| 5 | Check the employee's registered email inbox for notification email | Email notification is received within 1 minute containing accurate task information: task name, task ID, previous status, new status, who made the change, and timestamp |
| 6 | Click on the in-app notification to view details | Notification opens and displays complete task status update information. Clicking may redirect to the task details page |
| 7 | Verify notification content accuracy by comparing with actual task details in the system | All information in the notification (task name, status change, user who made change, timestamp) matches the actual task data in the system |
| 8 | Verify that all relevant employees (assignee, stakeholders, team members) configured to receive notifications have received them via their configured channels | All authorized and configured recipients receive notifications through their preferred channels (email and/or in-app) |

**Postconditions:**
- Notification is successfully sent to all relevant employees within 1 minute
- Notification contains accurate task and status information
- Notification is delivered via configured channels (email and in-app)
- Notification delivery is logged in the system
- Success metric of 99% notification delivery is maintained
- Employees are informed and can react promptly to status changes

---

### Test Case: Test notification preference settings
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is registered and logged into the task management system
- Notification preference settings page is accessible to the employee
- Notification service supports multiple channels (email, in-app)
- At least one task is assigned to or monitored by the employee
- Default notification preferences are set in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the user profile or settings section of the application | User profile or settings page is displayed with navigation options |
| 2 | Locate and click on 'Notification Preferences' or 'Notification Settings' option | Notification preferences page opens displaying available notification channels and options (email, in-app, frequency settings) |
| 3 | Review current notification preference settings and note the default configuration | Current preferences are displayed clearly showing which channels are enabled/disabled (e.g., Email: ON, In-app: ON) |
| 4 | Modify notification preferences by disabling email notifications and keeping in-app notifications enabled for task status updates | Preference toggles or checkboxes respond to user input and show the updated selection (Email: OFF, In-app: ON) |
| 5 | Click 'Save' or 'Update Preferences' button to save the changes | System displays confirmation message (e.g., 'Notification preferences updated successfully'). Changes are persisted to the database |
| 6 | Refresh the notification preferences page or navigate away and return to verify settings are saved | Updated preferences are displayed correctly showing Email: OFF and In-app: ON |
| 7 | Trigger a task status update event by updating the status of a task assigned to or monitored by the employee | Task status is successfully updated and status update event is triggered |
| 8 | Wait for notification processing period (within 1 minute) and check for in-app notification | In-app notification is received and displayed in the notification center with accurate task status update information |
| 9 | Check the employee's email inbox for any email notification | No email notification is received, respecting the disabled email preference setting |
| 10 | Update notification preferences again to enable email notifications and disable in-app notifications, then save | Preferences are updated and saved successfully (Email: ON, In-app: OFF) |
| 11 | Trigger another task status update event | Task status is updated and notification event is triggered |
| 12 | Verify that email notification is received but no in-app notification appears | Email notification is received in inbox with accurate information. No in-app notification is displayed, respecting the updated preferences |

**Postconditions:**
- Notification preferences are successfully saved in the system
- System respects employee notification preferences for all subsequent notifications
- Notifications are sent only through enabled channels
- Disabled notification channels do not receive notifications
- Preference changes are immediately effective for new notification events
- Employee satisfaction with notification control is improved

---

### Test Case: Ensure no notifications sent to unauthorized users
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Task management system is operational with proper authorization controls
- Multiple user accounts exist with different roles and permissions
- At least one task exists in the system with specific assignees and stakeholders
- Unauthorized user account exists (user not assigned to or stakeholder on the task)
- Notification service is operational and integrated
- Authorization rules are configured to prevent unauthorized notification delivery

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify a task in the system and note its assigned employees and authorized stakeholders | Task details show specific assignees and stakeholders who should receive notifications |
| 2 | Identify an unauthorized user who is not assigned to the task and is not listed as a stakeholder or team member | Unauthorized user account is confirmed to have no relationship or permission to access the specific task |
| 3 | Log into the system as an authorized user and update the status of the identified task | Task status is successfully updated and status update event is triggered in the system |
| 4 | Wait for the notification processing period (within 1 minute) to allow notification service to process and send notifications | Notification service processes the status update event and determines recipient list based on authorization rules |
| 5 | Log into the system as the unauthorized user and check the in-app notification center | No notification about the task status update appears in the unauthorized user's notification center |
| 6 | Check the unauthorized user's email inbox for any notification emails about the task status update | No email notification is received by the unauthorized user regarding the task status update |
| 7 | Verify in the notification service logs that the unauthorized user was not included in the recipient list for the notification | Notification logs show that only authorized users (assignees and stakeholders) were included in the recipient list. Unauthorized user is explicitly excluded |
| 8 | Verify that authorized users (assignees and stakeholders) did receive the notification through their configured channels | Authorized users confirm receipt of notifications via email and/or in-app channels as per their preferences |
| 9 | Attempt to manipulate notification delivery by trying to subscribe the unauthorized user to task notifications (if such functionality exists) | System prevents unauthorized subscription and displays error message or denies access based on authorization rules |

**Postconditions:**
- No notifications are sent to unauthorized users
- Only authorized assignees and stakeholders receive notifications
- Authorization rules are properly enforced by the notification service
- Notification delivery logs confirm proper authorization checks
- Success metric of no unauthorized notifications sent is maintained
- Data privacy and security requirements are met

---

## Story: As Employee, I want to receive error messages when task status updates fail to ensure data accuracy
**Story ID:** story-19

### Test Case: Verify error message displayed on status update failure
- **ID:** tc-001
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system
- Employee has access to task management module
- At least one task is available for status update
- Test environment is configured to simulate update failures
- Network connectivity is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management page | Task management page loads successfully with list of tasks displayed |
| 2 | Select a task from the task list | Task details are displayed with current status visible |
| 3 | Click on the status dropdown or status update button | Status options are displayed (e.g., In Progress, Completed, Blocked) |
| 4 | Select a new status from the available options | New status is selected and highlighted in the interface |
| 5 | Simulate failure during status update (e.g., disconnect network, trigger API error, or use test configuration) | System attempts to process the status update and encounters a failure |
| 6 | Observe the system response after the simulated failure | A clear, user-friendly error message is displayed on the screen (e.g., 'Unable to update task status. Please check your connection and try again.' or 'Status update failed. Please contact support if the issue persists.') |
| 7 | Verify that the error message does not contain sensitive technical information | Error message is user-friendly without exposing system internals, database details, or security-sensitive information |
| 8 | Check the current task status in the system | Task status remains unchanged from the original status (no partial or corrupted update) |

**Postconditions:**
- Task status remains at the original value
- Error message is visible to the employee
- No data corruption has occurred
- System remains in a stable state for retry attempts

---

### Test Case: Verify error logging on update failure
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the system
- Employee has access to task management module
- At least one task is available for status update
- Test environment is configured to simulate update failures
- System logging is enabled and accessible
- Support team has access to error logs
- Log monitoring tools are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management page | Task management page loads successfully with list of tasks displayed |
| 2 | Note the current timestamp before triggering the failure | Timestamp is recorded for log verification purposes |
| 3 | Select a task from the task list | Task details are displayed with current status visible |
| 4 | Attempt to update the task status to a new value | Status update request is initiated |
| 5 | Trigger status update failure (e.g., simulate API error, database connection failure, or network timeout) | System encounters an error during the status update process |
| 6 | Access the system error logs or log monitoring dashboard | Error log interface is accessible and displays recent log entries |
| 7 | Search for error entries matching the timestamp of the failed update | Error log entry is found corresponding to the failed status update attempt |
| 8 | Verify the error log contains essential details including: timestamp, user ID, task ID, attempted status change, error type, and error description | Error log entry contains all required details for troubleshooting: timestamp, employee identifier, task identifier, original status, attempted new status, error code/type, and descriptive error message |
| 9 | Verify that the error log includes technical details suitable for support team investigation | Log entry includes technical information such as API response codes, stack traces (if applicable), and system state information |
| 10 | Confirm that sensitive information (passwords, tokens) is not exposed in the logs | Error logs contain necessary troubleshooting information without exposing sensitive security credentials |

**Postconditions:**
- Error details are logged in the system
- Log entry is accessible to support teams
- Task status remains unchanged
- System is ready for subsequent troubleshooting or retry attempts
- No sensitive information is exposed in logs

---

